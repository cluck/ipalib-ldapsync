# -*- coding: utf-8 -*-

from collections import OrderedDict
import codecs
import datetime
import glob
import re
import ssl

try:
    import configparser
except ImportError:
    import ConfigParser as configparser

import ldap3
from ldap3 import Server, Connection, SUBTREE
from ldap3 import MODIFY_ADD, MODIFY_DELETE, MODIFY_REPLACE

import ipalib
from ipalib import _
from ipalib import errors, output
from ipalib.parameters import Str
from ipalib.plugable import Registry
from ipalib.plugins import user
from ipalib.plugins.baseldap import (
        LDAPQuery,
        pkey_to_value,
        add_missing_object_class,
    )
from ipalib.plugins.internal import i18n_messages



# No other way to do this?:
i18n_messages.messages['actions'].update({
        'user_ldap_sync_remotes': _("Resync to external LDAP"),
        'user_ldap_sync_remotes_confirm': _("Resync to external LDAP?"),
        'user_ldap_sync_remotes_success': _("Resynced to external LDAP"),
        'user_ldap_sync_local': _("Resync from external LDAP"),
        'user_ldap_sync_local_confirm': _("Resync from external LDAP?"),
        'user_ldap_sync_local_success': _("Resynced from external LDAP"),
    })


register = Registry()



class LdapSyncManager(object):

    connections = dict()
    connection_ts = dict()

    def __init__(self, ldap, dn, changes, entry=None):
        self.ldap = ldap
        self.dn = dn
        if not entry:
            entry = ldap.get_entry(dn, ['objectclass', '*'])
        self.entry = entry
        if changes:
            for key in changes:
                self.entry[key] = changes[key]

    def get_remotes(self):
        for conffile in glob.iglob('/etc/ipa/ldapsync/*.server.conf'):
            config = configparser.RawConfigParser()
            config.optionxform = lambda s: s
            config.read(conffile)
            try:
                if config.get('main', 'disabled').lower() in ('1', 'yes', 'true'):
                    continue
            except (configparser.NoOptionError, configparser.NoSectionError):
                pass
            config.filename = conffile
            yield config

    def get_connection(self, config):
        conn = self.connections.get(config.filename)
        if not conn or self.connection_ts[config.filename] != os.stat(config.filename).st_mtime:
            conn = self.create_connecton(config)
            self.set_connection(config, conn)
        return conn

    def set_connection(self, config, conn):
        self.connection_ts[config.filename] = os.stat(config.filename).st_mtime
        self.connections[config.filename] = conn

    def create_connecton(self, config):
        try:
            authentication = config.get('main', 'auth').lower()
            if authentication == 'simple':
                authentication=ldap3.SIMPLE
            else:
                raise configparser.Error('not supported [main]auth = {0}'.format(authentication))
        except (configparser.NoOptionError, configparser.NoSectionError):
            authentication = ldap3.SIMPLE
        host = config.get('main', 'server')
        try:
            port = config.get('main', 'port')
        except (configparser.NoOptionError, configparser.NoSectionError):
            port = 389
        try:
            use_ssl = config.get('main', 'ssl') in ('1', 'yes', 'true')
        except (configparser.NoOptionError, configparser.NoSectionError):
            use_ssl = port == 636
        try:
            user = config.get('main', 'binddn')
        except (configparser.NoOptionError, configparser.NoSectionError):
            user = None 
        try:
            pwfile = config.get('main', 'password')
            with codecs.open(pwfile, 'r', 'utf-8') as f:
                password = f.read().rstrip('\n')
        except (configparser.NoOptionError, configparser.NoSectionError):
            pwfile = None
            password = None
        try:
            use_tls = False
            if config.get('main', 'tls').lower() in ('1', 'yes', 'true'):
                use_tls = True
        except (configparser.NoOptionError, configparser.NoSectionError):
            pass
        tls = None
        if use_tls:
            try:
                tls_key = config.get('tls', 'key')
            except (configparser.NoOptionError, configparser.NoSectionError):
                tls_key = None
            try:
                tls_cert = config.get('tls', 'cert')
            except (configparser.NoOptionError, configparser.NoSectionError):
                tls_cert = None
            try:
                tls_ca = config.get('tls', 'ca')
            except (configparser.NoOptionError, configparser.NoSectionError):
                tls_ca = None
            tls = ldap3.Tls(local_private_key_file=tls_key,
                      local_certificate_file=tls_cert,
                      validate=ssl.CERT_REQUIRED,
                      # version=ssl.PROTOCOL_TLSv1,
                      ca_certs_file=tls_ca
            )

        try:
            sasl_mech = config.get('sasl', 'mechanism')
        except (configparser.NoOptionError, configparser.NoSectionError):
            sasl_mech = 'EXTERNAL' if authentication != 'simple' else None
        try:
            sasl_cred = config.get('sasl', 'credentials')
        except (configparser.NoOptionError, configparser.NoSectionError):
            sasl_cred = 'username'
 
        server = Server(host=host, port=port, use_ssl=use_ssl, tls=tls)
        if authentication == ldap3.SIMPLE:
            conn = Connection(server, version=3,
                      authentication=authentication,
                      user=user, password=password,
                      pool_size=2, pool_lifetime=30,
                      check_names=True, auto_referrals=False, raise_exceptions=True)
        else:
            conn = Connection(server, version=3,
                      authentication=authentication,
                      sasl_mechanism=sasl_mech, sasl_credentials=sasl_cred,
                      pool_size=2, pool_lifetime=30,
                      check_names=True, auto_referrals=False, raise_exceptions=True)
        conn.open()
        if use_tls:
            conn.start_tls()
        if user:
            conn.bind()
        return conn
 
    def create_proto_entry(self, config, refr_entry, export=True):
        """The entry with the content expected on the receiving side.

        This is used to compute the LDAP modify operations.
        """
        proto_entry = OrderedDict()
        for proto_att0, refr_att in config.items('export' if export else 'import'):
            proto_att = proto_att0.strip('?*+')
            try:
                if ':' in refr_att:
                    refr_att, refr_tpl = refr_att.split(':', 1)
                    proto_vals = [refr_tpl.format(val=refr_entry[refr_att][i], **refr_entry) for i in range(0, len(refr_entry[refr_att]))]
                else:
                    proto_vals = refr_entry[refr_att]
            except KeyError:
                if proto_att0[-1] in '?*': # ?* is OK, + is not OK
                    continue
                else:
                    proto_vals = []   # means: empty/delete on dest
            proto_entry[proto_att] = proto_vals
            if not export and proto_att0[-1] not in '?*+':
                    if len(proto_entry[proto_att]) > 0:
                        proto_entry[proto_att] = proto_entry[proto_att][0]
                    else:
                        proto_entry[proto_att] = None
        return proto_entry

    def compute_ldapmod(self, proto_entry, current_entry):
        changes = OrderedDict()
        for proto_att, proto_vals in proto_entry.items():
            if proto_vals is None:
                proto_vals = []
            elif not isinstance(proto_vals, (list, tuple)):
                proto_vals = [proto_vals]
            if proto_att.lower() in ('dn', 'objectclass'):
                continue
            if proto_vals is not None and proto_att not in current_entry:
                if len(proto_vals):
                    changes[proto_att] = [(MODIFY_ADD, proto_vals)]
            elif set(proto_vals) != set(current_entry[proto_att]):
                changes[proto_att] = [(MODIFY_REPLACE, proto_vals)]
        for current_att in current_entry:
            if current_att.lower() in ('dn', 'objectclass'):
                continue
            if current_att not in proto_entry:
                changes[current_att] = [(MODIFY_DELETE, [])]
        return changes

    def update_remotes(self):
        for remote in self.get_remotes():
            conn = self.get_connection(remote)
            proto_attrs = [kv[0].rstrip('?*+') for kv in remote.items('export')]
            proto_entry = self.create_proto_entry(remote, self.entry, export=True)
            self.ldap.log.info(repr(proto_entry))
            try:
                conn.search(proto_entry['dn'][0], '(objectClass=*)', ldap3.BASE, attributes=proto_attrs)
            except ldap3.LDAPNoSuchObjectResult:
                # self.ldap.log.debug('object %s does not exist on remote', proto_entry['dn'][0])
                conn.add(proto_entry['dn'][0], proto_entry['objectclass'][0], proto_entry)
                continue
            for result in conn.response:
                if 'dn' not in result:
                    continue
                ldap_mod = self.compute_ldapmod(proto_entry, result['attributes'])
                if ldap_mod:
                    conn.modify(proto_entry['dn'][0], ldap_mod)

    def update_local(self):
        for remote in self.get_remotes():
            conn = self.get_connection(remote)
            proto_attrs = [kv[0].rstrip('?*+') for kv in remote.items('import')]
            refr_dn = self.create_proto_entry(remote, self.entry, export=True)['dn'][0]
            try:
                conn.search(refr_dn, '(objectClass=*)', ldap3.BASE, attributes=proto_attrs)
            except ldap3.LDAPNoSuchObjectResult:
                continue
            for result in conn.response:
                if 'dn' not in result:
                    continue
                proto_entry = self.create_proto_entry(remote, result['attributes'], export=False)
                ipalib.api.Command['user_mod'](**proto_entry)



def useradd_precallback(self, ldap, dn, entry, attrs_list, *keys, **options):
    lsm = LdapSyncManager(ldap, dn, entry)
    lsm.update_remotes()
    return dn

user.user_add.register_pre_callback(useradd_precallback)



def usermod_precallback(self, ldap, dn, entry, attrs_list, *keys, **options):
    lsm = LdapSyncManager(ldap, dn, entry)
    lsm.update_remotes()
    return dn

user.user_mod.register_pre_callback(usermod_precallback)


@register()
class user_ldap_sync_remotes(LDAPQuery):
    __doc__ = _('Resync to external LDAP.')

    has_output = output.standard_value
    msg_summary = _('Resynced %(value)s to external LDAP.')

    def execute(self, *keys, **options):
        dn = self.obj.get_dn(*keys, **options)
        entry = self.obj.backend.get_entry(dn, ['objectclass', '*'])

        lsm = LdapSyncManager(self, dn, None, entry)
        lsm.update_remotes()

        return dict(
            result=True,
            value=pkey_to_value(keys[0], options),
        )


@register()
class user_ldap_sync_local(LDAPQuery):
    __doc__ = _('Resync to local LDAP.')

    has_output = output.standard_value
    msg_summary = _('Resynced %(value)s from external LDAP."')

    def execute(self, *keys, **options):
        dn = self.obj.get_dn(*keys, **options)
        entry = self.obj.backend.get_entry(dn, ['objectclass', '*'])

        lsm = LdapSyncManager(self, dn, None, entry)
        lsm.update_local()

        return dict(
            result=True,
            value=pkey_to_value(keys[0], options),
        )

