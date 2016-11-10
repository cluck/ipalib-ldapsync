define([
    'freeipa/phases',
    'freeipa/reg',
    'freeipa/rpc',
    'freeipa/ipa',
    'freeipa/user'],
    function(phases, reg, rpc, IPA, user_mod) {

function get_item_by_attrval(array, attr, value) {
    for (var i=0, l=array.length; i<l; i++) {
        if (array[i][attr] === value) return array[i];
    }
    return null;
}

var exp = IPA.ldapsync = {};

exp.add_ldapsync_actions = function() {
    reg.action.register('user_ldap_sync_remotes', exp.user_ldap_sync_local);
    reg.action.register('user_ldap_sync_local', exp.user_ldap_sync_remotes);

    var facet = get_item_by_attrval(user_mod.entity_spec.facets, '$type', 'details');
    var section = get_item_by_attrval(facet.sections, 'name', 'identity');

    facet.actions.push({
        $factory: IPA.object_action,
        name: 'user_ldap_sync_remotes',
        method: 'ldap_sync_remotes',
        label: '@i18n:actions.user_ldap_sync_remotes',
        needs_confirm: false
    });
    facet.header_actions.push('user_ldap_sync_remotes');

    facet.actions.push({
        $factory: IPA.object_action,
        name: 'user_ldap_sync_local',
        method: 'ldap_sync_local',
        label: '@i18n:actions.user_ldap_sync_local',
        needs_confirm: false
    });
    facet.header_actions.push('user_ldap_sync_local');

    return true;
};

phases.on('registration', exp.add_ldapsync_actions);
//phases.on('customization', exp.add_rfid_pre_op);

return exp;
}); 

