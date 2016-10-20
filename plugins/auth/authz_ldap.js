'use strict';

/**
 * authn_ldap.js
 * This haraka module implements authorization agains LDAP servers,
 * i.e. if the given user is allowed to use the given rcpt_to.
 */


//var mfaddr = connection.transaction.mail_from.address().toString();
// TODO: filter should check user owns mail_from address!
//       connection.transaction.rcpt_to is an array for that


exports.init_authz_ldap = function(next, server) {
    if (!server.notes.ldappool) {
        throw new Error('LDAP Pool not found! Make sure ldappool plugin is loaded first!');
    }
    else {
        this.pool = server.notes.ldappool;
    }
};

