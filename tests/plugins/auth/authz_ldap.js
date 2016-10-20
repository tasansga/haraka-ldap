'use strict';

var fixtures     = require('haraka-test-fixtures');
var ldappool     = require('../../../plugins/ldappool.js');

// test user data as defined in testdata.ldif
var users = [
    {
        uid : 'user1',
        dn : 'uid=user1,ou=users,dc=my-domain,dc=com',
        password : 'ykaHsOzEZD',
        mail : 'user1@my-domain.com'
    },
    {
        uid : 'user2',
        dn : 'uid=user2,ou=people,dc=my-domain,dc=com',
        password : 'KQD9zs,LGv',
        mail : 'user2@my-domain.com'
    },
    {
        uid : 'nonuniqe',
        dn : 'uid=nonunique,ou=users,dc=my-domain,dc=com',
        password : 'CZVm3,BLlx',
        mail : 'nonuniqe1@my-domain.com'
    },
    {
        uid : 'nonuniqe',
        dn : 'uid=nonunique,ou=people,dc=my-domain,dc=com',
        password : 'LsBHDGorAh',
        mail : 'nonuniqe2@my-domain.com'
    }
];
var _set_up =
        function (done) {
    this.users = users;
    this.plugin = new fixtures.plugin('auth/authz_ldap');
    this.plugin.cfg = {};
    this.connection = fixtures.connection.createConnection();
    this.plugin.init_authz_ldap(undefined, {
        notes : {
            ldappool : new ldappool.LdapPool({
                binddn : this.users[0].dn,
                bindpw : this.users[0].password,
                basedn : 'dc=my-domain,dc=com'
            })
        }
    });
    done();
};

exports.dummy = {
    setUp : _set_up,
    'no tests yet' : function(test) {
        test.expect(0);
        test.done();
    }
};
