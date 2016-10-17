'use strict';

var fixtures     = require('haraka-test-fixtures');
var ldappool     = require('../plugins/ldappool.js');

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

var _set_up = function (done) {
    this.users = users;
    this.plugin = new fixtures.plugin('auth/auth_ldap_ext');
    this.plugin.cfg = {};
    this.connection = fixtures.connection.createConnection();
    this.plugin.init_auth_ldap_ext(undefined, {
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

exports.verify_user = {
    setUp : _set_up,
    'verify test data' : function(test) {
        test.expect(this.users.length);
        var plugin = this.plugin;
        var counter = 0;
        var testUser = function(result) {
            test.equals(true, result);
            counter++;
            if (counter === users.length) {
                test.done();
            }
        };
        var users = this.users;
        this.users.forEach(function(user) {
            plugin._verify_user(user.dn, user.password, testUser);
        });
    },
    'safety check: wrong password fails' : function(test) {
        test.expect(1);
        this.plugin._verify_user(this.users[0].dn, 'wrong', function(ok) {
            test.equals(false, ok);
            test.done();
        });
    },
    'safety check: invalid dn fails' : function(test) {
        test.expect(1);
        this.plugin._verify_user('wrong', 'wrong', function(ok) {
            test.equals(false, ok);
            test.done();
        });
    }
};

exports.get_opts = {
    setUp : _set_up,
    'get defaults' : function(test) {
        test.expect(3);
        var opts = this.plugin._get_config('testUid');
        test.equals(opts.filter, '(&(objectclass=*)(uid=testUid))');
        test.equals(opts.scope, 'sub');
        test.equals(opts.attributes.toString(), ['dn', 'mail'].toString());
        test.done();
    },
    'get userdef' : function(test) {
        this.plugin.cfg.filter = '(&(objectclass=posixAccount)(uid=%u))';
        this.plugin.cfg.scope = 'single';
        this.plugin.cfg.mail_attribute = 'mailLocalAddress';
        test.expect(3);
        var opts = this.plugin._get_config('testUid');
        test.equals(opts.filter, '(&(objectclass=posixAccount)(uid=testUid))');
        test.equals(opts.scope, 'single');
        test.equals(opts.attributes.toString(), ['dn', 'mailLocalAddress'].toString());
        test.done();
    }
};

exports.get_dn_for_uid = {
    setUp : _set_up,
    'user 1 dn2uid' : function(test) {
        test.expect(2);
        var plugin = this.plugin;
        var user = this.users[0];
        plugin._get_dn_for_uid(user.uid, function (err, userdn) {
            test.equals(null, err);
            test.equals(userdn.toString(), user.dn);
            test.done();
        });
    },
    'nonunique dn2uid' : function(test) {
        test.expect(2);
        var plugin = this.plugin;
        plugin._get_dn_for_uid('nonunique', function (err, userdn) {
            test.equals(null, err);
            test.equals(2, userdn.length);
            test.done();
        });
    },
    'invalid uid' : function(test) {
        test.expect(2);
        var plugin = this.plugin;
        plugin._get_dn_for_uid('doesntexist', function (err, userdn) {
            test.equals(null, err);
            test.equals(0, userdn.length);
            test.done();
        });
    }
};

exports.hook_capabilities = {
    setUp : _set_up,
    'no tls no auth' : function(test) {
        var cb = function (rc, msg) {
            test.expect(1);
            test.ok(this.connection.capabilities.length === 0);
            test.done();
        }.bind(this);
        this.connection.using_tls = false;
        this.connection.capabilities = [];
        this.plugin.hook_capabilities(cb, this.connection);
    },
    'tls ante portas, ready for auth login' : function(test) {
        var cb = function (rc, msg) {
            test.expect(3);
            test.ok(this.connection.notes.allowed_auth_methods.length === 1);
            test.ok(this.connection.notes.allowed_auth_methods[0] === 'LOGIN');
            test.ok(this.connection.capabilities[0] === 'AUTH LOGIN');
            test.done();
        }.bind(this);
        this.connection.using_tls = true;
        this.connection.capabilities = [];
        this.plugin.hook_capabilities(cb, this.connection);
    }
};

exports.register = {
    setUp : _set_up
    // TODO
};

exports.check_plain_passwd = {
    setUp : _set_up,
    'check_plain_passwd with test users and invalid user' : function(test) {
        test.expect(5);
        var plugin = this.plugin;
        var users = this.users;
        var connection = this.connection;
        plugin.check_plain_passwd(connection, users[0].uid, users[0].password, function(result) {
            test.equals(true, result);
            plugin.check_plain_passwd(connection, users[1].uid, users[1].password, function(result) {
                test.equals(true, result);
                plugin.check_plain_passwd(connection, users[2].uid, users[2].password, function(result) {
                    test.equals(false, result);
                    plugin.check_plain_passwd(connection, users[3].uid, users[3].password, function(result) {
                        test.equals(false, result);
                        plugin.check_plain_passwd(connection, 'invalid', 'invalid', function(result) {
                            test.equals(false, result);
                            test.done();
                        });
                    });
                });
            });
        });
    }
};

