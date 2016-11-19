'use strict';

var fixtures     = require('haraka-test-fixtures');
var Address      = require('address-rfc2821').Address;
var btoa         = require('btoa');
var pool         = require('../pool');

var _set_up = function (done) {
    this.user = {
        uid : 'user1',
        dn : 'uid=user1,ou=users,dc=my-domain,dc=com',
        password : 'ykaHsOzEZD',
        mail : 'user1@my-domain.com'
    };
    this.plugin = new fixtures.plugin('ldap');
    this.server = { notes: { } };
    this.cfg = {
        main : {
            binddn : this.user.dn,
            bindpw : this.user.password,
            basedn : 'dc=my-domain,dc=com'
        }
    };
    this.connection = fixtures.connection.createConnection();
    this.connection.server = {
        notes: {
            ldappool : new pool.LdapPool({
                main : {
                    binddn : this.user.dn,
                    bindpw : this.user.password,
                    basedn : 'dc=my-domain,dc=com'
                }
            })
        }
    };
    done();
};

exports.handle_authn = {
    setUp : _set_up,
    'ok with test user and PLAIN' : function(test) {
        test.expect(1);
        var plugin = this.plugin;
        var connection = this.connection;
        connection.server.notes.ldappool.config.authn = {};
        connection.notes.allowed_auth_methods = ['PLAIN','LOGIN'];
        connection.notes.authenticating=true;
        connection.notes.auth_method='PLAIN';
        plugin.auth_plain = function(result) {
            test.ok(true);
            test.done();
        };
        var params = [ btoa('discard\0' + this.user.uid + '\0' + this.user.password) ];
        plugin.handle_authn(function() {}, connection, params);
    },
    'ok with test user and LOGIN' : function(test) {
        test.expect(1);
        var plugin = this.plugin;
        var connection = this.connection;
        connection.server.notes.ldappool.config.authn = {};
        connection.notes.allowed_auth_methods = ['PLAIN','LOGIN'];
        connection.notes.authenticating=true;
        connection.notes.auth_method='LOGIN';
        plugin.auth_login = function() {
            test.ok(true);
            test.done();
        };
        var params = [ btoa('discard\0' + this.user.uid + '\0' + this.user.password) ];
        plugin.handle_authn(function() {}, connection, params);
    },
    'ignore without connection.notes.authenticating' : function(test) {
        test.expect(1);
        var plugin = this.plugin;
        var connection = this.connection;
        connection.server.notes.ldappool.config.authn = {};
        var next = function() {
            test.ok(true);
            test.done();
        };
        plugin.handle_authn(next, connection, [ '' ]);
    },
    'ignore with unknown AUTH' : function(test) {
        test.expect(1);
        var plugin = this.plugin;
        var connection = this.connection;
        connection.server.notes.ldappool.config.authn = {};
        connection.notes.allowed_auth_methods = ['PLAIN','LOGIN'];
        connection.notes.authenticating=true;
        connection.notes.auth_method='OPENSESAME';
        var next = function() {
            test.ok(true);
            test.done();
        };
        plugin.handle_authn(next, connection, [ '' ]);
    },
    'next if ldappool.config.authn is not set' : function(test) {
        test.expect(1);
        var plugin = this.plugin;
        var connection = this.connection;
        var next = function() {
            test.ok(true);
            test.done();
        };
        plugin.handle_authn(next, connection, [ '' ]);
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
            test.expect(4);
            test.ok(this.connection.notes.allowed_auth_methods.length === 2);
            test.ok(this.connection.notes.allowed_auth_methods[0] === 'PLAIN');
            test.ok(this.connection.notes.allowed_auth_methods[1] === 'LOGIN');
            test.ok(this.connection.capabilities[0] === 'AUTH PLAIN LOGIN');
            test.done();
        }.bind(this);
        this.connection.using_tls = true;
        this.connection.capabilities = [];
        this.plugin.hook_capabilities(cb, this.connection);
    }
};

exports.check_plain_passwd = {
    setUp : _set_up,
    'basic functionality: valid login ok, invalid login fails' : function(test) {
        test.expect(2);
        var plugin = this.plugin;
        var user = this.user;
        var connection = this.connection;
        var next = function() {
            connection.server.notes.ldappool.config.authn = {  };
            plugin.check_plain_passwd(connection, user.uid, user.password, function(result) {
                test.equals(true, result);
                plugin.check_plain_passwd(connection, user.uid, 'invalid', function(result) {
                    test.equals(false, result);
                    test.done();
                });
            });
        };
        plugin._init_ldappool(next, this.server);
    }
};

exports.aliases = {
    setUp : _set_up,
    'basic functionality: resolve forwarding user' : function(test) {
        var plugin = this.plugin;
        var connection = this.connection;
        connection.transaction = { rcpt_to : [ 'forwarder@my-domain.com' ] };
        connection.server.notes.ldappool.config.aliases = {  };
        connection.server.notes.ldappool.config.aliases.searchfilter = '(&(objectclass=*)(mailLocalAddress=%a))';
        connection.server.notes.ldappool.config.aliases.attribute = 'mailRoutingAddress';
        test.expect(2);
        var next = function(result) {
            test.equals(undefined, result);
            test.equals('<user2@my-domain.com>', connection.transaction.rcpt_to.toString());
            test.done();
        };
        plugin.aliases(next, connection, [ { address : function() {
            return 'forwarder@my-domain.com';
        }}]);
    }
};

exports.check_rcpt = {
    setUp : _set_up,
    'basic functionality: lookup recipient' : function(test) {
        var plugin = this.plugin;
        var connection = this.connection;
        connection.server.notes.ldappool.config.rcpt_to = {
            searchfilter : '(&(objectclass=*)(mailLocalAddress=%a))'
        };
        test.expect(1);
        var callback = function(err) {
            test.equals(undefined, err);
            test.done();
        };
        plugin.check_rcpt(callback, connection, [{
            address : function(){ return 'user1@my-domain.com'; }
        }]);
    }
};

exports.check_authz = {
    setUp : _set_up,
    'basic functionality: matching address' : function(test) {
        var plugin = this.plugin;
        test.expect(1);
        var callback = function(err) {
            test.equals(undefined, err);
            test.done();
        };
        this.connection.server.notes.ldappool.config.authz = {
            searchfilter : '(&(objectclass=*)(uid=%u)(mailLocalAddress=%a))'
        };
        this.connection.notes = { auth_user : 'user1' };
        plugin.check_authz(callback, this.connection, [new Address('<user1@my-domain.com>')]);
    }
};

exports.register = {
    setUp : _set_up,
    'register sets master and child hooks to register pool' : function(test) {
        test.expect(11);
        test.equals(false, this.plugin.register_hook.called);
        this.plugin.register();
        test.equals('init_master', this.plugin.register_hook.args[0][0]);
        test.equals('init_child', this.plugin.register_hook.args[1][0]);
        test.equals('_init_ldappool', this.plugin.register_hook.args[0][1]);
        test.equals('_init_ldappool', this.plugin.register_hook.args[1][1]);
        test.equals('rcpt', this.plugin.register_hook.args[2][0]);
        test.equals('aliases', this.plugin.register_hook.args[2][1]);
        test.equals('rcpt', this.plugin.register_hook.args[3][0]);
        test.equals('check_rcpt', this.plugin.register_hook.args[3][1]);
        test.equals('mail', this.plugin.register_hook.args[4][0]);
        test.equals('check_authz', this.plugin.register_hook.args[4][1]);
        test.done();
    }
};

exports._load_ldap_ini = {
    setUp : _set_up,
    'check if values get loaded and set' : function(test) {
        test.expect(4);
        var plugin = this.plugin;
        var server = this.server;
        var next = function() {
            plugin._load_ldap_ini();
            test.equals('uid=user1,ou=users,dc=my-domain,dc=com', server.notes.ldappool.config.binddn);
            test.equals('ykaHsOzEZD', server.notes.ldappool.config.bindpw);
            test.equals('my-domain.com', server.notes.ldappool.config.basedn);
            test.equals('base', server.notes.ldappool.config.scope);
        };
        plugin._init_ldappool(next, server);
        test.done();
    },
    'set _tmp_pool_config if pool is not available' : function(test) {
        test.expect(5);
        var plugin = this.plugin;
        test.equals(undefined, plugin._tmp_pool_config);
        plugin._load_ldap_ini();
        var conf = plugin._tmp_pool_config.main;
        test.equals('uid=user1,ou=users,dc=my-domain,dc=com', conf.binddn);
        test.equals('ykaHsOzEZD', conf.bindpw);
        test.equals('my-domain.com', conf.basedn);
        test.equals('base', conf.scope);
        test.done();
    }
};

exports._init_ldappool = {
    setUp : _set_up,
    'check if this.server.notes.ldappool is set correctly' : function(test) {
        test.expect(2);
        var plugin = this.plugin;
        var server = this.server;
        var next = function() {
            test.equals(true, server.notes.ldappool instanceof pool.LdapPool);
            test.equals(true, plugin._pool instanceof pool.LdapPool);
            test.done();
        };
        plugin._init_ldappool(next, server);
    },
    'test proper _tmp_pool_config handling' : function(test) {
        test.expect(3);
        var plugin = this.plugin;
        plugin._load_ldap_ini();
        var server = this.server;
        var next = function() {
            var conf = plugin._pool.config;
            test.equals('uid=user1,ou=users,dc=my-domain,dc=com', conf.binddn);
            test.equals('ykaHsOzEZD', conf.bindpw);
            test.equals('my-domain.com', conf.basedn);
            test.done();
        };
        plugin._init_ldappool(next, server);
    }
};

exports.shutdown = {
    setUp : _set_up,
    'make sure ldappool gets closed' : function(test) {
        test.expect(1);
        var plugin = this.plugin;
        var server = this.server;
        var next = function() {
            server.notes.ldappool.get(function(err, client) {
                plugin.shutdown(function() {
                    test.equals(true, client.unbound);
                    test.done();
                });
            });
        };
        plugin._init_ldappool(next, server);
    }
};
