'use strict';

var ldappool  = require('../pool');

var _set_up = function (done) {
    this.user = {
        uid : 'user1',
        dn : 'uid=user1,ou=users,dc=my-domain,dc=com',
        password : 'ykaHsOzEZD',
        mail : 'user1@my-domain.com'
    };
    this.cfg = {
        main : {
            server : [ 'ldap://localhost:389', 'ldaps://localhost:636' ],
            binddn : this.user.dn,
            bindpw : this.user.password,
            basedn : 'dc=my-domain,dc=com'
        }
    };
    done();
};

exports._set_config = {
    setUp : _set_up,
    'defaults' : function(test) {
        test.expect(9);
        var pool = new ldappool.LdapPool(this.cfg);
        var config = pool._set_config();
        test.equals(pool._set_config().toString(),
                    pool._set_config({}).toString());
        test.equals(['ldap://localhost:389'].toString(), config.servers.toString());
        test.equals(undefined, config.timeout);
        test.equals(false, config.tls_enabled);
        test.equals(undefined, config.tls_rejectUnauthorized);
        test.equals('sub', config.scope);
        test.equals(undefined, config.binddn);
        test.equals(undefined, config.bindpw);
        test.equals(undefined, config.basedn);
        test.done();
    },
    'userdef' : function(test) {
        test.expect(8);
        var pool = new ldappool.LdapPool(this.cfg);
        var config = pool._set_config({ main : {
            server : 'testserver',
            timeout : 10000,
            tls_enabled : true,
            tls_rejectUnauthorized : true,
            scope : 'one',
            binddn : 'binddn-test',
            bindpw : 'bindpw-test',
            basedn : 'basedn-test'
        }});
        test.equals('testserver', config.servers);
        test.equals(10000, config.timeout);
        test.equals(true, config.tls_enabled);
        test.equals(true, config.tls_rejectUnauthorized);
        test.equals('one', config.scope);
        test.equals('binddn-test', config.binddn);
        test.equals('bindpw-test', config.bindpw);
        test.equals('basedn-test', config.basedn);
        test.done();
    }
};

exports._get_ldapjs_config = {
    setUp : _set_up,
    'defaults' : function(test) {
        test.expect(3);
        var pool = new ldappool.LdapPool(this.cfg);
        var config = pool._get_ldapjs_config();
        test.equals('ldap://localhost:389', config.url);
        test.equals(undefined, config.timeout);
        test.equals(undefined, config.tlsOptions);
        test.done();
    },
    'userdef' : function(test) {
        test.expect(3);
        this.cfg.main.server = [ 'ldap://127.0.0.1:389' ];
        this.cfg.main.timeout = 42;
        this.cfg.main.tls_rejectUnauthorized = true;
        this.cfg.main.ldap_pool_size = 20;
        var pool = new ldappool.LdapPool(this.cfg);
        var config = pool._get_ldapjs_config();
        test.equals('ldap://127.0.0.1:389', config.url);
        test.equals(42, config.timeout);
        test.equals(true, config.tlsOptions.rejectUnauthorized);
        test.done();
    }
};

exports._create_client = {
    setUp : _set_up,
    'get valid and connected client' : function(test) {
        test.expect(3);
        var pool = new ldappool.LdapPool(this.cfg);
        var user = this.user;
        var tests = function (err, client) {
            test.equals(null, err);
            test.equals(undefined, client._starttls);
            client.bind(user.dn, user.password, function(err) {
                if (!err) {
                    test.ok(true);
                }
                test.done();
            });
        };
        pool._create_client(tests);
    },
    'client with tls' : function (test) {
        test.expect(2);
        this.cfg.main.tls_enabled = true;
        process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
        var testTls = function(err, client) {
            test.equals(null, err);
            test.ok(client._starttls.success);
            test.done();
        };
        var pool = new ldappool.LdapPool(this.cfg);
        pool._create_client(testTls);
    }
};

exports.close = {
    setUp : _set_up,
    'test if connections are closed after call' : function(test) {
        test.expect(4);
        var pool = new ldappool.LdapPool(this.cfg);
        test.equals(0, pool.pool['servers'].length);
        var testClose = function(err, client) {
            test.equals(true, client.connected);
            test.equals(undefined, client.unbound);
            pool.close(function(err) {
                test.equals(true, client.unbound);
                test.done();
            });
        };
        pool.get(testClose);
    }
};

exports._bind_default = {
    setUp : _set_up,
    'bind with given binddn / bindpw' : function(test) {
        test.expect(1);
        var pool = new ldappool.LdapPool(this.cfg);
        var tests = function(err, client) {
            test.equals(true, client.connected);
            test.done();
        };
        pool._bind_default(tests);
    },
    'bind with no binddn / bindpw' : function(test) {
        test.expect(1);
        this.cfg.main.binddn = undefined;
        this.cfg.main.bindpw = undefined;
        var pool = new ldappool.LdapPool(this.cfg);
        var tests = function(err, client) {
            test.equals(false, client.connected);
            test.done();
        };
        pool._bind_default(tests);
    },
    'bind with invalid binddn / bindpw' : function(test) {
        test.expect(1);
        this.cfg.main.binddn = 'invalid';
        this.cfg.main.bindpw = 'invalid';
        var pool = new ldappool.LdapPool(this.cfg);
        var tests = function(err, client) {
            test.equals('InvalidDnSyntaxError', err.name);
            test.done();
        };
        pool._bind_default(tests);
    }
};

exports.get = {
    setUp : _set_up,
    'test connection validity and pooling' : function(test) {
        test.expect(9);
        var pool = new ldappool.LdapPool(this.cfg);
        test.equals(0, pool.pool['servers'].length);
        var tests = function(err, client) {
            test.equals(null, err);
            test.equals(1, pool.pool['servers'].length);
            test.equals('ldap://localhost:389', client.url.href);
            pool.get(function(err, client) {
                test.equals(null, err);
                test.equals(2, pool.pool['servers'].length);
                test.equals('ldaps://localhost:636', client.url.href);
                pool.get(function(err, client) {
                    test.equals(2, pool.pool['servers'].length);
                    test.equals('ldap://localhost:389', client.url.href);
                    test.done();
                });
            });
        };
        pool.get(tests);
    }
};
