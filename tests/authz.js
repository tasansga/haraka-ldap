'use strict';

var fixtures  = require('haraka-test-fixtures');
var Address   = require('address-rfc2821').Address;
var constants = require('haraka-constants');
var ldappool  = require('../pool');


var _set_up = function (done) {
    this.user = {
        uid : 'user1',
        dn : 'uid=user1,ou=users,dc=my-domain,dc=com',
        password : 'ykaHsOzEZD',
        mail : 'user1@my-domain.com'
    };
    this.plugin = require('../authz');
    this.connection = fixtures.connection.createConnection();
    this.connection.server = {
        notes: {
            ldappool : new ldappool.LdapPool({
                main : {
                    binddn : this.user.dn,
                    bindpw : this.user.password,
                    basedn : 'dc=my-domain,dc=com'
                }
            })
        }
    };
    this.connection.server.notes.ldappool.config.authz = {
        searchfilter : '(&(objectclass=*)(uid=%u)(mailLocalAddress=%a))'
    };
    done();
};

exports._verify_address = {
    setUp : _set_up,
    '1 entry' : function(test) {
        test.expect(1);
        var plugin = this.plugin;
        var user = this.user;
        plugin._verify_address(user.uid, user.mail, function(err, result) {
            test.equals(true, result);
            test.done();
        }, this.connection);
    },
    '0 entries' : function(test) {
        test.expect(1);
        var plugin = this.plugin;
        plugin._verify_address('alien', 'unknown', function(err, result) {
            test.equals(false, result);
            test.done();
        }, this.connection);
    },
    '2 entries' : function(test) {
        test.expect(1);
        var plugin = this.plugin;
        var pool = this.connection.server.notes.ldappool;
        pool.config.authz.searchfilter =  '(&(objectclass=*)(|(uid=%u)(uid=user2)))';
        plugin._verify_address('user1', 'who cares', function(err, result) {
            test.equals(true, result);
            test.done();
        }, this.connection);
    },
    'invalid search filter' : function(test) {
        test.expect(2);
        var plugin = this.plugin;
        var user = this.user;
        var pool = this.connection.server.notes.ldappool;
        pool.config.authz.searchfilter =  '(&(objectclass=*)(|(uid=%u';
        plugin._verify_address(user.uid, user.mail, function(err, result) {
            test.equals('Error: (|(uid=user has unbalanced parentheses', err.toString());
            test.equals(false, result);
            test.done();
        }, this.connection);
    },
    'no pool' : function(test) {
        test.expect(2);
        var plugin = this.plugin;
        this.connection.server.notes.ldappool = undefined;
        var user = this.user;
        plugin._verify_address(user.uid, user.mail, function (err, userdn) {
            test.equals('LDAP Pool not found!', err);
            test.equals(false, userdn);
            test.done();
        }, this.connection);
    }
};

exports._get_search_conf = {
    setUp : _set_up,
    'get defaults' : function(test) {
        test.expect(4);
        var pool = this.connection.server.notes.ldappool;
        var opts = this.plugin._get_search_conf('testUid', 'testMail', this.connection);
        test.equals(opts.basedn, pool.config.basedn);
        test.equals(opts.filter, '(&(objectclass=*)(uid=testUid)(mailLocalAddress=testMail))');
        test.equals(opts.scope, pool.config.scope);
        test.equals(opts.attributes.toString(), ['dn'].toString());
        test.done();
    },
    'get userdef' : function(test) {
        var pool = this.connection.server.notes.ldappool;
        pool.config.authz.basedn = 'hop around as you like';
        pool.config.authz.searchfilter = '(&(objectclass=posixAccount)(uid=%u)(mail=%a))';
        pool.config.authz.scope = 'one two three';
        test.expect(4);
        var opts = this.plugin._get_search_conf('testUid', 'testMail', this.connection);
        test.equals(opts.basedn, 'hop around as you like');
        test.equals(opts.filter, '(&(objectclass=posixAccount)(uid=testUid)(mail=testMail))');
        test.equals(opts.scope, 'one two three');
        test.equals(opts.attributes.toString(), ['dn'].toString());
        test.done();
    }
};

exports.check_authz = {
    setUp : _set_up,
    'ok' : function(test) {
        var plugin = this.plugin;
        test.expect(1);
        var callback = function(err) {
            test.equals(undefined, err);
            test.done();
        };
        this.connection.notes = { auth_user : 'user1' };
        plugin.check_authz(callback, this.connection, [new Address('<user1@my-domain.com>')]);
    },
    'deny if not authorized' : function(test) {
        var plugin = this.plugin;
        test.expect(1);
        var callback = function(err) {
            test.equals(constants.deny, err);
            test.done();
        };
        this.connection.notes = { auth_user : 'user1' };
        plugin.check_authz(callback, this.connection, [new Address('user2@my-domain.com')]);
    },
    'denysoft on error' : function(test) {
        var plugin = this.plugin;
        test.expect(1);
        var callback = function(err) {
            test.equals(constants.denysoft, err);
            test.done();
        };
        this.connection.server.notes.ldappool.config.authz.searchfilter =  '(&(objectclass=*)(|(uid=%u';
        this.connection.notes = { auth_user : 'user1' };
        plugin.check_authz(callback, this.connection, [new Address('user1@my-domain.com')]);
    },
    'ignore invalid params: missing auth_user' : function(test) {
        var plugin = this.plugin;
        test.expect(1);
        var callback = function(err) {
            test.equals(undefined, err);
            test.done();
        };
        plugin.check_authz(callback, this.connection, [new Address('user1@my-domain.com')]);
    },
    'ignore invalid params: missing address' : function(test) {
        var plugin = this.plugin;
        test.expect(1);
        var callback = function(err) {
            test.equals(undefined, err);
            test.done();
        };
        plugin.check_authz(callback, this.connection);
    }
};
