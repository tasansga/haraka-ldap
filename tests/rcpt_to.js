'use strict';

var fixtures     = require('haraka-test-fixtures');
var constants    = require('haraka-constants');
var ldappool     = require('../pool');

var _set_up = function (done) {
    this.user = {
        uid : 'user1',
        dn : 'uid=user1,ou=users,dc=my-domain,dc=com',
        password : 'ykaHsOzEZD',
        mail : 'user1@my-domain.com'
    };
    this.plugin = require('../rcpt_to');
    this.connection = fixtures.connection.createConnection();
    this.connection.transaction = { };
    this.connection.server = {
        notes : {
            ldappool : new ldappool.LdapPool({
                main : {
                    binddn : this.user.dn,
                    bindpw : this.user.password,
                    basedn : 'dc=my-domain,dc=com'
                }
            })
        }
    };
    this.connection.server.notes.ldappool.config.rcpt_to = {
        searchfilter : '(&(objectclass=*)(mailLocalAddress=%a))'
    };
    done();
};

exports._verify_existence = {
    setUp : _set_up,
    'default user' : function(test) {
        test.expect(1);
        var plugin = this.plugin;
        var user = this.user;
        plugin._verify_existence(user.mail, function(err, result) {
            test.equals(true, result);
            test.done();
        }, this.connection);
    },
    'invalid address' : function(test) {
        test.expect(1);
        var plugin = this.plugin;
        plugin._verify_existence('unknown', function(err, result) {
            test.equals(false, result);
            test.done();
        }, this.connection);
    },
    'invalid search filter' : function(test) {
        test.expect(2);
        var plugin = this.plugin;
        var user = this.user;
        this.connection.server.notes.ldappool.config.rcpt_to.searchfilter =  '(&(objectclass=*)(|(mail=%a';
        plugin._verify_existence(user.mail, function(err, result) {
            test.equals('Error: (|(mail=user1@my-domain.co has unbalanced parentheses', err.toString());
            test.equals(false, result);
            test.done();
        }, this.connection);
    },
    'no pool' : function(test) {
        test.expect(2);
        var plugin = this.plugin;
        var user = this.user;
        this.connection.server.notes.ldappool = undefined;
        plugin._verify_existence(user.mail, function (err, userdn) {
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
        var opts = this.plugin._get_search_conf('testMail', this.connection);
        var pool = this.connection.server.notes.ldappool;
        test.equals(opts.basedn, pool.config.basedn);
        test.equals(opts.filter, '(&(objectclass=*)(mailLocalAddress=testMail))');
        test.equals(opts.scope, pool.config.scope);
        test.equals(opts.attributes.toString(), ['dn'].toString());
        test.done();
    },
    'get userdef' : function(test) {
        this.connection.server.notes.ldappool.config.rcpt_to.basedn = 'hop around as you like';
        this.connection.server.notes.ldappool.config.rcpt_to.searchfilter = '(&(objectclass=posixAccount)(mail=%a))';
        this.connection.server.notes.ldappool.config.rcpt_to.scope = 'one two three';
        test.expect(4);
        var opts = this.plugin._get_search_conf('testMail', this.connection);
        test.equals(opts.basedn, 'hop around as you like');
        test.equals(opts.filter, '(&(objectclass=posixAccount)(mail=testMail))');
        test.equals(opts.scope, 'one two three');
        test.equals(opts.attributes.toString(), ['dn'].toString());
        test.done();
    }
};

exports.check_rcpt = {
    setUp : _set_up,
    'ok' : function(test) {
        var plugin = this.plugin;
        test.expect(1);
        var callback = function(err) {
            test.equals(constants.ok, err);
            test.done();
        };
        plugin.check_rcpt(callback, this.connection, [{
            address : function(){ return 'user1@my-domain.com'; }
        }]);
    },
    'denysoft on error' : function(test) {
        var plugin = this.plugin;
        test.expect(1);
        var callback = function(err) {
            test.equals(constants.denysoft, err);
            test.done();
        };
        this.connection.server.notes.ldappool.config.rcpt_to.searchfilter =  '(&(objectclass=*)(|(mail=%a';
        plugin.check_rcpt(callback, this.connection, [{
            address : function(){ return 'user1@my-domain.com'; }
        }]);
    },
    'ignore if missing params[0]' : function(test) {
        var plugin = this.plugin;
        test.expect(1);
        var callback = function(err) {
            test.equals(undefined, err);
            test.done();
        };
        plugin.check_rcpt(callback, this.connection, []);
    },
    'deny on invalid address' : function(test) {
        var plugin = this.plugin;
        test.expect(1);
        var callback = function(err) {
            test.equals(constants.deny, err);
            test.done();
        };
        plugin.check_rcpt(callback, this.connection, [{
            address : function(){ return 'unknown@address'; }
        }]);
    }
};
