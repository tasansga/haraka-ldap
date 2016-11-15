'use strict';

var fixtures  = require('haraka-test-fixtures');
var constants = require('haraka-constants');
var ldappool  = require('../pool');

var _set_up = function (done) {
    this.user = {
        uid : 'user1',
        dn : 'uid=user1,ou=users,dc=my-domain,dc=com',
        password : 'ykaHsOzEZD',
        mail : 'user1@my-domain.com'
    };
    this.group = {
        dn : 'cn=postmaster,dc=my-domain,dc=com',
        mail : 'postmaster@my-domain.com',
        member : [
            'uid=user1,ou=users,dc=my-domain,dc=com',
            'uid=user2,ou=people,dc=my-domain,dc=com',
            'uid=nonunique,ou=users,dc=my-domain,dc=com'
        ]
    };
    this.plugin = require('../aliases');
    this.connection = fixtures.connection.createConnection();
    this.connection.transaction = {};
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
    this.connection.server.notes.ldappool.config.aliases = {
        subattribute : 'mailLocalAddress',
        attribute : 'member',
        searchfilter : '(&(objectclass=groupOfNames)(mailLocalAddress=%a))'
    };
    done();
};

exports._get_alias = {
    setUp : _set_up,
    'ok with test group' : function(test) {
        test.expect(3);
        var callback = function(err, result) {
            result.sort();
            test.equals('nonunique1@my-domain.com', result[0]);
            test.equals('user1@my-domain.com', result[1]);
            test.equals('user2@my-domain.com', result[2]);
            test.done();
        };
        this.connection.server.notes.ldappool.config.aliases.attribute_is_dn = true;
        this.plugin._get_alias(this.group.mail, callback, this.connection);
    },
    'ok with forwarding user' : function(test) {
        this.connection.server.notes.ldappool.config.aliases.searchfilter = '(&(objectclass=*)(mailLocalAddress=%a))';
        this.connection.server.notes.ldappool.config.aliases.attribute = 'mailRoutingAddress';
        test.expect(1);
        var callback = function(err, result) {
            test.equals('user2@my-domain.com', result[0]);
            test.done();
        };
        this.plugin._get_alias('forwarder@my-domain.com', callback, this.connection);
    },
    'empty result with invalid mail' : function(test) {
        test.expect(1);
        var callback = function(err, result) {
            test.expect(0, result.length);
            test.done();
        };
        this.plugin._get_alias('invalid@email', callback, this.connection);
    }
};

exports._get_search_conf_alias = {
    setUp : _set_up,
    'get defaults' : function(test) {
        var pool = this.connection.server.notes.ldappool;
        pool.config.aliases.searchfilter = undefined;
        pool.config.aliases.attribute = undefined;
        test.expect(4);
        var opts = this.plugin._get_search_conf_alias('testMail', this.connection);
        test.equals(opts.basedn, pool.config.basedn);
        test.equals(opts.filter, '(&(objectclass=*)(mail=testMail)(mailForwardAddress=*))');
        test.equals(opts.scope, pool.config.scope);
        test.equals(opts.attributes.toString(), ['mailForwardingAddress'].toString());
        test.done();
    },
    'get userdef' : function(test) {
        var pool = this.connection.server.notes.ldappool;
        pool.config.aliases.basedn = 'hop around as you like';
        pool.config.aliases.searchfilter = '(&(objectclass=posixAccount)(mail=%a))';
        pool.config.aliases.scope = 'one two three';
        test.expect(4);
        var opts = this.plugin._get_search_conf_alias('testMail', this.connection);
        test.equals(opts.basedn, 'hop around as you like');
        test.equals(opts.filter, '(&(objectclass=posixAccount)(mail=testMail))');
        test.equals(opts.scope, 'one two three');
        test.equals(opts.attributes.toString(), ['member'].toString());
        test.done();
    }
};

exports._resolve_dn_to_alias = {
    setUp : _set_up,
    'ok one' : function(test) {
        var plugin = this.plugin;
        var user = this.user;
        test.expect(1);
        var callback = function(err, result) {
            test.equals(user.mail, result);
            test.done();
        };
        this.plugin._resolve_dn_to_alias([this.user.dn], callback, this.connection);
    },
    'ok multiple' : function(test) {
        var plugin = this.plugin;
        var user = this.user;
        test.expect(3);
        var callback = function(err, result) {
            result.sort();
            test.equals('nonunique1@my-domain.com', result[0]);
            test.equals('user1@my-domain.com', result[1]);
            test.equals('user2@my-domain.com', result[2]);
            test.done();
        };
        this.plugin._resolve_dn_to_alias(this.group.member, callback, this.connection);
    },
    'empty array when unknown dn' : function(test) {
        var plugin = this.plugin;
        var user = this.user;
        test.expect(1);
        var callback = function(err, result) {
            test.equals(0, result.length);
            test.done();
        };
        this.plugin._resolve_dn_to_alias(['uid=unknown,dc=wherever,dc=com'], callback, this.connection);
    }
};

exports.aliases = {
    setUp : _set_up,
    'ignore if invalid call / no rcpt' : function(test) {
        var plugin = this.plugin;
        var connection = this.connection;
        test.expect(3);
        var noParams = function(result) {
            test.equals(undefined, result);
            plugin.aliases(noRcpt, connection, []);
        };
        var noRcpt = function(result) {
            test.equals(undefined, result);
            plugin.aliases(noRcptAddress, connection, [ {} ]);
        };
        var noRcptAddress = function(result) {
            test.equals(undefined, result);
            test.done();
        };
        plugin.aliases(noParams, connection);
    },
    'DENYSOFT if LDAP not usable': function(test) {
        var plugin = this.plugin;
        var user = this.user;
        test.expect(1);
        this.connection.server.notes.ldappool.config.aliases.searchfilter = '(&(objectclass=posixAccount)(mail=%a';
        var callback = function(result) {
            test.equals(constants.denysoft, result);
            test.done();
        };
        plugin.aliases(callback, this.connection, [ { address : function() {
            return user.mail;
        }}]);
    },
    'next if no results' : function(test) {
        var plugin = this.plugin;
        test.expect(1);
        var next = function(result) {
            test.equals(undefined, result);
            test.done();
        };
        plugin.aliases(next, this.connection, [ { address : function() {
            return 'unknown@mail';
        }}]);
    },
    'resolve group members' : function(test) {
        var plugin = this.plugin;
        var group = this.group;
        var connection = this.connection;
        connection.transaction = { rcpt_to : [ group.mail ] };
        this.connection.server.notes.ldappool.config.aliases.attribute_is_dn = true;
        var expected = [
            '<user1@my-domain.com>',
            '<user2@my-domain.com>',
            '<nonunique1@my-domain.com>'
        ];
        expected.sort();
        test.expect(2);
        var next = function(result) {
            test.equals(undefined, result);
            connection.transaction.rcpt_to.sort();
            test.equals(expected.toString(), connection.transaction.rcpt_to.toString());
            test.done();
        };
        plugin.aliases(next, connection, [ { address : function() {
            return group.mail;
        }}]);
    },
    'do not change non-aliased user' : function(test) {
        var plugin = this.plugin;
        var user = this.user;
        var connection = this.connection;
        connection.transaction = { rcpt_to : [ 'still the same' ] };
        test.expect(2);
        var next = function(result) {
            test.equals(undefined, result);
            test.equals('still the same', connection.transaction.rcpt_to.toString());
            test.done();
        };
        plugin.aliases(next, connection, [ { address : function() {
            return user.mail;
        }}]);
    },
    'resolve forwarding user' : function(test) {
        var plugin = this.plugin;
        var connection = this.connection;
        connection.transaction = { rcpt_to : [ 'forwarder@my-domain.com' ] };
        this.connection.server.notes.ldappool.config.aliases.searchfilter = '(&(objectclass=*)(mailLocalAddress=%a))';
        this.connection.server.notes.ldappool.config.aliases.attribute = 'mailRoutingAddress';
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
