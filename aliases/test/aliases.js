'use strict';

var fixtures     = require('haraka-test-fixtures');
var ldappool     = require('haraka-plugin-ldap-pool');

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
    this.plugin = new fixtures.plugin('ldap-aliases');
    this.plugin.cfg = { main : { } };
    this.connection = fixtures.connection.createConnection();
    this.connection.transaction = { };
    this.plugin.init_ldap_aliases(function(){}, {
        notes : {
            ldappool : new ldappool.LdapPool({
                binddn : this.user.dn,
                bindpw : this.user.password,
                basedn : 'dc=my-domain,dc=com'
            })
        }
    });
    this.plugin.cfg.main.subattribute = 'mailLocalAddress';
    this.plugin.cfg.main.attribute = 'member';
    this.plugin.cfg.main.searchfilter = '(&(objectclass=groupOfNames)(mailLocalAddress=%a))';
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
        this.plugin.cfg.main.attribute_is_dn = true;
        this.plugin._get_alias(this.group.mail, callback, this.connection);
    },
    'ok with forwarding user' : function(test) {
        this.plugin.cfg.main.searchfilter = '(&(objectclass=*)(mailLocalAddress=%a))';
        this.plugin.cfg.main.attribute = 'mailRoutingAddress';
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
        this.plugin.cfg.main.searchfilter = undefined;
        this.plugin.cfg.main.attribute = undefined;
        test.expect(4);
        var opts = this.plugin._get_search_conf_alias('testMail');
        test.equals(opts.basedn, this.plugin.pool.config.basedn);
        test.equals(opts.filter, '(&(objectclass=*)(mail=testMail)(mailForwardAddress=*))');
        test.equals(opts.scope, this.plugin.pool.config.scope);
        test.equals(opts.attributes.toString(), ['mailForwardingAddress'].toString());
        test.done();
    },
    'get userdef' : function(test) {
        this.plugin.cfg.main.basedn = 'hop around as you like';
        this.plugin.cfg.main.searchfilter = '(&(objectclass=posixAccount)(mail=%a))';
        this.plugin.cfg.main.scope = 'one two three';
        test.expect(4);
        var opts = this.plugin._get_search_conf_alias('testMail');
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

exports.register = {
    setUp : _set_up,
    'set master and child hooks to gain pool access' : function(test) {
        test.expect(7);
        test.equals(false, this.plugin.register_hook.called);
        this.plugin.register();
        test.equals('init_master', this.plugin.register_hook.args[0][0]);
        test.equals('init_child', this.plugin.register_hook.args[1][0]);
        test.equals('rcpt', this.plugin.register_hook.args[2][0]);
        test.equals('init_ldap_aliases', this.plugin.register_hook.args[0][1]);
        test.equals('init_ldap_aliases', this.plugin.register_hook.args[1][1]);
        test.equals('aliases', this.plugin.register_hook.args[2][1]);
        test.done();
    },
    'load configuration file' : function(test) {
        var plugin = this.plugin;
        test.expect(5);
        this.plugin.register();
        test.equals('sub', plugin.cfg.main.scope);
        test.equals('(&(objectclass=groupOfNames)(mailLocalAddress=%a))', plugin.cfg.main.searchfilter);
        test.equals('member', plugin.cfg.main.attribute);
        test.ok(plugin.cfg.main.attribute_is_dn);
        test.equals('mailLocalAddress', plugin.cfg.main.subattribute);
        test.done();
    }
};

exports.init_ldap_aliases = {
    setUp : _set_up,
    'call next' : function(test) {
        var plugin = this.plugin;
        test.expect(1);
        var callback = function() {
            test.ok(true);
            test.done();
        };
        plugin.init_ldap_aliases(callback, { notes : { ldappool : {} } });
    },
    'no pool' : function(test) {
        var plugin = this.plugin;
        test.expect(1);
        plugin.pool = undefined;
        var callback = function() {
            test.equals(undefined, plugin.pool);
            test.done();
        };
        plugin.init_ldap_aliases(callback, { notes : { } });
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
        this.plugin.cfg.main.searchfilter = '(&(objectclass=posixAccount)(mail=%a';
        var callback = function(result) {
            test.equals(DENYSOFT, result);
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
        this.plugin.cfg.main.attribute_is_dn = true;
        var expected = [
            '<user1@my-domain.com>',
            '<user2@my-domain.com>',
            '<nonunique1@my-domain.com>'
        ];
        expected.sort();
        test.expect(2);
        var next = function(result) {
            test.equals(OK, result);
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
        this.plugin.cfg.main.searchfilter = '(&(objectclass=*)(mailLocalAddress=%a))';
        this.plugin.cfg.main.attribute = 'mailRoutingAddress';
        test.expect(2);
        var next = function(result) {
            test.equals(OK, result);
            test.equals('<user2@my-domain.com>', connection.transaction.rcpt_to.toString());
            test.done();
        };
        plugin.aliases(next, connection, [ { address : function() {
            return 'forwarder@my-domain.com';
        }}]);
    }
};
