'use strict';

var fixtures     = require('haraka-test-fixtures');
var ldappool     = require('../../plugins/ldappool.js');

var _set_up = function (done) {
    this.user = {
        uid : 'user1',
        dn : 'uid=user1,ou=users,dc=my-domain,dc=com',
        password : 'ykaHsOzEZD',
        mail : 'user1@my-domain.com'
    };
    this.plugin = new fixtures.plugin('rcpt_to.in_ldap');
    this.plugin.cfg = { main : { } };
    this.connection = fixtures.connection.createConnection();
    this.connection.transaction = { };
    this.plugin.init_rcpt_to_in_ldap(function(){}, {
        notes : {
            ldappool : new ldappool.LdapPool({
                binddn : this.user.dn,
                bindpw : this.user.password,
                basedn : 'dc=my-domain,dc=com'
            })
        }
    });
    this.plugin.cfg.main.filter =  '(&(objectclass=*)(mailLocalAddress=%a))';
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
        });
    },
    'invalid address' : function(test) {
        test.expect(1);
        var plugin = this.plugin;
        plugin._verify_existence('unknown', function(err, result) {
            test.equals(false, result);
            test.done();
        });
    },
    'invalid search filter' : function(test) {
        test.expect(2);
        var plugin = this.plugin;
        var user = this.user;
        plugin.cfg.main.filter =  '(&(objectclass=*)(|(mail=%a';
        plugin._verify_existence(user.mail, function(err, result) {
            test.equals('Error: (|(mail=user1@my-domain.co has unbalanced parentheses', err.toString());
            test.equals(false, result);
            test.done();
        });
    },
    'no pool' : function(test) {
        test.expect(2);
        var plugin = this.plugin;
        plugin.pool = undefined;
        var user = this.user;
        plugin._verify_existence(user.mail, function (err, userdn) {
            test.equals('LDAP Pool not found!', err);
            test.equals(false, userdn);
            test.done();
        });
    }
};

exports._get_search_conf = {
    setUp : _set_up,
    'get defaults' : function(test) {
        test.expect(3);
        var opts = this.plugin._get_search_conf('testMail');
        test.equals(opts.filter, '(&(objectclass=*)(mailLocalAddress=testMail))');
        test.equals(opts.scope, this.plugin.pool.config.scope);
        test.equals(opts.attributes.toString(), ['dn'].toString());
        test.done();
    },
    'get userdef' : function(test) {
        this.plugin.cfg.main.filter = '(&(objectclass=posixAccount)(mail=%a))';
        this.plugin.cfg.main.scope = 'one';
        test.expect(3);
        var opts = this.plugin._get_search_conf('testMail');
        test.equals(opts.filter, '(&(objectclass=posixAccount)(mail=testMail))');
        test.equals(opts.scope, 'one');
        test.equals(opts.attributes.toString(), ['dn'].toString());
        test.done();
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
        test.equals('init_rcpt_to_in_ldap', this.plugin.register_hook.args[0][1]);
        test.equals('init_rcpt_to_in_ldap', this.plugin.register_hook.args[1][1]);
        test.equals('check_rcpt', this.plugin.register_hook.args[2][1]);
        test.done();
    },
    'load configuration file' : function(test) {
        var plugin = this.plugin;
        test.expect(2);
        this.plugin.register();
        test.equals('sub', plugin.cfg.main.scope);
        test.equals('(&(objectclass=*)(mail=%a))', plugin.cfg.main.searchfilter);
        test.done();
    }
};

exports.init_rcpt_to_in_ldap = {
    setUp : _set_up,
    'call next' : function(test) {
        var plugin = this.plugin;
        test.expect(1);
        var callback = function() {
            test.ok(true);
            test.done();
        };
        plugin.init_rcpt_to_in_ldap(callback, { notes : { ldappool : {} } });
    },
    'no pool' : function(test) {
        var plugin = this.plugin;
        test.expect(1);
        plugin.pool = undefined;
        var callback = function() {
            test.equals(undefined, plugin.pool);
            test.done();
        };
        plugin.init_rcpt_to_in_ldap(callback, { notes : { } });
    }
};

exports.check_rcpt = {
    setUp : _set_up,
    'ok' : function(test) {
        var plugin = this.plugin;
        test.expect(1);
        var callback = function(err) {
            test.equals(undefined, err);
            test.done();
        };
        this.connection.transaction.rcpt_to = ['user1@my-domain.com'];
        plugin.check_rcpt(callback, this.connection, []);
    },
    'denysoft on error' : function(test) {
        var plugin = this.plugin;
        test.expect(1);
        var callback = function(err) {
            test.equals(DENYSOFT, err);
            test.done();
        };
        plugin.cfg.main.filter =  '(&(objectclass=*)(|(mail=%a';
        this.connection.transaction.rcpt_to = ['user1@my-domain.com'];
        plugin.check_rcpt(callback, this.connection, []);
    },
    'denysoft on missing rcpt_to array' : function(test) {
        var plugin = this.plugin;
        test.expect(1);
        var callback = function(err) {
            test.equals(DENYSOFT, err);
            test.done();
        };
        this.connection.transaction.rcpt_to = undefined;
        plugin.check_rcpt(callback, this.connection, []);
    },
    'denysoft on missing rcpt_to content' : function(test) {
        var plugin = this.plugin;
        test.expect(1);
        var callback = function(err) {
            test.equals(DENYSOFT, err);
            test.done();
        };
        this.connection.transaction.rcpt_to = [ ];
        plugin.check_rcpt(callback, this.connection, []);
    },
    'deny on invalid address' : function(test) {
        var plugin = this.plugin;
        test.expect(1);
        var callback = function(err) {
            test.equals(DENY, err);
            test.done();
        };
        this.connection.transaction.rcpt_to = [ 'unknown@address' ];
        plugin.check_rcpt(callback, this.connection, []);
    }
};
