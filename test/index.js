'use strict';

const assert       = require('assert')

const fixtures     = require('haraka-test-fixtures');
const Address      = require('address-rfc2821').Address;
const btoa         = require('btoa');
const constants    = require('haraka-constants');
const pool         = require('../pool');

function _set_up (done) {
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
                    server : [ 'ldap://localhost:3389' ],
                    binddn : this.user.dn,
                    bindpw : this.user.password,
                    basedn : 'dc=my-domain,dc=com'
                }
            })
        }
    };
    done();
}

describe('handle_authn', function () {

    beforeEach(_set_up)

    it('ok with test user and PLAIN', function (done) {
        const connection = this.connection;
        connection.server.notes.ldappool.config.authn = {};
        connection.notes.allowed_auth_methods = ['PLAIN','LOGIN'];
        connection.notes.authenticating=true;
        connection.notes.auth_method='PLAIN';
        this.plugin.auth_plain = function (result) {
            assert.ok(true);
            done();
        };
        const params = [ btoa(`discard\0${this.user.uid}\0${this.user.password}`) ];
        this.plugin.handle_authn(function () {}, connection, params);
    })

    it('ok with test user and LOGIN', function (done) {
        const plugin = this.plugin;
        const connection = this.connection;
        connection.server.notes.ldappool.config.authn = {};
        connection.notes.allowed_auth_methods = ['PLAIN','LOGIN'];
        connection.notes.authenticating=true;
        connection.notes.auth_method='LOGIN';
        plugin.auth_login = function () {
            assert.ok(true);
            done();
        };
        const params = [ btoa(`discard\0${this.user.uid}\0${this.user.password}`) ];
        plugin.handle_authn(function () {}, connection, params);
    })

    it('ignore without connection.notes.authenticating', function (done) {
        const plugin = this.plugin;
        const connection = this.connection;
        connection.server.notes.ldappool.config.authn = {};
        plugin.handle_authn(function () {
            assert.ok(true);
            done();
        }, connection, [ '' ]);
    })

    it('ignore with unknown AUTH', function (done) {
        const plugin = this.plugin;
        const connection = this.connection;
        connection.server.notes.ldappool.config.authn = {};
        connection.notes.allowed_auth_methods = ['PLAIN','LOGIN'];
        connection.notes.authenticating=true;
        connection.notes.auth_method='OPENSESAME';
        plugin.handle_authn(function () {
            assert.ok(true);
            done();
        }, connection, [ '' ]);
    })

    it('next if ldappool.config.authn is not set', function (done) {
        const plugin = this.plugin;
        const connection = this.connection;
        plugin.handle_authn(function () {
            assert.ok(true);
            done();
        }, connection, [ '' ]);
    })
})

describe('hook_capabilities', function () {
    beforeEach(_set_up)

    it('no tls no auth', function (done) {
        const cb = function (rc, msg) {
            assert.ok(this.connection.capabilities.length === 0);
            done();
        }.bind(this);
        this.connection.using_tls = false;
        this.connection.capabilities = [];
        this.plugin.hook_capabilities(cb, this.connection);
    })

    it('tls ante portas, ready for auth login', function (done) {
        const cb = function (rc, msg) {
            assert.ok(this.connection.notes.allowed_auth_methods.length === 2);
            assert.ok(this.connection.notes.allowed_auth_methods[0] === 'PLAIN');
            assert.ok(this.connection.notes.allowed_auth_methods[1] === 'LOGIN');
            assert.ok(this.connection.capabilities[0] === 'AUTH PLAIN LOGIN');
            done();
        }.bind(this);
        this.connection.using_tls = true;
        this.connection.capabilities = [];
        this.plugin.hook_capabilities(cb, this.connection);
    })
})

describe('check_plain_passwd', function () {

    beforeEach(_set_up)

    it('basic functionality: valid login ok, invalid login fails', function (done) {
        const plugin = this.plugin;
        const user = this.user;
        const connection = this.connection;
        plugin._init_ldappool(function next () {
            connection.server.notes.ldappool.config.authn = {  };
            plugin.check_plain_passwd(connection, user.uid, user.password, function (result) {
                assert.equal(true, result);
                plugin.check_plain_passwd(connection, user.uid, 'invalid', function (result2) {
                    assert.equal(false, result2);
                    done();
                })
            })
        }, this.server);
    })
})

describe('aliases', function () {

    beforeEach(_set_up)

    it('basic functionality: resolve forwarding user', function (done) {
        const connection = this.connection;
        connection.transaction = { rcpt_to : [ 'forwarder@my-domain.com' ] };
        connection.server.notes.ldappool.config.aliases = {  };
        connection.server.notes.ldappool.config.aliases.searchfilter = '(&(objectclass=*)(mailLocalAddress=%a))';
        connection.server.notes.ldappool.config.aliases.attribute = 'mailRoutingAddress';
        this.plugin.aliases(function (result) {
            assert.equal(undefined, result);
            assert.equal('<user2@my-domain.com>', connection.transaction.rcpt_to.toString());
            done();
        }, connection, [ { address : () => {
            return 'forwarder@my-domain.com';
        }}]);
    })

    it('next if ldappool.config.aliases is not set', function (done) {
        this.plugin.aliases(function () {
            assert.ok(true);
            done();
        }, this.connection, [ ]);
    })
})

describe('check_rcpt', function () {

    beforeEach(_set_up)

    it('basic functionality: lookup recipient', function (done) {
        this.connection.server.notes.ldappool.config.rcpt_to = {
            searchfilter : '(&(objectclass=*)(mailLocalAddress=%a))'
        };
        this.plugin.check_rcpt(function (err) {
            assert.equal(constants.ok, err);
            done();
        }, this.connection, [{
            address : () => { return 'user1@my-domain.com'; }
        }]);
    })

    it('next if ldappool.config.rcpt_to is not set', function (done) {
        this.plugin.check_rcpt(function () {
            assert.ok(true);
            done();
        }, this.connection, [ ]);
    })
})

describe('check_authz', function () {

    beforeEach(_set_up)

    it('basic functionality: matching address', function (done) {
        this.connection.server.notes.ldappool.config.authz = {
            searchfilter : '(&(objectclass=*)(uid=%u)(mailLocalAddress=%a))'
        };
        this.connection.notes = { auth_user : 'user1' };
        this.plugin.check_authz(function (err) {
            assert.ifError(err);
            done();
        }, this.connection, [new Address('<user1@my-domain.com>')]);
    })

    it('next if ldappool.config.authz is not set', function (done) {
        this.plugin.check_authz(function () {
            assert.ok(true);
            done();
        }, this.connection, [ ]);
    })
})

describe('register', function () {

    beforeEach(_set_up)

    it('register sets master and child hooks to register pool', function (done) {
        assert.equal(false, this.plugin.register_hook.called);
        this.plugin.register();
        assert.equal('init_master', this.plugin.register_hook.args[0][0]);
        assert.equal('init_child', this.plugin.register_hook.args[1][0]);
        assert.equal('_init_ldappool', this.plugin.register_hook.args[0][1]);
        assert.equal('_init_ldappool', this.plugin.register_hook.args[1][1]);
        assert.equal('rcpt', this.plugin.register_hook.args[2][0]);
        assert.equal('aliases', this.plugin.register_hook.args[2][1]);
        assert.equal('rcpt', this.plugin.register_hook.args[3][0]);
        assert.equal('check_rcpt', this.plugin.register_hook.args[3][1]);
        assert.equal('mail', this.plugin.register_hook.args[4][0]);
        assert.equal('check_authz', this.plugin.register_hook.args[4][1]);
        done();
    })
})

describe('_load_ldap_ini', function () {

    beforeEach(_set_up)

    it('check if values get loaded and set', function (done) {
        this.plugin._init_ldappool(() => {
            this.plugin._load_ldap_ini();
            assert.equal('uid=user1,ou=users,dc=my-domain,dc=com', this.server.notes.ldappool.config.binddn);
            assert.equal('ykaHsOzEZD', this.server.notes.ldappool.config.bindpw);
            assert.equal('my-domain.com', this.server.notes.ldappool.config.basedn);
            assert.equal('base', this.server.notes.ldappool.config.scope);
        }, this.server);
        done();
    })

    it('set _tmp_pool_config if pool is not available', function (done) {
        const plugin = this.plugin;
        assert.equal(undefined, plugin._tmp_pool_config);
        plugin._load_ldap_ini();
        const conf = plugin._tmp_pool_config.main;
        assert.equal('uid=user1,ou=users,dc=my-domain,dc=com', conf.binddn);
        assert.equal('ykaHsOzEZD', conf.bindpw);
        assert.equal('my-domain.com', conf.basedn);
        assert.equal('base', conf.scope);
        done();
    })
})

describe('_init_ldappool', function () {

    beforeEach(_set_up)

    it('check if this.server.notes.ldappool is set correctly', function (done) {
        this.plugin._init_ldappool(() => {
            assert.equal(true, this.server.notes.ldappool instanceof pool.LdapPool);
            assert.equal(true, this.plugin._pool instanceof pool.LdapPool);
            done();
        }, this.server);
    })

    it('test proper _tmp_pool_config handling', function (done) {
        this.plugin._load_ldap_ini();
        this.plugin._init_ldappool(() => {
            const conf = this.plugin._pool.config;
            assert.equal('uid=user1,ou=users,dc=my-domain,dc=com', conf.binddn);
            assert.equal('ykaHsOzEZD', conf.bindpw);
            assert.equal('my-domain.com', conf.basedn);
            done();
        }, this.server);
    })
})

describe('shutdown', function () {
    beforeEach(_set_up)
    it('make sure ldappool gets closed', function (done) {
        this.plugin._init_ldappool(() => {
            this.server.notes.ldappool.get((err, client) => {
                this.plugin.shutdown(function () {
                    assert.equal(true, client.unbound);
                    done();
                });
            });
        }, this.server);
    })
})
