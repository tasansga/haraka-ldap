'use strict';

const assert = require('assert')

const ldappool = require('../pool');

const testUser = {
    uid : 'user1',
    dn : 'uid=user1,ou=users,dc=example,dc=com',
    password : 'ykaHsOzEZD',
    mail : 'user1@example.com'
};
Object.freeze(testUser)

const testCfg = {
    main : {
        server : [ 'ldap://localhost:3389', 'ldaps://localhost:3636' ],
        binddn : testUser.dn,
        bindpw : testUser.password,
        basedn : 'dc=example,dc=com'
    }
};
Object.freeze(testCfg)

function _set_up () {
    this.user = testUser;
    this.cfg = testCfg;
}

describe('_set_config', () => {
    beforeEach(_set_up);

    it('defaults', (done) => {
        const pool = new ldappool.LdapPool(testCfg);
        const config = pool._set_config();
        assert.equal(pool._set_config().toString(), pool._set_config({}).toString());
        assert.equal(['ldap://localhost:389'].toString(), config.servers.toString());
        assert.equal(undefined, config.timeout);
        assert.equal(false, config.tls_enabled);
        assert.equal(undefined, config.tls_rejectUnauthorized);
        assert.equal('sub', config.scope);
        assert.equal(undefined, config.binddn);
        assert.equal(undefined, config.bindpw);
        assert.equal(undefined, config.basedn);
        done()
    })

    it('userdef', () => {
        const pool = new ldappool.LdapPool(testCfg);
        const cfg = { main : {
            server : 'testserver',
            timeout : 10_000,
            tls_enabled : true,
            tls_rejectUnauthorized : true,
            scope : 'one',
            binddn : 'binddn-test',
            bindpw : 'bindpw-test',
            basedn : 'basedn-test'
        }}
        const config = pool._set_config(cfg);
        assert.equal('testserver', config.servers);
        assert.equal(10000, config.timeout);
        assert.equal(true, config.tls_enabled);
        assert.equal(true, config.tls_rejectUnauthorized);
        assert.equal('one', config.scope);
        assert.equal('binddn-test', config.binddn);
        assert.equal('bindpw-test', config.bindpw);
        assert.equal('basedn-test', config.basedn);
    })
})

describe('_get_ldapjs_config', function () {
    beforeEach(_set_up);

    it('defaults', function (done) {
        const pool = new ldappool.LdapPool(this.cfg);
        const config = pool._get_ldapjs_config();
        assert.equal('ldap://localhost:3389', config.url);
        assert.equal(undefined, config.timeout);
        assert.equal(undefined, config.tlsOptions);
        done();
    })

    it('userdef', function (done) {
        const cfg = Object.assign({}, testCfg)
        cfg.main.server = [ 'ldap://127.0.0.1:3389' ];
        cfg.main.timeout = 42;
        cfg.main.tls_rejectUnauthorized = true;
        cfg.main.ldap_pool_size = 20;
        const pool = new ldappool.LdapPool(cfg);
        const config = pool._get_ldapjs_config();
        assert.equal('ldap://127.0.0.1:3389', config.url);
        assert.equal(42, config.timeout);
        assert.equal(true, config.tlsOptions.rejectUnauthorized);
        done();
    })
})

describe('_create_client', function () {

    beforeEach(_set_up);

    it('get valid and connected client', function (done) {
        const pool = new ldappool.LdapPool(this.cfg);
        const user = this.user;
        pool._create_client(function (err, client) {
            assert.ifError(err);
            assert.equal(undefined, client._starttls);
            client.bind(user.dn, user.password, function (err2) {
                assert.ifError(err2)
                done();
            });
        });
    })

    it('client with tls', function (done) {
        this.cfg.main.tls_enabled = true;
        process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
        const pool = new ldappool.LdapPool(this.cfg);
        pool._create_client(function (err, client) {
            assert.ifError(err);
            assert.ok(client._starttls.success);
            done();
        });
    })
})

describe('close', function () {

    beforeEach(_set_up);

    it('test if connections are closed after call', function (done) {
        const pool = new ldappool.LdapPool(this.cfg);
        assert.equal(0, pool.pool.servers.length);
        pool.get(function (err, client) {
            assert.equal(true, client.connected);
            assert.equal(undefined, client.unbound);
            pool.close((err2) => {
                assert.ifError(err2)
                assert.equal(true, client.unbound);
                done();
            })
        })
    })
})

describe('_bind_default', function () {

    beforeEach(_set_up);

    it('bind with given binddn / bindpw', function (done) {
        const pool = new ldappool.LdapPool(this.cfg);
        pool._bind_default((err, client) => {
            assert.equal(true, client.connected);
            done();
        });
    })

    it('bind with no binddn / bindpw', (done) => {
        const cfg = JSON.parse(JSON.stringify(testCfg))
        cfg.main.binddn = undefined;
        cfg.main.bindpw = undefined;

        const pool = new ldappool.LdapPool(cfg);
        pool._bind_default((err, client) => {
            assert.equal(false, client.connected);
            done();
        })
    })

    it('bind with invalid binddn / bindpw', (done) => {
        const cfg = JSON.parse(JSON.stringify(testCfg))
        cfg.main.binddn = 'invalid';
        cfg.main.bindpw = 'invalid';
        const pool = new ldappool.LdapPool(cfg);
        pool._bind_default((err, client) => {
            assert.equal('InvalidDnSyntaxError', err.name);
            done();
        });
    })
})

describe('get', () => {
    beforeEach(_set_up);

    it('test connection validity and pooling', (done) => {
        const pool = new ldappool.LdapPool(testCfg);
        assert.equal(0, pool.pool.servers.length);
        pool.get((err, client) => {
            assert.equal(null, err);
            assert.equal(1, pool.pool.servers.length);
            assert.equal('ldap://localhost:3389', client?.url?.href);
            pool.get((err2, client2) => {
                assert.equal(null, err2);
                assert.equal(2, pool.pool.servers.length);
                assert.equal('ldaps://localhost:3636', client2?.url?.href);
                pool.get((err3, client3) => {
                    assert.equal(2, pool.pool.servers.length);
                    assert.equal('ldap://localhost:3389', client3?.url?.href);
                    done();
                })
            })
        })
    })

    after(_set_up)
})
