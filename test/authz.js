'use strict';

const assert    = require('assert')

const fixtures  = require('haraka-test-fixtures');
const Address   = require('address-rfc2821').Address;
const constants = require('haraka-constants');
const ldappool  = require('../pool');

function _set_up (done) {
    this.user = {
        uid : 'user1',
        dn : 'uid=user1,ou=users,dc=example,dc=com',
        password : 'ykaHsOzEZD',
        mail : 'user1@example.com'
    };
    this.plugin = require('../authz');
    this.connection = fixtures.connection.createConnection();
    this.connection.server = {
        notes: {
            ldappool : new ldappool.LdapPool({
                main : {
                    server : [ 'ldap://localhost:3389' ],
                    binddn : this.user.dn,
                    bindpw : this.user.password,
                    basedn : 'dc=example,dc=com'
                }
            })
        }
    };
    this.connection.server.notes.ldappool.config.authz = {
        searchfilter : '(&(objectclass=*)(uid=%u)(mailLocalAddress=%a))'
    };
    done();
}

describe('_verify_address', function () {

    beforeEach(_set_up)

    it('1 entry', function (done) {
        const user = this.user;
        this.plugin._verify_address(user.uid, user.mail, function (err, result) {
            assert.equal(true, result);
            done();
        }, this.connection);
    })

    it('0 entries', function (done) {
        this.plugin._verify_address('alien', 'unknown', function (err, result) {
            assert.ifError(err)
            assert.equal(false, result)
            done()
        }, this.connection);
    })

    it('2 entries', function (done) {
        const pool = this.connection.server.notes.ldappool;
        pool.config.authz.searchfilter =  '(&(objectclass=*)(|(uid=%u)(uid=user2)))';
        this.plugin._verify_address('user1', 'who cares', function (err, result) {
            assert.ifError(err)
            assert.equal(true, result);
            done();
        }, this.connection);
    })

    it('invalid search filter', function (done) {
        const user = this.user;
        const pool = this.connection.server.notes.ldappool;
        pool.config.authz.searchfilter =  '(&(objectclass=*)(|(uid=%u';
        this.plugin._verify_address(user.uid, user.mail, function (err, result) {
            assert.equal('unbalanced parens', err.message);
            assert.equal(false, result);
            done();
        }, this.connection);
    })

    it('no pool', function (done) {
        this.connection.server.notes.ldappool = undefined;
        const user = this.user;
        this.plugin._verify_address(user.uid, user.mail, function (err, userdn) {
            assert.equal('LDAP Pool not found!', err);
            assert.equal(false, userdn);
            done();
        }, this.connection);
    })
})

describe('_get_search_conf', function () {

    beforeEach(_set_up)

    it('get defaults', function (done) {
        const pool = this.connection.server.notes.ldappool;
        const opts = this.plugin._get_search_conf('testUid', 'testMail', this.connection);
        assert.equal(opts.basedn, pool.config.basedn);
        assert.equal(opts.filter, '(&(objectclass=*)(uid=testUid)(mailLocalAddress=testMail))');
        assert.equal(opts.scope, pool.config.scope);
        assert.equal(opts.attributes.toString(), ['dn'].toString());
        done();
    })

    it('get userdef', function (done) {
        const pool = this.connection.server.notes.ldappool;
        pool.config.authz.basedn = 'hop around as you like';
        pool.config.authz.searchfilter = '(&(objectclass=posixAccount)(uid=%u)(mail=%a))';
        pool.config.authz.scope = 'one two three';
        const opts = this.plugin._get_search_conf('testUid', 'testMail', this.connection);
        assert.equal(opts.basedn, 'hop around as you like');
        assert.equal(opts.filter, '(&(objectclass=posixAccount)(uid=testUid)(mail=testMail))');
        assert.equal(opts.scope, 'one two three');
        assert.equal(opts.attributes.toString(), ['dn'].toString());
        done();
    })
})

describe('check_authz', function () {

    beforeEach(_set_up)

    it('ok', function (done) {
        this.connection.notes = { auth_user : 'user1' };
        this.plugin.check_authz(function (err) {
            assert.equal(undefined, err);
            done();
        }, this.connection, [new Address('<user1@example.com>')]);
    })

    it('deny if not authorized', function (done) {
        const plugin = this.plugin;
        this.connection.notes = { auth_user : 'user1' };
        plugin.check_authz(function (err) {
            assert.equal(constants.deny, err);
            done();
        }, this.connection, [new Address('user2@example.com')]);
    })

    it('denysoft on error', function (done) {
        this.connection.server.notes.ldappool.config.authz.searchfilter =  '(&(objectclass=*)(|(uid=%u';
        this.connection.notes = { auth_user : 'user1' };
        this.plugin.check_authz(function (err) {
            assert.equal(constants.denysoft, err);
            done();
        }, this.connection, [new Address('user1@example.com')]);
    })

    it('ignore invalid params: missing auth_user', function (done) {
        this.plugin.check_authz(function (err) {
            assert.ifError(err);
            done();
        }, this.connection, [new Address('user1@example.com')]);
    })

    it('ignore invalid params: missing address', function (done) {
        this.plugin.check_authz(function (err) {
            assert.ifError(err);
            done();
        }, this.connection);
    })
})
