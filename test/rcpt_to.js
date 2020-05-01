'use strict';

const assert       = require('assert')

const fixtures     = require('haraka-test-fixtures');
const constants    = require('haraka-constants');
const ldappool     = require('../pool');

function _set_up (done) {
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
                    server : [ 'ldap://localhost:3389' ],
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
}

describe('_verify_existence', function () {

    beforeEach(_set_up)

    it('default user', function (done) {
        this.plugin._verify_existence(this.user.mail, function (err, result) {
            assert.equal(true, result);
            done();
        }, this.connection);
    })

    it('invalid address', function (done) {
        this.plugin._verify_existence('unknown', function (err, result) {
            assert.equal(false, result);
            done();
        }, this.connection);
    })

    it('invalid search filter', function (done) {
        this.connection.server.notes.ldappool.config.rcpt_to.searchfilter =  '(&(objectclass=*)(|(mail=%a';
        this.plugin._verify_existence(this.user.mail, function (err, result) {
            assert.equal('Error: (|(mail=user1@my-domain.co has unbalanced parentheses', err.toString());
            assert.equal(false, result);
            done();
        }, this.connection);
    })

    it('no pool', function (done) {
        this.connection.server.notes.ldappool = undefined;
        this.plugin._verify_existence(this.user.mail, function (err, userdn) {
            assert.equal('LDAP Pool not found!', err);
            assert.equal(false, userdn);
            done();
        }, this.connection);
    })
})

describe('_get_search_conf', function () {

    beforeEach(_set_up)

    it('get defaults', function (done) {
        const opts = this.plugin._get_search_conf('testMail', this.connection);
        const pool = this.connection.server.notes.ldappool;
        assert.equal(opts.basedn, pool.config.basedn);
        assert.equal(opts.filter, '(&(objectclass=*)(mailLocalAddress=testMail))');
        assert.equal(opts.scope, pool.config.scope);
        assert.equal(opts.attributes.toString(), ['dn'].toString());
        done();
    })

    it('get userdef', function (done) {
        this.connection.server.notes.ldappool.config.rcpt_to.basedn = 'hop around as you like';
        this.connection.server.notes.ldappool.config.rcpt_to.searchfilter = '(&(objectclass=posixAccount)(mail=%a))';
        this.connection.server.notes.ldappool.config.rcpt_to.scope = 'one two three';
        const opts = this.plugin._get_search_conf('testMail', this.connection);
        assert.equal(opts.basedn, 'hop around as you like');
        assert.equal(opts.filter, '(&(objectclass=posixAccount)(mail=testMail))');
        assert.equal(opts.scope, 'one two three');
        assert.equal(opts.attributes.toString(), ['dn'].toString());
        done();
    })
})

describe('check_rcpt', function () {

    beforeEach(_set_up)

    it('ok', function (done) {
        this.plugin.check_rcpt(function (err) {
            assert.equal(constants.ok, err);
            done();
        }, this.connection, [{
            address : () => { return 'user1@my-domain.com'; }
        }]);
    })

    it('denysoft on error', function (done) {
        this.connection.server.notes.ldappool.config.rcpt_to.searchfilter =  '(&(objectclass=*)(|(mail=%a';
        this.plugin.check_rcpt(function (err) {
            assert.equal(constants.denysoft, err);
            done();
        }, this.connection, [{
            address : () => { return 'user1@my-domain.com'; }
        }]);
    })

    it('ignore if missing params[0]', function (done) {
        this.plugin.check_rcpt(function (err) {
            assert.equal(undefined, err);
            done();
        }, this.connection, []);
    })

    it('deny on invalid address', function (done) {
        this.plugin.check_rcpt(function (err) {
            assert.equal(constants.deny, err);
            done();
        }, this.connection, [{
            address : () => { return 'unknown@address'; }
        }]);
    })
})
