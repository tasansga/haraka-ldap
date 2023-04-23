'use strict';

const assert    = require('assert')
const util      = require('util');

const fixtures  = require('haraka-test-fixtures');
const constants = require('haraka-constants');
const ldappool  = require('../pool');

function _set_up (done) {
    this.user = {
        uid : 'user1',
        dn : 'uid=user1,ou=users,dc=example,dc=com',
        password : 'ykaHsOzEZD',
        mail : 'user1@example.com'
    };
    this.group = {
        dn : 'cn=postmaster,dc=example,dc=com',
        mail : 'postmaster@example.com',
        member : [
            'uid=user1,ou=users,dc=example,dc=com',
            'uid=user2,ou=people,dc=example,dc=com',
            'uid=nonunique,ou=users,dc=example,dc=com'
        ]
    };
    this.plugin = require('../aliases');
    this.connection = fixtures.connection.createConnection();
    this.connection.transaction = {};
    this.connection.server = {
        notes : {
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
    this.connection.server.notes.ldappool.config.aliases = {
        subattribute : 'mailLocalAddress',
        attribute : 'member',
        searchfilter : '(&(objectclass=groupOfNames)(mailLocalAddress=%a))'
    };
    done();
}

describe('_get_alias', function () {

    beforeEach(_set_up);

    it('ok with test group', function (done) {
        this.connection.server.notes.ldappool.config.aliases.attribute_is_dn = true;
        this.plugin._get_alias(this.group.mail, function (err, result) {
            assert.ifError(err);
            result.sort();
            assert.equal('nonunique1@example.com', result[0]);
            assert.equal('user1@example.com', result[1]);
            assert.equal('user2@example.com', result[2]);
            done();
        }, this.connection);
    })

    it('ok with forwarding user', function (done) {
        this.connection.server.notes.ldappool.config.aliases.searchfilter = '(&(objectclass=*)(mailLocalAddress=%a))';
        this.connection.server.notes.ldappool.config.aliases.attribute = 'mailRoutingAddress';
        this.plugin._get_alias('forwarder@example.com', function (err, result) {
            assert.equal('user2@example.com', result[0]);
            done();
        }, this.connection);
    })

    it('ok with resolve-by-dn', function (done) {
        this.connection.server.notes.ldappool.config.aliases.attribute_is_dn = true;
        this.plugin._get_alias('postmaster@example.com', function (err, result) {
            const expected = [ 'user1@example.com', 'user2@example.com', 'nonunique1@example.com' ];
            expected.sort();
            result.sort();
            assert.equal(util.inspect(expected), util.inspect(result));
            done();
        }, this.connection);
    })

    it('empty result with invalid mail', function (done) {
        this.plugin._get_alias('invalid@email', function (err, result) {
            done();
        }, this.connection);
    })
})

describe('_get_search_conf_alias', function () {

    beforeEach(_set_up);

    it('get defaults', function (done) {
        const pool = this.connection.server.notes.ldappool;
        pool.config.aliases.searchfilter = undefined;
        pool.config.aliases.attribute = undefined;
        const opts = this.plugin._get_search_conf_alias('testMail', this.connection);
        assert.equal(opts.basedn, pool.config.basedn);
        assert.equal(opts.filter, '(&(objectclass=*)(mail=testMail)(mailForwardAddress=*))');
        assert.equal(opts.scope, pool.config.scope);
        assert.equal(opts.attributes.toString(), ['mailForwardingAddress'].toString());
        done();
    })

    it('get userdef', function (done) {
        const pool = this.connection.server.notes.ldappool;
        pool.config.aliases.basedn = 'hop around as you like';
        pool.config.aliases.searchfilter = '(&(objectclass=posixAccount)(mail=%a))';
        pool.config.aliases.scope = 'one two three';
        const opts = this.plugin._get_search_conf_alias('testMail', this.connection);
        assert.equal(opts.basedn, 'hop around as you like');
        assert.equal(opts.filter, '(&(objectclass=posixAccount)(mail=testMail))');
        assert.equal(opts.scope, 'one two three');
        assert.equal(opts.attributes.toString(), ['member'].toString());
        done();
    })
})

describe('_resolve_dn_to_alias', function () {

    beforeEach(_set_up);

    it('ok one', function (done) {
        const user = this.user;
        this.plugin._resolve_dn_to_alias([this.user.dn], function (err, result) {
            assert.equal(user.mail, result);
            done();
        }, this.connection);
    })

    it('ok multiple', function (done) {
        this.plugin._resolve_dn_to_alias(this.group.member, function (err, result) {
            result.sort();
            assert.equal('nonunique1@example.com', result[0]);
            assert.equal('user1@example.com', result[1]);
            assert.equal('user2@example.com', result[2]);
            done();
        }, this.connection);
    })

    it('empty array when unknown dn', function (done) {
        this.plugin._resolve_dn_to_alias(['uid=unknown,dc=wherever,dc=com'], function (err, result) {
            assert.equal(0, result.length);
            done();
        }, this.connection);
    })
})

describe('aliases', function () {

    beforeEach(_set_up);

    it('ignore if invalid call / no rcpt', function (done) {
        const plugin = this.plugin;
        const connection = this.connection;
        function noParams (result) {
            assert.equal(undefined, result);
            plugin.aliases(noRcpt, connection, []);
        }
        function noRcpt (result) {
            assert.equal(undefined, result);
            plugin.aliases(noRcptAddress, connection, [ {} ]);
        }
        function noRcptAddress (result) {
            assert.equal(undefined, result);
            done();
        }
        plugin.aliases(noParams, connection);
    })

    it('DENYSOFT if LDAP not usable', function (done) {
        const plugin = this.plugin;
        const user = this.user;
        this.connection.server.notes.ldappool.config.aliases.searchfilter = '(&(objectclass=posixAccount)(mail=%a';
        plugin.aliases(function (result) {
            assert.equal(constants.denysoft, result);
            done();
        }, this.connection, [ { address : () => {
            return user.mail;
        }}]);
    })
    it('next if no results', function (done) {
        const plugin = this.plugin;
        function next (result) {
            assert.equal(undefined, result);
            done();
        }
        plugin.aliases(next, this.connection, [ { address : () => {
            return 'unknown@mail';
        }}]);
    })
    it('resolve group members', function (done) {
        const plugin = this.plugin;
        const group = this.group;
        const connection = this.connection;
        connection.transaction = { rcpt_to : [ group.mail ] };
        this.connection.server.notes.ldappool.config.aliases.attribute_is_dn = true;
        const expected = [
            '<user1@example.com>',
            '<user2@example.com>',
            '<nonunique1@example.com>'
        ];
        expected.sort();
        function next (result) {
            assert.equal(undefined, result);
            connection.transaction.rcpt_to.sort();
            assert.equal(expected.toString(), connection.transaction.rcpt_to.toString());
            done();
        }
        plugin.aliases(next, connection, [ { address : () => {
            return group.mail;
        }}]);
    })
    it('do not change non-aliased user', function (done) {
        const plugin = this.plugin;
        const user = this.user;
        const connection = this.connection;
        connection.transaction = { rcpt_to : [ 'still the same' ] };
        function next (result) {
            assert.equal(undefined, result);
            assert.equal('still the same', connection.transaction.rcpt_to.toString());
            done();
        }
        plugin.aliases(next, connection, [ { address : () => {
            return user.mail;
        }}]);
    })
    it('resolve forwarding user', function (done) {
        const plugin = this.plugin;
        const connection = this.connection;
        connection.transaction = { rcpt_to : [ 'forwarder@example.com' ] };
        connection.server.notes.ldappool.config.aliases.searchfilter = '(&(objectclass=*)(mailLocalAddress=%a))';
        connection.server.notes.ldappool.config.aliases.attribute = 'mailRoutingAddress';
        function next (result) {
            assert.equal(undefined, result);
            assert.equal('<user2@example.com>', connection.transaction.rcpt_to.toString());
            done();
        }
        plugin.aliases(next, connection, [ { address : () => {
            return 'forwarder@example.com';
        }}]);
    })
})
