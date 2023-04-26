'use strict';

const assert    = require('assert')

const fixtures  = require('haraka-test-fixtures');
const ldappool  = require('../pool');

// test user data as defined in testdata.ldif
const users = [
    {
        uid : 'user1',
        dn : 'uid=user1,ou=users,dc=example,dc=com',
        password : 'ykaHsOzEZD',
        mail : 'user1@example.com'
    },
    {
        uid : 'user2',
        dn : 'uid=user2,ou=people,dc=example,dc=com',
        password : 'KQD9zs,LGv',
        mail : 'user2@example.com'
    },
    {
        uid : 'nonunique',
        dn : 'uid=nonunique,ou=users,dc=example,dc=com',
        password : 'CZVm3,BLlx',
        mail : 'nonunique1@example.com'
    },
    {
        uid : 'nonunique',
        dn : 'uid=nonunique,ou=people,dc=example,dc=com',
        password : 'LsBHDGorAh',
        mail : 'nonunique2@example.com'
    }
];

function _set_up (done) {
    this.users = users;
    this.plugin = require('../authn');
    this.connection = fixtures.connection.createConnection();
    this.connection.server = {
        notes: {
            ldappool : new ldappool.LdapPool({
                main : {
                    server : [ 'ldap://localhost:3389' ],
                    binddn : this.users[0].dn,
                    bindpw : this.users[0].password,
                    basedn : 'dc=example,dc=com'
                }
            })
        }
    };
    this.connection.server.notes.ldappool.config.authn = {};
    done();
}

describe('_verify_user', function () {

    beforeEach(_set_up)

    it('verifies test data', function (done) {
        let counter = 0;
        for (const user of users) {
            this.plugin._verify_user(user.dn, user.password, (result) => {
                assert.equal(true, result);
                counter++;
                if (counter === users.length) done();
            }, this.connection);
        }
    })

    it('safety check: wrong password fails', function (done) {
        this.plugin._verify_user(this.users[0].dn, 'wrong', function (ok) {
            assert.equal(false, ok);
            done();
        }, this.connection);
    })

    it('safety check: invalid dn fails', function (done) {
        this.plugin._verify_user('wrong', 'wrong', function (ok) {
            assert.equal(false, ok);
            done();
        }, this.connection);
    })

    it('no pool', function (done) {
        const plugin = this.plugin;
        const connection = this.connection;
        connection.server.notes.ldappool = undefined;
        const user = this.users[0];
        plugin._verify_user(user.dn, user.password, function (result) {
            assert.equal(false, result);
            done();
        }, connection);
    })
})

describe('_get_search_conf', function () {

    beforeEach(_set_up)

    it('get defaults', function (done) {
        const pool = this.connection.server.notes.ldappool;
        const opts = this.plugin._get_search_conf('testUid', this.connection);
        assert.equal(opts.basedn, pool.config.basedn);
        assert.equal(opts.filter, '(&(objectclass=*)(uid=testUid))');
        assert.equal(opts.scope, pool.config.scope);
        assert.equal(opts.attributes.toString(), ['dn'].toString());
        done();
    })

    it('get userdef', function (done) {
        const pool = this.connection.server.notes.ldappool;
        pool.config.authn.basedn = 'hop around as you like';
        pool.config.authn.searchfilter = '(&(objectclass=posixAccount)(uid=%u))';
        pool.config.authn.scope = 'one two three';
        const opts = this.plugin._get_search_conf('testUid', this.connection);
        assert.equal(opts.basedn, 'hop around as you like');
        assert.equal(opts.filter, '(&(objectclass=posixAccount)(uid=testUid))');
        assert.equal(opts.scope, 'one two three');
        assert.equal(opts.attributes.toString(), ['dn'].toString());
        done();
    })
})

describe('get_dn_for_uid', function () {

    beforeEach(_set_up)

    it('user 1 dn2uid', function (done) {
        const user = this.users[0];
        this.plugin._get_dn_for_uid(user.uid, function (err, userdn) {
            assert.equal(null, err);
            assert.equal(userdn.toString(), user.dn);
            done();
        }, this.connection);
    })

    it('nonunique dn2uid', function (done) {
        this.plugin._get_dn_for_uid('nonunique', function (err, userdn) {
            assert.equal(null, err);
            assert.equal(2, userdn.length);
            done();
        }, this.connection);
    })
    it('invalid uid', function (done) {
        this.plugin._get_dn_for_uid('doesntexist', function (err, userdn) {
            assert.equal(null, err);
            assert.equal(0, userdn.length);
            done();
        }, this.connection);
    })
    it('invalid search filter', function (done) {
        const user = this.users[0];
        const pool = this.connection.server.notes.ldappool;
        pool.config.authn.searchfilter = '(&(objectclass=*)(uid=%u';
        this.plugin._get_dn_for_uid(user.uid, function (err, userdn) {
            assert.equal('Error: (uid=user has unbalanced parentheses', err.toString());
            assert.equal(undefined, userdn);
            done();
        }, this.connection);
    })
    it('invalid basedn', function (done) {
        const user = this.users[0];
        this.connection.server.notes.ldappool.config.basedn = 'invalid';
        this.plugin._get_dn_for_uid(user.uid, function (err, userdn) {
            assert.equal('InvalidDistinguishedNameError', err.name);
            assert.equal(undefined, userdn);
            done();
        }, this.connection);
    })
    it('no pool', function (done) {
        this.connection.server.notes.ldappool = undefined;
        const user = this.users[0];
        this.plugin._get_dn_for_uid(user.uid, function (err, userdn) {
            assert.equal('LDAP Pool not found!', err);
            assert.equal(undefined, userdn);
            done();
        }, this.connection);
    })
})

describe('check_plain_passwd', function () {

    beforeEach(_set_up)

    it('search with test users and invalid user', function (done) {
        const plugin = this.plugin;
        const connection = this.connection;
        plugin.check_plain_passwd(connection, users[0].uid, users[0].password, function (result) {
            assert.equal(true, result);
            plugin.check_plain_passwd(connection, users[1].uid, users[1].password, function (result2) {
                assert.equal(true, result2);
                plugin.check_plain_passwd(connection, users[2].uid, users[2].password, function (result3) {
                    assert.equal(false, result3);
                    plugin.check_plain_passwd(connection, users[3].uid, users[3].password, function (result4) {
                        assert.equal(false, result4);
                        plugin.check_plain_passwd(connection, 'invalid', 'invalid', function (result5) {
                            assert.equal(false, result5);
                            done();
                        });
                    });
                });
            });
        })
    })

    it('try dn with test users and invalid user', function (done) {
        const plugin = this.plugin;
        const pool = this.connection.server.notes.ldappool;
        const connection = this.connection;
        pool.config.authn.dn = [ 'uid=%u,ou=users,dc=example,dc=com', 'uid=%u,ou=people,dc=example,dc=com' ];
        plugin.check_plain_passwd(connection, users[0].uid, users[0].password, function (result) {
            assert.equal(true, result);
            plugin.check_plain_passwd(connection, users[1].uid, users[1].password, function (result2) {
                assert.equal(true, result2);
                plugin.check_plain_passwd(connection, users[2].uid, users[2].password, function (result3) {
                    assert.equal(true, result3);
                    plugin.check_plain_passwd(connection, users[3].uid, users[3].password, function (result4) {
                        assert.equal(true, result4);
                        plugin.check_plain_passwd(connection, 'invalid', 'invalid', function (result5) {
                            assert.equal(false, result5);
                            done();
                        });
                    });
                });
            });
        });
    })
})
