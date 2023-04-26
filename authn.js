'use strict';

const util  = require('util');

exports._verify_user = function (userdn, passwd, cb, connection) {
    const pool = connection.server.notes.ldappool;

    function onError (err) {
        connection.logerror(`Could not verify userdn and password: ${  util.inspect(err)}`);
        cb(false);
    }

    if (!pool) return onError('LDAP Pool not found');

    pool._create_client((err, client) => {
        if (err) return onError(err);

        client.bind(userdn, passwd, (err2) => {
            if (err2) {
                connection.logdebug(`Login failed, could not bind ${ util.inspect(userdn) }: ${ util.inspect(err)}`);
                return cb(false)
            }

            client.unbind();
            cb(true);
        })
    })
}

exports._get_search_conf = function (user, connection) {
    const pool = connection.server.notes.ldappool;
    const filter = pool.config.authn.searchfilter || '(&(objectclass=*)(uid=%u))';
    return {
        basedn: pool.config.authn.basedn || pool.config.basedn,
        filter: filter.replace(/%u/g, user),
        scope: pool.config.authn.scope || pool.config.scope,
        attributes: ['dn']
    };
};

exports._get_dn_for_uid = function (uid, callback, connection) {
    const plugin = this;
    const pool = connection.server.notes.ldappool;
    function onError (err) {
        connection.logerror(`Could not get DN for UID ${uid}`)
        connection.logdebug(`: ${util.inspect(err)}`);
        callback(err);
    }
    if (!pool) return onError('LDAP Pool not found!');

    pool.get((err, client) => {
        if (err) return onError(err);

        const config = plugin._get_search_conf(uid, connection);
        connection.logdebug(`Getting DN for uid: ${  util.inspect(config)}`);
        try {
            client.search(config.basedn, config, function (search_error, res) {
                if (search_error) onError(search_error);
                const userdn=[];
                res.on('searchEntry', function (entry) {
                    userdn.push(entry.object.dn);
                });
                res.on('error', onError);
                res.on('end', function () {
                    callback(null, userdn);
                });
            });
        }
        catch (e) {
            onError(e);
        }
    })
}

exports.check_plain_passwd = function (connection, user, passwd, cb) {

    if (Array.isArray(connection.server.notes.ldappool.config.authn.dn)) {
        return this.check_plain_passwd_dn(connection, user, passwd, cb)
    }

    connection.logdebug(`Looking up user ${  util.inspect(user)  } by search.`);
    this._get_dn_for_uid(user, (err, userdn) => {
        if (err) {
            connection.logerror(`Could not use LDAP for password check: ${  util.inspect(err)}`);
            cb(false);
        }
        else if (userdn.length !== 1) {
            connection.logdebug(`None or nonunique LDAP search result for user ${  util.inspect(user)  }, access denied`);
            cb(false);
        }
        else {
            this._verify_user(userdn[0], passwd, cb, connection);
        }
    }, connection);
};

exports.check_plain_passwd_dn = function (connection, user, passwd, cb) {
    connection.logdebug(`Looking up user ${ util.inspect(user) } by DN.`);

    let iter = 0
    let cbCalled = false

    function cbOnce (result) {
        iter++
        if (cbCalled) return
        if (result) {
            cbCalled = true
            return cb(result)
        }
        if (iter === connection.server.notes.ldappool.config.authn.dn.length) {
            cbCalled = true
            cb(result)
        }
    }

    for (const dn of connection.server.notes.ldappool.config.authn.dn) {
        this._verify_user(dn.replace(/%u/g, user), passwd, cbOnce, connection);
    }
}
