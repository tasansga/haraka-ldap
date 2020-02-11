'use strict';

const async = require('async');
const util  = require('util');

exports._verify_user = function (userdn, passwd, cb, connection) {
    const pool = connection.server.notes.ldappool;
    function onError (err) {
        connection.logerror(`Could not verify userdn and password: ${  util.inspect(err)}`);
        cb(false);
    }
    if (!pool) {
        return onError('LDAP Pool not found');
    }
    pool._create_client(function (err, client) {
        if (err) { return onError(err); }
        client.bind(userdn, passwd, function (err) {
            if (err) {
                connection.logdebug(`Login failed, could not bind ${  util.inspect(userdn)  }: ${  util.inspect(err)}`);
                return cb(false);
            }
            else {
                client.unbind();
                return cb(true);
            }
        });
    });
};

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
    const onError = function (err) {
        connection.logerror(`Could not get DN for UID ${  util.inspect(uid)  }: ${   util.inspect(err)}`);
        callback(err);
    };
    if (!pool) {
        return onError('LDAP Pool not found!');
    }
    const search = function (err, client) {
        if (err) {
            return onError(err);
        }
        else {
            const config = plugin._get_search_conf(uid, connection);
            connection.logdebug(`Getting DN for uid: ${  util.inspect(config)}`);
            try {
                client.search(config.basedn, config, function (search_error, res) {
                    if (search_error) { onError(search_error); }
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
                return onError(e);
            }
        }
    };
    pool.get(search);
};

exports.check_plain_passwd = function (connection, user, passwd, cb) {
    const plugin = this;
    const pool = connection.server.notes.ldappool;
    if (Array.isArray(pool.config.authn.dn)) {
        connection.logdebug(`Looking up user ${  util.inspect(user)  } by DN.`);
        function search (userdn, searchCallback) {
            userdn = userdn.replace(/%u/g, user);
            return plugin._verify_user(userdn, passwd, searchCallback, connection);
        }
        return async.detect(pool.config.authn.dn, search, (result) => {
            cb(result !== undefined && result !== null);
        });
    }
    function callback (err, userdn) {
        if (err) {
            connection.logerror(`Could not use LDAP for password check: ${  util.inspect(err)}`);
            return cb(false);
        }
        else if (userdn.length !== 1) {
            connection.logdebug(`None or nonunique LDAP search result for user ${  util.inspect(user)  }, access denied`);
            cb(false);
        }
        else {
            return plugin._verify_user(userdn[0], passwd, cb, connection);
        }
    }
    connection.logdebug(`Looking up user ${  util.inspect(user)  } by search.`);
    plugin._get_dn_for_uid(user, callback, connection);
};
