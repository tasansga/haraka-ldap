'use strict';

var async = require('async');
var util  = require('util');

exports._verify_user = function (userdn, passwd, cb, connection) {
    var pool = connection.server.notes.ldappool;
    var onError = function(err) {
        connection.logerror('Could not verify userdn and password: ' + err);
        cb(false);
    };
    if (!pool) {
        return onError('LDAP Pool not found');
    }
    pool._create_client(function (err, client) {
        if (err) { return onError(err); }
        client.bind(userdn, passwd, function(err) {
            if (err) {
                connection.logdebug("Login failed, could not bind '" + userdn + "': " + err);
                return cb(false);
            }
            else {
                client.unbind();
                return cb(true);
            }
        });
    });
};

exports._get_search_conf = function(user, connection) {
    var pool = connection.server.notes.ldappool;
    var filter = pool.config.authn.searchfilter || '(&(objectclass=*)(uid=%u))';
    filter = filter.replace(/%u/g, user);
    var config = {
        basedn: pool.config.authn.basedn || pool.config.basedn,
        filter: filter,
        scope: pool.config.authn.scope || pool.config.scope,
        attributes: ['dn']
    };
    return config;
};

exports._get_dn_for_uid = function (uid, callback, connection) {
    var plugin = this;
    var pool = connection.server.notes.ldappool;
    var onError = function(err) {
        connection.logerror('Could not get DN for UID "' + uid + '": ' +  err);
        callback(err);
    };
    if (!pool) {
        return onError('LDAP Pool not found!');
    }
    var search = function (err, client) {
        if (err) {
            return onError(err);
        }
        else {
            var config = plugin._get_search_conf(uid, connection);
            connection.logdebug('Getting DN for uid: ' + util.inspect(config));
            try {
                client.search(config.basedn, config, function(search_error, res) {
                    if (search_error) { onError(search_error); }
                    var userdn=[];
                    res.on('searchEntry', function(entry) {
                        userdn.push(entry.object.dn);
                    });
                    res.on('error', onError);
                    res.on('end', function() {
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
    var plugin = this;
    var pool = connection.server.notes.ldappool;
    if (Array.isArray(pool.config.authn.dn)) {
        connection.logdebug('Looking up user "' + user + '" by DN.');
        var search = function(userdn, searchCallback) {
            var userdn = userdn.replace(/%u/g, user);
            return plugin._verify_user(userdn, passwd, searchCallback, connection);
        };
        var asyncCallback = function(result) {
            cb(result !== undefined && result !== null);
        };
        return async.detect(pool.config.authn.dn, search, asyncCallback);
    }
    var callback = function(err, userdn) {
        if (err) {
            connection.logerror("Could not use LDAP for password check: " + err);
            return cb(false);
        }
        else if (userdn.length !== 1) {
            connection.logdebug('None or nonunique LDAP search result for user, access denied');
            cb(false);
        }
        else {
            return plugin._verify_user(userdn[0], passwd, cb, connection);
        }
    };
    connection.logdebug('Looking up user "' + user + '" by search.');
    plugin._get_dn_for_uid(user, callback, connection);
};
