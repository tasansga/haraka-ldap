'use strict';

var async     = require('async');
var util      = require('util');
var Address   = require('address-rfc2821').Address;
var constants = require('haraka-constants');

exports._get_alias = function (address, callback, connection) {
    var plugin = this;
    var pool = connection.server.notes.ldappool;
    if (!pool) {
        return onError('LDAP Pool not found!');
    }
    var onError = function(err) {
        connection.logerror('Could not resolve ' + util.inspect(address) + ' as alias: ' +  util.inspect(err));
        callback(err, false);
    };
    var search = function (err, client) {
        if (err) {
            return onError(err);
        }
        else {
            var config = plugin._get_search_conf_alias(address, connection);
            connection.logdebug('Checking address for alias: ' + util.inspect(config));
            try {
                client.search(config.basedn, config, function(search_error, res) {
                    if (search_error) { onError(search_error); }
                    var alias = [];
                    res.on('searchEntry', function(entry) {
                        alias = alias.concat(entry.object[config.attributes[0]]);
                    });
                    res.on('error', onError);
                    res.on('end', function() {
                        if (pool.config.aliases.attribute_is_dn) {
                            plugin._resolve_dn_to_alias(alias, callback, connection);
                        }
                        else {
                            callback(null, alias);
                        }
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

exports._get_search_conf_alias = function(address, connection) {
    var pool = connection.server.notes.ldappool;
    var filter = pool.config.aliases.searchfilter || '(&(objectclass=*)(mail=%a)(mailForwardAddress=*))';
    filter = filter.replace(/%a/g, address);
    var config = {
        basedn: pool.config.aliases.basedn || pool.config.basedn,
        filter: filter,
        scope: pool.config.aliases.scope || pool.config.scope,
        attributes: [ pool.config.aliases.attribute || 'mailForwardingAddress' ]
    };
    return config;
};

exports._resolve_dn_to_alias = function(dn, callback, connection) {
    var pool = connection.server.notes.ldappool;
    if (!pool) {
        return onError('LDAP Pool not found!');
    }
    var onError = function(err) {
        connection.logerror('Could not get address for DN ' + util.inspect(dn) + ': ' +  util.inspect(err));
        callback(err);
    };
    var config = {
        scope: 'base',
        attributes: [ pool.config.aliases.subattribute || 'mailLocalAddress' ]
    };
    var asyncDnSearch = function (err, client) {
        var client = client;
        connection.logdebug('Resolving DN ' + util.inspect(dn) + ' to alias: ' + util.inspect(config));
        var search = function(dn, searchCallback) {
            client.search(dn, config, function(search_error, res) {
                if (search_error) { onError(search_error, dn); }
                res.on('searchEntry', function(entry) {
                    var arr_addr = entry.object[config.attributes[0]];
                    if (Array.isArray(arr_addr)) {
                        arr_addr = arr_addr[0];
                    }
                    searchCallback(null, arr_addr);
                });
                res.on('error', function(e) {
                    connection.logwarn('Could not retrieve DN ' + util.inspect(dn) + ': ' + util.inspect(e));
                    searchCallback(null, []);
                });
            });
        };
        if (err) {
            return onError(err);
        }

        async.concat(dn, search, callback);
    };
    pool.get(asyncDnSearch);
};

exports.aliases = function(next, connection, params) {
    var plugin = this;
    if (!params || !params[0] || !params[0].address) {
        connection.logerror('Ignoring invalid call. Given params: ' +
                        util.inspect(params));
        return next();
    }
    var rcpt = params[0].address();
    var handleAliases = function(err, result) {
        if (err) {
            connection.logerror('Could not use LDAP to resolve aliases: ' + util.inspect(err));
            return next(constants.denysoft);
        }
        if (result.length === 0) {
            connection.logdebug('No aliases results found for rcpt: ' + util.inspect(rcpt));
            return next();
        }
        connection.logdebug(plugin, 'Aliasing ' + util.inspect(rcpt) + ' to ' + util.inspect(result));
        connection.transaction.rcpt_to.pop();
        for (var i=0; i<result.length; i++) {
            var toAddress = new Address('<' + result[i] + '>');
            connection.transaction.rcpt_to.push(toAddress);
        }
        next();
    };
    plugin._get_alias(rcpt, handleAliases, connection);
};
