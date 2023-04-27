'use strict';

const async     = require('async');
const util      = require('util');
const Address   = require('address-rfc2821').Address;
const constants = require('haraka-constants');

exports._get_alias = function (address, callback, connection) {
    const pool = connection.server.notes.ldappool;
    if (!pool) {
        return onError('LDAP Pool not found!');
    }
    function onError (err) {
        connection.logerror(`Could not resolve ${address} as alias`)
        connection.logdebug(`${util.inspect(err)}`);
        callback(err, false);
    }
    const search = (err, client) => {
        if (err)
            return onError(err);

        const config = this._get_search_conf_alias(address, connection);
        connection.logdebug(`Checking address for alias: ${  util.inspect(config)}`);
        try {
            client.search(config.basedn, config, (search_error, res) => {
                if (search_error) { onError(search_error); }
                let alias = [];
                res.on('searchEntry', (entry) => {
                    alias = alias.concat(entry.object[config.attributes[0]]);
                });
                res.on('error', onError);
                res.on('end', () => {
                    if (pool.config.aliases.attribute_is_dn) {
                        this._resolve_dn_to_alias(alias, callback, connection);
                    }
                    else {
                        callback(null, alias);
                    }
                })
            })
        }
        catch (e) {
            return onError(e);
        }
    };
    pool.get(search);
};

exports._get_search_conf_alias = (address, connection) => {
    const pool = connection.server.notes.ldappool;
    let filter = pool.config.aliases.searchfilter || '(&(objectclass=*)(mail=%a)(mailForwardAddress=*))';
    filter = filter.replace(/%a/g, address);
    return {
        basedn: pool.config.aliases.basedn || pool.config.basedn,
        filter,
        scope: pool.config.aliases.scope || pool.config.scope,
        attributes: [ pool.config.aliases.attribute || 'mailForwardingAddress' ]
    };
};

exports._resolve_dn_to_alias = (dn, callback, connection) => {
    const pool = connection.server.notes.ldappool;
    if (!pool) {
        return onError('LDAP Pool not found!');
    }
    function onError (err) {
        connection.logerror(`Could not get address for DN ${  util.inspect(dn)  }: ${   util.inspect(err)}`);
        callback(err);
    }
    const config = {
        scope: 'base',
        attributes: [ pool.config.aliases.subattribute || 'mailLocalAddress' ]
    };
    pool.get((err, client) => {
        if (err) return onError(err);
        connection.logdebug(`Resolving DN ${  util.inspect(dn)  } to alias: ${  util.inspect(config)}`);

        async.concat(dn, (dn2, searchCallback) => {
            client.search(dn2, config, (search_error, res) => {
                if (search_error) { onError(search_error, dn2); }
                res.on('searchEntry', (entry) => {
                    let arr_addr = entry.object[config.attributes[0]];
                    if (Array.isArray(arr_addr)) {
                        arr_addr = arr_addr[0];
                    }
                    searchCallback(null, arr_addr);
                });
                res.on('error', (e) => {
                    connection.logwarn(`Could not retrieve DN ${  util.inspect(dn)  }`);
                    connection.logdebug(`${util.inspect(e)}`);
                    searchCallback(null, []);
                });
            });
        }, callback);
    });
};

exports.aliases = function (next, connection, params) {
    const plugin = this;
    if (!params || !params[0] || !params[0].address) {
        connection.logerror(`Ignoring invalid call. Given params: ${util.inspect(params)}`);
        return next();
    }
    const rcpt = params[0].address();
    const handleAliases = function (err, result) {
        if (err) {
            connection.logerror(`Could not use LDAP to resolve aliases: ${err.message}`);
            return next(constants.denysoft);
        }
        if (result.length === 0) {
            connection.logdebug(`No aliases results found for rcpt: ${  util.inspect(rcpt)}`);
            return next();
        }
        connection.logdebug(plugin, `Aliasing ${  util.inspect(rcpt)  } to ${  util.inspect(result)}`);
        connection.transaction.rcpt_to.pop();
        for (const element of result) {
            const toAddress = new Address(`<${    element  }>`);
            connection.transaction.rcpt_to.push(toAddress);
        }
        next();
    };
    plugin._get_alias(rcpt, handleAliases, connection);
};
