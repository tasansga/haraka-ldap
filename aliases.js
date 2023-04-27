'use strict';

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
            onError(e);
        }
    };
    pool.get(search);
}

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
}

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

        const promises = []
        for (const d of dn) {
            promises.push(new Promise((resolve) => {
                const entries = []

                client.search(d, config, (search_error, res) => {
                    if (search_error)
                        onError(search_error, d);

                    res.on('searchEntry', (entry) => {
                        const arr_addr = entry.object[config.attributes[0]];
                        entries.push(Array.isArray(arr_addr) ? arr_addr[0] : arr_addr)
                    })

                    res.on('error', (e) => {
                        connection.logwarn(`Could not retrieve DN ${util.inspect(d)}`);
                        connection.logdebug(`${util.inspect(e)}`);
                        resolve([]);
                    })

                    res.on('end', (r) => {
                        resolve(entries);
                    })
                })
            }))
        }

        Promise.all(promises)
            .then((res) => {
                callback(null, res.flat())
            })
            .catch(e => {
                connection.logerror(`AllResolvedErr: ${e}`)
            })
    })
}

exports.aliases = function (next, connection, params) {
    if (!params || !params[0] || !params[0].address) {
        connection.logerror(`Ignoring invalid call. Given params: ${util.inspect(params)}`);
        return next();
    }
    const rcpt = params[0].address();
    this._get_alias(rcpt, (err, result) => {
        if (err) {
            connection.logerror(`Could not use LDAP to resolve aliases: ${err.message}`);
            return next(constants.denysoft);
        }
        if (result.length === 0) {
            connection.logdebug(`No aliases results found for rcpt: ${util.inspect(rcpt)}`);
            return next();
        }
        connection.logdebug(this, `Aliasing ${util.inspect(rcpt)} to ${util.inspect(result)}`);
        connection.transaction.rcpt_to.pop();
        for (const element of result) {
            const toAddress = new Address(`<${element}>`);
            connection.transaction.rcpt_to.push(toAddress);
        }
        next();
    }, connection);
}
