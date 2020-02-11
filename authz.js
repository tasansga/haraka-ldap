'use strict';

const util      = require('util');
const constants = require('haraka-constants');

exports._verify_address = function (uid, address, callback, connection) {
    const plugin = this;
    const pool = connection.server.notes.ldappool;
    const onError = function (err) {
        connection.logerror(`Could not verify address ${address}  for UID ${uid}`)
        connection.logdebug(`${util.inspect(err)}`);
        callback(err, false);
    }

    if (!pool) return onError('LDAP Pool not found!');

    pool.get((err, client) => {
        if (err) return onError(err);

        const config = plugin._get_search_conf(uid, address, connection);
        connection.logdebug(`Verifying address: ${  util.inspect(config)}`);
        try {
            client.search(config.basedn, config, function (search_error, res) {
                if (search_error) { onError(search_error); }
                let entries = 0;
                res.on('searchEntry', function (entry) {
                    entries++;
                });
                res.on('error', onError);
                res.on('end', function () {
                    callback(null, entries > 0);
                });
            });
        }
        catch (e) {
            return onError(e);
        }
    });
}

exports._get_search_conf = function (user, address, connection) {
    const pool = connection.server.notes.ldappool;
    let filter = pool.config.authz.searchfilter || '(&(objectclass=*)(uid=%u)(mail=%a))';
    filter = filter.replace(/%u/g, user).replace(/%a/g, address);
    return {
        basedn: pool.config.authz.basedn || pool.config.basedn,
        filter,
        scope: pool.config.authz.scope || pool.config.scope,
        attributes: [ 'dn' ]
    };
}

exports.check_authz = function (next, connection, params) {
    if (!connection.notes || !connection.notes.auth_user || !params || !params[0] || !params[0].address) {
        connection.logerror(`${'Ignoring invalid call. Given params are ' +
                            ' connection.notes:'}${util.inspect(connection.notes)
        } and params:${util.inspect(params)}`);
        return next();
    }
    const uid = connection.notes.auth_user;
    const address = params[0].address();
    this._verify_address(uid, address, function (err, verified) {
        if (err) {
            connection.logerror(`Could not use LDAP to match address to uid: ${err.message}`);
            next(constants.denysoft);
        }
        else if (!verified) {
            next(constants.deny, `User ${  util.inspect(uid)  } not allowed to send from address ${  util.inspect(address)  }.`);
        }
        else {
            next();
        }
    }, connection);
}
