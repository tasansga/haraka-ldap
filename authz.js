'use strict';

const util      = require('util');
const constants = require('haraka-constants');

exports._verify_address = function (uid, address, callback, connection) {
    const plugin = this;
    const pool = connection.server.notes.ldappool;
    const onError = function (err) {
        connection.logerror(`Could not verify address ${  util.inspect(address)  }  for UID ${  util.inspect(uid)  }: ${   util.inspect(err)}`);
        callback(err, false);
    };
    if (!pool) {
        return onError('LDAP Pool not found!');
    }
    const search = function (err, client) {
        if (err) {
            return onError(err);
        }
        else {
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
        }
    };
    pool.get(search);
};

exports._get_search_conf = function (user, address, connection) {
    const pool = connection.server.notes.ldappool;
    let filter = pool.config.authz.searchfilter || '(&(objectclass=*)(uid=%u)(mail=%a))';
    filter = filter.replace(/%u/g, user).replace(/%a/g, address);
    const config = {
        basedn: pool.config.authz.basedn || pool.config.basedn,
        filter,
        scope: pool.config.authz.scope || pool.config.scope,
        attributes: [ 'dn' ]
    };
    return config;
};

exports.check_authz = function (next, connection, params) {
    const plugin = this;
    if (!connection.notes || !connection.notes.auth_user ||
            !params || !params[0] || !params[0].address) {
        connection.logerror(`${'Ignoring invalid call. Given params are ' +
                            ' connection.notes:'}${  util.inspect(connection.notes)
        } and params:${  util.inspect(params)}`);
        return next();
    }
    const uid = connection.notes.auth_user;
    const address = params[0].address();
    const callback = function (err, verified) {
        if (err) {
            connection.logerror(`Could not use LDAP to match address to uid: ${  util.inspect(err)}`);
            next(constants.denysoft);
        }
        else if (!verified) {
            next(constants.deny, `User ${  util.inspect(uid)  } not allowed to send from address ${  util.inspect(address)  }.`);
        }
        else {
            next();
        }
    };
    plugin._verify_address(uid, address, callback, connection);
};
