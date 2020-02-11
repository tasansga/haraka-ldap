'use strict';

const util      = require('util');
const constants = require('haraka-constants');

exports._verify_existence = function (address, callback, connection) {
    const plugin = this;
    const pool = connection.server.notes.ldappool;
    function onError (err) {
        connection.logerror(`Could not verify address ${  util.inspect(address)  }: ${   util.inspect(err)}`);
        callback(err, false);
    }
    if (!pool) return onError('LDAP Pool not found!');

    pool.get((err, client) => {
        if (err) return onError(err);

        const config = plugin._get_search_conf(address, connection);
        connection.logdebug(`Verifying existence: ${  util.inspect(config)}`);
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
};

exports._get_search_conf = function (address, connection) {
    const pool = connection.server.notes.ldappool;
    let filter = pool.config.rcpt_to.searchfilter || '(&(objectclass=*)(mail=%a))';
    filter = filter.replace(/%a/g, address);
    return {
        basedn: pool.config.rcpt_to.basedn || pool.config.basedn,
        filter,
        scope: pool.config.rcpt_to.scope || pool.config.scope,
        attributes: [ 'dn' ]
    };
};

exports.check_rcpt = function (next, connection, params) {
    const plugin = this;
    if (!params || !params[0] || !params[0].address) {
        connection.logerror(`Ignoring invalid call. Given connection.transaction: ${util.inspect(connection.transaction)}`);
        return next();
    }
    const rcpt = params[0].address();
    plugin._verify_existence(rcpt, (err, result) => {
        if (err) {
            connection.logerror(`Could not use LDAP for address check: ${  util.inspect(err)}`);
            next(constants.denysoft);
        }
        else if (!result) {
            next(constants.deny);
        }
        else {
            next(constants.ok);
        }
    }, connection);
};
