'use strict';

var util = require('util');


exports._verify_address = function (uid, address, callback, connection) {
    var plugin = this;
    var pool = connection.server.notes.ldappool;
    var onError = function(err) {
        connection.logerror('Could not verify address "' + address + '"  for UID "' + uid + '": ' +  err);
        callback(err, false);
    };
    if (!pool) {
        return onError('LDAP Pool not found!');
    }
    var search = function (err, client) {
        if (err) {
            return onError(err);
        }
        else {
            var config = plugin._get_search_conf(uid, address, connection);
            connection.logdebug('Verifying address: ' + util.inspect(config));
            try {
                client.search(config.basedn, config, function(search_error, res) {
                    if (search_error) { onError(search_error); }
                    var entries = 0;
                    res.on('searchEntry', function(entry) {
                        entries++;
                    });
                    res.on('error', onError);
                    res.on('end', function() {
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

exports._get_search_conf = function(user, address, connection) {
    var plugin = this;
    var pool = connection.server.notes.ldappool;
    var filter = pool.config.authz.searchfilter || '(&(objectclass=*)(uid=%u)(mail=%a))';
    filter = filter.replace(/%u/g, user).replace(/%a/g, address);
    var config = {
        basedn: pool.config.authz.basedn || pool.config.basedn,
        filter: filter,
        scope: pool.config.authz.scope || pool.config.scope,
        attributes: [ 'dn' ]
    };
    if (config.basedn === undefined) {
        plugin.logerror('Undefined basedn. Please check your configuration!');
    }
    return config;
};

exports.register = function() {
    var plugin = this;
    plugin.register_hook('mail', 'check_authz');
};

exports.check_authz = function(next, connection, params) {
    var plugin = this;
    if (!connection.notes || !connection.notes.auth_user ||
            !params || !params[0] || !params[0].address) {
        connection.logerror('Ignoring invalid call. Given params are ' +
                            ' connection.notes:' + util.inspect(connection.notes) +
                            ' and params:' + util.inspect(params));
        return next();
    }
    var uid = connection.notes.auth_user;
    var address = params[0].address();
    var callback = function(err, verified) {
        if (err) {
            connection.logerror('Could not use LDAP to match address to uid: ' + err);
            next(DENYSOFT);
        }
        else if (!verified) {
            next(DENY, 'User not allowed to send from this address.');
        }
        else {
            next();
        }
    };
    plugin._verify_address(uid, address, callback, connection);
};
