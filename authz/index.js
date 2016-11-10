'use strict';

var util = require('util');


/**
 * ldap-authz.js
 * This haraka plugin implements authorization against LDAP servers,
 * i.e. if the given user is allowed to use the given "FROM" address.
 */


exports._verify_address = function (uid, address, callback) {
    var plugin = this;
    var onError = function(err) {
        plugin.logerror('Could not verify address "' + address + '"  for UID "' + uid + '": ' +  err);
        callback(err, false);
    };
    if (!this.pool) {
        return onError('LDAP Pool not found!');
    }
    var search = function (err, client) {
        if (err) {
            return onError(err);
        }
        else {
            var config = plugin._get_search_conf(uid, address);
            plugin.logdebug('Verifying address: ' + util.inspect(config));
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
    this.pool.get(search);
};

exports._get_search_conf = function(user, address) {
    var plugin = this;
    var filter = plugin.cfg.main.searchfilter || '(&(objectclass=*)(uid=%u)(mail=%a))';
    filter = filter.replace(/%u/g, user).replace(/%a/g, address);
    var config = {
        basedn: plugin.cfg.main.basedn || this.pool.config.basedn,
        filter: filter,
        scope: plugin.cfg.main.scope || this.pool.config.scope,
        attributes: [ 'dn' ]
    };
    if (config.basedn === undefined) {
        plugin.logerror('Undefined basedn. Please check your configuration!');
    }
    return config;
};

exports.register = function() {
    var plugin = this;
    plugin.register_hook('init_master',  'init_ldap_authz');
    plugin.register_hook('init_child',   'init_ldap_authz');
    var load_ldap_authz_ini = function() {
        plugin.loginfo("loading ldap-authz.ini");
        plugin.cfg = plugin.config.get('ldap-authz.ini', 'ini', load_ldap_authz_ini);
    };
    load_ldap_authz_ini();
    plugin.register_hook('mail', 'check_authz');
};

exports.init_ldap_authz = function(next, server) {
    var plugin = this;
    if (!server.notes.ldappool) {
        plugin.logerror('LDAP Pool not found! Make sure ldappool plugin is loaded!');
    }
    else {
        this.pool = server.notes.ldappool;
    }
    next();
};

exports.check_authz = function(next, connection, params) {
    var plugin = this;
    if (!connection.notes || !connection.notes.auth_user ||
            !params || !params[0] || !params[0].address) {
        plugin.logerror('Ignoring invalid call. Given params are ' +
                        ' connection.notes:' + util.inspect(connection.notes) +
                        ' and params:' + util.inspect(params));
        return next();
    }
    var uid = connection.notes.auth_user;
    var address = params[0].address();
    var callback = function(err, verified) {
        if (err) {
            plugin.logerror('Could not use LDAP to match address to uid: ' + err);
            next(DENYSOFT);
        }
        else if (!verified) {
            next(DENY, 'User not allowed to send from this address.');
        }
        else {
            next();
        }
    };
    plugin._verify_address(uid, address, callback);
};
