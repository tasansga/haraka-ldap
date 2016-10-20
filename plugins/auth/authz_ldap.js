'use strict';

/**
 * authz_ldap.js
 * This haraka module implements authorization agains LDAP servers,
 * i.e. if the given user is allowed to use the given from address.
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
    var dnSearch = function (err, client) {
        if (err) {
            return onError(err);
        }
        else {
            var config = plugin._get_search_conf(uid, address);
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
    this.pool.get(dnSearch);
};

exports._get_search_conf = function(user, address) {
    var plugin = this;
    var filter = plugin.cfg.main.filter || '(&(objectclass=*)(uid=%u)(mail=%a))';
    filter = filter.replace(/%u/g, user).replace(/%a/g, address);
    var config = {
        basedn: this.pool.config.basedn,
        filter: filter,
        scope: plugin.cfg.main.scope || 'sub',
        attributes: [ 'dn' ]
    };
    if (config.basedn === undefined) {
        plugin.logerror('Undefined basedn. Please check your configuration!');
    }
    return config;
};

exports.register = function() {
    this.inherits('auth/auth_base');
    var plugin = this;
    plugin.register_hook('init_master',  'init_authz_ldap');
    plugin.register_hook('init_child',   'init_authz_ldap');
    var load_authz_ldap_ini = function() {
        plugin.loginfo("loading authz_ldap.ini");
        plugin.cfg = plugin.config.get('authz_ldap.ini', 'ini', load_authz_ldap_ini);
    };
    load_authz_ldap_ini();
    plugin.register_hook('mail', 'check_authz');
};

exports.init_authz_ldap = function(next, server) {
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
    var uid = connection.notes.auth_user;
    var address = params[0];
    //var address = connection.transaction.mail_from.address().toString();
    var callback = function(err, verified) {
        if (err) {
            plugin.logerror('Could not use LDAP for address check: ' + err);
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
