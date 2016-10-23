'use strict';

/**
 * rcpt_to.in_ldap.js
 * This haraka plugin check if a given recipient address exists in LDAP.
 */


exports._verify_existence = function (address, callback) {
    var plugin = this;
    var onError = function(err) {
        plugin.logerror('Could not verify address "' + address + '": ' +  err);
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
            var config = plugin._get_search_conf(address);
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

exports._get_search_conf = function(address) {
    var plugin = this;
    var filter = plugin.cfg.main.searchfilter || '(&(objectclass=*)(mail=%a))';
    filter = filter.replace(/%a/g, address);
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
    this.inherits('auth/auth_base');
    var plugin = this;
    plugin.register_hook('init_master',  'init_rcpt_to_in_ldap');
    plugin.register_hook('init_child',   'init_rcpt_to_in_ldap');
    var load_rcpt_to_in_ldap_ini = function() {
        plugin.loginfo("loading rcpt_to.in_ldap.ini");
        plugin.cfg = plugin.config.get('rcpt_to.in_ldap.ini', 'ini', load_rcpt_to_in_ldap_ini);
    };
    load_rcpt_to_in_ldap_ini();
    plugin.register_hook('rcpt', 'check_rcpt');
};

exports.init_rcpt_to_in_ldap = function(next, server) {
    var plugin = this;
    if (!server.notes.ldappool) {
        plugin.logerror('LDAP Pool not found! Make sure ldappool plugin is loaded!');
    }
    else {
        this.pool = server.notes.ldappool;
    }
    next();
};

exports.check_rcpt = function(next, connection, params) {
    var plugin = this;
    if (!connection.transaction ||
            !connection.transaction.rcpt_to ||
            connection.transaction.rcpt_to.length === 0) {
        var util = require('util');
        plugin.logerror('Invalid call. Given connection.transaction:' +
                        util.inspect(connection.transaction));
        return next(DENYSOFT);
    }
    var rcpt = connection.transaction.rcpt_to[connection.transaction.rcpt_to.length - 1];
    var callback = function(err, result) {
        if (err) {
            plugin.logerror('Could not use LDAP for address check: ' + err);
            next(DENYSOFT);
        }
        else if (!result) {
            next(DENY);
        }
        else {
            next();
        }
    };
    plugin._verify_existence(rcpt, callback);
};
