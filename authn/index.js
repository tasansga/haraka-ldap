'use strict';

var async = require('async');
var util = require('util');


/**
 * ldap-authn.js
 * This haraka plugin implements authentication agains LDAP servers,
 * i.e. it checks if the given user credentials are valid in LDAP.
 */


exports._verify_user = function (userdn, passwd, cb) {
    var plugin = this;
    if (!this.pool) {
        plugin.logerror('Could not verify userdn and password: LDAP Pool not found!');
        return cb(false);
    }
    this.pool._create_client(function (err, client) {
        if (err) {
            plugin.logdebug("Login failed, could not get connection: " + err);
            return cb(false);
        }
        client.bind(userdn, passwd, function(err) {
            if (err) {
                plugin.logdebug("Login failed, could not bind '" + userdn + "': " + err);
                return cb(false);
            }
            else {
                client.unbind();
                return cb(true);
            }
        });
    });
};

exports._get_search_conf = function(user) {
    var plugin = this;
    var filter = plugin.cfg.main.searchfilter || '(&(objectclass=*)(uid=%u))';
    filter = filter.replace(/%u/g, user);
    var config = {
        basedn: plugin.cfg.main.basedn || this.pool.config.basedn,
        filter: filter,
        scope: plugin.cfg.main.scope || this.pool.config.scope,
        attributes: ['dn']
    };
    if (config.basedn === undefined) {
        plugin.logerror("Undefined basedn. Please check your configuration!");
    }
    return config;
};

exports._get_dn_for_uid = function (uid, callback) {
    var plugin = this;
    var onError = function(err) {
        plugin.logerror('Could not get DN for UID "' + uid + '": ' +  err);
        callback(err);
    };
    if (!this.pool) {
        return onError('LDAP Pool not found!');
    }
    var search = function (err, client) {
        if (err) {
            return onError(err);
        }
        else {
            var config = plugin._get_search_conf(uid);
            plugin.logdebug('Getting DN for uid: ' + util.inspect(config));
            try {
                client.search(config.basedn, config, function(search_error, res) {
                    if (search_error) { onError(search_error); }
                    var userdn=[];
                    res.on('searchEntry', function(entry) {
                        userdn.push(entry.object.dn);
                    });
                    res.on('error', onError);
                    res.on('end', function() {
                        callback(null, userdn);
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

exports.hook_capabilities = function (next, connection) {
    // Don't offer AUTH capabilities by default unless session is encrypted
    if (connection.using_tls) {
        var methods = [ 'PLAIN', 'LOGIN' ];
        connection.capabilities.push('AUTH ' + methods.join(' '));
        connection.notes.allowed_auth_methods = methods;
    }
    next();
};

exports.register = function() {
    this.inherits('auth/auth_base');
    var plugin = this;
    plugin.register_hook('init_master',  'init_ldap_authn');
    plugin.register_hook('init_child',   'init_ldap_authn');
    var load_ldap_authn_ini = function() {
        plugin.loginfo("loading ldap-authn.ini");
        plugin.cfg = plugin.config.get('ldap-authn.ini', 'ini', load_ldap_authn_ini);
    };
    load_ldap_authn_ini();
};

exports.init_ldap_authn = function(next, server) {
    var plugin = this;
    if (!server.notes.ldappool) {
        plugin.logerror('LDAP Pool not found! Make sure ldappool plugin is loaded!');
    }
    else {
        this.pool = server.notes.ldappool;
    }
    next();
};

exports.check_plain_passwd = function (connection, user, passwd, cb) {
    var plugin = this;
    if (Array.isArray(plugin.cfg.main.dn)) {
        plugin.logdebug('Looking up user "' + user + '" by DN.');
        var search = function(userdn, searchCallback) {
            var userdn = userdn.replace(/%u/g, user);
            return plugin._verify_user(userdn, passwd, searchCallback);
        };
        var asyncCallback = function(result) {
            cb(result !== undefined && result !== null);
        };
        return async.detect(plugin.cfg.main.dn, search, asyncCallback);
    }
    var callback = function(err, userdn) {
        if (err) {
            plugin.logerror("Could not use LDAP for password check: " + err);
            return cb(false);
        }
        else if (userdn.length !== 1) {
            plugin.logdebug('None or nonunique LDAP search result for user, access denied');
            cb(false);
        }
        else {
            return plugin._verify_user(userdn[0], passwd, cb);
        }
    };
    plugin.logdebug('Looking up user "' + user + '" by search.');
    plugin._get_dn_for_uid(user, callback);
};
