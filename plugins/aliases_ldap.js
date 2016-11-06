'use strict';

var async = require('async');
var util = require('util');
var Address = require('address-rfc2821').Address;


/**
 * aliases_ldap.js
 * This haraka plugin allows to resolve email aliases
 * i.e. to deliver an email to one or multiple recipients on the same server.
 */


exports._get_alias = function (address, callback) {
    var plugin = this;
    if (!this.pool) {
        return onError('LDAP Pool not found!');
    }
    var onError = function(err) {
        plugin.logerror('Could not resolve "' + address + '" as alias: ' +  err);
        callback(err, false);
    };
    var search = function (err, client) {
        if (err) {
            return onError(err);
        }
        else {
            var config = plugin._get_search_conf_alias(address);
            plugin.logdebug('Checking address for alias: ' + util.inspect(config));
            try {
                client.search(config.basedn, config, function(search_error, res) {
                    if (search_error) { onError(search_error); }
                    var alias = [];
                    res.on('searchEntry', function(entry) {
                        alias = alias.concat(entry.object[config.attributes[0]]);
                    });
                    res.on('error', onError);
                    res.on('end', function() {
                        if (plugin.cfg.main.attribute_is_dn) {
                            plugin._resolve_dn_to_alias(alias, callback);
                        }
                        else {
                            callback(null, alias);
                        }
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

exports._get_search_conf_alias = function(address) {
    var plugin = this;
    var filter = plugin.cfg.main.searchfilter || '(&(objectclass=*)(mail=%a)(mailForwardAddress=*))';
    filter = filter.replace(/%a/g, address);
    var config = {
        basedn: plugin.cfg.main.basedn || this.pool.config.basedn,
        filter: filter,
        scope: plugin.cfg.main.scope || this.pool.config.scope,
        attributes: [ plugin.cfg.main.attribute || 'mailForwardingAddress' ]
    };
    if (config.basedn === undefined) {
        plugin.logerror('Undefined basedn. Please check your configuration!');
    }
    return config;
};

exports._resolve_dn_to_alias = function(dn, callback) {
    var plugin = this;
    if (!this.pool) {
        return onError('LDAP Pool not found!');
    }
    var onError = function(err) {
        plugin.logerror('Could not get address for dn "' + util.inspect(dn) + '": ' +  err);
        callback(err);
    };
    var config = {
        scope: 'base',
        attributes: [ plugin.cfg.main.subattribute || 'mail' ]
    };
    var asyncDnSearch = function (err, client) {
        var client = client;
        var search = function(dn, searchCallback) {
            client.search(dn, config, function(search_error, res) {
                if (search_error) { onError(search_error, dn); }
                res.on('searchEntry', function(entry) {
                    var arr_addr = entry.object[config.attributes[0]];
                    if (Array.isArray(arr_addr)) {
                        arr_addr = arr_addr[0];
                    }
                    searchCallback(null, arr_addr);
                });
                res.on('error', function(e) {
                    plugin.logwarn('Could not retrieve dn "' + dn + '": ' + e);
                    searchCallback(null, []);
                });
            });
        };
        if (err) {
            return onError(err);
        }
        else {
            async.concat(dn, search, callback);
        }
    };
    this.pool.get(asyncDnSearch);
};

exports.register = function() {
    var plugin = this;
    plugin.register_hook('init_master',  'init_aliases_ldap');
    plugin.register_hook('init_child',   'init_aliases_ldap');
    var load_aliases_ldap_ini = function() {
        plugin.loginfo("loading aliases_ldap.ini");
        plugin.cfg = plugin.config.get('aliases_ldap.ini', 'ini', load_aliases_ldap_ini);
    };
    load_aliases_ldap_ini();
    plugin.register_hook('rcpt', 'aliases');
};

exports.init_aliases_ldap = function(next, server) {
    var plugin = this;
    if (!server.notes.ldappool) {
        plugin.logerror('LDAP Pool not found! Make sure ldappool plugin is loaded!');
    }
    else {
        this.pool = server.notes.ldappool;
    }
    next();
};

exports.aliases = function(next, connection, params) {
    var plugin = this;
    if (!params || !params[0] || !params[0].address) {
        plugin.logerror('Ignoring invalid call. Given params: ' +
                        util.inspect(params));
        return next();
    }
    var rcpt = params[0].address();
    var handleAliases = function(err, result) {
        if (err) {
            plugin.logerror('Could not use LDAP to resolve aliases: ' + err);
            return next(DENYSOFT);
        }
        if (result.length === 0) {
            plugin.logdebug('No aliases results found for rcpt: ' + rcpt);
            return next();
        }
        connection.logdebug(plugin, 'Aliasing ' + rcpt + ' to ' + util.inspect(result));
        connection.transaction.rcpt_to.pop();
        for (var i=0; i<result.length; i++) {
            var toAddress = new Address('<' + result[i] + '>');
            connection.transaction.rcpt_to.push(toAddress);
        }
        next(OK);
    };
    plugin._get_alias(rcpt, handleAliases);
};
