'use strict';

var util = require('util');

exports.LdapPool = require('./pool').LdapPool;

exports.register = function() {
    var plugin = this;
    plugin.register_hook('init_master',  '_init_ldappool');
    plugin.register_hook('init_child',   '_init_ldappool');
    plugin._load_ldap_ini();
};

exports._load_ldap_ini = function() {
    var plugin = this;
    plugin.loginfo("loading ldap-pool.ini");
    var cfg = plugin.config.get('ldap-pool.ini', function() {
        plugin._load_ldap_ini();
    });
    if (plugin._pool) {
        plugin._pool._set_config(cfg);
        plugin.logdebug('Current config: ' + util.inspect(plugin._pool.config));
    }
    else {
        plugin._tmp_pool_config = cfg;
    }
};

exports._init_ldappool = function(next, server) {
    var plugin = this;
    if (!server.notes.ldappool) {
        server.notes.ldappool = new this.LdapPool();
        if (plugin._tmp_pool_config) {
            server.notes.ldappool._set_config(plugin._tmp_pool_config);
            plugin._tmp_pool_config = undefined;
            plugin.logdebug('Current config: ' + util.inspect(server.notes.ldappool.config));
        }
    }
    this._pool = server.notes.ldappool;
    next();
};

exports.shutdown = function (next) {
    var cb = next || function() { };
    if (this._pool) {
        this._pool.close(cb);
    }
};
