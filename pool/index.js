'use strict';

var ldap = require('ldapjs');
var util = require('util');


/**
 * ldap-pool.js
 * This haraka module implements pooling of bound LDAP connections to avoid
 * the necessity to open and bind new connections for every request.
 */


var LdapPool = function(config) {
    this._set_config(config);
    this.pool = { 'servers' : [] };
};

LdapPool.prototype._set_config = function(config) {
    if (config === undefined) { config = {}; }
    this.config = {
        servers : config.server || [ 'ldap://localhost:389' ],
        timeout : config.timeout,
        tls_enabled : config.tls_enabled || false,
        tls_rejectUnauthorized : config.tls_rejectUnauthorized,
        scope : config.scope || 'sub',
        binddn : config.binddn,
        bindpw : config.bindpw,
        basedn : config.basedn
    };
    return this.config;
};

LdapPool.prototype._get_ldapjs_config = function() {
    var config = { // see: http://ldapjs.org/client.html
        url: this.config.servers.shift(),
        timeout: this.config.timeout
    };
    this.config.servers.push(config.url);
    if (this.config.tls_rejectUnauthorized !== undefined) {
        config.tlsOptions = {
            rejectUnauthorized: this.config.tls_rejectUnauthorized
        };
    }
    return config;
};

LdapPool.prototype._create_client = function(next) {
    var client = ldap.createClient(this._get_ldapjs_config());
    var starttls = function(err) {
        if (err) {
            return next(err);
        }
        return next(null, client);
    };
    if (this.config.tls_enabled || false) {
        client.starttls({ }, null, starttls);
    }
    else {
        return next(null, client);
    }
};

LdapPool.prototype.close = function(next) {
    if (this.pool['servers'].length > 0) {
        while (this.pool['servers'].length > 0) {
            this.pool['servers'].shift().unbind(next);
        }
    }
    else {
        next();
    }
};

LdapPool.prototype._bind_default = function(next) {
    var cfg = this.config;
    if (cfg.binddn !== undefined && cfg.bindpw !== undefined) {
        var _do_bind = function(err, client) {
            if (err) {
                return next(err);
            }
            else {
                client.bind(cfg.binddn, cfg.bindpw, function(err) {
                    return next(err, client);
                });
            }
        };
        this._create_client(_do_bind);
    }
    else {
        return this._create_client(next);
    }
};

LdapPool.prototype.get = function(next) {
    var pool = this.pool;
    if (pool['servers'].length >= this.config.servers.length) {
        // shift and push for round-robin
        var client = pool['servers'].shift();
        pool['servers'].push(client);
        return next(null, client);
    }
    var setClient = function(err, client) {
        pool['servers'].push(client);
        return next(err, client);
    };
    this._bind_default(setClient);
};


exports.LdapPool = LdapPool;

exports.register = function() {
    var plugin = this;
    plugin.register_hook('init_master',  '_init_ldappool');
    plugin.register_hook('init_child',   '_init_ldappool');
    plugin._load_ldappool_ini();
};

exports._load_ldappool_ini = function() {
    var plugin = this;
    plugin.loginfo("loading ldap-pool.ini");
    var cfg = plugin.config.get('ldap-pool.ini', function() {
        plugin._load_ldappool_ini();
    });
    if (plugin._pool) {
        plugin._pool._set_config(cfg.main);
        plugin.logdebug('Current config: ' + util.inspect(plugin._pool.config));
    }
    else {
        plugin._tmp_pool_config = cfg.main;
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
