'use strict';

var ldap = require('ldapjs');

var LdapPool = function(config) {
    this._set_config(config);
    this.pool = { 'servers' : [] };
};

LdapPool.prototype._set_config = function(config) {
    if (config === undefined) { config = {}; }
    if (config.main === undefined) { config.main = {}; }
    this.config = {
        servers : config.main.server || [ 'ldap://localhost:389' ],
        timeout : config.main.timeout,
        tls_enabled : config.main.tls_enabled || false,
        tls_rejectUnauthorized : config.main.tls_rejectUnauthorized,
        scope : config.main.scope || 'sub',
        binddn : config.main.binddn,
        bindpw : config.main.bindpw,
        basedn : config.main.basedn,
        aliases : config.aliases,
        authn : config.authn,
        authz : config.authz,
        rcpt_to : config.rcpt_to
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
    if (this.pool.servers.length > 0) {
        while (this.pool.servers.length > 0) {
            this.pool.servers.shift().unbind(next);
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
            client.bind(cfg.binddn, cfg.bindpw, function (err2) {
                next(err2, client);
            });
        };
        this._create_client(_do_bind);
    }
    else {
        this._create_client(next);
    }
};

LdapPool.prototype.get = function(next) {
    var pool = this.pool;
    if (pool.servers.length >= this.config.servers.length) {
        // shift and push for round-robin
        var client = pool.servers.shift();
        pool.servers.push(client);
        return next(null, client);
    }
    var setClient = function(err, client2) {
        pool.servers.push(client2);
        return next(err, client2);
    };
    this._bind_default(setClient);
};

exports.LdapPool = LdapPool;
