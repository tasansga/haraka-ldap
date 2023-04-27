'use strict';

const ldap = require('ldapjs');

const LdapPool = function (config) {
    this._set_config(config);
    this.pool = { 'servers' : [] };
}

LdapPool.prototype._set_config = function (config) {
    if (config === undefined) config = {};
    if (config.main === undefined) config.main = {};
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
}

LdapPool.prototype._get_ldapjs_config = function () {
    const config = { // see: http://ldapjs.org/client.html
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
}

LdapPool.prototype._create_client = function (next) {
    const client = ldap.createClient(this._get_ldapjs_config());

    if (!this.config.tls_enabled) return next(null, client);

    client.starttls({ }, null, function (err) {
        if (err) return next(err);
        next(null, client);
    });
}

LdapPool.prototype.close = function (next) {
    if (this.pool.servers.length <= 0) return next();

    while (this.pool.servers.length > 0) {
        this.pool.servers.shift().unbind(() => {
            if (this.pool.servers.length === 0) next()
	});
    }
}

LdapPool.prototype._bind_default = function (next) {
    const cfg = this.config;

    this._create_client((err, client) => {
        if (err) return next(err)

        if (cfg.binddn && cfg.bindpw) {
            client.bind(cfg.binddn, cfg.bindpw, (err2) => {
                next(err2, client);
            })
        }
        else {
            next(null, client)
        }
    })
}

LdapPool.prototype.get = function (next) {
    const pool = this.pool;

    if (pool.servers.length >= this.config.servers.length) {
        // shift and push for round-robin
        const client = pool.servers.shift();
        pool.servers.push(client);
        return next(null, client);
    }

    this._bind_default( (err, client) => {
        pool.servers.push(client);
        next(err, client);
    })
}

exports.LdapPool = LdapPool;
