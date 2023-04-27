'use strict';

const util     = require('util');
const authn    = require('./authn');
const aliases  = require('./aliases');
const rcpt_to  = require('./rcpt_to');
const authz    = require('./authz');
const LdapPool = require('./pool').LdapPool;

const AUTH_COMMAND = 'AUTH';
const AUTH_METHOD_PLAIN = 'PLAIN';
const AUTH_METHOD_LOGIN = 'LOGIN';

exports.handle_authn = function (next, connection, params) {
    // we use this as hook so we can ignore auth calls with disabled auth plugin
    // see: auth/auth_base.js, exports.hook_unrecognized_command
    if (!connection.server.notes.ldappool.config.authn) return next();

    if (params[0].toUpperCase() === AUTH_COMMAND && params[1]) {
        return this.select_auth_method(next, connection, params.slice(1).join(' '));
    }

    if (!connection.notes.authenticating) return next();

    switch (connection.notes.auth_method) {
        case AUTH_METHOD_LOGIN:
            this.auth_login(next, connection, params);
            break;
        case AUTH_METHOD_PLAIN:
            this.auth_plain(next, connection, params);
            break;
        default:
            next();
    }
}

exports.hook_capabilities = (next, connection) => {
    // default: don't offer AUTH unless session is encrypted
    if (connection.using_tls) {
        const methods = [ 'PLAIN', 'LOGIN' ];
        connection.capabilities.push(`AUTH ${  methods.join(' ')}`);
        connection.notes.allowed_auth_methods = methods;
    }
    next();
}

exports.check_plain_passwd = function () {
    authn.check_plain_passwd(...arguments);
}

exports.aliases = function (next, connection, params) {
    if (!connection.server.notes.ldappool.config.aliases) return next();

    aliases.aliases(...arguments);
}

exports.check_rcpt = function (next, connection, params) {
    if (!connection.server.notes.ldappool.config.rcpt_to) return next();

    rcpt_to.check_rcpt.apply(rcpt_to, arguments);
}

exports.check_authz = function (next, connection, params) {
    if (!connection.server.notes.ldappool.config.authz) return next();

    authz.check_authz.apply(authz, arguments);
}

exports.register = function () {
    this.inherits('auth/auth_base');
    this.register_hook('init_master',  '_init_ldappool');
    this.register_hook('init_child',   '_init_ldappool');
    this.register_hook('rcpt', 'aliases');
    this.register_hook('rcpt', 'check_rcpt');
    this.register_hook('mail', 'check_authz');
    this.register_hook('unrecognized_command', 'handle_authn');
    this._load_ldap_ini();
}

exports._load_ldap_ini = function () {

    this.loginfo("loading ldap.ini");
    const cfg = this.config.get('ldap.ini', () => {
        this._load_ldap_ini();
    });

    if (this._pool) {
        this._pool._set_config(cfg);
        this.logdebug(`Current config: ${  util.inspect(this._pool.config)}`);
    }
    else {
        this._tmp_pool_config = cfg;
    }
}

exports._init_ldappool = function (next, server) {

    if (!server.notes.ldappool) {
        server.notes.ldappool = new LdapPool();
        if (this._tmp_pool_config) {
            server.notes.ldappool._set_config(this._tmp_pool_config);
            this._tmp_pool_config = undefined;
            this.logdebug(`Current config: ${  util.inspect(server.notes.ldappool.config)}`);
        }
    }
    this._pool = server.notes.ldappool;
    next();
}

exports.shutdown = function (next) {
    if (this._pool) this._pool.close(next || function () { });
}
