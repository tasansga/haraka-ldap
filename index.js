'use strict';

var util     = require('util');
var authn    = require('./authn');
var aliases  = require('./aliases');
var rcpt_to  = require('./rcpt_to');
var authz    = require('./authz');
var LdapPool = require('./pool').LdapPool;

var AUTH_COMMAND = 'AUTH';
var AUTH_METHOD_PLAIN = 'PLAIN';
var AUTH_METHOD_LOGIN = 'LOGIN';

exports.handle_authn = function (next, connection, params) {
    // we use this as hook so we can ignore auth calls with disabled auth plugin
    // see: auth/auth_base.js, exports.hook_unrecognized_command
    var plugin = this;
    if (params[0].toUpperCase() === AUTH_COMMAND && params[1]) {
        return plugin.select_auth_method(next, connection,
                params.slice(1).join(' '));
    }
    if (!connection.notes.authenticating) { return next(); }

    var am = connection.notes.auth_method;
    if (am === AUTH_METHOD_LOGIN) {
        return plugin.auth_login(next, connection, params);
    }
    if (am === AUTH_METHOD_PLAIN) {
        return plugin.auth_plain(next, connection, params);
    }
    return next();
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

exports.check_plain_passwd = function() {
    authn.handle_auth.apply(authn, arguments);
};

exports.aliases = function() {
    aliases.aliases.apply(aliases, arguments);
};

exports.check_rcpt = function() {
    rcpt_to.check_rcpt(rcpt_to, arguments);
};

exports.check_authz = function() {
    authz.check_authz.apply(authz, arguments);
};

exports.register = function() {
    var plugin = this;
    this.inherits('auth/auth_base');
    plugin.register_hook('init_master',  '_init_ldappool');
    plugin.register_hook('init_child',   '_init_ldappool');
    plugin.register_hook('rcpt', 'aliases');
    plugin.register_hook('rcpt', 'check_rcpt');
    plugin.register_hook('mail', 'check_authz');
    plugin.register_hook('unrecognized_command', 'handle_authn')
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
        server.notes.ldappool = new LdapPool();
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
