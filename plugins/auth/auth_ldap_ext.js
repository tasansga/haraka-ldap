'use strict';

exports._verify_user = function (userdn, passwd, cb) {
    var plugin = this;
    if (!this.pool) {
        throw new Error('LDAP Pool not found!');
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
    var filter = plugin.cfg.filter || '(&(objectclass=*)(uid=%u))';
    filter = filter.replace(/%u/g, user);
    var config = {
        basedn: this.pool.config.basedn,
        filter: filter,
        scope: plugin.cfg.scope || 'sub',
        attributes: ['dn', plugin.cfg.mail_attribute || 'mail']
    };
    if (config.basedn === undefined) {
        plugin.logerror("Undefined basedn. Please check your configuration!");
    }
    return config;
};

exports._get_dn_for_uid = function (uid, callback) {
    if (!this.pool) {
        throw new Error('LDAP Pool not found!');
    }
    var plugin = this;
    var onError = function(err) {
        plugin.logerror('Could not get DN for UID "' + uid + '": ' +  err);
        callback(err);
    };
    var dnSearch = function (err, client) {
        var config = plugin._get_search_conf(uid);
        if (err) {
            onError(err);
        }
        else {
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
    };
    this.pool.get(dnSearch);
};

exports.hook_capabilities = function (next, connection) {
    // Don't offer AUTH capabilities by default unless session is encrypted
    if (connection.using_tls) {
        var methods = [ 'LOGIN' ];
        connection.capabilities.push('AUTH LOGIN');
        connection.notes.allowed_auth_methods = methods;
    }
    next();
};

exports.register = function() {
    this.inherits('auth/auth_base');
    var plugin = this;
    plugin.register_hook('init_master',  'init_auth_ldap_ext');
    plugin.register_hook('init_child',   'init_auth_ldap_ext');
    var load_auth_ldap_ext_ini = function() {
        plugin.loginfo("loading auth_ext_ldap.ini");
        plugin.cfg = plugin.config.get('auth_ldap_ext.ini', 'ini', load_auth_ldap_ext_ini);
    };
    load_auth_ldap_ext_ini();
};

exports.init_auth_ldap_ext = function(next, server) {
    if (!server.notes.ldappool) {
        throw new Error('LDAP Pool not found! Make sure ldappool plugin is loaded first!');
    }
    else {
        this.pool = server.notes.ldappool;
    }
};

exports.check_plain_passwd = function (connection, user, passwd, cb) {
    var plugin = this;
    var errWhileCheck = function(err) {
        plugin.logerror("Could not use LDAP for password check: " + err);
        return cb(false);
    };
    plugin._get_dn_for_uid(user, function(err, userdn) {
        if (err) {
            errWhileCheck(err);
        }
        else if (userdn.length !== 1) {
            plugin.logdebug('None or nonunique LDAP search result for user, access denied');
            return cb(false);
        }
        else {
            plugin._verify_user(userdn[0], passwd, cb);
        }
    });
    //var mfaddr = connection.transaction.mail_from.address().toString();
    // TODO: filter should check user owns mail_from address!
    //       connection.transaction.rcpt_to is an array for that
};
