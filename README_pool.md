# haraka-plugin-ldap-pool

The haraka-plugin-ldap-pool module provides a LDAP client connection pool for other LDAP
modules.

## Configuration

All configuration is done in `config/ldap-pool.ini`.
The following options are configurable:

* `server`: *optional*, default: `server[]=ldap://localhost:389`  
Specify LDAP server addresses.
This is an array of *url* from [ldapjs](http://ldapjs.org/client.html).
Apply multiple server[] values for some simple load-balancing.
* `timeout`: *optional*, default: No timeout.  
Define time out for LDAP ops.
This is the same as *timeout* from [ldapjs](http://ldapjs.org/client.html).
* `tls_enabled`: *optional*, default: `tls_enabled=false`  
Enable or disable TLS. If enabled, all LDAP connections will be secured first 
by calling starttls.
* `tls_rejectUnauthorized`: *optional*, default: `tls_rejectUnauthorized`false`  
Enable or disable rejection of secured connections without valid server certificate.
This is as *rejectUnauthorized* from the [node.js server API as used by ldapjs](https://nodejs.org/api/tls.html#tls_tls_createserver_options_secureconnectionlistener).
* `scope`: *optional*, default: `cope=sub`  
This defines the scope of the LDAP search operation, like *base* or *sub*.
This is the same as *scope* from [ldapjs](http://ldapjs.org/client.html).
* `binddn`: *optional*, default: not set  
The binddn is basically the LDAP user to be used to look up data in LDAP. It
is optional (the LDAP server might allow anonymous binds).
* `bindpw`: *optional*, default: not set  
A bindpw might be necessary to bind with the given binddn. It can be supplied
here. 
* `basedn`: *required*, default: not set  
The basedn is a requirement for many LDAP options. It must be defined with
this option.

