ldappool
========

The ldappool module provides a LDAP client connection pool for other LDAP
modules.

Configuration
-------------

All configuration is done in `config/ldappool.ini`.
The following options are configurable:

* `server`: *optional*  
Specify LDAP server addresses.
This is an array of *url* from [ldapjs](http://ldapjs.org/client.html).
Apply multiple server[] values for some simple load-balancing.
Default: server[]=*ldap://localhost:389*
* `timeout`: *optional*  
Define time out for LDAP ops.
This is the same as *timeout* from [ldapjs](http://ldapjs.org/client.html).
Default: No timeout.
* `tls_enabled`: *optional*  
Enable or disable TLS. If enabled, all LDAP connections will be secured first 
by calling starttls.
Default: tls_enabled=*false*
* `tls_rejectUnauthorized`: *optional*  
Enable or disable rejection of secured connections without valid server certificate.
This is as *rejectUnauthorized* from the [node.js server API as used by ldapjs](https://nodejs.org/api/tls.html#tls_tls_createserver_options_secureconnectionlistener).
Default: tls_rejectUnauthorized=*false*
* `scope`: *optional*  
This defines the scope of the LDAP search operation, like *base* or *sub*.
This is the same as *scope* from [ldapjs](http://ldapjs.org/client.html).
Default: scope=*sub*
* `binddn`: *optional*  
The binddn is basically the LDAP user to be used to look up data in LDAP. It
is optional (the LDAP server might allow anonymous binds).
Default: not set
* `bindpw`: *optional*  
A bindpw might be necessary to bind with the given binddn. It can be supplied
here. 
Default: not set
* `basedn`: *required*
The basedn is a requirement for many LDAP options. It must be defined with
this option.
Default: not set
