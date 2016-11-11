# haraka-ldap
Here is a set of LDAP plugins for Haraka.  
The [ldap-pool](https://www.npmjs.com/package/haraka-plugin-ldap-pool) module provides a LDAP client connection pool for other LDAP modules.  
The [ldap-authn](https://www.npmjs.com/package/haraka-plugin-ldap-authn) module implements authentication agains LDAP servers, i.e. it checks if the given user credentials are valid in LDAP.  
With the [ldap-authz](https://www.npmjs.com/package/haraka-plugin-ldap-authz) module is it possible to check an user's authorization agains LDAP servers, i.e. if the given user is allowed to use the given "FROM" address.  
Use the [ldap-rcpt_to](https://www.npmjs.com/package/haraka-plugin-ldap-rcpt_to) module to check if a given recipient exists in LDAP.  
For advanced email delivery exists the [ldap-aliases](https://www.npmjs.com/package/haraka-plugin-ldap-aliases) module, it can resolve email forward addresses and deliver an email to one or multiple recipients on the same server.

