# haraka-ldap
Here is a set of LDAP plugins for Haraka.  
The [ldappool](./docs/plugins/ldappool.md) module provides a LDAP client connection pool for other LDAP modules.  
The [authn_ldap](./docs/plugins/auth/authn_ldap.md) module implements authentication agains LDAP servers, i.e. it checks if the given user credentials are valid in LDAP.  
With the [authz_ldap](./docs/plugins/auth/authz_ldap.md) module is it possible to check an user's authorization agains LDAP servers, i.e. if the given user is allowed to use the given "FROM" address.  
Use the [rcpt_to.in_ldap](./docs/plugins/rcpt_to.in_ldap.md) module to check if a given recipient exists in LDAP.  
For advanced email delivery exists the [aliases_ldap](./docs/plugins/aliases_ldap.md) module, it can resolve email forward addresses and deliver an email to one or multiple recipients on the same server.

