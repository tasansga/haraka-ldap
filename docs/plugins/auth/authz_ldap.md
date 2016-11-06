# authz_ldap

This haraka plugin implements authorization (authz) against LDAP servers, i.e. if the given user is allowed to use the given "FROM" address. It utilizes the ldappool plugin.

## Configuration
All configuration is done in `config/authz_ldap.ini`.
The following options are configurable:  
* `basedn`: *optional*, default: as used by ldappool  
It's possible to override ldappool's default basedn for this plugin.
* `scope`: *optional*, default: as used by ldappool  
It's possible to override ldappool's default scope for this plugin.
* `searchfilter`: *optional*, default: (&(objectclass=*)(uid=%u)(mail=%a))  
Search filter to verify authorization. If the search result yields at least one object, authorization is given. The param `%u` denotes the uid/username as given during login. The param `%a` denotes the email address as given in "FROM".

