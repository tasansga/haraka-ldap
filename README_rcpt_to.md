# haraka-plugin-ldap-rcpt_to

This haraka plugin checks if a given recipient address exists in LDAP. It utilizes the haraka-plugin-ldap-pool.

## Configuration
All configuration is done in `config/ldap-rcpt_to.ini`.
The following options are configurable:  
* `basedn`: *optional*, default: as used by haraka-plugin-ldap-pool  
It's possible to override haraka-plugin-ldap-pool's default basedn for this plugin.
* `scope`: *optional*, default: as used by haraka-plugin-ldap-pool  
It's possible to override haraka-plugin-ldap-pool's default scope for this plugin.
* `searchfilter`: *optional*, default: (&(objectclass=*)(mail=%a))  
Search filter to look up the given address. The plugin will call `next(OK)` only if the search returned at least one object. The param `%a` denotes the email address given as recipient.

