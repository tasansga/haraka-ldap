# rcpt_to.in_ldap

This haraka plugin check if a given recipient address exists in LDAP. It utilizes the ldappool plugin.

## Configuration
All configuration is done in `config/authz_ldap.ini`.
The following options are configurable:  
* `basedn`: *optional*, default: as used by ldappool  
It's possible to override ldappool's default basedn for this plugin.
* `scope`: *optional*, default: as used by ldappool  
It's possible to override ldappool's default scope for this plugin.
* `searchfilter`: *optional*, default: (&(objectclass=*)(mail=%a))  
Search filter to look up the given address. The plugin will call `next(OK)` only if the search returned at least one object. The param `%a` denotes the email address given as recipient.

