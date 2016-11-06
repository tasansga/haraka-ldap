# auth/authn_ldap

This haraka plugin implements authentication (authn) agains LDAP servers, i.e. it checks if the given user credentials are valid in LDAP. It can either search for the user DN first, or it can try to bind by predefined DN templates.

## Configuration
All configuration is done in `config/authn_ldap.ini`.
The following options are configurable:  
* `basedn`: *optional*, default: as used by ldappool  
It's possible to override ldappool's default basedn for this plugin.
* `scope`: *optional*, default: as used by ldappool  
It's possible to override ldappool's default scope for this plugin.
* `searchfilter`: *optional*, default: (&(objectclass=*)(uid=%u))  
Search filter to lookup the user's DN. The param %u denotes the uid/username as given during login. As result the search filter should return the object(s) to be used for a simple bind attempt. Authentication will fail if the search filter doesn't return exactly one matching object.
* `dn`: *optional*, default: undefined  
`dn` is an array of template DN to check for the given uid. This is an alternate mode of lookup, where the plugin inserts the uid in the DN template and immediately tries to bind instead of doing a search for the DN first.

## Examples
Below are two examples to explain both modes of operation.

### By search
Given the following configuration:

```
searchfilter = (&(objectclass=*)(uid=%u))
```

Here the plugin will search for the object(s) first. The search filter should return some object's DN like `uid=user1,ou=users,dc=my-domain,dc=com`. Then the plugin will attempt a simple bind with the found DN and the given password.

### By DN templates
Given the following configuration:

```
dn[] = uid=%u,ou=users,dc=my-domain,dc=com
dn[] = uid=%u,ou=people,dc=my-domain,dc=com
```

The plugin will replace `%u` with the given username and immediately attempts to simple bind with the resulting DN(s) and the given password.

### Difference between both approaches

While the search filter approach offers more flexibility, a limited number of DN templates might be faster as they don't need to search first.

However, there's also another noteworthy difference. Given the following LDAP data:

```
dn: uid=nonunique,ou=users,dc=my-domain,dc=com
uid: nonunique

dn: uid=nonunique,ou=people,dc=my-domain,dc=com
uid: nonunique
```

In this scenario, the search filter approach will always deny login for uid `nonunique`, because the search doesn't return exactly one single result. However, if using DN templates instead the user would be able to log in.

