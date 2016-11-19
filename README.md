# haraka-ldap

This an universal LDAP plugin for Haraka. It supports aliases, authentication, authorization and recipient lookup. Check it out on [github](https://github.com/tasansga/haraka-ldap) or [npm](https://www.npmjs.com/package/haraka-plugin-ldap).

## Configuration

All configuration is done in `config/ldap.ini`.
The following options are configurable:


### Main section

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
The basedn is a requirement for many LDAP operations. It must be defined with
this option.

Every task is enabled by adding a task-specific section in the configuration file. They are described below.

### \[aliases\]

By enabling \[aliases\] is it possible to query LDAP to resolve email aliases and to forward email to one or multiple configured targets. 

* `basedn`: *optional*, default: as set in main section 
It's possible to override the default basedn
* `scope`: *optional*, default: as set in main section
It's possible to override the default scope
* `searchfilter`: *optional*, default: (&(objectclass=*)(mail=%a)(mailForwardAddress=*))  
Search filter to lookup aliases. The param %a denotes the recipient's mail address as given on the email's envelope. As result the search filter should return the objects containing the dealiased recipient addresses within a given `attribute` (see below). 
* `attribute`: *optional*, default: `mailForwardingAddress`
Attribute used to parse as recipient's email address or as recipient's DN (see below).
* `attribute_is_dn`: *optional*, default: false
Set this to `true` if the attribute does not contain an email address but a fully qualified DN.
* `subattribute`: *optional*, default: `mailLocalAddress`
If the attribute references a DN then the subattribute references the DN's email address that should be used as recipient.


### \[authn\]

With the \[authn\] is authentication (authn) against LDAP servers enabled, i.e. this checks if a given user credentials are valid in LDAP. It can either search for the user DN first, or it can try to bind by predefined DN templates

* `basedn`: *optional*, default: as set in main section 
It's possible to override the default basedn
* `scope`: *optional*, default: as set in main section
It's possible to override the default scope
* `searchfilter`: *optional*, default: (&(objectclass=*)(uid=%u))  
Search filter to lookup the user's DN. The param `%u` denotes the uid/username as given during login. As result the search filter should return the object(s) to be used for a simple bind attempt. Authentication will fail if the search filter doesn't return exactly one matching object.
* `dn`: *optional*, default: undefined  
`dn` is an array of template DN to check for the given uid. This is an alternate mode of lookup, where the plugin inserts the uid in the DN template and immediately tries to bind instead of doing a search for the DN first. A template DN looks like `uid=%u,ou=users,dc=my-domain,dc=com`. The param `%u` denotes the uid/username as given during login.


### \[authz\]

Adding the \[authn\] section enables authorization (authz) against LDAP servers, i.e. if the given user is allowed to use the given "FROM" address.

* `basedn`: *optional*, default: as set in main section 
It's possible to override the default basedn
* `scope`: *optional*, default: as set in main section
It's possible to override the default scope
* `searchfilter`: *optional*, default: (&(objectclass=*)(uid=%u)(mail=%a))  
Search filter to verify authorization. If the search result yields at least one object, authorization is given. The param `%u` denotes the uid/username as given during login. The param `%a` denotes the email address as given in "FROM".


### \[rcpt_to\]

Enable \[rcpt_to\] to verify that a given recipient address exists in LDAP. 

* `basedn`: *optional*, default: as set in main section 
It's possible to override the default basedn
* `scope`: *optional*, default: as set in main section
It's possible to override the default scope
* `searchfilter`: *optional*, default: (&(objectclass=*)(mail=%a))  
Search filter to look up the given address. The plugin will call `next(OK)` only if the search returned at least one object. The param `%a` denotes the email address given as recipient.


## Examples


### \[authn\]

Below are two examples to explain both modes of operation.


#### By search
Given the following configuration:

```
searchfilter = (&(objectclass=*)(uid=%u))
```

Here the plugin will search for the object(s) first. The search filter should return some object's DN like `uid=user1,ou=users,dc=my-domain,dc=com`. Then the plugin will attempt a simple bind with the found DN and the given password.


#### By DN templates
Given the following configuration:

```
dn[] = uid=%u,ou=users,dc=my-domain,dc=com
dn[] = uid=%u,ou=people,dc=my-domain,dc=com
```

The plugin will replace `%u` with the given username and immediately attempts to simple bind with the resulting DN(s) and the given password.


#### Difference between both approaches

While the search filter approach offers more flexibility, a limited number of DN templates might be faster as they don't need to search first.

However, there's also another noteworthy difference. Given the following LDAP data:

```
dn: uid=nonunique,ou=users,dc=my-domain,dc=com
uid: nonunique

dn: uid=nonunique,ou=people,dc=my-domain,dc=com
uid: nonunique
```

In this scenario, the search filter approach will always deny login for uid `nonunique`, because the search doesn't return exactly one single result. However, if using DN templates instead the user would be able to log in.


### aliases
Following are a few examples to explain the proper usage of aliases.

#### simple aliases
It is possible to use email aliases to deliver email for one address to another address. Given the following LDAP objects:

```
dn: uid=forwarder,ou=people,dc=my-domain,dc=com
objectClass: inetLocalMailRecipient
uid: forwarder
cn: Forwarding User
mailLocalAddress: forwarder@my-domain.com
mailRoutingAddress: user@my-domain.com

dn: uid=user,dc=my-domain,dc=com
uid: user
cn: Our User
mailLocalAddress: user@my-domain.com
```

So here are two users in LDAP, both with a `mailLocalAddress` and one with a `mailRoutingAddress`. Email send to the user with a `mailRoutingAddress` should be delivered to `user@my-domain.com`. This can be accomplished with the following configuration:

```
searchfilter = (&(mailLocalAddress=%a)(mailRoutingAddress=*))
attribute = mailRoutingAddress
```

Given this configuration, the haraka-plugin-ldap-aliases plugin will simply change recipients that match the given searchfilter to the value referenced by the `mailRoutingAddress` attribute: Mail send to `forwarder@my-domain.com` will be delivered to `user@my-domain.com`.


#### attribute_is_dn
attribute_is_dn is handy to use LDAP groups as mail groups. Let's check the following LDAP group and user:

```
dn: cn=postmaster,dc=my-domain,dc=com
objectclass: groupOfNames
mailLocalAddress: postmaster@my-domain.com
member: uid=user,dc=my-domain,dc=com

dn: uid=user,dc=my-domain,dc=com
uid: user
cn: Our User
mailLocalAddress: user@my-domain.com
```

So, we have one group with the email address `postmaster@my-domain.com` and one user with the email address `user@my-domain.com`. Also, the user is a member of the group.

To use the LDAP group as email group the haraka-plugin-ldap-aliases plugin would need the following configuration settings:

```
searchfilter = (&(objectclass=groupOfNames)(mailLocalAddress=%a))
attribute = member
attribute_is_dn = true
subattribute = mailLocalAddress
```

The search filter applies only to groups (`objectclass=groupOfNames`) with an email address of the alias email (`mailLocalAddress=%a`). Then the plugin checks the group's attribute `member` and assumes it contains a DN (`attribute_is_dn = true`) and looks up and returns every member DN's attribute `mailLocalAddress`. In other words, email to `postmaster@my-domain.com` would be send to `user@my-domain.com`. Of course a group may contain multiple members, in which case every member with a valid `mailLocalAddress` would receive the email.

