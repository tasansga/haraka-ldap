# aliases_ldap

With aliases_ldap it is possible to query LDAP to resolve email aliases and to forward email to one or multiple configured targets. It utilizes the ldappool plugin.

## Configuration
All configuration is done in `config/aliases_ldap.ini`.
The following options are configurable:  

* `basedn`: *optional*, default: as used by ldappool
It's possible to override ldappool's default basedn for this plugin.
* `scope`: *optional*, default: as used by ldappool
It's possible to override ldappool's default scope for this plugin.
* `searchfilter`: *optional*, default: (&(objectclass=*)(mail=%a)(mailForwardAddress=*))  
Search filter to lookup aliases. The param %a denotes the recipient's mail address as given on the email's envelope. As result the search filter should return the objects containing the dealiased recipient addresses within a given `attribute` (see below). 
* `attribute`: *optional*, default: `mailForwardingAddress`
Attribute used to parse as recipient's email address or as recipient's DN (see below).
* `attribute_is_dn`: *optional*, default: false
Set this to `true` if the attribute does not contain an email address but a fully qualified DN.
* `subattribute`: *optional*, default: `mailLocalAddress`
If the attribute references a DN then the subattribute references the DN's email address that should be used as recipient.

## Examples
Following are a few examples to explain the proper usage of the alias_ldap plugin.

### simple aliases
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

Given this configuration, the aliases_ldap plugin will simply change recipients that match the given searchfilter to the value referenced by the `mailRoutingAddress` attribute: Mail send to `forwarder@my-domain.com` will be delivered to `user@my-domain.com`.


### attribute_is_dn
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

To use the LDAP group as email group the aliases_ldap plugin would need the following configuration settings:

```
searchfilter = (&(objectclass=groupOfNames)(mailLocalAddress=%a))
attribute = member
attribute_is_dn = true
subattribute = mailLocalAddress
```

The search filter applies only to groups (`objectclass=groupOfNames`) with an email address of the alias email (`mailLocalAddress=%a`). Then the plugin checks the group's attribute `member` and assumes it contains a DN (`attribute_is_dn = true`) and looks up and returns every member DN's attribute `mailLocalAddress`. In other words, email to `postmaster@my-domain.com` would be send to `user@my-domain.com`. Of course a group may contain multiple members, in which case every member with a valid `mailLocalAddress` would receive the email.

