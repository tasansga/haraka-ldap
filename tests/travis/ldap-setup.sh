#!/bin/sh

# sed -i '/127.0.0.1/ s/.*/127.0.0.1	ubuntu.my-domain.com ubuntu/' /etc/hosts
# sed -i '/127.0.1.1/ s/.*/127.0.1.1	ubuntu.my-domain.com ubuntu/' /etc/hosts

# export DEBIAN_FRONTEND=noninteractive
# apt-get update -qq
# apt-get install -y ldap-utils slapd

ldapadd -Y EXTERNAL -H ldapi:/// <<EO_CONFIG

# set root password to: rAR84,NZ=F
dn: olcDatabase={2}mdb,cn=config
changetype: modify
add: olcRootPW
olcRootPW: {SSHA}bPf32h0ItVUKLlVzsR6od+Ub5GDZRBIr

# enable tls
# dn: cn=config
# changetype: modify
# replace: olcTLSCACertificateFile
# olcTLSCACertificateFile: tests/env/slapdcert.pem
# -
# replace: olcTLSCertificateKeyFile
# olcTLSCertificateKeyFile: tests/env/slapdkey.pem
# -
# replace: olcTLSCertificateFile
# olcTLSCertificateFile: tests/env/slapdcert.pem

EO_CONFIG


ldapadd -x -D "cn=Manager,dc=my-domain,dc=com" -w "rAR84,NZ=F" -H ldapi:/// <<EO_TESTDATA

# add base dn
dn: dc=my-domain,dc=com
changetype: add
objectclass: top
objectclass: organization
objectClass: dcObject
dc: my-domain
o: my-domain.com

# add 2 dn for people
dn: ou=users,dc=my-domain,dc=com
changetype: add
objectclass: top
objectclass: organizationalUnit
ou: users

dn: ou=people,dc=my-domain,dc=com
changetype: add
objectclass: top
objectclass: organizationalUnit
ou: people

# add user1 in 1st dn
# password is: ykaHsOzEZD
dn: uid=user1,ou=users,dc=my-domain,dc=com
changetype: add
objectClass: top
objectClass: uidObject
objectClass: device
objectClass: simpleSecurityObject
objectClass: inetLocalMailRecipient
uid: user1
cn: Test User 1
mailLocalAddress: user1@my-domain.com
userPassword: {SSHA}ul8jaq76hmLRuvheYxSqPDCQrPxldRkl

# add user2 in 2nd dn
# password is: KQD9zs,LGv
dn: uid=user2,ou=people,dc=my-domain,dc=com
changetype: add
objectClass: top
objectClass: uidObject
objectClass: device
objectClass: simpleSecurityObject
objectClass: inetLocalMailRecipient
uid: user2
cn: Test User 2
mailLocalAddress: user2@my-domain.com
userPassword: {SSHA}j999dNJUvKzt480ky0/A5VvNRqzSS1TA

# add nonunique in both dn
# password is: CZVm3,BLlx
dn: uid=nonunique,ou=users,dc=my-domain,dc=com
changetype: add
objectClass: top
objectClass: uidObject
objectClass: device
objectClass: simpleSecurityObject
objectClass: inetLocalMailRecipient
uid: nonunique
cn: Nonunique Test User 1
mailLocalAddress: nonunique1@my-domain.com
userPassword: {SSHA}/zz+SrbdIhlwQ6ypFP2bupP6IUKzgA2z

# password is: LsBHDGorAh
dn: uid=nonunique,ou=people,dc=my-domain,dc=com
changetype: add
objectClass: top
objectClass: uidObject
objectClass: device
objectClass: simpleSecurityObject
objectClass: inetLocalMailRecipient
uid: nonunique
cn: Nonunique Test User 2
mailLocalAddress: nonunique2@my-domain.com
userPassword: {SSHA}gLTxl9QpE1dHNgfZK9d3Ne8MKXtFRRfn

# add user who forwards mail
# password is: 1QRSrUECyKLR
dn: uid=forwarder,ou=people,dc=my-domain,dc=com
changetype: add
objectClass: top
objectClass: uidObject
objectClass: device
objectClass: simpleSecurityObject
objectClass: inetLocalMailRecipient
uid: forwarder
cn: Forwarding Test User
mailLocalAddress: forwarder@my-domain.com
mailRoutingAddress: user2@my-domain.com
userPassword: {SSHA}h53i1Xy3/Hi27rr+krH/TwSGkEohfbxH

# add group to resolve by-dn
dn: cn=postmaster,dc=my-domain,dc=com
changetype: add
objectclass: top
objectclass: groupOfNames
objectClass: inetLocalMailRecipient
mailLocalAddress: postmaster@my-domain.com
member: uid=user1,ou=users,dc=my-domain,dc=com
member: uid=user2,ou=people,dc=my-domain,dc=com
member: uid=nonunique,ou=users,dc=my-domain,dc=com
member: uid=unknown,dc=wherever,dc=com

EO_TESTDATA
