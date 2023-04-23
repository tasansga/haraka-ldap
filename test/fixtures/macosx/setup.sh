#!/bin/sh

sed -i -e '/^server/ s/:389/:3389/' -e 's/^server.*:636$/:3636/' config/ldap.ini
mkdir /var/tmp/slapd
slapd -f test/fixtures/macosx/slapd.conf -h "ldap://localhost:3389 ldaps://localhost:3636" &
sleep 3
ldapadd -x -D "cn=admin,dc=example,dc=com" -w "rAR84,NZ=F" -H ldap://localhost:3389 -f test/config/env/testdata.ldif
