#!/bin/sh

/usr/bin/sed -i -e '/^server/ s/:389/:3389/' -e 's/^server.*:636$/:3636/' config/ldap.ini
if [ ! -d "/var/tmp/slapd" ]; then mkdir /var/tmp/slapd; fi
rm -r /var/tmp/slapd/* || exit

/opt/local/sbin/slapadd -n 0 -F /var/tmp/slapd -l test/fixtures/macosx/slapd.ldif || exit

/opt/local/libexec/slapd -f test/fixtures/macosx/slapd.conf -h "ldap://localhost:3389 ldaps://localhost:3636" &
sleep 3

/opt/local/bin/ldapadd -x -D "cn=admin,dc=example,dc=com" -w "rAR84,NZ=F" -H ldap://localhost:3389 -f test/config/env/testdata.ldif
