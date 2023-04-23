#!/bin/sh

sudo apt install --no-install-recommends -y gcc gettext make g++ apparmor-utils slapd
sudo aa-complain /usr/sbin/slapd
# sed -i -e '/^server/ s/:389/:3389/' -e 's/^server.*:636$/:3636/' config/ldap.ini
if [ ! -d "/tmp/slapd" ]; then mkdir /tmp/slapd; fi
slapd -f test/fixtures/linux/slapd.conf -h "ldap://localhost:3389 ldaps://localhost:3636"
sleep 3
ldapadd -x -D "cn=admin,dc=example,dc=com" -w "rAR84,NZ=F" -H ldap://localhost:3389 -f test/config/env/testdata.ldif


#slapadd -F /etc/ldap/slapd.d -b dc=example,dc=com -l test/config/env/testdata.ldif