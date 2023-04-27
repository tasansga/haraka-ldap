#!/bin/sh

if ! dpkg -l | grep -q slapd; then
    sudo apt install --no-install-recommends -y gcc gettext make g++ apparmor-utils slapd ldap-utils ldapscripts
    sudo service slapd stop
    sudo systemctl disable slapd.service
fi

sudo killall slapd
sudo aa-complain /usr/sbin/slapd

sed -i -e '/^server/ s/:389/:3389/' -e '/^server/ s/:636$/:3636/' config/ldap.ini

if [ ! -d "/tmp/slapd" ]; then sudo mkdir /tmp/slapd; fi
sudo rm -rf /tmp/slapd/* /var/lib/ldap/*

sudo slapd -f test/fixtures/linux/slapd.conf -h "ldap://localhost:3389 ldaps://localhost:3636"
sleep 2
ldapadd -x -D "cn=admin,dc=example,dc=com" -w "rAR84,NZ=F" -H ldap://localhost:3389 -f test/env/testdata.ldif
