FROM fedora:latest

RUN dnf -y install openldap-servers openldap-clients
COPY config.ldif testdata.ldif /
COPY slapdcert.pem slapdkey.pem /etc/openldap/certs/

RUN \
    chmod 600 /etc/openldap/certs/slapdkey.pem && \
    chown ldap /etc/openldap/certs/* && \
    /usr/sbin/slapd -u ldap -h "ldapi:///" && \
    sleep 2 && \
    ldapadd -Y EXTERNAL -H ldapi:/// -f /etc/openldap/schema/cosine.ldif && \
    ldapadd -Y EXTERNAL -H ldapi:/// -f /etc/openldap/schema/misc.ldif && \
    ldapadd -Y EXTERNAL -H ldapi:/// -f /config.ldif && \
    ldapadd -x -D "cn=Manager,dc=example,dc=com" \
            -w "rAR84,NZ=F" -H ldapi:/// -f /testdata.ldif && \
    rm -f /config.ldif /testdata.ldif

EXPOSE 389
EXPOSE 636

ENTRYPOINT ["/usr/sbin/slapd", "-u", "ldap", "-h" , "ldap:/// ldaps:///", "-d129"]

# run with: docker run -p 389:389 -p 636:636 [...]
