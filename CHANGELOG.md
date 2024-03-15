### Unreleased

#### 1.1.1 - 2024-03-15

- config: comment out default server entries, fixes #9
- doc(README): update doc badge URL #8
- test: use 127.0.0.1 vs localhost to avoid IPv6 failure

#### 1.1.0 - 2023-04-26

- authn: replace async.detect with local fn
- aliases: replace async with Promise.all
- dep(async): removed
- dep(ldapjs): update from 1.0.2 to 2.3.3
- noop: remove useless returns
- es6: more arrow functions
- style: inline use of `plugin`
- ci: switch travis -> GHA
- ci: enable codeql
- test: use RFC example.com for test domain
- test: refactored some to improve error messages
- test: add fixtures for setting up slapd on macosx and linux
- doc(README): update with GHA badge


#### 1.0.2 - 2017-09-30

- check_rcpt must return next(ok) if a valid recipient was found


#### 1.0.2 - 2016-12-10

- test get_alias for resolve-by-dn case
- added debug log to _resolve_dn_to_alias
- fixed wrong default attribute there
- include all ops in config

[1.1.1]: https://github.com/haraka/haraka-plugin-ldap/releases/tag/1.1.1
