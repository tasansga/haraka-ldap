####


### 1.1.0 - 2023-04-26

- ci: switch travis -> GHA
- test: use RFC example.com for test domain
- authn: replace async.detect with local fn
- noop: remove some useless returns
- test: refactored some to improve error messages


### 1.0.2 - 2017-09-30

- check_rcpt must return next(ok) if a valid recipient was found


### 1.0.2 - 2016-12-10

- test get_alias for resolve-by-dn case
- added debug log to _resolve_dn_to_alias
- fixed wrong default attribute there
- include all ops in config