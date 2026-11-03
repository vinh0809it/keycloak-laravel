# Security policy

This package verifies the access tokens a Laravel guard trusts, so a flaw in it can let a request
through as someone else. Please report one privately, not in a public issue.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting:
[Report a vulnerability](https://github.com/vinh0809it/keycloak-laravel/security/advisories/new).

Include what an attacker sends, what the guard does with it, and the package, Laravel, php-jwt and
Keycloak versions. You will get an answer within 7 days. A confirmed issue is fixed in a release and
published as a GitHub security advisory, crediting you unless you prefer otherwise.

## Supported versions

Only the latest release receives security fixes while the package is on 0.x.

## Scope

In scope: anything that makes the `keycloak` guard accept a token it should refuse (a bad
signature, another issuer, another audience, an expired token, an algorithm it does not accept, a
key of another realm), a dev token honoured outside development, a browser login completed with a state, code or login cookie that is not the
browser's own or returning to a URL it does not allow, or a token or secret leaked by the client,
the service token, the session cookies or the logs.

Out of scope: Keycloak itself and firebase/php-jwt, which are reported to their own projects, and
`KeycloakFake`, which is a test tool.
