# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Until 1.0, a minor version may break
backward compatibility; each such break is listed here.

## [Unreleased]

### Added

- `keycloak.role`: a route middleware letting through the tokens that hold a realm role (`admin`)
  or a client's (`my-api:editor`), a 403 otherwise.
- `Claims::of($request)`: the claims of the token a `keycloak` guard authenticated the request with.

## [0.1.0] - 2026-11-03

### Added

- The `keycloak` auth guard driver: the bearer (or the access cookie) verified with firebase/php-jwt
  against the keys of the realm its `iss` names, `exp`, `iss`, `aud` and `sub` required, and
  resolved to the app's user by a `ClaimsResolver`: per realm (`by_realm`, with its own `by_client`
  and `resolver`), per client (`by_client`) or the guard's own.
- Several realms under `keycloak.realms`; a guard names the ones it accepts. A realm with an empty
  `url` takes no token.
- `other_issuers` on a guard: OpenID providers other than the realms, their keys found through
  their discovery document, each with its resolver.
- `keycloak.dev_tokens`: bearers for local development, literal or with `{claim}` placeholders,
  standing for configured claims; the app refuses to boot with them outside the `local` and
  `testing` environments or with debug off.
- The realms' keys cached in a cache store and refetched, at most once a minute, for a `kid` they
  lack. Only signing keys of an accepted algorithm are used.
- `Keycloak`: the realms, clients and session cookies of config/keycloak.php.
- `Client\KeycloakClient`: any grant (an SPI's direct grant included), refresh, logout, revocation,
  userinfo, the authorization and logout URLs and the realm's own resources;
  `Client\ServiceToken`, a client-credentials token shared through the cache store;
  `RequestRefused`, `InvalidClient` and `KeycloakUnavailable`, all `KeycloakException`s.
- `Browser\BrowserLogin`: the authorization code flow with PKCE, `state` and `iss` checked, kept in a
  login cookie signed with `app.key`; a refused callback's code is spent. `Browser\SessionCookies`
  (`Keycloak::sessionCookies()`) for a backend-for-frontend. Laravel's cookie encryption is turned
  off for the package's cookies.
- `Testing\KeycloakFake`: a realm through `Http::fake()` serving its keys and discovery document,
  signing tokens and answering the token, logout and revoke endpoints; `rotateKey()`, `removeKey()`,
  `failKeys()`, `code()`, `onToken()`, `keyFetches()`, `requests()`. Each key has a random `kid`,
  and installing it forgets the keys a persistent store kept for the same realm.
- A realm's ID and logout tokens (`typ` other than `Bearer`) are refused.
- Every verification reads the keys from the cache store, so a key the realm drops stops verifying
  in long-lived workers once the cache expires; one process fetches at a time where the store has
  locks, and a failed fetch is not tried again for 10 seconds.
- `ServiceToken::forget()`; a service token is cached under its realm and client id.
- A misconfigured `keycloak` guard fails when it is first built, not on a request carrying a token.
  `cookies.refresh.path` is required with a refresh cookie.
- A return URL holding a control character, a space or a backslash, or whose host is not plain
  letters, digits, dots and hyphens, is refused: a browser would read it differently.
- `KeycloakUnavailable` does not chain the HTTP client's exception, which holds the request and its
  secrets; the client's grant fields, PKCE verifier and code are `#[\SensitiveParameter]`.

[Unreleased]: https://github.com/vinh0809it/keycloak-laravel/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/vinh0809it/keycloak-laravel/releases/tag/v0.1.0
