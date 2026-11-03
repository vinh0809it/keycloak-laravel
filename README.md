# Keycloak for Laravel

Keycloak for Laravel APIs and backends-for-frontends, stateless: every request carries its access
token, as a bearer or in a cookie, and is verified on its own. Nothing is kept in Laravel's session,
so it suits APIs, SPAs and mobile backends; a Blade or Livewire app signing in through Laravel's
session guard is not what it is built for.

- **The `keycloak` auth guard**: each bearer verified against its realm's published keys with
  [firebase/php-jwt](https://github.com/googleapis/php-jwt) (fetched from the JWKS endpoint, cached,
  refetched when the realm rotates them), the realm's `iss`, your API's `aud`, an `exp` and a `sub`
  required, then turned into your user by a resolver of yours, chosen per realm and per client.
- **`keycloak.role`**: a route middleware letting through the tokens that hold a realm or client role.
- **A client for the realm**: any grant (an SPI's direct grant included), refresh, logout,
  revocation, userinfo, the realm's own resources, and a service account's token cached for every
  process.
- **A browser login for a backend-for-frontend**: authorization code flow with PKCE and `state`, kept
  in a signed cookie, and the session kept in HttpOnly cookies the guard reads.
- **`KeycloakFake`**: a realm for your tests that signs real tokens and answers the token endpoint.

```php
Route::middleware('auth:api')->get('/me', fn (Request $request) => $request->user());
```

## Requirements

PHP 8.2+, Laravel 12 or 13, a Keycloak realm whose access tokens carry your API in `aud` (an
audience mapper on the client), signed with RS256 by default.

## Installation

```bash
composer require vinh0809it/keycloak-laravel
php artisan vendor:publish --tag=keycloak-config    # config/keycloak.php
```

```dotenv
KEYCLOAK_REALM_URL=https://sso.example.com/realms/my-realm
KEYCLOAK_AUDIENCE=my-api
# KEYCLOAK_ISSUER=https://sso.example.com/realms/my-realm   # when this app reaches the realm at another URL
# KEYCLOAK_CACHE_STORE=redis                                # one key fetch and one service token for every server
```

`KEYCLOAK_REALM_URL` is the realm as this app reaches it, an internal address included
(`http://keycloak:8080/realms/my-realm`); `KEYCLOAK_ISSUER` is the realm as its tokens name it in
`iss` and as browsers reach it, and defaults to the realm URL. They are compared exactly, so a
trailing slash matters.

## The guard

In `config/auth.php`:

```php
'guards' => [
    'api' => [
        'driver' => 'keycloak',
        'resolver' => App\Auth\MemberResolver::class,
        // Optional:
        'by_client' => ['admin-web' => App\Auth\StaffResolver::class],   // azp => resolver
        'cookie' => false,             // true: also read keycloak.cookies.access, after the header
        'audience' => null,            // this guard's own audience; defaults to keycloak.audience
        'realms' => null,              // the realms it accepts, with several declared
        'by_realm' => [],              // see "Several realms"
        'other_issuers' => [],         // see "Other issuers and existing tokens"
    ],
],
```

A resolver turns the verified claims into your user:

```php
use Vinh0809it\KeycloakLaravel\Auth\Claims;
use Vinh0809it\KeycloakLaravel\Auth\ClaimsResolver;

final class MemberResolver implements ClaimsResolver
{
    public function resolve(Claims $claims): ?Authenticatable
    {
        return User::firstOrCreate(['keycloak_id' => $claims->sub], ['email' => $claims->string('email')]);
    }
}
```

`Claims` has `sub`, `realm` (its name under `keycloak.realms`), `issuer`, `client` (`azp`),
`audience`, `realmRoles` and `clientRoles`, every claim through `get()`, `string()` (a claim the user
cannot be built without: its absence refuses the token), `stringOrNull()` and `list()`, and
`hasRole('admin')` / `hasRole('editor', 'my-api')` for a realm or a client role. Resolvers are built
by the container, so they take dependencies.

A token is resolved by the resolver of its client (`by_client`, keyed by the token's `azp`), else
the guard's `resolver`. A guard with only `by_client` accepts only those clients. A resolver that
returns null or throws `InvalidToken` leaves the request unauthenticated.

A refused token is a 401 behind `auth:<guard>`, with the reason logged at debug level. A realm whose
keys cannot be fetched throws `KeycloakUnavailable` instead: the caller's token may be valid, so it
is a server error rather than a sign-out.

### What is checked

- The token's `iss` picks the realm, and only that realm's keys verify it: a token cannot name one
  realm and be signed with another's key.
- The signature, with a key the realm publishes for signing (`use: sig`) in one of
  `keycloak.algorithms` (RS256 by default). php-jwt binds the token's `alg` to its key's, so `none`
  and HMAC tokens keyed with a public key are refused. The token must name its key (`kid`).
- `exp` is required and not past; `nbf` and `iat` are not in the future. `keycloak.leeway` (10
  seconds by default) absorbs clock differences between Keycloak and this app.
- `iss` is exactly the realm's issuer, `aud` contains the guard's audience, and `sub` is present.
- A realm's ID and logout tokens (`typ` other than `Bearer`) are refused: Keycloak signs them with
  the same keys, and an ID token's `aud` is the client it was issued to, which may be your API's.

The keys are cached in `keycloak.cache.store` for `keycloak.cache.ttl` seconds, and every
verification reads them there, so a key the realm drops stops verifying once the cache expires, in
long-lived workers (Octane, queues) too. A token naming a key the cache lacks has the keys fetched
afresh, at most once a minute per realm across every process sharing the cache store, so a rotated
key is picked up at once and made-up `kid`s cannot make every request call the realm. One process
fetches at a time where the store has locks, and a realm whose keys could not be fetched is not
asked again for 10 seconds. The keys come from `{realm}/protocol/openid-connect/certs` directly, not
through discovery, whose URLs Keycloak may name with its public host.

A misconfigured `keycloak` guard (no audience, an undeclared realm, nothing to resolve with...)
fails when it is first built, on any request that uses it, rather than only on one carrying a token.
The app itself still boots, so artisan runs in a build step without the runtime environment.

`keycloak.leeway` is set on php-jwt's `JWT::$leeway`, a process-wide static: code of the app that
calls `JWT::decode()` itself sees the same leeway once the guard has verified a token.

### Roles

`keycloak.role` lets a request through when the token that authenticated it holds one of the listed
roles, a realm role (`admin`) or a client's (`my-api:editor`), and answers a 403 otherwise. It goes
after `auth:<guard>`:

```php
Route::middleware(['auth:api', 'keycloak.role:admin'])->group(...);
Route::middleware(['auth:api', 'keycloak.role:admin,my-api:editor'])->get(...);   // any of them
```

`Claims::of($request)` gives the claims of that token anywhere later on (a controller, a policy, a
gate). A request another guard authenticated (`auth:api,legacy`) has none, so `keycloak.role`
refuses it.

### Several realms

Declare each under `keycloak.realms` and name the ones a guard accepts:

```php
// config/keycloak.php
'realms' => [
    'customers' => ['url' => env('KEYCLOAK_CUSTOMERS_URL'), 'issuer' => env('KEYCLOAK_CUSTOMERS_ISSUER')],
    'employees' => ['url' => env('KEYCLOAK_EMPLOYEES_URL'), 'issuer' => env('KEYCLOAK_EMPLOYEES_ISSUER')],
],

// config/auth.php
'main' => [
    'driver' => 'keycloak',
    'realms' => ['customers', 'employees'],
    'by_client' => ['web' => App\Auth\CustomerResolver::class],
    'by_realm' => [
        'employees' => [
            'by_client' => ['web' => App\Auth\StaffResolver::class, 'admin-web' => App\Auth\AdminResolver::class],
            // 'resolver' => App\Auth\StaffResolver::class,   // the realm's other clients; without it they are refused
        ],
        // 'partners' => App\Auth\PartnerResolver::class,    // every token of that realm
    ],
],
```

A realm under `by_realm` takes all of its tokens: they are resolved among its own entry alone,
never by the guard's `by_client` or `resolver`. A client id is unique only within its realm, so on a
guard over several realms list each realm's clients under its `by_realm` entry: in the guard's
`by_client`, a client of the same id created in another realm would be resolved as yours.

### Other issuers and existing tokens

A guard can also take the tokens of an OpenID provider other than the realms (another service's
own issuer, with a discovery document): list it with the resolver of its users. Its keys come from
the `jwks_uri` of its discovery document, and its tokens are resolved by that resolver alone. A key
it publishes without an `alg` takes the only accepted algorithm, when `keycloak.algorithms` lists
one; its tokens' `typ` is not checked. An empty `url` (its env var unset) takes no token.

```php
'other_issuers' => [
    ['url' => env('LEGACY_ISSUER_URL'), 'issuer' => env('LEGACY_ISSUER'), 'resolver' => App\Auth\LegacyResolver::class],
],
```

Tokens with no discovery behind them (an app's own JWTs from before Keycloak, say) belong to a guard
of their own. Laravel tries the guards of a route in order, so both are accepted:

```php
Route::middleware('auth:api,legacy')->group(...);   // the keycloak guard, then the legacy one
```

### Dev tokens

For local development, `keycloak.dev_tokens` maps bearers to the claims they stand for, resolved
by the same resolvers as a real token, ahead of the verification:

```php
'dev_tokens' => [
    'member.1' => [],                                   // sub "member.1", the default resolver
    'admin.1' => ['sub' => 'a-1', 'azp' => 'admin-web'],
    '{azp}~{sub}' => ['email_verified' => true],        // "mobile-app~42": azp mobile-app, sub 42
],
```

A `{name}` placeholder matches any text and sets claim `name`. A pattern must hold a character a JWT
never does (anything but letters, digits, `-`, `_` and `.`), so it never takes a real token. A
signed token keeps working beside them, and a realm with an empty `url` takes no real token, so a
development setup can live on dev tokens alone. They are allowed only with `APP_ENV` `local` or
`testing` and debug on; anywhere else the app refuses to boot.

## Calling the realm

```php
// config/keycloak.php
'clients' => [
    'service' => ['id' => 'my-api', 'secret' => env('KEYCLOAK_CLIENT_SECRET')],
    'web' => ['id' => 'my-web', 'secret' => env('KEYCLOAK_WEB_CLIENT_SECRET'), 'return_origins' => [env('WEB_ORIGIN')]],
],
```

```php
use Vinh0809it\KeycloakLaravel\Keycloak;

public function __construct(private Keycloak $keycloak) {}

$this->keycloak->serviceToken('service')->get();                  // cached client-credentials token
$this->keycloak->serviceToken('service')->forget();               // one a downstream service refused: mint another
$web = $this->keycloak->client('web');
$web->password($email, $password);                                // TokenSet
$web->refresh($refreshToken);
$web->logout($refreshToken);
$web->revoke($refreshToken);
$web->userinfo($accessToken);                                     // needs the openid scope
$web->logoutUrl($afterLogout, $idToken);                          // where a browser ends its SSO session

// An SPI: a direct grant with its own fields, and the realm's own resources.
$web->password($phone, '', ['session' => $session, 'otp' => $otp]);
$web->realm('POST', 'my-provider/send', ['json' => ['to' => $phone]]);
```

A service token is kept in `keycloak.cache.store` until 30 seconds before it expires, under its
realm and client id, so every request and worker sharing the store uses one. A client names its
realm with `realm` when several are declared.

Failures say whose they are; all implement `KeycloakException`:

| Exception | Meaning | Usually |
|---|---|---|
| `Client\RequestRefused` | Keycloak refused the request (a spent code, an expired refresh token, a wrong OTP) | 401 to the caller |
| `Client\InvalidClient` (a `RequestRefused`) | Keycloak refused THIS app's client (a wrong secret, a grant it may not use) | 502, never retry |
| `KeycloakUnavailable` | unreachable, 5xx, or a success without a token | 502 |
| `Browser\LoginFailed` | a browser's login could not be completed (see below) | start a new login |

## Browser login

`Keycloak::login($client)` signs a browser in at the realm: the authorization code flow with PKCE,
with the `state`, the PKCE verifier, the redirect URI and the page to return to kept in a
short-lived login cookie (HttpOnly, Secure, SameSite=Lax, signed with `app.key`, 10 minutes). On the
callback it checks the cookie, the `state` the realm sent back and its `iss` (RFC 9207), then
exchanges the code with the kept verifier. A callback it refuses has its code spent (Keycloak
invalidates a code on a failed exchange), so whoever started the login the code belongs to cannot
redeem it.

The page to return to is a path of this app, or a URL on one of the client's `return_origins`
(`https://web.example.com`, or `https://*.example.com` for its subdomains). `start()` refuses any
other, so the one the callback hands back is safe to redirect to.

```php
// config/keycloak.php
'cookies' => [
    'access' => ['name' => 'app_at', 'domain' => env('COOKIE_DOMAIN')],
    'refresh' => ['name' => 'app_rt', 'path' => '/auth'],
],
```

```php
Route::get('/auth/login', function (Request $request, Keycloak $keycloak) {
    try {
        return $keycloak->login('web')->start(route('auth.callback'), $request->string('return')->value() ?: null);
    } catch (LoginFailed) {
        return $keycloak->login('web')->start(route('auth.callback'));   // a return URL it does not allow
    }
});

Route::get('/auth/callback', function (Request $request, Keycloak $keycloak) {
    $login = $keycloak->login('web');
    try {
        $done = $login->finish($request);
        $response = redirect($done->returnTo ?? '/');
        $keycloak->sessionCookies()->set($response, $done->tokens);
    } catch (LoginFailed $e) {
        $response = redirect(($e->returnTo ?? '/').'#login_error='.($e->error ?? 'failed'));
    }
    $login->clearLoginCookie($response);

    return $response;
})->name('auth.callback');

Route::post('/auth/refresh', function (Request $request, Keycloak $keycloak) {
    $response = response()->noContent();
    try {
        $keycloak->sessionCookies()->set($response, $keycloak->client('web')->refresh((string) $keycloak->sessionCookies()->refreshToken($request)));
    } catch (RequestRefused) {
        $response = response()->noContent(401);
        $keycloak->sessionCookies()->clear($response);
    }

    return $response;
});

Route::post('/auth/logout', function (Request $request, Keycloak $keycloak) {
    if (null !== $refreshToken = $keycloak->sessionCookies()->refreshToken($request)) {
        try {
            $keycloak->client('web')->logout($refreshToken);
        } catch (KeycloakException) {
        }
    }

    return tap(response()->noContent(), fn ($response) => $keycloak->sessionCookies()->clear($response));
});
```

These routes keep no session: put them in `routes/api.php`, or exclude the refresh and logout
routes from CSRF verification if they live in the `web` group (the refresh cookie is
SameSite=Strict, so another site cannot send it). The API guard reads the access cookie with
`'cookie' => true`. The session and login cookies are signed by Keycloak or by this package, so
the package turns Laravel's cookie encryption off for them. `cookies.refresh.path` is required: it
should cover only the refresh and logout routes.

SameSite keeps other sites from sending the cookies, not other subdomains of the same site: with
`domain` set, a page on any subdomain can make credentialed requests to a cookie-authenticated API,
and routes in `routes/api.php` have no CSRF check. Check the `Origin` header of state-changing
requests against your web's origins, or keep the cookies host-only.

## Testing

`KeycloakFake` stands in for a realm through `Http::fake()`: it serves its keys, signs tokens the
guard verifies like real ones, and answers the token, logout and revoke endpoints.

```php
use Vinh0809it\KeycloakLaravel\Testing\KeycloakFake;

$realm = KeycloakFake::install($this->app);              // or ($this->app, $url, 'employees')

$this->withToken($realm->token(['sub' => 'user-1', 'email' => 'a@example.com']))
    ->getJson('/api/me')
    ->assertOk();

$realm->token(['exp' => null]);                          // null removes a claim
$realm->token([], ['kid' => 'other']);                   // header fields
$kid = $realm->rotateKey();                              // a new key signs the next tokens
$realm->rotateKey(['use' => 'enc', 'alg' => null]);      // ... with its JWK members overridden or left out
$realm->removeKey($kid);                                 // the realm stops publishing it
$realm->failKeys(503);                                   // the JWKS endpoint fails, until restoreKeys()
$realm->keyFetches();                                    // how many times the keys were fetched

$code = $realm->code(['sub' => 'user-1']);               // an authorization code for a callback
$realm->onToken(fn (array $form) => ['error' => 'invalid_grant']);   // a grant of your own
$realm->requests();                                      // what the token, logout and revoke endpoints received
```

The token endpoint answers `client_credentials` for the client's service account, `password` for
the username, `authorization_code` for a code from `code()`, and `refresh_token` for a refresh token
it issued that no refresh, logout or revocation spent.

It forgets the keys a persistent cache store kept from an earlier test's fake of the same realm,
and gives each key a random `kid`. Install it before any catch-all `Http::fake()` of the test: Laravel answers a request with the first
fake that answers it, so an earlier catch-all would answer the realm too.

Laravel keeps a guard's user for the rest of a test once it has served a request. To send several
tokens in one test, call `$this->app['auth']->forgetGuards()` between the requests. For a cookie on
a JSON test request, add `withCredentials()`.

## License

MIT
