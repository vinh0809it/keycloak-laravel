<?php

return [
    // The realms whose tokens a guard accepts and whose clients this app calls as. `url` is where
    // this app reaches the realm (an internal address included); `issuer` is the realm as its tokens
    // name it in `iss` and as browsers reach it, when it differs from `url`.
    'realms' => [
        'default' => [
            'url' => env('KEYCLOAK_REALM_URL'),
            'issuer' => env('KEYCLOAK_ISSUER'),
        ],
    ],

    // The `aud` a token must carry, for every keycloak guard that does not set its own.
    'audience' => env('KEYCLOAK_AUDIENCE'),

    // Signature algorithms accepted on access tokens.
    'algorithms' => ['RS256'],

    // Seconds of clock difference tolerated on `exp`, `nbf` and `iat`.
    'leeway' => (int) env('KEYCLOAK_LEEWAY', 10),

    // Where the realms' keys and the service tokens are cached: a store shared by every process
    // (redis, database...) fetches them once for all; null is the default store.
    'cache' => [
        'store' => env('KEYCLOAK_CACHE_STORE'),
        'ttl' => 3600,
    ],

    // Bearers for local development => the claims they stand for, resolved like a real token's; `sub`
    // defaults to the bearer. `{name}` placeholders match any text and set that claim: '{azp}~{sub}'
    // takes 'mobile-app~42'. Only with APP_ENV local or testing and debug on; elsewhere the app fails to boot.
    'dev_tokens' => [],

    // Seconds to wait for Keycloak.
    'http_timeout' => 5,

    // Keycloak clients this app calls a realm as: Keycloak::client(), ::serviceToken() for one with a
    // secret, ::login() for a browser's sign-in.
    'clients' => [
        // 'service' => ['id' => 'my-api', 'secret' => env('KEYCLOAK_CLIENT_SECRET')],
        // 'web' => [
        //     'id' => 'my-web',
        //     'secret' => env('KEYCLOAK_WEB_CLIENT_SECRET'),
        //     'realm' => null,                      // with several realms
        //     'return_origins' => [],               // https://web.example.com, https://*.example.com
        //     'login_cookie' => ['name' => null, 'path' => '/', 'domain' => null],
        // ],
    ],

    // A backend-for-frontend's session cookies (Keycloak::sessionCookies()); a guard with `cookie => true`
    // reads the access token from the access cookie.
    'cookies' => [
        'access' => ['name' => null, 'path' => '/', 'domain' => null, 'same_site' => 'lax'],
        // `path`: only the routes that refresh and end the session, e.g. /auth; required with a name.
        'refresh' => ['name' => null, 'path' => null, 'domain' => null, 'same_site' => 'strict', 'session_lifetime' => 1209600],
    ],
];
