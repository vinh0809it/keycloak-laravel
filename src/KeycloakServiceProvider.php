<?php

/**
 * Copyright (c) 2026 Vinh Vo. MIT License.
 */

declare(strict_types=1);

namespace Vinh0809it\KeycloakLaravel;

use Illuminate\Auth\AuthManager;
use Illuminate\Auth\RequestGuard;
use Illuminate\Container\Container;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Cookie\Middleware\EncryptCookies;
use Illuminate\Http\Client\Factory as Http;
use Illuminate\Routing\Router;
use Illuminate\Support\ServiceProvider;
use Vinh0809it\KeycloakLaravel\Auth\DevTokens;
use Vinh0809it\KeycloakLaravel\Auth\KeycloakGuard;
use Vinh0809it\KeycloakLaravel\Auth\TokenVerifier;
use Vinh0809it\KeycloakLaravel\Http\Middleware\RequireRole;

/**
 * The `keycloak` auth guard driver, configured per guard in config/auth.php:
 *
 *     'guards' => [
 *         'api' => [
 *             'driver' => 'keycloak',
 *             'resolver' => App\Auth\UserResolver::class,                  // tokens of any other client
 *             'by_client' => ['admin-web' => App\Auth\AdminResolver::class], // azp => resolver
 *             'cookie' => false,                                             // true: also read keycloak.cookies.access, after the header
 *             'realms' => null,                                              // with several realms
 *             'by_realm' => [],                                              // realm => resolver, or [resolver, by_client]
 *             'other_issuers' => [],                                         // [url, issuer, resolver] of other OpenID providers
 *             'audience' => null,                                            // defaults to keycloak.audience
 *         ],
 *     ],
 *
 * and {@see Keycloak}, the realms, clients and session cookies of config/keycloak.php. The session
 * and login cookies are signed or verified by this package, so Laravel's cookie encryption is
 * turned off for them.
 */
final class KeycloakServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/keycloak.php', 'keycloak');

        $this->app->singleton(Keycloak::class, static function (Application $app): Keycloak {
            /** @var array{realms: array<string, array{url: ?string, issuer?: ?string}>, algorithms: list<string>, cache: array{store: ?string, ttl: int}, http_timeout: int, cookies?: array{access?: array{name?: ?string, path?: string, domain?: ?string, same_site?: string}, refresh?: array{name?: ?string, path?: string, domain?: ?string, same_site?: string, session_lifetime?: ?int}}, clients?: array<string, array{realm?: ?string, id?: ?string, secret?: ?string, return_origins?: list<string>, login_cookie?: array{name?: ?string, path?: string, domain?: ?string}}>} $config */
            $config = $app['config']['keycloak'];

            return new Keycloak($config, $app->make(Http::class), $app['cache'], (string) $app['config']['app.key']);
        });

        $this->app->singleton(TokenVerifier::class, static fn (Application $app): TokenVerifier => new TokenVerifier((int) $app['config']['keycloak.leeway']));
    }

    public function boot(): void
    {
        $this->publishes([__DIR__.'/../config/keycloak.php' => $this->app->configPath('keycloak.php')], 'keycloak-config');

        /** @var array{dev_tokens?: array<string, mixed>, cookies?: array{access?: array{name?: ?string}, refresh?: array{name?: ?string}}, clients?: array<string, array{login_cookie?: array{name?: ?string}}>} $config */
        $config = $this->app['config']['keycloak'];
        EncryptCookies::except(Keycloak::cookieNames($config));
        $this->app->make(Router::class)->aliasMiddleware(RequireRole::ALIAS, RequireRole::class);
        DevTokens::assertAllowed((array) ($config['dev_tokens'] ?? []), $this->app->environment(), (bool) $this->app['config']['app.debug']);

        // AuthManager binds the callback to itself: $this in it is the AuthManager.
        $this->app->make(AuthManager::class)->extend('keycloak', function (Container $app, string $name, array $config): RequestGuard {
            /* @var array{realms?: list<string>, audience?: ?string, cookie?: bool|string|null, other_issuers?: list<array{url?: ?string, issuer?: ?string, resolver: class-string<Auth\ClaimsResolver>}>, resolver?: ?class-string<Auth\ClaimsResolver>, by_client?: array<string, class-string<Auth\ClaimsResolver>>, by_realm?: array<string, class-string<Auth\ClaimsResolver>|array{resolver?: ?class-string<Auth\ClaimsResolver>, by_client?: array<string, class-string<Auth\ClaimsResolver>>}>} $config */
            KeycloakGuard::assertConfigured($name, $config, (array) $app['config']['keycloak']);
            $guard = new RequestGuard(new KeycloakGuard($app, $name, $config), $app['request']);
            $app->refresh('request', $guard, 'setRequest');

            return $guard;
        });
    }
}
