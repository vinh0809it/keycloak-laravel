<?php

/**
 * Copyright (c) 2026 Vinh Vo. MIT License.
 */

declare(strict_types=1);

namespace Vinh0809it\KeycloakLaravel\Tests;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Support\Facades\Route;
use Orchestra\Testbench\TestCase as Orchestra;
use Vinh0809it\KeycloakLaravel\KeycloakServiceProvider;
use Vinh0809it\KeycloakLaravel\Testing\KeycloakFake;
use Vinh0809it\KeycloakLaravel\Tests\Fixtures\PrefixResolver;

abstract class TestCase extends Orchestra
{
    protected KeycloakFake $realm;

    protected function getPackageProviders($app): array
    {
        return [KeycloakServiceProvider::class];
    }

    protected function defineEnvironment($app): void
    {
        $app->make(Repository::class)->set([
            'app.key' => 'base64:'.base64_encode(str_repeat('k', 32)),
            'keycloak.audience' => 'api',
            'keycloak.cookies.access.name' => 'access_token',
            'auth.guards.api' => [
                'driver' => 'keycloak',
                'resolver' => PrefixResolver::class,
                'by_client' => ['admin-web' => 'test.admin_resolver'],
                'cookie' => true,
            ],
            'auth.guards.admin' => ['driver' => 'keycloak', 'by_client' => ['admin-web' => 'test.admin_resolver'], 'audience' => 'admin-api'],
        ]);
        $app->bind('test.admin_resolver', static fn (): PrefixResolver => new PrefixResolver('admin'));
    }

    protected function defineRoutes($router): void
    {
        $whoami = static fn (): array => ['user' => auth()->guard()->user()?->getAuthIdentifier()];
        Route::middleware('auth:api')->get('/whoami', $whoami);
        Route::middleware('auth:admin')->get('/admin/whoami', $whoami);
    }

    protected function setUp(): void
    {
        parent::setUp();
        $this->realm = KeycloakFake::install($this->app);
    }

    /** @return \Illuminate\Testing\TestResponse<\Symfony\Component\HttpFoundation\Response> */
    protected function whoami(?string $token, string $path = '/whoami'): \Illuminate\Testing\TestResponse
    {
        // A guard keeps the user of the first request it served.
        $this->app->make('auth')->forgetGuards();

        return null !== $token ? $this->withToken($token)->getJson($path) : $this->getJson($path);
    }

    protected static function id(?Authenticatable $user): mixed
    {
        return $user?->getAuthIdentifier();
    }
}
