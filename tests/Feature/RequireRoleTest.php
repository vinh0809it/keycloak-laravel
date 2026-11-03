<?php

/**
 * Copyright (c) 2026 Vinh Vo. MIT License.
 */

declare(strict_types=1);

namespace Vinh0809it\KeycloakLaravel\Tests\Feature;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use PHPUnit\Framework\Attributes\DataProvider;
use Vinh0809it\KeycloakLaravel\Auth\Claims;
use Vinh0809it\KeycloakLaravel\Tests\TestCase;

final class RequireRoleTest extends TestCase
{
    protected function defineRoutes($router): void
    {
        parent::defineRoutes($router);
        $ok = static fn (Request $request): array => ['sub' => Claims::of($request)?->sub];
        Route::middleware(['auth:api', 'keycloak.role:admin'])->get('/admin', $ok);
        Route::middleware(['auth:api', 'keycloak.role:admin,my-api:editor'])->get('/edit', $ok);
        Route::middleware('keycloak.role:admin')->get('/no-auth', $ok);
    }

    /** @return iterable<string, array{string, array<string, mixed>, int}> */
    public static function roles(): iterable
    {
        $realm = static fn (string ...$roles): array => ['realm_access' => ['roles' => $roles]];
        $client = static fn (string $client, string ...$roles): array => ['resource_access' => [$client => ['roles' => $roles]]];

        yield 'the realm role' => ['/admin', $realm('admin'), 200];
        yield 'another realm role' => ['/admin', $realm('user'), 403];
        yield 'no roles' => ['/admin', [], 403];
        yield 'a client role of the same name is no realm role' => ['/admin', $client('my-api', 'admin'), 403];
        yield 'any of the listed: the realm role' => ['/edit', $realm('admin'), 200];
        yield 'any of the listed: the client role' => ['/edit', $client('my-api', 'editor'), 200];
        yield 'the role of another client' => ['/edit', $client('other-api', 'editor'), 403];
        yield 'the client role as a realm role' => ['/edit', $realm('editor'), 403];
    }

    /**
     * @param array<string, mixed> $claims
     */
    #[DataProvider('roles')]
    public function testARouteTakesTheTokensThatHoldOneOfItsRoles(string $path, array $claims, int $status): void
    {
        $this->whoami($this->realm->token($claims + ['sub' => 's']), $path)->assertStatus($status);
    }

    public function testTheRouteSeesTheTokensClaims(): void
    {
        $this->whoami($this->realm->token(['sub' => 'alice', 'realm_access' => ['roles' => ['admin']]]), '/admin')->assertExactJson(['sub' => 'alice']);
    }

    public function testARequestNoKeycloakTokenAuthenticatedIsForbidden(): void
    {
        $this->whoami($this->realm->token(['realm_access' => ['roles' => ['admin']]]), '/no-auth')->assertForbidden();
    }

    public function testAnUnauthenticatedRequestStopsAtTheGuard(): void
    {
        $this->whoami(null, '/admin')->assertUnauthorized();
    }

    public function testADevTokensRolesCountToo(): void
    {
        $this->app['config']->set('keycloak.dev_tokens', ['admin.1' => ['realm_access' => ['roles' => ['admin']]]]);
        $this->app->forgetInstance(\Vinh0809it\KeycloakLaravel\Keycloak::class);

        $this->whoami('admin.1', '/admin')->assertOk();
    }
}
