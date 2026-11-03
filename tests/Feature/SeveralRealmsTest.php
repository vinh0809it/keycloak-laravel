<?php

/**
 * Copyright (c) 2026 Vinh Vo. MIT License.
 */

declare(strict_types=1);

namespace Vinh0809it\KeycloakLaravel\Tests\Feature;

use Illuminate\Support\Facades\Route;
use Vinh0809it\KeycloakLaravel\Testing\KeycloakFake;
use Vinh0809it\KeycloakLaravel\Tests\Fixtures\PrefixResolver;
use Vinh0809it\KeycloakLaravel\Tests\TestCase;

final class SeveralRealmsTest extends TestCase
{
    private KeycloakFake $customers;
    private KeycloakFake $employees;

    protected function setUp(): void
    {
        parent::setUp();
        $this->app['config']->set('keycloak.realms', []);
        $this->customers = KeycloakFake::install($this->app, 'https://keycloak.test/realms/customers', 'customers');
        $this->employees = KeycloakFake::install($this->app, 'https://keycloak.test/realms/employees', 'employees');
        $this->app->bind('test.staff_resolver', static fn (): PrefixResolver => new PrefixResolver('staff'));
        $this->app['config']->set('auth.guards.main', [
            'driver' => 'keycloak',
            'realms' => ['customers', 'employees'],
            'by_client' => ['web' => PrefixResolver::class],
            'by_realm' => ['employees' => ['by_client' => ['web' => 'test.staff_resolver', 'admin-web' => 'test.admin_resolver']]],
        ]);
        Route::middleware('auth:main')->get('/main/whoami', static fn (): array => ['user' => auth()->guard()->user()?->getAuthIdentifier()]);
    }

    public function testTheSameClientIdIsToldApartByItsRealm(): void
    {
        $this->whoami($this->customers->token(['azp' => 'web', 'sub' => 'c']), '/main/whoami')->assertExactJson(['user' => 'user:c']);
        $this->whoami($this->employees->token(['azp' => 'web', 'sub' => 'e']), '/main/whoami')->assertExactJson(['user' => 'staff:e']);
        $this->whoami($this->employees->token(['azp' => 'admin-web', 'sub' => 'a']), '/main/whoami')->assertExactJson(['user' => 'admin:a']);
    }

    public function testARealmsEntryIsItsAllowListOfClients(): void
    {
        $this->whoami($this->employees->token(['azp' => 'mobile-app']), '/main/whoami')->assertUnauthorized();
        $this->whoami($this->customers->token(['azp' => 'admin-web']), '/main/whoami')->assertUnauthorized();
    }

    public function testATokenNamingOneRealmSignedByAnothersKeyIsRefused(): void
    {
        $this->whoami($this->customers->token(['iss' => $this->employees->issuer, 'azp' => 'web']), '/main/whoami')->assertUnauthorized();
    }

    public function testARealmTheGuardDoesNotAcceptIsRefused(): void
    {
        $this->app['config']->set('auth.guards.main.realms', ['customers']);
        $this->app['config']->set('auth.guards.main.by_realm', []);

        $this->whoami($this->employees->token(['azp' => 'web']), '/main/whoami')->assertUnauthorized();
    }

    public function testEachRealmsKeysAreItsOwn(): void
    {
        $this->whoami($this->customers->token(['azp' => 'web']), '/main/whoami')->assertOk();
        $this->whoami($this->employees->token(['azp' => 'web']), '/main/whoami')->assertOk();

        self::assertSame([1, 1], [$this->customers->keyFetches(), $this->employees->keyFetches()]);
    }

    public function testAGuardMustNameItsRealmAmongSeveral(): void
    {
        $this->withoutExceptionHandling();
        $this->expectExceptionMessage('auth.guards.api: it must name its "realms"');

        $this->whoami($this->customers->token());
    }
}
