<?php

/**
 * Copyright (c) 2026 Vinh Vo. MIT License.
 */

declare(strict_types=1);

namespace Vinh0809it\KeycloakLaravel\Tests\Feature;

use PHPUnit\Framework\Attributes\DataProvider;
use Vinh0809it\KeycloakLaravel\KeycloakServiceProvider;
use Vinh0809it\KeycloakLaravel\Tests\Fixtures\PrefixResolver;
use Vinh0809it\KeycloakLaravel\Tests\TestCase;

/** A `keycloak` guard the app could not serve fails when it is first built, not on a request with a token. */
final class GuardConfigurationTest extends TestCase
{
    /** @return iterable<string, array{array<string, mixed>, array<string, mixed>, string}> */
    public static function guardsItCannotServe(): iterable
    {
        $two = ['realms' => ['customers' => ['url' => 'https://kc/realms/customers'], 'employees' => ['url' => 'https://kc/realms/employees']]];

        yield 'no audience' => [['resolver' => PrefixResolver::class], ['audience' => null], 'needs an "audience"'];
        yield 'no realm named among several' => [['resolver' => PrefixResolver::class], $two, 'must name its "realms"'];
        yield 'an undeclared realm' => [['realms' => ['partners'], 'resolver' => PrefixResolver::class], $two, '"realms" names "partners"'];
        yield 'by_realm on a realm it does not take' => [['realms' => ['customers'], 'by_realm' => ['employees' => PrefixResolver::class]], $two, '"by_realm" names "employees"'];
        yield 'an other issuer without a resolver' => [['resolver' => PrefixResolver::class, 'other_issuers' => [['url' => 'https://legacy.test']]], [], 'needs a "resolver"'];
        yield 'a cookie name' => [['resolver' => PrefixResolver::class, 'cookie' => 'at'], [], '"cookie" is true'];
        yield 'nothing to resolve with' => [[], [], 'needs a "resolver", or entries'];
    }

    /**
     * @param array<string, mixed> $guard
     * @param array<string, mixed> $keycloak over the test's own
     */
    #[DataProvider('guardsItCannotServe')]
    public function testAGuardItCannotServeFailsWhenBuilt(array $guard, array $keycloak, string $message): void
    {
        $this->app['config']->set('auth.guards', ['broken' => ['driver' => 'keycloak'] + $guard]);
        foreach ($keycloak as $key => $value) {
            $this->app['config']->set('keycloak.'.$key, $value);
        }

        $this->expectExceptionMessageMatches('/^auth\.guards\.broken: .*'.preg_quote($message, '/').'/');
        $this->app->make('auth')->guard('broken');
    }

    public function testTheAppStillBootsWithoutTheGuardsEnvironment(): void
    {
        // artisan (package:discover, config:cache...) boots every provider, in steps without the runtime env too.
        $this->app['config']->set('keycloak.audience', null);
        (new KeycloakServiceProvider($this->app))->boot();

        $this->expectExceptionMessage('auth.guards.api: it needs an "audience"');
        $this->withoutExceptionHandling()->getJson('/whoami');
    }
}
