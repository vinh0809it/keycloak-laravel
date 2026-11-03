<?php

/**
 * Copyright (c) 2026 Vinh Vo. MIT License.
 */

declare(strict_types=1);

namespace Vinh0809it\KeycloakLaravel\Tests\Feature;

use PHPUnit\Framework\Attributes\DataProvider;
use Vinh0809it\KeycloakLaravel\Auth\DevTokens;
use Vinh0809it\KeycloakLaravel\Keycloak;
use Vinh0809it\KeycloakLaravel\Testing\KeycloakFake;
use Vinh0809it\KeycloakLaravel\Tests\Fixtures\PrefixResolver;
use Vinh0809it\KeycloakLaravel\Tests\TestCase;

final class DevTokensAndOtherIssuersTest extends TestCase
{
    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);
        $app['config']->set('app.debug', true);
        $app['config']->set('keycloak.dev_tokens', [
            'member.1' => [],
            'admin.1' => ['sub' => 'a-1', 'azp' => 'admin-web'],
            '{azp}~{sub}' => ['email_verified' => true],
        ]);
    }

    public function testADevTokenStandsForItsClaimsThroughTheSameResolvers(): void
    {
        $this->whoami('member.1')->assertExactJson(['user' => 'user:member.1']);
        $this->whoami('admin.1')->assertExactJson(['user' => 'admin:a-1']);
        $this->whoami('admin-web~42')->assertExactJson(['user' => 'admin:42']);
        $this->whoami('mobile-app~42')->assertExactJson(['user' => 'user:42']);
    }

    public function testASignedTokenKeepsWorkingBesideThem(): void
    {
        $this->whoami($this->realm->token(['sub' => 'real']))->assertExactJson(['user' => 'user:real']);
        $this->whoami('member.2')->assertUnauthorized();
    }

    public function testADevTokenNeedsNoRealm(): void
    {
        $this->app['config']->set('keycloak.realms.default.url', null);
        $this->app->forgetInstance(Keycloak::class);

        $this->whoami('member.1')->assertExactJson(['user' => 'user:member.1']);
        $this->whoami($this->realm->token())->assertUnauthorized();
    }

    /** @return iterable<string, array{string, bool, array<string, mixed>, string}> */
    public static function refusedDevTokens(): iterable
    {
        yield 'production' => ['production', true, ['t' => []], 'only be set in the local and testing environments'];
        yield 'staging, debug on' => ['staging', true, ['t' => []], 'only be set in the local and testing environments'];
        yield 'debug off' => ['local', false, ['t' => []], 'with debug on'];
        yield 'a pattern a JWT could match' => ['local', true, ['{azp}.{sub}' => []], 'a character a JWT never holds'];
        yield 'a placeholder twice' => ['local', true, ['{sub}~{sub}' => []], 'names a placeholder twice'];
        yield 'claims that are no map' => ['local', true, ['t' => 'x'], 'a map of claims'];
    }

    /**
     * @param array<string, mixed> $tokens
     */
    #[DataProvider('refusedDevTokens')]
    public function testDevTokensAreRefusedOutsideDevelopment(string $environment, bool $debug, array $tokens, string $message): void
    {
        $this->expectExceptionMessage($message);

        DevTokens::assertAllowed($tokens, $environment, $debug);
    }

    public function testTheAppDoesNotBootWithDevTokensInProduction(): void
    {
        $this->app['env'] = 'production';

        $this->expectExceptionMessage('only be set in the local and testing environments');
        (new \Vinh0809it\KeycloakLaravel\KeycloakServiceProvider($this->app))->boot();
    }

    public function testAnotherIssuersTokenIsVerifiedWithItsKeysAndResolvedByItsResolver(): void
    {
        $legacy = KeycloakFake::serve($this->app, 'https://legacy.test');
        $this->app->bind('test.legacy_resolver', static fn (): PrefixResolver => new PrefixResolver('legacy'));
        $this->app['config']->set('auth.guards.api.other_issuers', [['url' => 'https://legacy.test', 'resolver' => 'test.legacy_resolver']]);

        $this->whoami($legacy->token(['azp' => 'admin-web', 'sub' => 'l']))->assertExactJson(['user' => 'legacy:l']);
        $this->whoami($this->realm->token(['sub' => 'k']))->assertExactJson(['user' => 'user:k']);
        $this->whoami($legacy->token(['iss' => $this->realm->issuer]))->assertUnauthorized();
        $this->whoami($this->realm->token(['iss' => 'https://legacy.test']))->assertUnauthorized();
    }

    public function testAnOtherIssuersTokenTypeIsItsOwnBusiness(): void
    {
        $legacy = KeycloakFake::serve($this->app, 'https://legacy.test');
        $this->app['config']->set('auth.guards.api.other_issuers', [['url' => 'https://legacy.test', 'resolver' => PrefixResolver::class]]);

        $this->whoami($legacy->token(['typ' => 'ID']))->assertOk();
    }

    public function testAnOtherIssuersKeyWithoutAlgTakesTheOnlyAcceptedOne(): void
    {
        $legacy = KeycloakFake::serve($this->app, 'https://legacy.test');
        $legacy->rotateKey(['alg' => null]);
        $this->app['config']->set('auth.guards.api.other_issuers', [['url' => 'https://legacy.test', 'resolver' => PrefixResolver::class]]);

        $this->whoami($legacy->token([], ['alg' => 'RS256']))->assertOk();
    }

    public function testAnOtherIssuerWithoutAUrlTakesNoToken(): void
    {
        $legacy = KeycloakFake::serve($this->app, 'https://legacy.test');
        $this->app['config']->set('auth.guards.api.other_issuers', [['url' => '', 'issuer' => 'https://legacy.test', 'resolver' => PrefixResolver::class]]);

        $this->whoami($legacy->token())->assertUnauthorized();
    }
}
