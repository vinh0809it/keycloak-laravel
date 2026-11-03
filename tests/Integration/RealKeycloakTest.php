<?php

/**
 * Copyright (c) 2026 Vinh Vo. MIT License.
 */

declare(strict_types=1);

namespace Vinh0809it\KeycloakLaravel\Tests\Integration;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Http\Client\Factory as Http;
use Illuminate\Support\Facades\Route;
use Orchestra\Testbench\TestCase;
use Vinh0809it\KeycloakLaravel\Client\InvalidClient;
use Vinh0809it\KeycloakLaravel\Client\RequestRefused;
use Vinh0809it\KeycloakLaravel\Keycloak;
use Vinh0809it\KeycloakLaravel\KeycloakServiceProvider;
use Vinh0809it\KeycloakLaravel\Tests\Fixtures\PrefixResolver;

/**
 * The guard against a real Keycloak running tests/Integration/realm.json, reached at KEYCLOAK_URL;
 * skipped without it.
 *
 *     docker run -p 8080:8080 -v "$PWD/tests/Integration/realm.json:/opt/keycloak/data/import/realm.json:ro" \
 *         quay.io/keycloak/keycloak:26.7.2 start-dev --import-realm
 *     KEYCLOAK_URL=http://localhost:8080 vendor/bin/phpunit --testsuite Integration
 */
final class RealKeycloakTest extends TestCase
{
    protected function setUp(): void
    {
        if ('' === (string) getenv('KEYCLOAK_URL')) {
            self::markTestSkipped('KEYCLOAK_URL is not set.');
        }
        parent::setUp();
    }

    protected function getPackageProviders($app): array
    {
        return [KeycloakServiceProvider::class];
    }

    protected function defineEnvironment($app): void
    {
        $app->make(Repository::class)->set([
            'keycloak.realms.default.url' => self::realm(),
            'keycloak.audience' => 'demo-api',
            'app.key' => 'base64:'.base64_encode(str_repeat('k', 32)),
            'keycloak.clients' => ['app' => ['id' => 'demo-app'], 'service' => ['id' => 'demo-service', 'secret' => 'demo-secret']],
            'auth.guards.api' => ['driver' => 'keycloak', 'resolver' => PrefixResolver::class],
        ]);
    }

    protected function defineRoutes($router): void
    {
        Route::middleware('auth:api')->get('/whoami', static fn (): array => ['user' => auth()->guard()->user()?->getAuthIdentifier()]);
    }

    public function testAUsersTokenIsAccepted(): void
    {
        $token = $this->token(['grant_type' => 'password', 'client_id' => 'demo-app', 'username' => 'alice', 'password' => 'alice-password']);

        $this->withToken($token)->getJson('/whoami')->assertOk()->assertJsonPath('user', fn (string $user): bool => str_starts_with($user, 'user:'));
    }

    public function testAServiceAccountsTokenIsAccepted(): void
    {
        $token = $this->token(['grant_type' => 'client_credentials', 'client_id' => 'demo-service', 'client_secret' => 'demo-secret']);

        $this->withToken($token)->getJson('/whoami')->assertOk();
    }

    public function testATokenForAnotherAudienceIsRefused(): void
    {
        $token = $this->token(['grant_type' => 'password', 'client_id' => 'other-app', 'username' => 'alice', 'password' => 'alice-password']);

        $this->withToken($token)->getJson('/whoami')->assertUnauthorized();
    }

    public function testATamperedTokenIsRefused(): void
    {
        [$header, $payload, $signature] = explode('.', $this->token(['grant_type' => 'password', 'client_id' => 'demo-app', 'username' => 'alice', 'password' => 'alice-password']));

        $this->withToken($header.'.'.$payload.'.'.strrev($signature))->getJson('/whoami')->assertUnauthorized();
    }

    public function testTheClientSignsInRefreshesAndLogsOut(): void
    {
        $client = $this->app->make(Keycloak::class)->client('app');
        $tokens = $client->password('alice', 'alice-password');
        $refreshed = $client->refresh((string) $tokens->refreshToken);
        $this->withToken($refreshed->accessToken)->getJson('/whoami')->assertOk();

        $client->logout((string) $refreshed->refreshToken);
        $this->expectException(RequestRefused::class);
        $client->refresh((string) $refreshed->refreshToken);
    }

    public function testAServiceTokenIsTheServiceAccountsAndAWrongSecretIsOurs(): void
    {
        $this->withToken($this->app->make(Keycloak::class)->serviceToken('service')->get())->getJson('/whoami')->assertOk();

        $this->app['config']->set('keycloak.clients.service.secret', 'wrong');
        $this->app->forgetInstance(Keycloak::class);
        $this->app->make('cache')->store()->flush();
        $this->expectException(InvalidClient::class);
        $this->app->make(Keycloak::class)->serviceToken('service')->get();
    }

    public function testABrowserSignsInAtTheRealmsPage(): void
    {
        $login = $this->app->make(Keycloak::class)->login('app');
        $start = $login->start('http://localhost/callback', '/orders');
        $loginCookie = $start->headers->getCookies()[0];

        // The browser: the realm's login page, then its form posted with Keycloak's own cookies.
        $page = $this->app->make(Http::class)->withoutRedirecting()->get($start->getTargetUrl());
        $cookies = implode('; ', array_map(static fn (string $header): string => explode(';', $header)[0], $page->headers()['Set-Cookie'] ?? []));
        preg_match('/<form[^>]*action="([^"]+)"/', $page->body(), $form);
        $back = $this->app->make(Http::class)->withoutRedirecting()->withHeaders(['Cookie' => $cookies])->asForm()
            ->post(html_entity_decode($form[1]), ['username' => 'alice', 'password' => 'alice-password']);
        parse_str((string) parse_url($back->header('Location'), \PHP_URL_QUERY), $query);
        self::assertSame(self::realm(), $query['iss'] ?? null, 'Keycloak names itself on the callback');

        $done = $login->finish(\Symfony\Component\HttpFoundation\Request::create('http://localhost/callback', 'GET', $query, [$loginCookie->getName() => (string) $loginCookie->getValue()]));

        self::assertSame('/orders', $done->returnTo);
        $this->withToken($done->tokens->accessToken)->getJson('/whoami')->assertOk();
    }

    /**
     * @param array<string, string> $form
     */
    private function token(array $form): string
    {
        return (string) $this->app->make(Http::class)->asForm()->post(self::realm().'/protocol/openid-connect/token', $form)->throw()->json('access_token');
    }

    private static function realm(): string
    {
        return rtrim((string) getenv('KEYCLOAK_URL'), '/').'/realms/demo';
    }
}
