<?php

/**
 * Copyright (c) 2026 Vinh Vo. MIT License.
 */

declare(strict_types=1);

namespace Vinh0809it\KeycloakLaravel\Tests\Feature;

use Illuminate\Http\Client\ConnectionException;
use Illuminate\Http\Client\Factory as Http;
use Illuminate\Http\Client\Request;
use Vinh0809it\KeycloakLaravel\Client\InvalidClient;
use Vinh0809it\KeycloakLaravel\Client\RequestRefused;
use Vinh0809it\KeycloakLaravel\Keycloak;
use Vinh0809it\KeycloakLaravel\KeycloakUnavailable;
use Vinh0809it\KeycloakLaravel\Tests\TestCase;

final class ClientTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        $this->app['config']->set('keycloak.clients', [
            'service' => ['id' => 'my-service', 'secret' => 'service-secret'],
            'app' => [],
        ]);
        $this->app->forgetInstance(Keycloak::class);
    }

    public function testAConfidentialClientAuthenticatesItsGrants(): void
    {
        $tokens = $this->keycloak()->client('service')->clientCredentials();

        self::assertSame(['grant_type' => 'client_credentials', 'client_id' => 'my-service', 'client_secret' => 'service-secret'], $this->realm->requests()[0]['form']);
        self::assertSame(300, $tokens->expiresIn);
        self::assertNull($tokens->refreshToken);
    }

    public function testAPublicClientSendsItsIdAlone(): void
    {
        $tokens = $this->keycloak()->client('app')->password('alice', 'secret');

        self::assertSame(['grant_type' => 'password', 'username' => 'alice', 'password' => 'secret', 'client_id' => 'app'], $this->realm->requests()[0]['form']);
        self::assertNotNull($tokens->refreshToken);
    }

    public function testAnSpiDirectGrantCarriesItsOwnFields(): void
    {
        $this->keycloak()->client('app')->password('+15550100', '', ['session' => 's-1', 'otp' => '123456']);

        self::assertSame(['session' => 's-1', 'otp' => '123456'], array_intersect_key($this->realm->requests()[0]['form'], ['session' => 1, 'otp' => 1]));
    }

    public function testARefreshTokenIsSpentByItsRefreshAndEndedByALogout(): void
    {
        $client = $this->keycloak()->client('app');
        $first = $client->password('alice', 'secret');
        $second = $client->refresh((string) $first->refreshToken);

        try {
            $client->refresh((string) $first->refreshToken);
            self::fail('A spent refresh token was refreshed.');
        } catch (RequestRefused $e) {
            self::assertSame('invalid_grant', $e->error);
        }
        $client->logout((string) $second->refreshToken);
        $this->expectException(RequestRefused::class);
        $client->refresh((string) $second->refreshToken);
    }

    public function testARefusedGrantIsTheCallersAndARefusedClientIsOurs(): void
    {
        $this->realm->onToken(static fn (array $form): ?array => 'wrong' === ($form['password'] ?? null) ? ['error' => 'invalid_grant', 'error_description' => 'Invalid user credentials'] : null);
        $this->realm->onToken(static fn (array $form): ?array => 'client_credentials' === $form['grant_type'] ? ['error' => 'unauthorized_client', 'status' => 401] : null);

        try {
            $this->keycloak()->client('app')->password('alice', 'wrong');
            self::fail('A refused grant passed.');
        } catch (RequestRefused $e) {
            self::assertNotInstanceOf(InvalidClient::class, $e);
            self::assertSame(400, $e->status);
            self::assertStringContainsString('Invalid user credentials', $e->getMessage());
        }

        $this->expectException(InvalidClient::class);
        $this->keycloak()->client('service')->clientCredentials();
    }

    public function testKeycloakDownOrUnreachableIsUnavailable(): void
    {
        $this->app->make(Http::class)->fake(['keycloak.down/*' => Http::response('', 503)]);
        $this->app['config']->set('keycloak.realms.down', ['url' => 'https://keycloak.down/realms/x']);
        $this->app['config']->set('keycloak.clients.down', ['realm' => 'down']);
        $this->app->forgetInstance(Keycloak::class);

        try {
            $this->keycloak()->client('down')->clientCredentials();
            self::fail('A 503 passed.');
        } catch (KeycloakUnavailable) {
        }

        $this->app->make(Http::class)->fake(static fn (Request $request) => str_contains($request->url(), 'keycloak.gone') ? throw new ConnectionException('gone') : null);
        $this->app['config']->set('keycloak.realms.gone', ['url' => 'https://keycloak.gone/realms/x']);
        $this->app['config']->set('keycloak.clients.gone', ['realm' => 'gone']);
        $this->app->forgetInstance(Keycloak::class);
        $this->expectException(KeycloakUnavailable::class);
        $this->keycloak()->client('gone')->clientCredentials();
    }

    public function testASuccessWithoutAnAccessTokenIsUnavailable(): void
    {
        $this->realm->onToken(static fn (): array => ['token_type' => 'Bearer']);

        $this->expectException(KeycloakUnavailable::class);
        $this->keycloak()->client('app')->password('alice', 'secret');
    }

    public function testTheAuthorizationUrlIsTheBrowsersRealmWithPkce(): void
    {
        $this->app['config']->set('keycloak.realms.default.url', 'http://keycloak:8080/realms/test');
        $this->app->forgetInstance(Keycloak::class);

        $url = $this->keycloak()->client('app')->authorizationUrl('https://app.test/callback', 'st', 'ch', ['login_hint' => 'alice', 'prompt' => null, 'response_mode' => 'fragment']);

        self::assertStringStartsWith('https://keycloak.test/realms/test/protocol/openid-connect/auth?', $url);
        parse_str((string) parse_url($url, \PHP_URL_QUERY), $query);
        self::assertSame(['client_id' => 'app', 'response_type' => 'code', 'scope' => 'openid', 'redirect_uri' => 'https://app.test/callback', 'state' => 'st', 'code_challenge' => 'ch', 'code_challenge_method' => 'S256', 'login_hint' => 'alice'], $query);
    }

    public function testUserinfoAndRealmResourcesAreReachedUnderTheRealm(): void
    {
        $this->app->make(Http::class)->fake([
            'keycloak.test/realms/test/protocol/openid-connect/userinfo' => static fn (Request $request) => Http::response(['sub' => 'sub-1', 'auth' => $request->header('Authorization')[0]]),
            'keycloak.test/realms/test/my-provider/send' => static fn (Request $request) => Http::response($request->data(), 'nope' === ($request->data()['to'] ?? null) ? 422 : 200),
        ]);

        self::assertSame(['sub' => 'sub-1', 'auth' => 'Bearer at'], $this->keycloak()->client('app')->userinfo('at'));
        self::assertSame(['to' => 'alice'], $this->keycloak()->client('app')->realm('POST', '/my-provider/send', ['json' => ['to' => 'alice']]));
        try {
            $this->keycloak()->client('app')->realm('POST', 'my-provider/send', ['json' => ['to' => 'nope']]);
            self::fail('A 422 passed.');
        } catch (RequestRefused $e) {
            self::assertSame(['to' => 'nope'], $e->body);
        }
    }

    public function testAServiceTokenIsMintedOnceForEveryInstanceSharingTheCache(): void
    {
        $token = $this->keycloak()->serviceToken('service')->get();
        self::assertSame($token, $this->keycloak()->serviceToken('service')->get());
        $this->app->forgetInstance(Keycloak::class);
        self::assertSame($token, $this->keycloak()->serviceToken('service')->get());

        self::assertCount(1, $this->realm->requests());
    }

    public function testAServiceTokenIsMintedAgainNearItsExpiry(): void
    {
        $this->keycloak()->serviceToken('service')->get();
        $this->app->forgetInstance(Keycloak::class);
        $this->travel(300 - 30 + 1)->seconds();

        $this->keycloak()->serviceToken('service')->get();
        self::assertCount(2, $this->realm->requests());
    }

    public function testAServiceTokenIsKeptPerRealmAndClientWhateverItsName(): void
    {
        $token = $this->keycloak()->serviceToken('service')->get();
        $this->app['config']->set('keycloak.clients.service.id', 'another-service');
        $this->app->forgetInstance(Keycloak::class);

        self::assertNotSame($token, $this->keycloak()->serviceToken('service')->get(), 'a client retargeted under the same name mints its own');
        self::assertCount(2, $this->realm->requests());
    }

    public function testAForgottenServiceTokenIsMintedAgainForEveryInstance(): void
    {
        $this->keycloak()->serviceToken('service')->get();
        $this->keycloak()->serviceToken('service')->forget();
        $this->app->forgetInstance(Keycloak::class);
        $this->keycloak()->serviceToken('service')->get();

        self::assertCount(2, $this->realm->requests());
    }

    public function testAnUnreachableRealmsErrorCarriesNoSecret(): void
    {
        $this->app->make(Http::class)->fake(static fn (Request $request) => str_contains($request->url(), 'keycloak.gone') ? throw new ConnectionException('cURL error 7: Failed to connect to keycloak.gone') : null);
        $this->app['config']->set('keycloak.realms.gone', ['url' => 'https://keycloak.gone/realms/x']);
        $this->app['config']->set('keycloak.clients.gone', ['realm' => 'gone', 'secret' => 's3cr3t']);
        $this->app->forgetInstance(Keycloak::class);

        try {
            $this->keycloak()->client('gone')->password('alice', 'hunter2');
            self::fail('An unreachable realm answered.');
        } catch (KeycloakUnavailable $e) {
            self::assertNull($e->getPrevious(), 'the HTTP client\'s exception holds the request');
            self::assertStringContainsString('Failed to connect', $e->getMessage());
            self::assertStringNotContainsString('s3cr3t', $e->getMessage().$e->getTraceAsString());
            self::assertStringNotContainsString('hunter2', $e->getMessage().$e->getTraceAsString());
        }
    }

    public function testAPublicClientHasNoServiceToken(): void
    {
        $this->expectExceptionMessage('keycloak.clients.app has no secret');

        $this->keycloak()->serviceToken('app');
    }

    private function keycloak(): Keycloak
    {
        return $this->app->make(Keycloak::class);
    }
}
