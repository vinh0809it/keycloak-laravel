<?php

/**
 * Copyright (c) 2026 Vinh Vo. MIT License.
 */

declare(strict_types=1);

namespace Vinh0809it\KeycloakLaravel\Tests\Feature;

use Firebase\JWT\JWT;
use Illuminate\Http\Client\Factory as Http;
use PHPUnit\Framework\Attributes\DataProvider;
use Vinh0809it\KeycloakLaravel\KeycloakUnavailable;
use Vinh0809it\KeycloakLaravel\Auth\RealmKeys;
use Vinh0809it\KeycloakLaravel\Keycloak;
use Vinh0809it\KeycloakLaravel\Testing\KeycloakFake;
use Vinh0809it\KeycloakLaravel\Tests\TestCase;

final class GuardTest extends TestCase
{
    public function testARealmTokenIsTheResolversUser(): void
    {
        $this->whoami($this->realm->token(['sub' => 'sub-1']))->assertOk()->assertExactJson(['user' => 'user:sub-1']);
    }

    public function testNoTokenIsUnauthenticated(): void
    {
        $this->whoami(null)->assertUnauthorized();
    }

    /**
     * @param array<string, mixed> $claims
     */
    #[DataProvider('refusedClaims')]
    public function testATokenThisServiceMustNotAcceptIsRefused(array $claims): void
    {
        $this->whoami($this->realm->token($claims))->assertUnauthorized();
    }

    /** @return iterable<string, array{array<string, mixed>}> */
    public static function refusedClaims(): iterable
    {
        yield 'no exp' => [['exp' => null]];
        yield 'expired' => [['exp' => time() - 60]];
        yield 'issued in the future' => [['iat' => time() + 600, 'exp' => time() + 900]];
        yield 'not yet valid' => [['nbf' => time() + 600]];
        yield 'no sub' => [['sub' => null]];
        yield 'empty sub' => [['sub' => '']];
        yield 'no iss' => [['iss' => null]];
        yield 'another issuer' => [['iss' => 'https://keycloak.test/realms/other']];
        yield 'the issuer with a trailing slash' => [['iss' => 'https://keycloak.test/realms/test/']];
        yield 'no aud' => [['aud' => null]];
        yield 'another audience' => [['aud' => 'other-api']];
        yield 'another audience among several' => [['aud' => ['other-api', 'account']]];
    }

    public function testTheAudienceMayBeOneOfSeveral(): void
    {
        $this->whoami($this->realm->token(['aud' => ['account', 'api']]))->assertOk();
    }

    public function testClockSkewWithinTheLeewayIsTolerated(): void
    {
        $this->whoami($this->realm->token(['iat' => time() + 5]))->assertOk();
    }

    public function testATamperedTokenIsRefused(): void
    {
        [$header, $payload, $signature] = explode('.', $this->realm->token(['sub' => 'sub-1']));
        $forged = JWT::urlsafeB64Encode((string) json_encode(['sub' => 'sub-2'] + (array) json_decode(JWT::urlsafeB64Decode($payload), true)));

        $this->whoami("$header.$forged.$signature")->assertUnauthorized();
    }

    public function testATokenSignedByAnotherKeyIsRefused(): void
    {
        $other = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => \OPENSSL_KEYTYPE_RSA]);
        self::assertNotFalse($other);
        openssl_pkey_export($other, $pem);

        $this->whoami(JWT::encode(['iss' => 'https://keycloak.test/realms/test', 'aud' => 'api', 'sub' => 's', 'exp' => time() + 60], $pem, 'RS256', $this->realm->kid()))->assertUnauthorized();
    }

    public function testAnHmacTokenKeyedWithThePublishedKeyIsRefused(): void
    {
        $jwks = $this->app->make(Http::class)->get($this->app->make(Keycloak::class)->realm()->keys->certsUrl())->json('keys.0');
        $claims = ['iss' => 'https://keycloak.test/realms/test', 'aud' => 'api', 'sub' => 's', 'exp' => time() + 60];

        $this->whoami(JWT::encode($claims, (string) json_encode($jwks), 'HS256', $this->realm->kid()))->assertUnauthorized();
    }

    public function testAnUnsignedTokenIsRefused(): void
    {
        $header = JWT::urlsafeB64Encode((string) json_encode(['alg' => 'none', 'typ' => 'JWT', 'kid' => $this->realm->kid()]));
        $payload = JWT::urlsafeB64Encode((string) json_encode(['iss' => 'https://keycloak.test/realms/test', 'aud' => 'api', 'sub' => 's', 'exp' => time() + 60]));

        $this->whoami("$header.$payload.")->assertUnauthorized();
    }

    public function testATokenWithoutAKidIsRefused(): void
    {
        $token = $this->realm->token();
        [, $payload, $signature] = explode('.', $token);
        $header = JWT::urlsafeB64Encode((string) json_encode(['alg' => 'RS256', 'typ' => 'JWT']));

        $this->whoami("$header.$payload.$signature")->assertUnauthorized();
    }

    public function testAnEncryptionKeyNeverVerifiesAToken(): void
    {
        $this->realm->rotateKey(['use' => 'enc']);

        $this->whoami($this->realm->token())->assertUnauthorized();
    }

    public function testAKeyOfAnAlgorithmNotAcceptedNeverVerifiesAToken(): void
    {
        $this->realm->rotateKey(['alg' => 'RS512']);

        $this->whoami($this->realm->token())->assertUnauthorized();
        $this->app['config']->set('keycloak.algorithms', ['RS256', 'RS512']);
        $this->app->forgetInstance(Keycloak::class);
        $this->app->make('cache')->store()->flush();
        $this->whoami($this->realm->token())->assertOk();
    }

    public function testTheResolverSeesTheRoles(): void
    {
        $this->app->bind('test.admin_resolver', static fn () => new class () implements \Vinh0809it\KeycloakLaravel\Auth\ClaimsResolver {
            public function resolve(\Vinh0809it\KeycloakLaravel\Auth\Claims $claims): \Illuminate\Auth\GenericUser
            {
                return new \Illuminate\Auth\GenericUser(['id' => json_encode([$claims->hasRole('admin'), $claims->hasRole('editor', 'api'), $claims->hasRole('editor')])]);
            }
        });
        $token = $this->realm->token(['azp' => 'admin-web', 'realm_access' => ['roles' => ['admin']], 'resource_access' => ['api' => ['roles' => ['editor']]]]);

        $this->whoami($token)->assertExactJson(['user' => '[true,true,false]']);
    }

    public function testTheKeysAreFetchedOnceAndCached(): void
    {
        $this->whoami($this->realm->token())->assertOk();
        $this->whoami($this->realm->token())->assertOk();
        $this->app->forgetInstance(Keycloak::class);
        $this->whoami($this->realm->token())->assertOk();

        self::assertSame(1, $this->realm->keyFetches());
    }

    public function testAKeyTheRealmPublishedSinceIsFetchedOnce(): void
    {
        $this->whoami($this->realm->token())->assertOk();
        $this->realm->rotateKey();

        $this->whoami($this->realm->token())->assertOk();
        self::assertSame(2, $this->realm->keyFetches());
    }

    public function testUnknownKeysRefetchAtMostOncePerInterval(): void
    {
        $this->whoami($this->realm->token())->assertOk();

        $this->whoami($this->realm->token([], ['kid' => 'made-up-1']))->assertUnauthorized();
        $this->whoami($this->realm->token([], ['kid' => 'made-up-2']))->assertUnauthorized();
        $this->realm->rotateKey();
        $this->whoami($this->realm->token())->assertUnauthorized();

        self::assertSame(2, $this->realm->keyFetches(), 'one refetch for the first unknown kid, none after');
        $this->travel(RealmKeys::REFETCH_INTERVAL + 1)->seconds();
        $this->whoami($this->realm->token())->assertOk();
        self::assertSame(3, $this->realm->keyFetches());
    }

    public function testAKeyTheRealmDroppedStopsVerifyingInTheSameProcessOnceTheCacheExpires(): void
    {
        $token = $this->realm->token();
        $this->whoami($token)->assertOk();
        $this->realm->rotateKey();
        $this->realm->removeKey((string) json_decode((string) base64_decode(explode('.', $token)[0]), true)['kid']);

        $this->travel(3601)->seconds();
        $this->whoami($token)->assertUnauthorized();
    }

    public function testARealmThatIsDownIsAskedAgainOnlyAfterAPause(): void
    {
        $this->realm->failKeys();
        foreach ([1, 2, 3] as $_) {
            try {
                $this->withoutExceptionHandling()->whoami($this->realm->token());
                self::fail('A realm that is down verified a token.');
            } catch (KeycloakUnavailable) {
            }
        }
        self::assertSame(1, $this->realm->keyFetches());

        $this->realm->restoreKeys();
        $this->travel(RealmKeys::OUTAGE_INTERVAL + 1)->seconds();
        $this->whoami($this->realm->token())->assertOk();
        self::assertSame(2, $this->realm->keyFetches());
    }

    public function testARestoredFakeAnswersAtOnce(): void
    {
        $this->realm->failKeys();
        $this->whoami($this->realm->token())->assertServerError();

        $this->realm->restoreKeys();
        $this->whoami($this->realm->token())->assertOk();
    }

    public function testATokenIsVerifiedWithOneReadOfTheCachedKeys(): void
    {
        $this->whoami($this->realm->token())->assertOk();
        $reads = 0;
        $this->app['events']->listen(\Illuminate\Cache\Events\CacheHit::class, static function () use (&$reads): void {
            ++$reads;
        });

        $this->whoami($this->realm->token())->assertOk();
        self::assertSame(1, $reads);
    }

    /** @return iterable<string, array{mixed, bool}> */
    public static function tokenTypes(): iterable
    {
        yield 'an access token' => ['Bearer', true];
        yield 'an access token, lower case' => ['bearer', true];
        yield 'no typ' => [null, true];
        yield 'an ID token' => ['ID', false];
        yield 'a logout token' => ['Logout', false];
        yield 'a refresh token' => ['Refresh', false];
        yield 'a typ that is no string' => [['Bearer'], false];
    }

    #[DataProvider('tokenTypes')]
    public function testOnlyARealmsAccessTokensAreAccepted(mixed $type, bool $accepted): void
    {
        $this->whoami($this->realm->token(['typ' => $type]))->assertStatus($accepted ? 200 : 401);
    }

    public function testAFakeOfTheSameRealmDoesNotInheritTheKeysAPersistentStoreKept(): void
    {
        try {
            foreach ([1, 2] as $_) {
                // Each round is a test of its own: a new app, a new fake of the same realm, the same store on disk.
                $this->refreshApplication();
                $this->app['config']->set('keycloak.cache.store', 'file');
                $realm = KeycloakFake::install($this->app);
                $this->whoami($realm->token())->assertOk();
                $this->whoami($realm->token([], ['kid' => 'made-up']))->assertUnauthorized();   // spends the refetch of the minute
            }
        } finally {
            $this->app->make('cache')->store('file')->flush();
        }
    }

    public function testATokenIsRoutedByItsClient(): void
    {
        $this->whoami($this->realm->token(['azp' => 'admin-web', 'sub' => 's']))->assertOk()->assertExactJson(['user' => 'admin:s']);
        $this->whoami($this->realm->token(['azp' => 'mobile-app', 'sub' => 's']))->assertOk()->assertExactJson(['user' => 'user:s']);
    }

    public function testAClientWithNoResolverIsRefusedWhereTheGuardHasNoDefault(): void
    {
        $this->whoami($this->realm->token(['azp' => 'admin-web', 'aud' => 'admin-api']), '/admin/whoami')->assertOk();
        $this->whoami($this->realm->token(['azp' => 'mobile-app', 'aud' => 'admin-api']), '/admin/whoami')->assertUnauthorized();
    }

    public function testAGuardMayHaveItsOwnAudience(): void
    {
        $this->whoami($this->realm->token(['azp' => 'admin-web']), '/admin/whoami')->assertUnauthorized();
    }

    public function testTheTokenMayRideInTheConfiguredCookie(): void
    {
        $this->withCredentials()->withUnencryptedCookie('access_token', $this->realm->token(['sub' => 'c']))->getJson('/whoami')->assertOk()->assertExactJson(['user' => 'user:c']);
    }

    public function testTheBearerHeaderWinsOverTheCookie(): void
    {
        $this->withCredentials()->withUnencryptedCookie('access_token', $this->realm->token(['sub' => 'cookie']))
            ->withToken($this->realm->token(['sub' => 'header']))
            ->getJson('/whoami')->assertExactJson(['user' => 'user:header']);
    }

    public function testAnUnreachableRealmIsAServerErrorNotA401(): void
    {
        $this->realm->failKeys(503);

        $this->withoutExceptionHandling();
        $this->expectException(KeycloakUnavailable::class);

        $this->whoami($this->realm->token());
    }
}
