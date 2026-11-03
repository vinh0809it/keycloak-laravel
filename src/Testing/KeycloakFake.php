<?php

/**
 * Copyright (c) 2026 Vinh Vo. MIT License.
 */

declare(strict_types=1);

namespace Vinh0809it\KeycloakLaravel\Testing;

use Firebase\JWT\JWT;
use Illuminate\Container\Container;
use Illuminate\Http\Client\Factory as Http;
use Illuminate\Http\Client\Request;
use Vinh0809it\KeycloakLaravel\Keycloak;

/**
 * A realm for tests, answering through Http::fake(): its discovery document and JWKS, and its
 * token, logout and revoke endpoints. Its tokens are signed like real ones, so the `keycloak` guard verifies them.
 *
 *     $realm = KeycloakFake::install($this->app);
 *     $this->withToken($realm->token(['sub' => 'user-1']))->getJson('/api/me')->assertOk();
 *
 * The token endpoint answers each grant with an access token for the requesting client (`azp`):
 * `client_credentials` for its service account, `password` for the username, `authorization_code`
 * for a code {@see code()} issued, `refresh_token` for a refresh token it issued and no logout or
 * revocation ended. Anything else is `invalid_grant`; {@see onToken()} answers grants of its own.
 */
final class KeycloakFake
{
    public const REALM = 'https://keycloak.test/realms/test';

    /** @var list<array{private: string, public: array<string, string>}> */
    private array $keys = [];
    /** @var array<string, array<string, mixed>> codes not redeemed yet => the claims of their tokens */
    private array $codes = [];
    /** @var array<string, array<string, mixed>> live refresh tokens => the claims of their tokens */
    private array $refreshTokens = [];
    /** @var list<\Closure(array<string, string>): ?array<string, mixed>> */
    private array $tokenHandlers = [];

    private int $keyFetches = 0;
    private int $keysStatus = 200;
    /** @var list<array{endpoint: string, form: array<string, string>}> */
    private array $requests = [];

    private function __construct(
        private readonly Container $app,
        public readonly string $issuer,
    ) {
        $this->rotateKey();
    }

    /**
     * Declares this realm as keycloak.realms.$name (its URL and issuer both $url) and answers its
     * endpoints. keycloak.audience stays the app's.
     */
    public static function install(Container $app, string $url = self::REALM, string $name = 'default'): self
    {
        $app['config']->set('keycloak.realms.'.$name, ['url' => rtrim($url, '/'), 'issuer' => rtrim($url, '/')]);
        $app->forgetInstance(Keycloak::class);

        return self::serve($app, $url);
    }

    /**
     * Answers $url's endpoints, its discovery document included, without declaring it a realm: an
     * OpenID provider for a guard's `other_issuers`.
     */
    public static function serve(Container $app, string $url): self
    {
        $fake = new self($app, rtrim($url, '/'));
        // A persistent cache store may hold the keys of an earlier test's fake of this URL.
        $fake->forgetCachedKeys();
        $app->make(Http::class)->fake(static fn (Request $request) => $fake->answer($request));

        return $fake;
    }

    /**
     * A signed access token: `iss` this realm, `aud` keycloak.audience, `exp` in five minutes, and
     * $claims over them (null removes a claim).
     *
     * @param array<string, mixed>  $claims
     * @param array<string, string> $header over the signing key's `kid` and `alg`
     */
    public function token(array $claims = [], array $header = []): string
    {
        $now = time();
        $payload = array_filter($claims + [
            'iss' => $this->issuer,
            'aud' => $this->app['config']['keycloak.audience'],
            'sub' => 'sub-1',
            'azp' => 'test-app',
            'typ' => 'Bearer',
            'iat' => $now,
            'exp' => $now + 300,
        ], static fn (mixed $value): bool => null !== $value);
        $key = $this->keys[array_key_last($this->keys)];

        return JWT::encode($payload, $key['private'], $header['alg'] ?? $key['public']['alg'] ?? 'RS256', $header['kid'] ?? $key['public']['kid'], $header);
    }

    /**
     * An authorization code the token endpoint redeems once, for tokens carrying $claims.
     *
     * @param array<string, mixed> $claims
     */
    public function code(array $claims = []): string
    {
        $code = 'code-'.bin2hex(random_bytes(8));
        $this->codes[$code] = $claims;

        return $code;
    }

    /**
     * Answers the grants $handler returns a token endpoint body for (one with an `error` is a 400,
     * or its `status`); the grants it returns null for fall through to the defaults.
     *
     * @param \Closure(array<string, string>): ?array<string, mixed> $handler
     */
    public function onToken(\Closure $handler): void
    {
        $this->tokenHandlers[] = $handler;
    }

    /**
     * A new key, published beside the earlier ones with $jwk over its JWK (`use`, `alg`...; null
     * leaves a member out), signs the next tokens.
     *
     * @param array<string, ?string> $jwk
     *
     * @return string its `kid`
     */
    public function rotateKey(array $jwk = []): string
    {
        $private = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => \OPENSSL_KEYTYPE_RSA]);
        if (false === $private || !openssl_pkey_export($private, $pem)) {
            throw new \RuntimeException('openssl cannot generate an RSA key.');
        }
        $rsa = openssl_pkey_get_details($private)['rsa'] ?? throw new \RuntimeException('openssl gave no RSA details.');
        $kid = 'kid-'.bin2hex(random_bytes(4));

        $this->keys[] = ['private' => $pem, 'public' => array_filter($jwk + [
            'kid' => $kid,
            'kty' => 'RSA',
            'alg' => 'RS256',
            'use' => 'sig',
            'n' => JWT::urlsafeB64Encode($rsa['n']),
            'e' => JWT::urlsafeB64Encode($rsa['e']),
        ], static fn (?string $value): bool => null !== $value)];

        return $kid;
    }

    /** The `kid` of the key signing the next tokens. */
    public function kid(): string
    {
        return $this->keys[array_key_last($this->keys)]['public']['kid'];
    }

    /** Stops publishing a key, as a realm does when it retires or revokes one. */
    public function removeKey(string $kid): void
    {
        $this->keys = array_values(array_filter($this->keys, static fn (array $key): bool => $kid !== $key['public']['kid']));
    }

    /** Answers the JWKS endpoint with $status and no keys, until {@see restoreKeys()}. */
    public function failKeys(int $status = 503): void
    {
        $this->keysStatus = $status;
    }

    /** Answers the JWKS endpoint again, and forgets that a fetch failed, so the next one goes through. */
    public function restoreKeys(): void
    {
        $this->keysStatus = 200;
        $this->forgetCachedKeys();
    }

    private function forgetCachedKeys(): void
    {
        $this->app->make(Keycloak::class)->otherIssuer($this->issuer)?->keys->forget();
    }

    /** How many times the keys were fetched. */
    public function keyFetches(): int
    {
        return $this->keyFetches;
    }

    /**
     * What the token, logout and revoke endpoints received, oldest first.
     *
     * @return list<array{endpoint: string, form: array<string, string>}>
     */
    public function requests(): array
    {
        return $this->requests;
    }

    private function answer(Request $request): mixed
    {
        if ($this->issuer.'/.well-known/openid-configuration' === $request->url()) {
            return Http::response(['issuer' => $this->issuer, 'jwks_uri' => $this->issuer.'/protocol/openid-connect/certs']);
        }
        $prefix = $this->issuer.'/protocol/openid-connect/';
        $endpoint = str_starts_with($request->url(), $prefix) ? substr($request->url(), \strlen($prefix)) : null;
        if ('certs' === $endpoint) {
            ++$this->keyFetches;

            return 200 === $this->keysStatus
                ? Http::response(['keys' => array_map(static fn (array $key): array => $key['public'], $this->keys)])
                : Http::response('', $this->keysStatus);
        }
        if (!\in_array($endpoint, ['token', 'logout', 'revoke'], true)) {
            return null;
        }

        /** @var array<string, string> $form */
        $form = $request->data();
        $this->requests[] = ['endpoint' => $endpoint, 'form' => $form];
        if ('token' !== $endpoint) {
            unset($this->refreshTokens[$form['refresh_token'] ?? $form['token'] ?? '']);

            return Http::response('', 204);
        }

        foreach ($this->tokenHandlers as $handler) {
            if (null !== ($body = $handler($form))) {
                return Http::response($body, (int) ($body['status'] ?? (isset($body['error']) ? 400 : 200)));
            }
        }
        $claims = match ($form['grant_type'] ?? null) {
            'client_credentials' => ['sub' => 'service-account-'.($form['client_id'] ?? '')],
            'password' => ['sub' => $form['username'] ?? '', 'username' => $form['username'] ?? ''],
            'authorization_code' => isset($form['code_verifier'], $form['redirect_uri']) ? self::redeem($this->codes, $form['code'] ?? '') : null,
            'refresh_token' => self::redeem($this->refreshTokens, $form['refresh_token'] ?? ''),
            default => null,
        };
        if (null === $claims || '' === ($form['client_id'] ?? '')) {
            return Http::response(['error' => 'invalid_grant'], 400);
        }

        $claims += ['azp' => $form['client_id']];
        $body = ['access_token' => $this->token($claims), 'token_type' => 'Bearer', 'expires_in' => 300];
        if ('client_credentials' !== $form['grant_type']) {
            $refreshToken = 'refresh-'.bin2hex(random_bytes(8));
            $this->refreshTokens[$refreshToken] = $claims;
            $body += ['refresh_token' => $refreshToken, 'refresh_expires_in' => 1800];
        }

        return Http::response($body);
    }

    /**
     * @param array<string, array<string, mixed>> $issued
     *
     * @return ?array<string, mixed> the claims $value was issued for, which spends it
     */
    private static function redeem(array &$issued, string $value): ?array
    {
        $claims = $issued[$value] ?? null;
        unset($issued[$value]);

        return $claims;
    }
}
