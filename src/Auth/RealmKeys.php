<?php

/**
 * Copyright (c) 2026 Vinh Vo. MIT License.
 */

declare(strict_types=1);

namespace Vinh0809it\KeycloakLaravel\Auth;

use Firebase\JWT\JWK;
use Firebase\JWT\Key;
use Illuminate\Contracts\Cache\LockProvider;
use Illuminate\Contracts\Cache\LockTimeoutException;
use Illuminate\Contracts\Cache\Repository as Cache;
use Illuminate\Http\Client\ConnectionException;
use Illuminate\Http\Client\Factory as Http;
use Vinh0809it\KeycloakLaravel\KeycloakUnavailable;

/**
 * The realm's (or another OpenID provider's) signing keys by `kid`, as php-jwt looks them up:
 * fetched from its JWKS endpoint and kept in the cache store, which every lookup reads, so a key
 * the realm drops stops verifying once the cache expires, in long-lived workers too.
 *
 * A `kid` the cached keys lack has the keys fetched afresh, at most once per
 * {@see REFETCH_INTERVAL} seconds across every process sharing the cache, so a key the realm
 * publishes is picked up at once and tokens with made-up `kid`s cannot make every request call the
 * realm. One process fetches at a time where the store has locks, and a failed fetch is not tried
 * again for {@see OUTAGE_INTERVAL} seconds.
 *
 * Only signing keys (`use` absent or `sig`) of an accepted algorithm are kept: php-jwt binds the
 * token's `alg` to its key's, so a token can only be verified with an algorithm listed here. A key
 * of another OpenID provider that names no `alg` takes the only accepted one, when there is one.
 *
 * @internal
 *
 * @implements \ArrayAccess<string, Key>
 */
final class RealmKeys implements \ArrayAccess
{
    public const REFETCH_INTERVAL = 60;
    public const OUTAGE_INTERVAL = 10;

    /** @var array<string, array<string, mixed>> the keys the last lookup found */
    private array $found = [];
    private ?string $foundKid = null;

    /**
     * @param list<string> $algorithms
     */
    public function __construct(
        private readonly string $realm,
        private readonly array $algorithms,
        private readonly Cache $cache,
        private readonly Http $http,
        private readonly int $ttl = 3600,
        private readonly int $timeout = 5,
        private readonly bool $discovery = false,
    ) {
    }

    /**
     * A Keycloak realm's JWKS endpoint; another OpenID provider's (`$discovery`) is the `jwks_uri` of
     * its discovery document, cached with the keys.
     *
     * @throws KeycloakUnavailable
     */
    public function certsUrl(): string
    {
        if (!$this->discovery) {
            return rtrim($this->realm, '/').'/protocol/openid-connect/certs';
        }

        $jwksUri = $this->cache->get($this->cacheKey().':jwks_uri');
        if (\is_string($jwksUri)) {
            return $jwksUri;
        }
        $url = rtrim($this->realm, '/').'/.well-known/openid-configuration';
        try {
            $jwksUri = $this->http->timeout($this->timeout)->acceptJson()->get($url)->json('jwks_uri');
        } catch (ConnectionException $e) {
            throw new KeycloakUnavailable(\sprintf('The discovery document could not be fetched from %s: %s', $url, $e->getMessage()));
        }
        if (!\is_string($jwksUri) || '' === $jwksUri) {
            throw new KeycloakUnavailable(\sprintf('The discovery document at %s names no jwks_uri.', $url));
        }
        $this->cache->put($this->cacheKey().':jwks_uri', $jwksUri, $this->ttl);

        return $jwksUri;
    }

    public function offsetExists(mixed $offset): bool
    {
        $kid = (string) $offset;
        $keys = $this->cache->get($this->cacheKey());
        if (!\is_array($keys)) {
            $keys = $this->fetch($kid, false);
        } elseif (!isset($keys[$kid]) && $this->cache->add($this->cacheKey().':refetched', true, self::REFETCH_INTERVAL)) {
            $keys = $this->fetch($kid, true);
        }
        /* @var array<string, array<string, mixed>> $keys */
        $this->found = $keys;
        $this->foundKid = isset($keys[$kid]) ? $kid : null;

        return isset($keys[$kid]);
    }

    public function offsetGet(mixed $offset): Key
    {
        // php-jwt asks offsetExists() first: the keys it just read serve the same kid.
        if ((string) $offset !== $this->foundKid && !$this->offsetExists($offset)) {
            throw new InvalidToken(\sprintf('The realm publishes no key "%s".', (string) $offset));
        }

        return JWK::parseKey($this->found[(string) $offset]) ?? throw new KeycloakUnavailable(\sprintf('The realm\'s key "%s" cannot be used.', (string) $offset));
    }

    public function offsetSet(mixed $offset, mixed $value): void
    {
        throw new \LogicException('The realm\'s keys are read-only.');
    }

    public function offsetUnset(mixed $offset): void
    {
        throw new \LogicException('The realm\'s keys are read-only.');
    }

    /**
     * The keys, from the cache when another process fetched them while this one waited for the lock.
     *
     * @param bool $refetch whether keys are cached already, without $kid
     *
     * @return array<string, array<string, mixed>>
     */
    private function fetch(string $kid, bool $refetch): array
    {
        $fetch = function () use ($kid, $refetch): array {
            $cached = $this->cache->get($this->cacheKey());
            if (\is_array($cached) && (!$refetch || isset($cached[$kid]))) {
                /* @var array<string, array<string, mixed>> $cached */
                return $cached;
            }

            return $this->download();
        };

        $store = $this->cache->getStore();
        if (!$store instanceof LockProvider) {
            return $fetch();
        }
        try {
            /* @var array<string, array<string, mixed>> */
            // A discovery issuer's fetch is two requests.
            return $store->lock($this->cacheKey().':lock', ($this->discovery ? 2 : 1) * $this->timeout + 1)->block($this->timeout, $fetch);
        } catch (LockTimeoutException) {
            $cached = $this->cache->get($this->cacheKey());
            if (\is_array($cached)) {
                /* @var array<string, array<string, mixed>> $cached */
                return $cached;
            }

            throw new KeycloakUnavailable(\sprintf('The realm\'s keys are being fetched by another process that has not finished: %s.', $this->realm));
        }
    }

    /** @return array<string, array<string, mixed>> */
    private function download(): array
    {
        if (null !== $this->cache->get($this->cacheKey().':down')) {
            throw new KeycloakUnavailable(\sprintf('The realm\'s keys could not be fetched less than %d seconds ago: %s.', self::OUTAGE_INTERVAL, $this->realm));
        }

        try {
            $certsUrl = $this->certsUrl();
            try {
                $response = $this->http->timeout($this->timeout)->acceptJson()->get($certsUrl);
            } catch (ConnectionException $e) {
                throw new KeycloakUnavailable(\sprintf('The realm\'s keys could not be fetched from %s: %s', $certsUrl, $e->getMessage()));
            }
            if (!$response->successful()) {
                throw new KeycloakUnavailable(\sprintf('The realm\'s keys could not be fetched from %s: HTTP %d.', $certsUrl, $response->status()));
            }

            $only = 1 === \count($this->algorithms) && $this->discovery ? $this->algorithms[0] : null;
            $keys = [];
            foreach ((array) $response->json('keys', []) as $jwk) {
                if (!\is_array($jwk) || !isset($jwk['kid']) || 'sig' !== ($jwk['use'] ?? 'sig')) {
                    continue;
                }
                $jwk['alg'] ??= $only;
                if (\in_array($jwk['alg'], $this->algorithms, true)) {
                    $keys[(string) $jwk['kid']] = $jwk;
                }
            }
            if ([] === $keys) {
                throw new KeycloakUnavailable(\sprintf('The realm publishes no signing key for %s at %s.', implode(', ', $this->algorithms), $certsUrl));
            }
        } catch (KeycloakUnavailable $e) {
            $this->cache->put($this->cacheKey().':down', true, self::OUTAGE_INTERVAL);

            throw $e;
        }

        $this->cache->put($this->cacheKey(), $keys, $this->ttl);

        return $keys;
    }

    /** Forgets the cached keys and discovery, as a realm's fake does between tests. */
    public function forget(): void
    {
        foreach (['', ':jwks_uri', ':refetched', ':down'] as $suffix) {
            $this->cache->forget($this->cacheKey().$suffix);
        }
    }

    private function cacheKey(): string
    {
        return 'keycloak:keys:'.hash('xxh128', $this->realm);
    }
}
