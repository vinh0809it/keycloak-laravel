<?php

/**
 * Copyright (c) 2026 Vinh Vo. MIT License.
 */

declare(strict_types=1);

namespace Vinh0809it\KeycloakLaravel\Client;

use Illuminate\Contracts\Cache\Repository as Cache;
use Vinh0809it\KeycloakLaravel\KeycloakException;

/**
 * A confidential client's client-credentials token, kept in the cache store until
 * {@see EXPIRY_MARGIN} seconds before it expires, so every request and worker sharing the store
 * shares one token.
 */
final class ServiceToken
{
    public const EXPIRY_MARGIN = 30;

    /** @var ?array{string, int} the token and when it expires, as last read or minted */
    private ?array $token = null;

    public function __construct(
        private readonly KeycloakClient $client,
        private readonly Cache $cache,
    ) {
    }

    /**
     * @throws KeycloakException
     *
     * @phpstan-impure
     */
    public function get(): string
    {
        $now = time();
        if (null !== $this->token && $now < $this->token[1] - self::EXPIRY_MARGIN) {
            return $this->token[0];
        }

        $cached = $this->cache->get($this->cacheKey());
        if (\is_array($cached) && \is_string($cached[0] ?? null) && \is_int($cached[1] ?? null) && $now < $cached[1] - self::EXPIRY_MARGIN) {
            return ($this->token = [$cached[0], $cached[1]])[0];
        }

        $tokens = $this->client->clientCredentials();
        $this->token = [$tokens->accessToken, $now + $tokens->expiresIn];
        $this->cache->put($this->cacheKey(), $this->token, max(1, $tokens->expiresIn - self::EXPIRY_MARGIN));

        return $this->token[0];
    }

    /**
     * Drops the token, so the next {@see get()} mints another: for a token a downstream service
     * refused before it expired.
     */
    public function forget(): void
    {
        $this->token = null;
        $this->cache->forget($this->cacheKey());
    }

    /** One per realm and client id, whatever the client's name in the config. */
    private function cacheKey(): string
    {
        return 'keycloak:service_token:'.hash('xxh128', $this->client->issuer().'|'.$this->client->clientId);
    }
}
