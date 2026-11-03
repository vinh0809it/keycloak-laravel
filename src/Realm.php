<?php

/**
 * Copyright (c) 2026 Vinh Vo. MIT License.
 */

declare(strict_types=1);

namespace Vinh0809it\KeycloakLaravel;

use Vinh0809it\KeycloakLaravel\Auth\RealmKeys;

/**
 * One realm under `keycloak.realms`, or one of a guard's other OpenID providers: where this app
 * reaches it, the `iss` its tokens carry (also where a browser reaches it), and its signing keys.
 */
final readonly class Realm
{
    public string $url;
    public string $issuer;

    /**
     * @internal built by {@see Keycloak}
     */
    public function __construct(
        public string $name,
        string $url,
        ?string $issuer,
        public RealmKeys $keys,
        public bool $keycloak = true,
    ) {
        $this->url = rtrim($url, '/');
        $this->issuer = '' !== (string) $issuer ? (string) $issuer : $this->url;
    }
}
