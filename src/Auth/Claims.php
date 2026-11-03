<?php

/**
 * Copyright (c) 2026 Vinh Vo. MIT License.
 */

declare(strict_types=1);

namespace Vinh0809it\KeycloakLaravel\Auth;

use Symfony\Component\HttpFoundation\Request;

/**
 * The verified claims of a Keycloak access token: the standard ones typed, the rest reachable by
 * name.
 *
 * `realm` is the name under `keycloak.realms` of the realm that issued it. `client` is the token's
 * `azp`, the Keycloak client it was minted for, which Keycloak sets from the authenticated client: a
 * caller cannot claim to be another one; a client id is unique only within its realm.
 */
final readonly class Claims
{
    /**
     * @param list<string>                $audience    `aud`, one entry per audience whether the token carried a string or a list
     * @param list<string>                $realmRoles  `realm_access.roles`
     * @param array<string, list<string>> $clientRoles `resource_access.<client>.roles`, keyed by client
     * @param array<string, mixed>        $all         every claim as received
     */
    private function __construct(
        public string $sub,
        public string $realm,
        public string $issuer,
        public ?string $client,
        public array $audience,
        public array $realmRoles,
        public array $clientRoles,
        public array $all,
    ) {
    }

    /** The claims of the token a `keycloak` guard authenticated $request with, if one did. */
    public static function of(Request $request): ?self
    {
        $claims = $request->attributes->get(self::class);

        return $claims instanceof self ? $claims : null;
    }

    /**
     * @param array<string, mixed> $claims a token's claims, its `sub` and `iss` already checked
     * @param string               $realm  the name of the realm that issued it
     */
    public static function fromArray(array $claims, string $realm): self
    {
        $clientRoles = [];
        foreach ((array) ($claims['resource_access'] ?? []) as $client => $access) {
            $clientRoles[(string) $client] = self::strings((array) ($access['roles'] ?? []));
        }

        return new self(
            (string) $claims['sub'],
            $realm,
            (string) $claims['iss'],
            self::scalarString($claims['azp'] ?? null),
            self::strings((array) ($claims['aud'] ?? [])),
            self::strings((array) ($claims['realm_access']['roles'] ?? [])),
            $clientRoles,
            $claims,
        );
    }

    public function has(string $claim): bool
    {
        return \array_key_exists($claim, $this->all);
    }

    public function get(string $claim): mixed
    {
        return $this->all[$claim] ?? null;
    }

    /**
     * A claim the user cannot be built without; its absence refuses the token.
     */
    public function string(string $claim): string
    {
        return $this->stringOrNull($claim) ?? throw new InvalidToken(\sprintf('The token carries no "%s" claim.', $claim));
    }

    public function stringOrNull(string $claim): ?string
    {
        return self::scalarString($this->all[$claim] ?? null);
    }

    /**
     * @return list<string>
     */
    public function list(string $claim): array
    {
        return self::strings((array) ($this->all[$claim] ?? []));
    }

    /** A realm role, or $client's role when $client is given. */
    public function hasRole(string $role, ?string $client = null): bool
    {
        return \in_array($role, null !== $client ? $this->clientRoles[$client] ?? [] : $this->realmRoles, true);
    }

    private static function scalarString(mixed $value): ?string
    {
        return \is_scalar($value) && '' !== (string) $value ? (string) $value : null;
    }

    /**
     * @param array<mixed> $values
     *
     * @return list<string>
     */
    private static function strings(array $values): array
    {
        $strings = [];
        foreach ($values as $value) {
            if (\is_scalar($value)) {
                $strings[] = (string) $value;
            }
        }

        return $strings;
    }
}
