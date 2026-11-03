<?php

/**
 * Copyright (c) 2026 Vinh Vo. MIT License.
 */

declare(strict_types=1);

namespace Vinh0809it\KeycloakLaravel\Auth;

use Firebase\JWT\JWT;
use Vinh0809it\KeycloakLaravel\KeycloakUnavailable;
use Vinh0809it\KeycloakLaravel\Realm;

/**
 * Verifies an access token of one of the accepted realms. The realm is the one whose issuer the
 * token names in `iss`, and only that realm's keys verify it, so a token cannot name one realm and
 * be signed with another's key. php-jwt checks the signature, `nbf`, `iat` and `exp`; this then
 * requires what php-jwt leaves optional: an `exp`, a `sub`, and the audience among `aud`. A realm's
 * ID and logout tokens (`typ` other than `Bearer`), signed with the same keys, are refused.
 *
 * @internal
 */
final readonly class TokenVerifier
{
    public function __construct(private int $leeway = 0)
    {
    }

    /**
     * @param list<Realm> $realms the realms whose tokens are accepted
     *
     * @throws InvalidToken        the token is not one this audience may accept
     * @throws KeycloakUnavailable the realm's keys could not be fetched
     */
    public function verify(string $token, string $audience, array $realms): Claims
    {
        $issuer = self::unverifiedIssuer($token);
        $realm = null;
        foreach ($realms as $candidate) {
            if ($candidate->issuer === $issuer) {
                $realm = $candidate;
                break;
            }
        }
        if (null === $realm) {
            throw new InvalidToken(\sprintf('The token\'s issuer "%s" is not an accepted realm.', $issuer ?? ''));
        }

        JWT::$leeway = $this->leeway;
        try {
            $payload = JWT::decode($token, $realm->keys);
        } catch (\UnexpectedValueException|\DomainException|\InvalidArgumentException $e) {
            throw new InvalidToken($e->getMessage(), 0, $e);
        }

        /** @var array<string, mixed> $claims */
        $claims = json_decode((string) json_encode($payload), true);

        if (!isset($claims['exp']) || !is_numeric($claims['exp'])) {
            throw new InvalidToken('The token carries no "exp".');
        }
        if (!\is_string($claims['sub'] ?? null) || '' === $claims['sub']) {
            throw new InvalidToken('The token carries no "sub".');
        }
        if (($claims['iss'] ?? null) !== $realm->issuer) {
            throw new InvalidToken(\sprintf('The token\'s issuer is not "%s".', $realm->issuer));
        }
        if ($realm->keycloak && isset($claims['typ']) && (!\is_string($claims['typ']) || 0 !== strcasecmp($claims['typ'], 'Bearer'))) {
            throw new InvalidToken(\sprintf('A "%s" token is not an access token.', \is_scalar($claims['typ']) ? $claims['typ'] : get_debug_type($claims['typ'])));
        }
        if (!\in_array($audience, (array) ($claims['aud'] ?? []), true)) {
            throw new InvalidToken(\sprintf('The token is not for the audience "%s".', $audience));
        }

        return Claims::fromArray($claims, $realm->name);
    }

    /** The `iss` a token names, before anything about it is verified. */
    private static function unverifiedIssuer(string $token): ?string
    {
        $parts = explode('.', $token);
        if (3 !== \count($parts)) {
            return null;
        }
        $claims = json_decode(JWT::urlsafeB64Decode($parts[1]), true);

        return \is_array($claims) && \is_string($claims['iss'] ?? null) ? $claims['iss'] : null;
    }
}
