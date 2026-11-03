<?php

/**
 * Copyright (c) 2026 Vinh Vo. MIT License.
 */

declare(strict_types=1);

namespace Vinh0809it\KeycloakLaravel\Auth;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Container\Container;
use Illuminate\Http\Request;
use Psr\Log\LoggerInterface;
use Vinh0809it\KeycloakLaravel\Keycloak;
use Vinh0809it\KeycloakLaravel\Realm;

/**
 * One `keycloak` guard's user for a request, as its RequestGuard asks for it: the token from the
 * `Authorization: Bearer` header, else the guard's cookie; verified against the guard's realms; then
 * resolved.
 *
 * A token of a realm under `by_realm` is resolved among that realm's entry alone: its `by_client`
 * by the token's `azp`, else its `resolver`; a token of an other issuer by that issuer's resolver.
 * Any other token: the guard's `by_client`, else its `resolver`. A token none of them claims is
 * refused. A dev token ({@see DevTokens}) skips the verification, not the resolution. The claims of
 * the token that authenticated the request are kept on it: {@see Claims::of()}.
 *
 * @phpstan-type Resolvers array{resolver?: ?class-string<ClaimsResolver>, by_client?: array<string, class-string<ClaimsResolver>>}
 * @phpstan-type GuardConfig array{realms?: list<string>, other_issuers?: list<array{url?: ?string, issuer?: ?string, resolver: class-string<ClaimsResolver>}>, audience?: ?string, cookie?: bool, resolver?: ?class-string<ClaimsResolver>, by_client?: array<string, class-string<ClaimsResolver>>, by_realm?: array<string, class-string<ClaimsResolver>|Resolvers>}
 *
 * @internal
 */
final readonly class KeycloakGuard
{
    /**
     * @param GuardConfig $config the guard's, from config/auth.php
     */
    public function __construct(
        private Container $container,
        private string $name,
        private array $config,
    ) {
    }

    public function __invoke(Request $request): ?Authenticatable
    {
        $token = $request->bearerToken() ?? (null !== ($cookie = $this->cookie()) ? $request->cookie($cookie) : null);
        if (!\is_string($token) || '' === $token) {
            return null;
        }

        /** @var Keycloak $keycloak */
        $keycloak = $this->container->make(Keycloak::class);
        $audience = (string) ($this->config['audience'] ?? $this->container->make('config')->get('keycloak.audience'));
        $names = array_map($keycloak->realmName(...), $this->config['realms'] ?? [null]);
        $realms = array_values(array_filter(array_map($keycloak->configuredRealm(...), $names)));
        $others = [];
        foreach ($this->config['other_issuers'] ?? [] as $provider) {
            if (null !== $issuer = $keycloak->otherIssuer((string) ($provider['url'] ?? ''), $provider['issuer'] ?? null)) {
                $realms[] = $issuer;
                $others[$issuer->name] = $provider['resolver'];
            }
        }

        try {
            $claims = $this->devClaims($keycloak, $token, $names, $realms)
                ?? $this->container->make(TokenVerifier::class)->verify($token, $audience, $realms);

            /** @var ClaimsResolver $resolver */
            $resolver = $this->container->make($this->resolverOf($claims, $others));
            $user = $resolver->resolve($claims);
            if (null !== $user) {
                $request->attributes->set(Claims::class, $claims);
            }

            return $user;
        } catch (InvalidToken $e) {
            $this->container->make(LoggerInterface::class)->debug('The keycloak guard "{guard}" refused a token: {reason}', ['guard' => $this->name, 'reason' => $e->getMessage()]);

            return null;
        }
    }

    /**
     * The claims of a dev token, of the guard's realm its `iss` names, else of the guard's first.
     *
     * @param list<string> $names  the guard's realms
     * @param list<Realm>  $realms the guard's configured realms and other issuers
     */
    private function devClaims(Keycloak $keycloak, #[\SensitiveParameter] string $token, array $names, array $realms): ?Claims
    {
        $claims = (new DevTokens($keycloak->devTokens()))->claims($token);
        if (null === $claims) {
            return null;
        }

        $realm = null;
        foreach ($realms as $candidate) {
            if (($claims['iss'] ?? null) === $candidate->issuer) {
                $realm = $candidate;
                break;
            }
        }
        $realm ??= $keycloak->configuredRealm($names[0]);

        return Claims::fromArray($claims + ['iss' => $realm->issuer ?? ''], $realm->name ?? $names[0]);
    }

    /**
     * @param array<string, class-string<ClaimsResolver>> $others the other issuers' resolvers by their realm name
     *
     * @return class-string<ClaimsResolver>
     */
    private function resolverOf(Claims $claims, array $others): string
    {
        $resolvers = $this->config;
        $entry = $this->config['by_realm'][$claims->realm] ?? $others[$claims->realm] ?? null;
        if (null !== $entry) {
            $resolvers = \is_string($entry) ? ['resolver' => $entry] : $entry;
        }

        return (null !== $claims->client ? $resolvers['by_client'][$claims->client] ?? null : null)
            ?? $resolvers['resolver']
            ?? throw new InvalidToken(\sprintf('No resolver for tokens of client "%s" of realm "%s".', $claims->client ?? '', $claims->realm));
    }

    private function cookie(): ?string
    {
        return true === ($this->config['cookie'] ?? false) ? (string) $this->container->make('config')->get('keycloak.cookies.access.name') : null;
    }

    /**
     * Fails a `keycloak` guard the app could not serve when it is first built, whatever the request,
     * rather than on a request that carries a token.
     *
     * @param array<string, mixed> $config   the guard's
     * @param array<string, mixed> $keycloak config/keycloak.php
     *
     * @throws \LogicException
     */
    public static function assertConfigured(string $name, array $config, array $keycloak): void
    {
        $fail = static fn (string $problem): \LogicException => new \LogicException(\sprintf('auth.guards.%s: %s', $name, $problem));
        $declared = array_map('strval', array_keys((array) ($keycloak['realms'] ?? [])));

        if ('' === (string) ($config['audience'] ?? $keycloak['audience'] ?? '')) {
            throw $fail('it needs an "audience", or keycloak.audience one.');
        }
        $realms = $config['realms'] ?? null;
        if (null === $realms && 1 !== \count($declared)) {
            throw $fail('it must name its "realms": keycloak.realms declares '.([] === $declared ? 'none.' : 'several.'));
        }
        foreach ((array) ($realms ?? []) as $realm) {
            if (!\in_array($realm, $declared, true)) {
                throw $fail(\sprintf('"realms" names "%s", which keycloak.realms does not declare.', (string) $realm));
            }
        }
        foreach (array_keys((array) ($config['by_realm'] ?? [])) as $realm) {
            if (!\in_array($realm, (array) ($realms ?? $declared), true)) {
                throw $fail(\sprintf('"by_realm" names "%s", which is not one of its realms.', $realm));
            }
        }
        foreach ((array) ($config['other_issuers'] ?? []) as $i => $provider) {
            if (!\is_array($provider) || '' === (string) ($provider['resolver'] ?? '')) {
                throw $fail(\sprintf('"other_issuers" entry %s needs a "resolver".', (string) $i));
            }
        }
        if (!\is_bool($config['cookie'] ?? false)) {
            throw $fail('"cookie" is true (read keycloak.cookies.access) or false.');
        }
        if (null === ($config['resolver'] ?? null) && [] === ($config['by_client'] ?? []) && [] === ($config['by_realm'] ?? []) && [] === ($config['other_issuers'] ?? [])) {
            throw $fail('it needs a "resolver", or entries under "by_client", "by_realm" or "other_issuers".');
        }
    }
}
