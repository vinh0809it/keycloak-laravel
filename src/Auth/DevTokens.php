<?php

/**
 * Copyright (c) 2026 Vinh Vo. MIT License.
 */

declare(strict_types=1);

namespace Vinh0809it\KeycloakLaravel\Auth;

/**
 * Configured bearers for local development, ahead of the real verification: a configured token
 * (`member.1`), or one matching a configured pattern (`{azp}~{sub}` takes `mobile-app~42`), stands
 * for its configured claims, resolved through the same resolvers as a real token. Anything else is
 * verified as usual, so a signed token keeps working beside them.
 *
 * Refused outside development: {@see assertAllowed()} fails the app's boot when they are set in an
 * environment other than `local` and `testing`, or with debug off.
 *
 * @internal
 */
final readonly class DevTokens
{
    /** The environments dev tokens may be set in. */
    public const ENVIRONMENTS = ['local', 'testing'];

    /**
     * @param array<string, array<string, mixed>> $tokens bearer => claims; `sub` defaults to the bearer
     */
    public function __construct(private array $tokens)
    {
    }

    /**
     * The claims $token stands for, `sub` included, or null when it is no dev token.
     *
     * @return ?array<string, mixed>
     */
    public function claims(#[\SensitiveParameter] string $token): ?array
    {
        $claims = $this->tokens[$token] ?? $this->matchPattern($token);

        return null !== $claims ? $claims + ['sub' => $token] : null;
    }

    /**
     * @param array<string, mixed> $tokens
     *
     * @throws \LogicException dev tokens outside local and testing or with debug off, or a pattern that is unsafe or malformed
     */
    public static function assertAllowed(array $tokens, string $environment, bool $debug): void
    {
        if ([] === $tokens) {
            return;
        }
        if (!\in_array($environment, self::ENVIRONMENTS, true) || !$debug) {
            throw new \LogicException(\sprintf('keycloak.dev_tokens can only be set in the %s environments, with debug on.', implode(' and ', self::ENVIRONMENTS)));
        }
        foreach ($tokens as $token => $claims) {
            $token = (string) $token;
            if (!\is_array($claims)) {
                throw new \LogicException(\sprintf('keycloak.dev_tokens."%s" stands for a map of claims.', $token));
            }
            $placeholders = self::placeholders($token);
            foreach ($placeholders as $placeholder) {
                if (1 !== preg_match('/^[A-Za-z_]\w{0,31}$/', $placeholder)) {
                    throw new \LogicException(\sprintf('keycloak.dev_tokens."%s": a placeholder is a claim name of at most 32 letters, digits and "_", not starting with a digit.', $token));
                }
            }
            if (\count($placeholders) !== \count(array_unique($placeholders))) {
                throw new \LogicException(\sprintf('keycloak.dev_tokens."%s" names a placeholder twice.', $token));
            }
            if ([] !== $placeholders && 1 !== preg_match('/[^A-Za-z0-9_.\-]/', (string) preg_replace('/\{\w+\}/', '', $token))) {
                throw new \LogicException(\sprintf('keycloak.dev_tokens."%s": a pattern needs a character a JWT never holds outside its placeholders (anything but letters, digits, "-", "_" and "."), e.g. "{azp}~{sub}", or it could take a real token.', $token));
            }
        }
    }

    /** @return list<string> the names of the `{name}` placeholders in $token, in order */
    private static function placeholders(string $token): array
    {
        preg_match_all('/\{(\w+)\}/', $token, $matches);

        return $matches[1];
    }

    /** @return ?array<string, mixed> the claims of the first pattern $token matches, its placeholders' text included */
    private function matchPattern(string $token): ?array
    {
        foreach ($this->tokens as $pattern => $claims) {
            $pattern = (string) $pattern;
            if ([] === self::placeholders($pattern)) {
                continue;
            }
            $parts = preg_split('/\{(\w+)\}/', $pattern, -1, \PREG_SPLIT_DELIM_CAPTURE) ?: [];
            $regex = '';
            foreach ($parts as $i => $part) {
                $regex .= 0 === $i % 2 ? preg_quote($part, '/') : '(?P<'.$part.'>.+?)';
            }
            if (1 === preg_match('/^'.$regex.'$/', $token, $match)) {
                return array_filter($match, 'is_string', \ARRAY_FILTER_USE_KEY) + $claims;
            }
        }

        return null;
    }
}
