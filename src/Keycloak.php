<?php

/**
 * Copyright (c) 2026 Vinh Vo. MIT License.
 */

declare(strict_types=1);

namespace Vinh0809it\KeycloakLaravel;

use Illuminate\Contracts\Cache\Factory as CacheFactory;
use Illuminate\Contracts\Cache\Repository as Cache;
use Illuminate\Http\Client\Factory as Http;
use Illuminate\Support\Carbon;
use Vinh0809it\KeycloakLaravel\Auth\RealmKeys;
use Vinh0809it\KeycloakLaravel\Client\KeycloakClient;
use Vinh0809it\KeycloakLaravel\Client\ServiceToken;
use Vinh0809it\KeycloakLaravel\Browser\BrowserLogin;
use Vinh0809it\KeycloakLaravel\Browser\CookieOptions;
use Vinh0809it\KeycloakLaravel\Browser\SessionCookies;

/**
 * The realms, clients and session cookies declared in config/keycloak.php, built on first use:
 *
 *     $keycloak->client('web')->refresh($refreshToken);
 *     $keycloak->serviceToken('service')->get();
 *     $keycloak->login('web')->start($callbackUrl);
 *     $keycloak->sessionCookies()->set($response, $tokens);
 *
 * @phpstan-type RealmConfig array{url: ?string, issuer?: ?string}
 * @phpstan-type CookieConfig array{name?: ?string, path?: string, domain?: ?string, same_site?: string, session_lifetime?: ?int}
 * @phpstan-type ClientConfig array{realm?: ?string, id?: ?string, secret?: ?string, return_origins?: list<string>, login_cookie?: array{name?: ?string, path?: string, domain?: ?string}}
 * @phpstan-type Config array{realms: array<string, RealmConfig>, dev_tokens?: array<string, array<string, mixed>>, algorithms?: list<string>, cache?: array{store?: ?string, ttl?: int}, http_timeout?: int, cookies?: array{access?: CookieConfig, refresh?: CookieConfig}, clients?: array<string, ClientConfig>}
 */
final class Keycloak
{
    /** @var array<string, ?Realm> */
    private array $realms = [];
    /** @var array<string, KeycloakClient> */
    private array $clients = [];
    /** @var array<string, ServiceToken> */
    private array $serviceTokens = [];

    /**
     * @param Config $config
     */
    public function __construct(
        private readonly array $config,
        private readonly Http $http,
        private readonly CacheFactory $cache,
        #[\SensitiveParameter]
        private readonly string $appKey,
    ) {
    }

    /**
     * The realm $name names, or the only one declared when $name is null.
     */
    public function realm(?string $name = null): Realm
    {
        $realm = $this->configuredRealm($name);
        if (null === $realm) {
            throw new \LogicException(\sprintf('keycloak.realms.%s.url is not configured.', $this->realmName($name)));
        }

        return $realm;
    }

    /**
     * @internal
     *
     * The realm $name names, or the only one declared when $name is null; null when its URL is empty
     * (its env var unset, as in a development setup living on dev tokens): it takes no token
     */
    public function configuredRealm(?string $name = null): ?Realm
    {
        $name = $this->realmName($name);
        $realm = $this->config['realms'][$name];

        return $this->realms[$name] ??= $this->provider($name, (string) ($realm['url'] ?? ''), $realm['issuer'] ?? null, false);
    }

    /**
     * @internal
     *
     * $name when keycloak.realms declares it, or the only realm declared when $name is null.
     */
    public function realmName(?string $name = null): string
    {
        $name ??= 1 === \count($this->config['realms']) ? (string) array_key_first($this->config['realms'])
            : throw new \LogicException('Several realms are declared under keycloak.realms: name one.');

        return isset($this->config['realms'][$name]) ? $name : throw new \LogicException(\sprintf('keycloak.realms declares no realm "%s".', $name));
    }

    /**
     * @internal
     *
     * An OpenID provider other than the realms, its keys found through its discovery document. Its
     * tokens' realm name is its issuer. Null when $url is empty: it takes no token.
     */
    public function otherIssuer(string $url, ?string $issuer = null): ?Realm
    {
        $issuer = '' !== (string) $issuer ? (string) $issuer : rtrim($url, '/');

        return $this->realms['issuer:'.$url.'|'.$issuer] ??= $this->provider($issuer, $url, $issuer, true);
    }

    /**
     * @internal
     *
     * Bearers for development => the claims they stand for. A bearer with `{name}` placeholders
     * matches any text in their place, which sets claim `name`.
     *
     * @return array<string, array<string, mixed>>
     */
    public function devTokens(): array
    {
        return $this->config['dev_tokens'] ?? [];
    }

    private function provider(string $name, string $url, ?string $issuer, bool $discovery): ?Realm
    {
        if ('' === $url) {
            return null;
        }

        return new Realm($name, $url, $issuer, new RealmKeys(
            $url,
            $this->config['algorithms'] ?? ['RS256'],
            $this->cacheStore(),
            $this->http,
            $this->config['cache']['ttl'] ?? 3600,
            $this->timeout(),
            $discovery,
        ), !$discovery);
    }

    public function client(string $name): KeycloakClient
    {
        if (isset($this->clients[$name])) {
            return $this->clients[$name];
        }
        $client = $this->clientConfig($name);
        $realm = $this->realm($client['realm'] ?? null);

        return $this->clients[$name] = new KeycloakClient($this->http, $realm->url, $client['id'] ?? $name, $client['secret'] ?? null, $realm->issuer, $this->timeout());
    }

    /** The client-credentials token of a confidential client, shared through the cache store. */
    public function serviceToken(string $name): ServiceToken
    {
        if (null === ($this->clientConfig($name)['secret'] ?? null)) {
            throw new \LogicException(\sprintf('keycloak.clients.%s has no secret: a public client has no service account.', $name));
        }

        return $this->serviceTokens[$name] ??= new ServiceToken($this->client($name), $this->cacheStore());
    }

    public function login(string $name): BrowserLogin
    {
        if ('' === $this->appKey) {
            throw new \LogicException('A browser login signs its cookie with app.key, which is not set.');
        }
        $client = $this->clientConfig($name);
        $cookie = $client['login_cookie'] ?? [];

        return new BrowserLogin(
            $this->client($name),
            new CookieOptions($cookie['name'] ?? 'keycloak_login_'.$name, $cookie['path'] ?? '/', $cookie['domain'] ?? null, 'lax'),
            $this->appKey,
            $client['return_origins'] ?? [],
            static fn (): int => Carbon::now()->getTimestamp(),
        );
    }

    /** A backend-for-frontend's session, kept in the browser's cookies: nothing is stored here. */
    public function sessionCookies(): SessionCookies
    {
        $access = $this->config['cookies']['access'] ?? [];
        $refresh = $this->config['cookies']['refresh'] ?? [];
        if ('' === (string) ($access['name'] ?? '')) {
            throw new \LogicException('keycloak.cookies.access.name is not configured.');
        }
        if ('' !== (string) ($refresh['name'] ?? '') && '' === (string) ($refresh['path'] ?? '')) {
            throw new \LogicException('keycloak.cookies.refresh.path is not configured: only the routes that refresh and end the session should receive the refresh token.');
        }

        return new SessionCookies(
            self::cookie($access, 'lax'),
            '' !== (string) ($refresh['name'] ?? '') ? self::cookie($refresh, 'strict') : null,
            \array_key_exists('session_lifetime', $refresh) ? $refresh['session_lifetime'] : 1209600,
        );
    }

    /**
     * @internal
     *
     * @param array{cookies?: array{access?: array{name?: ?string}, refresh?: array{name?: ?string}}, clients?: array<string, array{login_cookie?: array{name?: ?string}}>} $config
     *
     * @return list<string> the names of the cookies the session and the browser logins set
     */
    public static function cookieNames(array $config): array
    {
        $names = [
            $config['cookies']['access']['name'] ?? null,
            $config['cookies']['refresh']['name'] ?? null,
        ];
        foreach ($config['clients'] ?? [] as $name => $client) {
            $names[] = $client['login_cookie']['name'] ?? 'keycloak_login_'.$name;
        }

        return array_values(array_filter(array_map('strval', $names), static fn (string $name): bool => '' !== $name));
    }

    /** @return ClientConfig */
    private function clientConfig(string $name): array
    {
        return $this->config['clients'][$name] ?? throw new \LogicException(\sprintf('keycloak.clients declares no client "%s".', $name));
    }

    private function cacheStore(): Cache
    {
        return $this->cache->store($this->config['cache']['store'] ?? null);
    }

    private function timeout(): int
    {
        return $this->config['http_timeout'] ?? 5;
    }

    /** @param CookieConfig $cookie */
    private static function cookie(array $cookie, string $sameSite): CookieOptions
    {
        return new CookieOptions((string) $cookie['name'], $cookie['path'] ?? '/', $cookie['domain'] ?? null, $cookie['same_site'] ?? $sameSite);
    }
}
