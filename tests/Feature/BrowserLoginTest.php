<?php

/**
 * Copyright (c) 2026 Vinh Vo. MIT License.
 */

declare(strict_types=1);

namespace Vinh0809it\KeycloakLaravel\Tests\Feature;

use Illuminate\Cookie\Middleware\EncryptCookies;
use PHPUnit\Framework\Attributes\DataProvider;
use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Vinh0809it\KeycloakLaravel\Client\RequestRefused;
use Vinh0809it\KeycloakLaravel\Client\TokenSet;
use Vinh0809it\KeycloakLaravel\Keycloak;
use Vinh0809it\KeycloakLaravel\Browser\BrowserLogin;
use Vinh0809it\KeycloakLaravel\Browser\LoginFailed;
use Vinh0809it\KeycloakLaravel\Tests\TestCase;

final class BrowserLoginTest extends TestCase
{
    private const CALLBACK = 'https://app.test/callback';

    private BrowserLogin $login;

    protected function setUp(): void
    {
        parent::setUp();
        $this->app['config']->set('keycloak.clients.web', [
            'id' => 'web-app',
            'secret' => 'web-secret',
            'return_origins' => ['https://web.example.com', 'https://*.apps.example.com'],
            'login_cookie' => ['name' => 'kc_login'],
        ]);
        $this->app['config']->set('keycloak.cookies', [
            'access' => ['name' => 'app_at', 'domain' => 'example.com'],
            'refresh' => ['name' => 'app_rt', 'path' => '/auth'],
        ]);
        $this->app->forgetInstance(Keycloak::class);
        $this->login = $this->app->make(Keycloak::class)->login('web');
    }

    public function testStartRedirectsToTheRealmWithStateAndPkceKeptInALoginCookie(): void
    {
        $redirect = $this->login->start(self::CALLBACK, '/orders', ['login_hint' => 'user@example.com']);
        $query = self::authorizationQuery($redirect);

        self::assertStringStartsWith($this->realm->issuer.'/protocol/openid-connect/auth?', $redirect->getTargetUrl());
        self::assertSame(['web-app', self::CALLBACK, 'S256', 'user@example.com'], [$query['client_id'], $query['redirect_uri'], $query['code_challenge_method'], $query['login_hint']]);
        self::assertGreaterThanOrEqual(43, \strlen($query['state']));

        $cookie = self::cookie($redirect);
        self::assertSame('kc_login', $cookie->getName());
        self::assertTrue($cookie->isHttpOnly() && $cookie->isSecure());
        self::assertSame('lax', $cookie->getSameSite());
        self::assertSame($query['code_challenge'], rtrim(strtr(base64_encode(hash('sha256', self::login($redirect)['verifier'], true)), '+/', '-_'), '='), 'the challenge is the kept verifier\'s');
    }

    public function testTheCallbackOfThisBrowsersLoginExchangesTheCodeWithItsVerifier(): void
    {
        $redirect = $this->login->start(self::CALLBACK, '/orders');

        $done = $this->login->finish($this->callbackOf($redirect, ['code' => $this->realm->code(['sub' => 'alice']), 'iss' => $this->realm->issuer]));

        self::assertSame('/orders', $done->returnTo);
        self::assertNotNull($done->tokens->refreshToken);
        $exchange = array_slice($this->realm->requests(), -1)[0]['form'];
        self::assertSame([self::login($redirect)['verifier'], self::CALLBACK, 'web-app', 'web-secret'], [$exchange['code_verifier'], $exchange['redirect_uri'], $exchange['client_id'], $exchange['client_secret']]);
    }

    public function testAStateThatIsNotTheLoginsOwnIsRefusedAndItsCodeSpent(): void
    {
        $redirect = $this->login->start(self::CALLBACK);
        $code = $this->realm->code();

        try {
            $this->login->finish($this->callbackOf($redirect, ['code' => $code, 'state' => 'forged']));
            self::fail('A forged state was accepted.');
        } catch (LoginFailed $e) {
            self::assertStringContainsString('state', $e->getMessage());
        }

        $exchanges = array_values(array_filter($this->realm->requests(), static fn (array $request): bool => 'authorization_code' === ($request['form']['grant_type'] ?? null)));
        self::assertCount(1, $exchanges);
        self::assertSame($code, $exchanges[0]['form']['code']);
        self::assertNotSame(self::login($redirect)['verifier'], $exchanges[0]['form']['code_verifier'], 'with a verifier the login never had');
        $this->expectException(RequestRefused::class);
        $this->app->make(Keycloak::class)->client('web')->exchangeCode($code, self::CALLBACK, self::login($redirect)['verifier']);
    }

    public function testACallbackWithNoLoginInProgressHasItsCodeSpentToo(): void
    {
        $code = $this->realm->code();
        try {
            $this->login->finish(Request::create(self::CALLBACK, 'GET', ['state' => 's', 'code' => $code]));
            self::fail('A callback without a login was accepted.');
        } catch (LoginFailed $e) {
            self::assertStringContainsString('no login in progress', $e->getMessage());
        }

        self::assertSame([$code], array_column(array_column($this->realm->requests(), 'form'), 'code'));
    }

    public function testAnotherIssuersCallbackIsRefused(): void
    {
        $this->expectException(LoginFailed::class);

        $this->login->finish($this->callbackOf($this->login->start(self::CALLBACK), ['code' => $this->realm->code(), 'iss' => 'https://elsewhere.test']));
    }

    public function testALoginTheRealmEndedCarriesItsError(): void
    {
        try {
            $this->login->finish($this->callbackOf($this->login->start(self::CALLBACK, '/orders'), ['error' => 'access_denied', 'error_description' => 'The user said no']));
            self::fail('An ended login was completed.');
        } catch (LoginFailed $e) {
            self::assertSame(['access_denied', '/orders'], [$e->error, $e->returnTo]);
            self::assertStringContainsString('The user said no', $e->getMessage());
        }
    }

    public function testATamperedLoginCookieIsRefused(): void
    {
        $request = $this->callbackOf($this->login->start(self::CALLBACK, '/orders'), ['code' => $this->realm->code()]);
        [$payload, $signature] = explode('.', (string) $request->cookies->get('kc_login'));
        $login = json_decode((string) base64_decode(strtr($payload, '-_', '+/')), true);
        $login['return_to'] = 'https://evil.test';
        $request->cookies->set('kc_login', rtrim(strtr(base64_encode((string) json_encode($login)), '+/', '-_'), '=').'.'.$signature);

        $this->expectException(LoginFailed::class);
        $this->login->finish($request);
    }

    public function testAnExpiredLoginIsRefused(): void
    {
        $request = $this->callbackOf($this->login->start(self::CALLBACK), ['code' => $this->realm->code()]);
        $this->travel(BrowserLogin::LIFETIME + 1)->seconds();

        $this->expectExceptionMessage('expired');
        $this->login->finish($request);
    }

    public function testACodeTheRealmRefusesFailsTheLoginWithItsError(): void
    {
        try {
            $this->login->finish($this->callbackOf($this->login->start(self::CALLBACK, '/orders'), ['code' => 'unknown']));
            self::fail('A refused code completed the login.');
        } catch (LoginFailed $e) {
            self::assertSame(['invalid_grant', '/orders'], [$e->error, $e->returnTo]);
            self::assertInstanceOf(RequestRefused::class, $e->getPrevious());
        }
    }

    /** @return iterable<string, array{string, bool}> */
    public static function returnUrls(): iterable
    {
        yield 'a path of this app' => ['/orders?tab=2', true];
        yield 'an allowed origin' => ['https://web.example.com/orders', true];
        yield 'a subdomain of an allowed wildcard' => ['https://shop.apps.example.com/', true];
        yield 'another origin' => ['https://evil.test/', false];
        yield 'the wildcard\'s own domain' => ['https://apps.example.com/', false];
        yield 'another scheme' => ['http://web.example.com/', false];
        yield 'another port' => ['https://web.example.com:8443/', false];
        yield 'a protocol-relative URL' => ['//evil.test/', false];
        yield 'a backslash path' => ['/\\evil.test', false];
        yield 'credentials in the URL' => ['https://web.example.com@evil.test/', false];
        yield 'javascript' => ['javascript:alert(1)', false];
        yield 'a backslash ending the host of an allowed wildcard' => ['https://evil.test\\.apps.example.com/', false];
        yield 'a tab in a path' => ["/\t/evil.test", false];
        yield 'a newline in a path' => ["/\n/evil.test", false];
        yield 'a space before the host' => [' https://web.example.com/', false];
        yield 'a percent-encoded host' => ['https://evil%2etest/', false];
    }

    #[DataProvider('returnUrls')]
    public function testOnlyAPathOrAnAllowedOriginIsAPageToReturnTo(string $url, bool $allowed): void
    {
        if (!$allowed) {
            $this->expectException(LoginFailed::class);
        }

        $done = $this->login->finish($this->callbackOf($this->login->start(self::CALLBACK, $url), ['code' => $this->realm->code()]));
        self::assertSame($url, $done->returnTo);
    }

    public function testClearLoginCookieExpiresIt(): void
    {
        $response = new Response();
        $this->login->clearLoginCookie($response);

        self::assertSame('kc_login', $response->headers->getCookies()[0]->getName());
        self::assertTrue($response->headers->getCookies()[0]->isCleared());
    }

    public function testTheSessionCookiesCarryTheTokensAndTheGuardReadsTheAccessOne(): void
    {
        $this->app['config']->set('auth.guards.api.cookie', true);
        $response = new Response();
        $this->app->make(Keycloak::class)->sessionCookies()->set($response, new TokenSet($this->realm->token(['sub' => 'web-user']), 300, 'rt', 0));

        [$access, $refresh] = $response->headers->getCookies();
        self::assertSame(['app_at', 'example.com', '/', 'lax'], [$access->getName(), $access->getDomain(), $access->getPath(), $access->getSameSite()]);
        self::assertSame(['app_rt', '/auth', 'strict'], [$refresh->getName(), $refresh->getPath(), $refresh->getSameSite()]);
        self::assertTrue($access->isHttpOnly() && $access->isSecure() && $refresh->isHttpOnly() && $refresh->isSecure());
        self::assertEqualsWithDelta(time() + 1209600, $refresh->getExpiresTime(), 5, 'a refresh token living as long as the session gets the session lifetime');

        $this->withCredentials()->withUnencryptedCookie('app_at', (string) $access->getValue())->getJson('/whoami')->assertExactJson(['user' => 'user:web-user']);
        self::assertSame('rt', $this->app->make(Keycloak::class)->sessionCookies()->refreshToken(Request::create('/auth/refresh', cookies: ['app_rt' => 'rt'])));
    }

    public function testClearingTheSessionExpiresItsCookies(): void
    {
        $response = new Response();
        $this->app->make(Keycloak::class)->sessionCookies()->clear($response);

        $cleared = array_map(static fn (Cookie $cookie): string => $cookie->getName().'@'.($cookie->getDomain() ?? 'host'), $response->headers->getCookies());
        self::assertSame(['app_at@example.com', 'app_at@host', 'app_rt@host'], $cleared);
    }

    public function testALoginNeedsTheAppKey(): void
    {
        $this->app['config']->set('app.key', '');
        $this->app->forgetInstance(Keycloak::class);

        $this->expectExceptionMessage('app.key');
        $this->app->make(Keycloak::class)->login('web');
    }

    public function testTheRefreshCookieNeedsItsPath(): void
    {
        $this->app['config']->set('keycloak.cookies.refresh.path', null);
        $this->app->forgetInstance(Keycloak::class);

        $this->expectExceptionMessage('keycloak.cookies.refresh.path is not configured');
        $this->app->make(Keycloak::class)->sessionCookies();
    }

    public function testLaravelLeavesThePackagesCookiesUnencrypted(): void
    {
        $this->app->make(Keycloak::class);
        (new \Vinh0809it\KeycloakLaravel\KeycloakServiceProvider($this->app))->boot();
        $middleware = $this->app->make(EncryptCookies::class);

        self::assertTrue($middleware->isDisabled('app_at') && $middleware->isDisabled('app_rt') && $middleware->isDisabled('kc_login'));
        self::assertFalse($middleware->isDisabled('laravel_session'));
    }

    /** @return array<string, string> */
    private static function authorizationQuery(RedirectResponse $redirect): array
    {
        parse_str((string) parse_url($redirect->getTargetUrl(), \PHP_URL_QUERY), $query);

        /* @var array<string, string> $query */
        return $query;
    }

    private static function cookie(RedirectResponse $redirect): Cookie
    {
        return $redirect->headers->getCookies()[0];
    }

    /** @return array{state: string, verifier: string, redirect_uri: string, return_to: ?string} what the login cookie keeps */
    private static function login(RedirectResponse $redirect): array
    {
        [$payload] = explode('.', (string) self::cookie($redirect)->getValue());

        /* @var array{state: string, verifier: string, redirect_uri: string, return_to: ?string} */
        return json_decode((string) base64_decode(strtr($payload, '-_', '+/')), true);
    }

    /**
     * The realm's redirect back: the login's own state unless $params says otherwise, with the login
     * cookie the browser kept.
     *
     * @param array<string, string> $params
     */
    private function callbackOf(RedirectResponse $redirect, array $params): Request
    {
        return Request::create(self::CALLBACK, 'GET', $params + ['state' => self::authorizationQuery($redirect)['state']], [self::cookie($redirect)->getName() => (string) self::cookie($redirect)->getValue()]);
    }
}
