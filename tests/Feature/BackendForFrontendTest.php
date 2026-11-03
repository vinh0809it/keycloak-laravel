<?php

/**
 * Copyright (c) 2026 Vinh Vo. MIT License.
 */

declare(strict_types=1);

namespace Vinh0809it\KeycloakLaravel\Tests\Feature;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use Vinh0809it\KeycloakLaravel\Client\RequestRefused;
use Vinh0809it\KeycloakLaravel\Keycloak;
use Vinh0809it\KeycloakLaravel\KeycloakException;
use Vinh0809it\KeycloakLaravel\Browser\LoginFailed;
use Vinh0809it\KeycloakLaravel\Tests\TestCase;

/** The README's backend-for-frontend routes, in the `web` middleware group, end to end. */
final class BackendForFrontendTest extends TestCase
{
    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);
        $app['config']->set('keycloak.clients.web', ['id' => 'web-app', 'secret' => 'web-secret', 'return_origins' => ['https://web.example.com']]);
        $app['config']->set('keycloak.cookies', ['access' => ['name' => 'app_at'], 'refresh' => ['name' => 'app_rt', 'path' => '/auth']]);
        $app['config']->set('auth.guards.api.cookie', true);
    }

    protected function defineRoutes($router): void
    {
        parent::defineRoutes($router);
        Route::middleware('web')->group(static function (): void {
            Route::get('/auth/login', static fn (Request $request, Keycloak $keycloak) => $keycloak->login('web')
                ->start(route('auth.callback'), $request->string('return')->value() ?: null));

            Route::get('/auth/callback', static function (Request $request, Keycloak $keycloak) {
                $login = $keycloak->login('web');
                try {
                    $done = $login->finish($request);
                    $response = redirect($done->returnTo ?? '/');
                    $keycloak->sessionCookies()->set($response, $done->tokens);
                } catch (LoginFailed $e) {
                    $response = redirect(($e->returnTo ?? '/').'#login_error='.($e->error ?? 'failed'));
                }
                $login->clearLoginCookie($response);

                return $response;
            })->name('auth.callback');

            Route::post('/auth/refresh', static function (Request $request, Keycloak $keycloak) {
                $response = response()->noContent();
                try {
                    $keycloak->sessionCookies()->set($response, $keycloak->client('web')->refresh((string) $keycloak->sessionCookies()->refreshToken($request)));
                } catch (RequestRefused) {
                    $response = response()->noContent(401);
                    $keycloak->sessionCookies()->clear($response);
                }

                return $response;
            })->withoutMiddleware(\Illuminate\Foundation\Http\Middleware\ValidateCsrfToken::class);

            Route::post('/auth/logout', static function (Request $request, Keycloak $keycloak) {
                if (null !== $refreshToken = $keycloak->sessionCookies()->refreshToken($request)) {
                    try {
                        $keycloak->client('web')->logout($refreshToken);
                    } catch (KeycloakException) {
                    }
                }

                return tap(response()->noContent(), static fn ($response) => $keycloak->sessionCookies()->clear($response));
            })->withoutMiddleware(\Illuminate\Foundation\Http\Middleware\ValidateCsrfToken::class);
        });
    }

    public function testABrowserSignsInUsesTheApiRefreshesAndSignsOut(): void
    {
        $start = $this->get('/auth/login?return='.urlencode('https://web.example.com/orders'));
        $start->assertRedirectContains($this->realm->issuer.'/protocol/openid-connect/auth');
        parse_str((string) parse_url((string) $start->headers->get('Location'), \PHP_URL_QUERY), $authorization);
        $loginCookie = $start->getCookie('keycloak_login_web', false);
        self::assertNotNull($loginCookie);

        $callback = $this->withUnencryptedCookie('keycloak_login_web', (string) $loginCookie->getValue())
            ->get('/auth/callback?'.http_build_query(['state' => $authorization['state'], 'code' => $this->realm->code(['sub' => 'alice']), 'iss' => $this->realm->issuer]));
        $callback->assertRedirect('https://web.example.com/orders');
        $access = $callback->getCookie('app_at', false);
        $refresh = $callback->getCookie('app_rt', false);
        self::assertNotNull($access);
        self::assertNotNull($refresh);
        self::assertTrue($callback->getCookie('keycloak_login_web', false)?->isCleared());

        $this->app->make('auth')->forgetGuards();
        $this->withCredentials()->withUnencryptedCookie('app_at', (string) $access->getValue())->getJson('/whoami')->assertExactJson(['user' => 'user:alice']);

        $refreshed = $this->withUnencryptedCookie('app_rt', (string) $refresh->getValue())->post('/auth/refresh');
        $refreshed->assertNoContent();
        $newRefresh = (string) $refreshed->getCookie('app_rt', false)?->getValue();
        self::assertNotSame((string) $refresh->getValue(), $newRefresh);

        $this->withUnencryptedCookie('app_rt', $newRefresh)->post('/auth/logout')->assertNoContent()->assertCookieExpired('app_at');
        $this->withUnencryptedCookie('app_rt', $newRefresh)->post('/auth/refresh')->assertStatus(401);
    }

    public function testACallbackOfAnotherBrowserGoesBackWithTheError(): void
    {
        $this->get('/auth/callback?'.http_build_query(['state' => 'x', 'code' => $this->realm->code()]))
            ->assertRedirect('/#login_error=failed');
    }
}
