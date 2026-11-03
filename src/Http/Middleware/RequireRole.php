<?php

/**
 * Copyright (c) 2026 Vinh Vo. MIT License.
 */

declare(strict_types=1);

namespace Vinh0809it\KeycloakLaravel\Http\Middleware;

use Illuminate\Auth\Access\AuthorizationException;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;
use Vinh0809it\KeycloakLaravel\Auth\Claims;

/**
 * `keycloak.role`: lets a request through when the token that authenticated it holds one of the
 * listed roles, a realm role (`admin`) or a client's (`my-api:editor`); a 403 otherwise. It reads
 * the token a `keycloak` guard verified, so it goes after `auth:<guard>`:
 *
 *     Route::middleware(['auth:api', 'keycloak.role:admin,my-api:editor'])->group(...);
 */
final class RequireRole
{
    public const ALIAS = 'keycloak.role';

    /**
     * @param \Closure(Request): Response $next
     *
     * @throws AuthorizationException
     */
    public function handle(Request $request, \Closure $next, string ...$roles): Response
    {
        if ([] === $roles) {
            throw new \LogicException('The keycloak.role middleware needs the roles it accepts: keycloak.role:admin,my-api:editor.');
        }

        $claims = Claims::of($request);
        foreach ($roles as $role) {
            [$client, $name] = str_contains($role, ':') ? explode(':', $role, 2) : [null, $role];
            if (null !== $claims && $claims->hasRole($name, $client)) {
                return $next($request);
            }
        }

        throw new AuthorizationException(null !== $claims ? 'This token holds none of the roles this route needs.' : 'No Keycloak token authenticated this request.');
    }
}
