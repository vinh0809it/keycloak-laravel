<?php

/**
 * Copyright (c) 2026 Vinh Vo. MIT License.
 */

declare(strict_types=1);

namespace Vinh0809it\KeycloakLaravel\Auth;

use Illuminate\Contracts\Auth\Authenticatable;

/**
 * Turns a verified token's claims into the app's user. Return null, or throw {@see InvalidToken},
 * to leave the request unauthenticated.
 */
interface ClaimsResolver
{
    public function resolve(Claims $claims): ?Authenticatable;
}
