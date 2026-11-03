<?php

/**
 * Copyright (c) 2026 Vinh Vo. MIT License.
 */

declare(strict_types=1);

namespace Vinh0809it\KeycloakLaravel\Auth;

use Vinh0809it\KeycloakLaravel\KeycloakException;

/**
 * A bearer the guard refuses: not a token of the realm, not for this audience, expired, or one a
 * resolver will not take. The request is then unauthenticated (a 401 behind `auth:<guard>`).
 */
final class InvalidToken extends \RuntimeException implements KeycloakException
{
}
