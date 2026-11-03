<?php

/**
 * Copyright (c) 2026 Vinh Vo. MIT License.
 */

declare(strict_types=1);

namespace Vinh0809it\KeycloakLaravel;

/**
 * Keycloak could not be reached, failed with a 5xx, or answered a success without what it owes (no
 * access token, no usable signing key). A server error rather than a 401: the caller's token may be
 * perfectly valid.
 */
final class KeycloakUnavailable extends \RuntimeException implements KeycloakException
{
}
