<?php

/**
 * Copyright (c) 2026 Vinh Vo. MIT License.
 */

declare(strict_types=1);

namespace Vinh0809it\KeycloakLaravel\Client;

/**
 * The token endpoint refused THIS app's client (`invalid_client`, `unauthorized_client`): a wrong
 * secret, or a grant the client is not allowed. Configuration, so a 5xx of ours rather than a 4xx
 * to the caller, and pointless to retry.
 */
final class InvalidClient extends RequestRefused
{
}
