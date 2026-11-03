<?php

/**
 * Copyright (c) 2026 Vinh Vo. MIT License.
 */

declare(strict_types=1);

namespace Vinh0809it\KeycloakLaravel;

/**
 * Anything a call to the realm throws. Catch the implementations to tell who is at fault:
 *
 *  - {@see KeycloakUnavailable}: Keycloak could not be reached or failed (5xx), retryable;
 *  - {@see Client\InvalidClient}: this app's client is misconfigured (a wrong secret, a client
 *    without a service account), never the end user's doing and never worth retrying;
 *  - {@see Client\RequestRefused}: Keycloak refused what was asked (a spent code, an expired
 *    refresh token, wrong credentials), usually the end user signs in again;
 *  - {@see Browser\LoginFailed}: a browser's login could not be completed, the app starts a new one;
 *  - {@see Auth\InvalidToken}: a guard refused a token, or a resolver refuses one.
 */
interface KeycloakException extends \Throwable
{
}
