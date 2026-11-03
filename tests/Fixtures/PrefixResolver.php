<?php

/**
 * Copyright (c) 2026 Vinh Vo. MIT License.
 */

declare(strict_types=1);

namespace Vinh0809it\KeycloakLaravel\Tests\Fixtures;

use Illuminate\Auth\GenericUser;
use Illuminate\Contracts\Auth\Authenticatable;
use Vinh0809it\KeycloakLaravel\Auth\Claims;
use Vinh0809it\KeycloakLaravel\Auth\ClaimsResolver;

/** A user named after the resolver that built it and the token's `sub`. */
final readonly class PrefixResolver implements ClaimsResolver
{
    public function __construct(private string $prefix = 'user')
    {
    }

    public function resolve(Claims $claims): Authenticatable
    {
        return new GenericUser(['id' => $this->prefix.':'.$claims->sub]);
    }
}
