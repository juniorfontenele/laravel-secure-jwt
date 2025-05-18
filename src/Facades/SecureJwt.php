<?php

declare(strict_types = 1);

namespace JuniorFontenele\LaravelSecureJwt\Facades;

use Illuminate\Support\Facades\Facade;
use JuniorFontenele\LaravelSecureJwt\Services\JwtService;

class SecureJwt extends Facade
{
    protected static function getFacadeAccessor(): string
    {
        return JwtService::class;
    }
}
