<?php

declare(strict_types = 1);

return [
    'issuer' => env('SECUREJWT_ISSUER', 'http://localhost'),
    'ttl' => env('SECUREJWT_TTL', 60 * 5), // 5 minutes
    'nonce_ttl' => env('SECUREJWT_NONCE_TTL', 60 * 60 * 24), // 24 hours
    'blacklist_ttl' => env('SECUREJWT_BLACKLIST_TTL', 60 * 60 * 24 * 30), // 30 days

    'providers' => [
        'driver' => JuniorFontenele\LaravelSecureJwt\Drivers\FirebaseJwtDriver::class,
        'blacklist' => JuniorFontenele\LaravelSecureJwt\Repositories\LaravelCacheBlacklistRepository::class,
        'nonce' => JuniorFontenele\LaravelSecureJwt\Repositories\LaravelCacheNonceRepository::class,
        'claim_validator' => JuniorFontenele\LaravelSecureJwt\Validators\JwtClaimValidator::class,
    ],
];
