<?php

declare(strict_types = 1);

namespace JuniorFontenele\LaravelSecureJwt\Providers;

use Illuminate\Support\ServiceProvider;
use JuniorFontenele\LaravelSecureJwt\Contracts\JwtBlacklistRepositoryInterface;
use JuniorFontenele\LaravelSecureJwt\Contracts\JwtClaimValidatorInterface;
use JuniorFontenele\LaravelSecureJwt\Contracts\JwtDriverInterface;
use JuniorFontenele\LaravelSecureJwt\Contracts\JwtNonceRepositoryInterface;
use JuniorFontenele\LaravelSecureJwt\Drivers\FirebaseJwtDriver;
use JuniorFontenele\LaravelSecureJwt\JwtConfig;
use JuniorFontenele\LaravelSecureJwt\Repositories\LaravelCacheBlacklistRepository;
use JuniorFontenele\LaravelSecureJwt\Repositories\LaravelCacheNonceRepository;
use JuniorFontenele\LaravelSecureJwt\Validators\JwtClaimValidator;

class LaravelSecureJwtServiceProvider extends ServiceProvider
{
    /**
     * Register services.
     *
     * @return void
     */
    public function register()
    {
        $this->publishes([
            __DIR__ . '/../../config/secure-jwt.php' => config_path('secure-jwt.php'),
        ], 'secure-jwt-config');

        $this->app->singleton(JwtConfig::class, function () {
            return new JwtConfig(
                issuer: config('secure-jwt.issuer'),
                ttl: config('secure-jwt.ttl'),
                nonceTtl: config('secure-jwt.nonce_ttl'),
                blacklistTtl: config('secure-jwt.blacklist_ttl'),
            );
        });

        $this->app->singleton(JwtDriverInterface::class, config('secure-jwt.providers.driver', FirebaseJwtDriver::class));
        $this->app->singleton(JwtBlacklistRepositoryInterface::class, config('secure-jwt.providers.blacklist', LaravelCacheBlacklistRepository::class));
        $this->app->singleton(JwtNonceRepositoryInterface::class, config('secure-jwt.providers.nonce', LaravelCacheNonceRepository::class));
        $this->app->singleton(JwtClaimValidatorInterface::class, config('secure-jwt.providers.claim_validator', JwtClaimValidator::class));
    }

    /**
     * Bootstrap services.
     *
     * @return void
     */
    public function boot()
    {
        $this->mergeConfigFrom(
            __DIR__ . '/../../config/secure-jwt.php',
            'secure-jwt'
        );
    }
}
