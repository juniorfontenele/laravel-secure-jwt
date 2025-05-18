<?php

declare(strict_types = 1);

namespace JuniorFontenele\LaravelSecureJwt\Repositories;

use Illuminate\Support\Facades\Cache;
use JuniorFontenele\LaravelSecureJwt\Contracts\JwtBlacklistRepositoryInterface;

class LaravelCacheBlacklistRepository implements JwtBlacklistRepositoryInterface
{
    private string $cacheKey = 'jwt:jti-blacklist:';

    public function add(string $jti, int $ttl): void
    {
        Cache::put($this->cacheKey . $jti, true, $ttl);
    }

    public function isBlacklisted(string $jti): bool
    {
        return Cache::has($this->cacheKey . $jti);
    }

    public function remove(string $jti): void
    {
        Cache::forget($this->cacheKey . $jti);
    }
}
