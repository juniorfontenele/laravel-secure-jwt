<?php

declare(strict_types = 1);

namespace JuniorFontenele\LaravelSecureJwt\Repositories;

use Illuminate\Support\Facades\Cache;
use JuniorFontenele\LaravelSecureJwt\Contracts\JwtNonceRepositoryInterface;

class LaravelCacheNonceRepository implements JwtNonceRepositoryInterface
{
    private string $cacheKey = 'jwt:nonce:';

    public function add(string $nonce, int $ttl): void
    {
        Cache::put($this->cacheKey . $nonce, true, $ttl);
    }

    public function isUsed(string $nonce): bool
    {
        return Cache::has($this->cacheKey . $nonce);
    }
}
