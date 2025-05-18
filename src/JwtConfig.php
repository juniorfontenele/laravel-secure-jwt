<?php

declare(strict_types = 1);

namespace JuniorFontenele\LaravelSecureJwt;

class JwtConfig
{
    public function __construct(
        private string $issuer,
        private int $ttl = 60 * 5, // 5 minutes
        private int $nonceTtl = 60 * 60 * 24, // 24 hours
        private int $blacklistTtl = 60 * 60 * 24 * 30, // 30 days
    ) {
        //
    }

    public function ttl(): int
    {
        return $this->ttl;
    }

    public function issuer(): string
    {
        return $this->issuer;
    }

    public function nonceTtl(): int
    {
        return $this->nonceTtl;
    }

    public function blacklistTtl(): int
    {
        return $this->blacklistTtl;
    }
}
