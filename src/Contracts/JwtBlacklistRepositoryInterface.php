<?php

declare(strict_types = 1);

namespace JuniorFontenele\LaravelSecureJwt\Contracts;

interface JwtBlacklistRepositoryInterface
{
    public function add(string $jti, int $ttl): void;

    public function isBlacklisted(string $jti): bool;

    public function remove(string $jti): void;
}
