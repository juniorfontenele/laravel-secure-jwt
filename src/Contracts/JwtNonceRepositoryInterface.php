<?php

declare(strict_types = 1);

namespace JuniorFontenele\LaravelSecureJwt\Contracts;

interface JwtNonceRepositoryInterface
{
    public function add(string $nonce, int $ttl): void;

    public function isUsed(string $nonce): bool;
}
