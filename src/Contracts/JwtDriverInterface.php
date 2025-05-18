<?php

declare(strict_types = 1);

namespace JuniorFontenele\LaravelSecureJwt\Contracts;

use JuniorFontenele\LaravelSecureJwt\JwtKey;
use JuniorFontenele\LaravelSecureJwt\SecureJwt;

interface JwtDriverInterface
{
    public function encode(SecureJwt $jwt, JwtKey $signingKey): string;

    public function decode(string $token, JwtKey $verificationKey): SecureJwt;

    public function isValidKid(string $token, JwtKey $verificationKey): bool;
}
