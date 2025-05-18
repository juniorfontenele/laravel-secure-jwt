<?php

declare(strict_types = 1);

namespace JuniorFontenele\LaravelSecureJwt\Contracts;

use JuniorFontenele\LaravelSecureJwt\Exceptions\JwtValidationException;
use JuniorFontenele\LaravelSecureJwt\SecureJwt;

interface JwtClaimValidatorInterface
{
    /**
     * Validates a decoded JWT token
     * @param SecureJwt $jwt
     * @return void
     * @throws JwtValidationException
     */
    public function validate(SecureJwt $jwt): void;

    public function isValid(SecureJwt $jwt): bool;
}
