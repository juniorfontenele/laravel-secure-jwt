<?php

declare(strict_types = 1);

namespace JuniorFontenele\LaravelSecureJwt\Validators;

use JuniorFontenele\LaravelSecureJwt\Contracts\JwtClaimValidatorInterface;
use JuniorFontenele\LaravelSecureJwt\Exceptions\JwtExpiredException;
use JuniorFontenele\LaravelSecureJwt\Exceptions\JwtInFutureException;
use JuniorFontenele\LaravelSecureJwt\Exceptions\JwtNotValidYetException;
use JuniorFontenele\LaravelSecureJwt\SecureJwt;

class JwtClaimValidator implements JwtClaimValidatorInterface
{
    public function validate(SecureJwt $jwt): void
    {
        $now = time();

        if ($now > $jwt->exp()) {
            throw new JwtExpiredException('Token is expired.');
        }

        if ($jwt->iat() > $now) {
            throw new JwtInFutureException('Token was issued in future.');
        }

        if ($jwt->nbf() > $now) {
            throw new JwtNotValidYetException('Token is not valid yet.');
        }
    }

    public function isValid(SecureJwt $jwt): bool
    {
        try {
            $this->validate($jwt);

            return true;
        } catch (\Exception $e) {
            return false;
        }
    }
}
