<?php

declare(strict_types = 1);

namespace JuniorFontenele\LaravelSecureJwt\Tests\Feature\Validators;

use JuniorFontenele\LaravelSecureJwt\CustomClaims;
use JuniorFontenele\LaravelSecureJwt\Exceptions\JwtExpiredException;
use JuniorFontenele\LaravelSecureJwt\Exceptions\JwtInFutureException;
use JuniorFontenele\LaravelSecureJwt\Exceptions\JwtNotValidYetException;
use JuniorFontenele\LaravelSecureJwt\Jti;
use JuniorFontenele\LaravelSecureJwt\Nonce;
use JuniorFontenele\LaravelSecureJwt\SecureJwt;
use JuniorFontenele\LaravelSecureJwt\Tests\TestCase;
use JuniorFontenele\LaravelSecureJwt\Validators\JwtClaimValidator;

class JwtClaimValidatorTest extends TestCase
{
    private JwtClaimValidator $validator;

    protected function setUp(): void
    {
        $this->validator = new JwtClaimValidator();
    }

    public function testValidateValidToken(): void
    {
        $now = time();
        $jwt = new SecureJwt(
            iss: 'test-issuer',
            customClaims: new CustomClaims(),
            iat: $now - 60,
            nbf: $now - 30,
            exp: $now + 300,
            jti: new Jti(),
            nonce: new Nonce(),
            alg: 'HS256',
            kid: 'test-key'
        );

        $this->assertNull($this->validator->validate($jwt));
        $this->assertTrue($this->validator->isValid($jwt));
    }

    public function testValidateExpiredToken(): void
    {
        $now = time();
        $jwt = new SecureJwt(
            iss: 'test-issuer',
            customClaims: new CustomClaims(),
            iat: $now - 120,
            nbf: $now - 120,
            exp: $now - 60,
            jti: new Jti(),
            nonce: new Nonce(),
            alg: 'HS256',
            kid: 'test-key'
        );

        $this->expectException(JwtExpiredException::class);
        $this->validator->validate($jwt);
    }

    public function testValidateTokenIssuedInFuture(): void
    {
        $now = time();
        $jwt = new SecureJwt(
            iss: 'test-issuer',
            customClaims: new CustomClaims(),
            iat: $now + 60,
            nbf: $now + 60,
            exp: $now + 300,
            jti: new Jti(),
            nonce: new Nonce(),
            alg: 'HS256',
            kid: 'test-key'
        );

        $this->expectException(JwtInFutureException::class);
        $this->validator->validate($jwt);
    }

    public function testValidateTokenNotValidYet(): void
    {
        $now = time();
        $jwt = new SecureJwt(
            iss: 'test-issuer',
            customClaims: new CustomClaims(),
            iat: $now - 60,
            nbf: $now + 60,
            exp: $now + 300,
            jti: new Jti(),
            nonce: new Nonce(),
            alg: 'HS256',
            kid: 'test-key'
        );

        $this->expectException(JwtNotValidYetException::class);
        $this->validator->validate($jwt);
    }

    public function testIsValidReturnsFalseForInvalidToken(): void
    {
        $now = time();
        $jwt = new SecureJwt(
            iss: 'test-issuer',
            customClaims: new CustomClaims(),
            iat: $now - 120,
            nbf: $now - 120,
            exp: $now - 60,
            jti: new Jti(),
            nonce: new Nonce(),
            alg: 'HS256',
            kid: 'test-key'
        );

        $this->assertFalse($this->validator->isValid($jwt));
    }
}
