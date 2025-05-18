<?php

declare(strict_types = 1);

namespace JuniorFontenele\LaravelSecureJwt\Tests\Unit;

use JuniorFontenele\LaravelSecureJwt\CustomClaims;
use JuniorFontenele\LaravelSecureJwt\Exceptions\JwtException;
use JuniorFontenele\LaravelSecureJwt\Jti;
use JuniorFontenele\LaravelSecureJwt\Nonce;
use JuniorFontenele\LaravelSecureJwt\SecureJwt;
use JuniorFontenele\LaravelSecureJwt\Tests\TestCase;

class SecureJwtTest extends TestCase
{
    public function testCreateNewGeneratesValidJwt(): void
    {
        $issuer = 'test-issuer';
        $kid = 'test-key';
        $alg = 'HS256';
        $customClaims = new CustomClaims(['sub' => '123']);
        $ttl = 300;

        $jwt = SecureJwt::createNew($issuer, $kid, $alg, $customClaims, $ttl);

        $this->assertEquals($issuer, $jwt->iss());
        $this->assertEquals($kid, $jwt->kid());
        $this->assertEquals($alg, $jwt->alg());
        $this->assertEquals('JWT', $jwt->typ());
        $this->assertEquals(['sub' => '123'], $jwt->claims());

        $now = time();
        $this->assertLessThanOrEqual($now, $jwt->iat());
        $this->assertLessThanOrEqual($now, $jwt->nbf());
        $this->assertGreaterThanOrEqual($now + $ttl - 5, $jwt->exp());
        $this->assertLessThanOrEqual($now + $ttl, $jwt->exp());

        // Non-empty values
        $this->assertNotEmpty($jwt->jti());
        $this->assertNotEmpty($jwt->nonce());
    }

    public function testHeaderReturnsValidHeader(): void
    {
        $jwt = new SecureJwt(
            iss: 'test-issuer',
            customClaims: new CustomClaims(),
            iat: time(),
            nbf: time(),
            exp: time() + 300,
            jti: new Jti(),
            nonce: new Nonce(),
            alg: 'HS256',
            kid: 'test-key'
        );

        $header = $jwt->header();

        $this->assertArrayHasKey('alg', $header);
        $this->assertArrayHasKey('kid', $header);
        $this->assertArrayHasKey('typ', $header);
        $this->assertEquals('HS256', $header['alg']);
        $this->assertEquals('test-key', $header['kid']);
        $this->assertEquals('JWT', $header['typ']);
    }

    public function testPayloadReturnsValidPayload(): void
    {
        $iat = time();
        $nbf = $iat;
        $exp = $iat + 300;
        $jti = new Jti('test-jti');
        $nonce = new Nonce('test-nonce');

        $jwt = new SecureJwt(
            iss: 'test-issuer',
            customClaims: new CustomClaims(['sub' => '123']),
            iat: $iat,
            nbf: $nbf,
            exp: $exp,
            jti: $jti,
            nonce: $nonce,
            alg: 'HS256',
            kid: 'test-key'
        );

        $payload = $jwt->payload();

        $this->assertArrayHasKey('iss', $payload);
        $this->assertArrayHasKey('iat', $payload);
        $this->assertArrayHasKey('nbf', $payload);
        $this->assertArrayHasKey('exp', $payload);
        $this->assertArrayHasKey('jti', $payload);
        $this->assertArrayHasKey('nonce', $payload);
        $this->assertArrayHasKey('sub', $payload);

        $this->assertEquals('test-issuer', $payload['iss']);
        $this->assertEquals($iat, $payload['iat']);
        $this->assertEquals($nbf, $payload['nbf']);
        $this->assertEquals($exp, $payload['exp']);
        $this->assertEquals('test-jti', $payload['jti']);
        $this->assertEquals('test-nonce', $payload['nonce']);
        $this->assertEquals('123', $payload['sub']);
    }

    public function testInvalidTypThrowsException(): void
    {
        $this->expectException(JwtException::class);
        $this->expectExceptionMessage('Invalid type (typ). Only JWT is supported.');

        new SecureJwt(
            iss: 'test-issuer',
            customClaims: new CustomClaims(),
            iat: time(),
            nbf: time(),
            exp: time() + 300,
            jti: new Jti(),
            nonce: new Nonce(),
            alg: 'HS256',
            kid: 'test-key',
            typ: 'INVALID'
        );
    }

    public function testInvalidIatNbfThrowsException(): void
    {
        $this->expectException(JwtException::class);
        $this->expectExceptionMessage('Invalid issued at (iat). It must be less than or equal to not before (nbf).');

        $iat = time() + 60;
        $nbf = time();

        new SecureJwt(
            iss: 'test-issuer',
            customClaims: new CustomClaims(),
            iat: $iat,
            nbf: $nbf,
            exp: time() + 300,
            jti: new Jti(),
            nonce: new Nonce(),
            alg: 'HS256',
            kid: 'test-key'
        );
    }

    public function testInvalidNbfExpThrowsException(): void
    {
        $this->expectException(JwtException::class);
        $this->expectExceptionMessage('Invalid not before (nbf). It must be less than or equal to expiration (exp).');

        $nbf = time() + 120;
        $exp = time() + 60;

        new SecureJwt(
            iss: 'test-issuer',
            customClaims: new CustomClaims(),
            iat: time(),
            nbf: $nbf,
            exp: $exp,
            jti: new Jti(),
            nonce: new Nonce(),
            alg: 'HS256',
            kid: 'test-key'
        );
    }
}
