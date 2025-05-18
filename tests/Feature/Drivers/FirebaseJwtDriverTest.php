<?php

declare(strict_types = 1);

namespace JuniorFontenele\LaravelSecureJwt\Tests\Feature\Drivers;

use JuniorFontenele\LaravelSecureJwt\CustomClaims;
use JuniorFontenele\LaravelSecureJwt\Drivers\FirebaseJwtDriver;
use JuniorFontenele\LaravelSecureJwt\Exceptions\JwtInvalidKidException;
use JuniorFontenele\LaravelSecureJwt\Jti;
use JuniorFontenele\LaravelSecureJwt\JwtKey;
use JuniorFontenele\LaravelSecureJwt\Nonce;
use JuniorFontenele\LaravelSecureJwt\SecureJwt;
use JuniorFontenele\LaravelSecureJwt\Services\JwtService;
use JuniorFontenele\LaravelSecureJwt\Tests\TestCase;

class FirebaseJwtDriverTest extends TestCase
{
    private FirebaseJwtDriver $driver;

    private JwtKey $signingKey;

    private SecureJwt $jwt;

    private JwtService $service;

    protected function setUp(): void
    {
        parent::setUp();

        $this->driver = new FirebaseJwtDriver();
        $this->signingKey = new JwtKey('test-key-id', 'my-secret', 'HS256');
        $this->service = app(JwtService::class);

        $this->jwt = new SecureJwt(
            iss: 'test-issuer',
            customClaims: new CustomClaims(['sub' => '123', 'name' => 'Test User']),
            iat: time(),
            nbf: time(),
            exp: time() + 3600,
            jti: new Jti('unique-id-123'),
            nonce: new Nonce('test-nonce'),
            alg: 'HS256',
            kid: 'test-key-id'
        );
    }

    public function testEncodeCreatesTokenWithCorrectPayload(): void
    {
        $token = $this->driver->encode($this->jwt, $this->signingKey);

        // Split the token and decode the payload part
        $parts = explode('.', $token);
        $payload = json_decode(base64_decode(strtr($parts[1], '-_', '+/')), true);

        $this->assertEquals('test-issuer', $payload['iss']);
        $this->assertEquals('123', $payload['sub']);
        $this->assertEquals('Test User', $payload['name']);
        $this->assertEquals('unique-id-123', $payload['jti']);
        $this->assertEquals('test-nonce', $payload['nonce']);
    }

    public function testEncodeCreatesTokenWithCorrectHeaders(): void
    {
        $token = $this->driver->encode($this->jwt, $this->signingKey);

        // Split the token and decode the header part
        $parts = explode('.', $token);
        $header = json_decode(base64_decode(strtr($parts[0], '-_', '+/')), true);

        $this->assertEquals('HS256', $header['alg']);
        $this->assertEquals('test-key-id', $header['kid']);
        $this->assertEquals('JWT', $header['typ']);
    }

    public function testDecodeReturnsCorrectSecureJwtObject(): void
    {
        $token = $this->driver->encode($this->jwt, $this->signingKey);
        $verificationKey = new JwtKey('test-key-id', $this->signingKey->key(), $this->signingKey->algorithm());
        $decoded = $this->driver->decode($token, $verificationKey);

        $this->assertEquals($this->jwt->iss(), $decoded->iss());
        $this->assertEquals($this->jwt->jti(), $decoded->jti());
        $this->assertEquals($this->jwt->nonce(), $decoded->nonce());
        $this->assertEquals($this->jwt->claims()['sub'], $decoded->claims()['sub']);
        $this->assertEquals($this->jwt->claims()['name'], $decoded->claims()['name']);
        $this->assertEquals($this->jwt->iat(), $decoded->iat());
        $this->assertEquals($this->jwt->exp(), $decoded->exp());
        $this->assertEquals($this->jwt->nbf(), $decoded->nbf());
        $this->assertEquals($this->jwt->alg(), $decoded->alg());
        $this->assertEquals($this->jwt->kid(), $decoded->kid());
        $this->assertEquals($this->jwt->typ(), $decoded->typ());
    }

    public function testIsValidKidReturnsTrueWhenKidMatches(): void
    {
        $token = $this->driver->encode($this->jwt, $this->signingKey);
        $verificationKey = new JwtKey('test-key-id', $this->signingKey->key(), $this->signingKey->algorithm());

        $this->assertTrue($this->driver->isValidKid($token, $verificationKey));
    }

    public function testIsValidKidReturnsFalseWhenKidDoesNotMatch(): void
    {
        $token = $this->driver->encode($this->jwt, $this->signingKey);
        $verificationKey = new JwtKey('different-key', $this->signingKey->key(), $this->signingKey->algorithm());

        $this->assertFalse($this->driver->isValidKid($token, $verificationKey));
    }

    public function testDecodeThrowsExceptionWhenKidMismatch(): void
    {
        $token = $this->driver->encode($this->jwt, $this->signingKey);
        $verificationKey = new JwtKey('different-key', $this->signingKey->key(), $this->signingKey->algorithm());

        $this->expectException(JwtInvalidKidException::class);
        $this->expectExceptionMessage('Token kid is not valid.');

        $this->service->decode($token, $verificationKey);
    }
}
