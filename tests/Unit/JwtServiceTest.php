<?php

declare(strict_types = 1);

namespace JuniorFontenele\LaravelSecureJwt\Tests\Unit;

use JuniorFontenele\LaravelSecureJwt\Contracts\JwtBlacklistRepositoryInterface;
use JuniorFontenele\LaravelSecureJwt\Contracts\JwtClaimValidatorInterface;
use JuniorFontenele\LaravelSecureJwt\Contracts\JwtDriverInterface;
use JuniorFontenele\LaravelSecureJwt\Contracts\JwtNonceRepositoryInterface;
use JuniorFontenele\LaravelSecureJwt\CustomClaims;
use JuniorFontenele\LaravelSecureJwt\Exceptions\JwtInvalidKidException;
use JuniorFontenele\LaravelSecureJwt\Exceptions\NonceUsedException;
use JuniorFontenele\LaravelSecureJwt\Exceptions\TokenBlacklistedException;
use JuniorFontenele\LaravelSecureJwt\Jti;
use JuniorFontenele\LaravelSecureJwt\JwtConfig;
use JuniorFontenele\LaravelSecureJwt\JwtKey;
use JuniorFontenele\LaravelSecureJwt\Nonce;
use JuniorFontenele\LaravelSecureJwt\SecureJwt;
use JuniorFontenele\LaravelSecureJwt\Services\JwtService;
use JuniorFontenele\LaravelSecureJwt\Tests\TestCase;

class JwtServiceTest extends TestCase
{
    private JwtService $service;

    private JwtConfig $config;

    private JwtClaimValidatorInterface $claimValidator;

    private JwtDriverInterface $driver;

    private JwtBlacklistRepositoryInterface $blacklist;

    private JwtNonceRepositoryInterface $nonceRepository;

    protected function setUp(): void
    {
        parent::setUp();

        $this->config = new JwtConfig('test-issuer', 300, 3600, 86400);

        $this->claimValidator = $this->createMock(JwtClaimValidatorInterface::class);
        $this->driver = $this->createMock(JwtDriverInterface::class);
        $this->blacklist = $this->createMock(JwtBlacklistRepositoryInterface::class);
        $this->nonceRepository = $this->createMock(JwtNonceRepositoryInterface::class);

        $this->service = new JwtService(
            $this->config,
            $this->claimValidator,
            $this->driver,
            $this->blacklist,
            $this->nonceRepository
        );
    }

    public function testEncodeCreatesTokenWithCorrectParameters(): void
    {
        $customClaims = new CustomClaims(['sub' => '123']);
        $signingKey = new JwtKey('test-key', 'secret-key', 'HS256');

        $this->driver
            ->expects($this->once())
            ->method('encode')
            ->willReturnCallback(function (SecureJwt $jwt, JwtKey $key) use ($signingKey) {
                $this->assertEquals('test-issuer', $jwt->iss());
                $this->assertEquals('test-key', $jwt->kid());
                $this->assertEquals('HS256', $jwt->alg());
                $this->assertEquals(['sub' => '123'], $jwt->claims());
                $this->assertEquals($signingKey->id(), $key->id());
                $this->assertEquals($signingKey->key(), $key->key());
                $this->assertEquals($signingKey->algorithm(), $key->algorithm());

                return 'encoded-token';
            });

        $token = $this->service->encode($customClaims, $signingKey);
        $this->assertEquals('encoded-token', $token);
    }

    public function testDecodeValidatesTokenCorrectly(): void
    {
        $token = 'valid-token';
        $verificationKey = new JwtKey('test-key', 'secret-key', 'HS256');

        $jwt = new SecureJwt(
            iss: 'test-issuer',
            customClaims: new CustomClaims(['sub' => '123']),
            iat: time(),
            nbf: time(),
            exp: time() + 300,
            jti: new Jti('test-jti'),
            nonce: new Nonce('test-nonce'),
            alg: 'HS256',
            kid: 'test-key'
        );

        $this->driver
            ->expects($this->once())
            ->method('isValidKid')
            ->with($token, $verificationKey)
            ->willReturn(true);

        $this->driver
            ->expects($this->once())
            ->method('decode')
            ->with($token, $verificationKey)
            ->willReturn($jwt);

        $this->blacklist
            ->expects($this->once())
            ->method('isBlacklisted')
            ->with('test-jti')
            ->willReturn(false);

        $this->nonceRepository
            ->expects($this->once())
            ->method('isUsed')
            ->with('test-nonce')
            ->willReturn(false);

        $this->nonceRepository
            ->expects($this->once())
            ->method('add')
            ->with('test-nonce', 3600);

        $this->claimValidator
            ->expects($this->once())
            ->method('validate')
            ->with($jwt);

        $result = $this->service->decode($token, $verificationKey);
        $this->assertSame($jwt, $result);
    }

    public function testDecodeThrowsExceptionWhenKidMismatch(): void
    {
        $token = 'valid-token';
        $verificationKey = new JwtKey('different-key', 'secret-key', 'HS256');

        $jwt = new SecureJwt(
            iss: 'test-issuer',
            customClaims: new CustomClaims(['sub' => '123']),
            iat: time(),
            nbf: time(),
            exp: time() + 300,
            jti: new Jti('test-jti'),
            nonce: new Nonce('test-nonce'),
            alg: 'HS256',
            kid: 'test-key'
        );

        // $this->driver
        //     ->expects($this->once())
        //     ->method('isValidKid')
        //     ->with($token, $verificationKey)
        //     ->willReturn($jwt);

        $this->expectException(JwtInvalidKidException::class);

        $this->service->decode($token, $verificationKey);
    }

    public function testDecodeThrowsExceptionWhenTokenBlacklisted(): void
    {
        $token = 'valid-token';
        $verificationKey = new JwtKey('test-key', 'secret-key', 'HS256');

        $jwt = new SecureJwt(
            iss: 'test-issuer',
            customClaims: new CustomClaims(['sub' => '123']),
            iat: time(),
            nbf: time(),
            exp: time() + 300,
            jti: new Jti('test-jti'),
            nonce: new Nonce('test-nonce'),
            alg: 'HS256',
            kid: 'test-key'
        );

        $this->driver
            ->expects($this->once())
            ->method('isValidKid')
            ->with($token, $verificationKey)
            ->willReturn(true);

        $this->driver
            ->expects($this->once())
            ->method('decode')
            ->with($token, $verificationKey)
            ->willReturn($jwt);

        $this->blacklist
            ->expects($this->once())
            ->method('isBlacklisted')
            ->with('test-jti')
            ->willReturn(true);

        $this->expectException(TokenBlacklistedException::class);

        $this->service->decode($token, $verificationKey);
    }

    public function testDecodeThrowsExceptionWhenNonceUsed(): void
    {
        $token = 'valid-token';
        $verificationKey = new JwtKey('test-key', 'secret-key', 'HS256');

        $jwt = new SecureJwt(
            iss: 'test-issuer',
            customClaims: new CustomClaims(['sub' => '123']),
            iat: time(),
            nbf: time(),
            exp: time() + 300,
            jti: new Jti('test-jti'),
            nonce: new Nonce('test-nonce'),
            alg: 'HS256',
            kid: 'test-key'
        );

        $this->driver
            ->expects($this->once())
            ->method('isValidKid')
            ->with($token, $verificationKey)
            ->willReturn(true);

        $this->driver
            ->expects($this->once())
            ->method('decode')
            ->with($token, $verificationKey)
            ->willReturn($jwt);

        $this->blacklist
            ->expects($this->once())
            ->method('isBlacklisted')
            ->with('test-jti')
            ->willReturn(false);

        $this->nonceRepository
            ->expects($this->once())
            ->method('isUsed')
            ->with('test-nonce')
            ->willReturn(true);

        $this->expectException(NonceUsedException::class);

        $this->service->decode($token, $verificationKey);
    }
}
