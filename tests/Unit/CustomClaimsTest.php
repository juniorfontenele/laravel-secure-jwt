<?php

declare(strict_types = 1);

namespace JuniorFontenele\LaravelSecureJwt\Tests\Unit;

use JuniorFontenele\LaravelSecureJwt\CustomClaims;
use JuniorFontenele\LaravelSecureJwt\Tests\TestCase;

class CustomClaimsTest extends TestCase
{
    public function testConstructorFiltersOutReservedClaims(): void
    {
        $claims = [
            'sub' => '123',
            'name' => 'Test User',
            'email' => 'test@example.com',
            'iss' => 'should-be-filtered',
            'exp' => 12345,
            'nbf' => 12345,
            'iat' => 12345,
            'jti' => 'should-be-filtered',
            'nonce' => 'should-be-filtered',
            'typ' => 'should-be-filtered',
            'alg' => 'should-be-filtered',
            'kid' => 'should-be-filtered',
        ];

        $customClaims = new CustomClaims($claims);
        $result = $customClaims->claims();

        $this->assertArrayHasKey('sub', $result);
        $this->assertArrayHasKey('name', $result);
        $this->assertArrayHasKey('email', $result);

        $this->assertArrayNotHasKey('iss', $result);
        $this->assertArrayNotHasKey('exp', $result);
        $this->assertArrayNotHasKey('nbf', $result);
        $this->assertArrayNotHasKey('iat', $result);
        $this->assertArrayNotHasKey('jti', $result);
        $this->assertArrayNotHasKey('nonce', $result);
        $this->assertArrayNotHasKey('typ', $result);
        $this->assertArrayNotHasKey('alg', $result);
        $this->assertArrayNotHasKey('kid', $result);
    }

    public function testEmptyClaimsConstructor(): void
    {
        $customClaims = new CustomClaims();
        $this->assertEmpty($customClaims->claims());
    }
}
