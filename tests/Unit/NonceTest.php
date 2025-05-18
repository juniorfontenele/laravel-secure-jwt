<?php

declare(strict_types = 1);

namespace JuniorFontenele\LaravelSecureJwt\Tests\Unit;

use JuniorFontenele\LaravelSecureJwt\Nonce;
use JuniorFontenele\LaravelSecureJwt\Tests\TestCase;

class NonceTest extends TestCase
{
    public function testConstructWithoutValueGeneratesRandomNonce(): void
    {
        $nonce1 = new Nonce();
        $nonce2 = new Nonce();

        $this->assertNotEquals($nonce1->value(), $nonce2->value());
        $this->assertMatchesRegularExpression('/^[0-9a-f]{32}$/', $nonce1->value());
        $this->assertMatchesRegularExpression('/^[0-9a-f]{32}$/', $nonce2->value());
    }

    public function testConstructWithValueUsesGivenValue(): void
    {
        $value = 'custom-nonce-value';
        $nonce = new Nonce($value);

        $this->assertEquals($value, $nonce->value());
    }

    public function testToStringReturnsValue(): void
    {
        $value = 'custom-nonce-value';
        $nonce = new Nonce($value);

        $this->assertEquals($value, (string) $nonce);
    }
}
