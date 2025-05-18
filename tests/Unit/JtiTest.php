<?php

declare(strict_types = 1);

namespace JuniorFontenele\LaravelSecureJwt\Tests\Unit;

use JuniorFontenele\LaravelSecureJwt\Jti;
use JuniorFontenele\LaravelSecureJwt\Tests\TestCase;
use Ramsey\Uuid\Uuid;

class JtiTest extends TestCase
{
    public function testConstructWithoutValueGeneratesUuid7(): void
    {
        $jti1 = new Jti();
        $jti2 = new Jti();

        $this->assertNotEquals($jti1->value(), $jti2->value());
        $this->assertTrue(Uuid::isValid($jti1->value()));
        $this->assertTrue(Uuid::isValid($jti2->value()));
    }

    public function testConstructWithValueUsesGivenValue(): void
    {
        $value = 'custom-jti-value';
        $jti = new Jti($value);

        $this->assertEquals($value, $jti->value());
    }

    public function testToStringReturnsValue(): void
    {
        $value = 'custom-jti-value';
        $jti = new Jti($value);

        $this->assertEquals($value, (string) $jti);
    }
}
