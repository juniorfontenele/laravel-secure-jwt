<?php

declare(strict_types = 1);

namespace JuniorFontenele\LaravelSecureJwt\Tests\Unit;

use JuniorFontenele\LaravelSecureJwt\JwtConfig;
use JuniorFontenele\LaravelSecureJwt\Tests\TestCase;

class JwtConfigTest extends TestCase
{
    public function testConstructorWithDefaultValues(): void
    {
        $issuer = 'test-issuer';
        $config = new JwtConfig($issuer);

        $this->assertEquals($issuer, $config->issuer());
        $this->assertEquals(60 * 5, $config->ttl()); // 5 minutes
        $this->assertEquals(60 * 60 * 24, $config->nonceTtl()); // 24 hours
        $this->assertEquals(60 * 60 * 24 * 30, $config->blacklistTtl()); // 30 days
    }

    public function testConstructorWithCustomValues(): void
    {
        $issuer = 'test-issuer';
        $ttl = 600; // 10 minutes
        $nonceTtl = 3600; // 1 hour
        $blacklistTtl = 86400; // 1 day

        $config = new JwtConfig($issuer, $ttl, $nonceTtl, $blacklistTtl);

        $this->assertEquals($issuer, $config->issuer());
        $this->assertEquals($ttl, $config->ttl());
        $this->assertEquals($nonceTtl, $config->nonceTtl());
        $this->assertEquals($blacklistTtl, $config->blacklistTtl());
    }
}
