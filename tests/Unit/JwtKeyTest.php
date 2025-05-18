<?php

declare(strict_types = 1);

namespace JuniorFontenele\LaravelSecureJwt\Tests\Unit;

use JuniorFontenele\LaravelSecureJwt\JwtKey;
use JuniorFontenele\LaravelSecureJwt\Tests\TestCase;

class JwtKeyTest extends TestCase
{
    public function testConstructorAndGetters(): void
    {
        $id = 'test-key-id';
        $key = 'secret-key-value';
        $algorithm = 'HS256';

        $jwtKey = new JwtKey($id, $key, $algorithm);

        $this->assertEquals($id, $jwtKey->id());
        $this->assertEquals($key, $jwtKey->key());
        $this->assertEquals($algorithm, $jwtKey->algorithm());
    }
}
