<?php

declare(strict_types = 1);

namespace JuniorFontenele\LaravelSecureJwt\Tests\Feature\Repositories;

use Illuminate\Support\Facades\Cache;
use JuniorFontenele\LaravelSecureJwt\Repositories\LaravelCacheNonceRepository;
use JuniorFontenele\LaravelSecureJwt\Tests\TestCase;

class LaravelCacheNonceRepositoryTest extends TestCase
{
    private LaravelCacheNonceRepository $repository;

    private string $testNonce = 'test-nonce-12345';

    private string $cacheKeyPrefix = 'jwt:nonce:';

    protected function setUp(): void
    {
        parent::setUp();

        $this->repository = new LaravelCacheNonceRepository();

        // Clear any existing test data
        Cache::forget($this->cacheKeyPrefix . $this->testNonce);
    }

    public function testAddMarksNonceAsUsed(): void
    {
        // Arrange
        $ttl = 3600; // 1 hour

        // Act
        $this->repository->add($this->testNonce, $ttl);

        // Assert
        $this->assertTrue(Cache::has($this->cacheKeyPrefix . $this->testNonce));
    }

    public function testIsUsedReturnsTrueForUsedNonce(): void
    {
        // Arrange
        $ttl = 3600;
        $this->repository->add($this->testNonce, $ttl);

        // Act
        $result = $this->repository->isUsed($this->testNonce);

        // Assert
        $this->assertTrue($result);
    }

    public function testIsUsedReturnsFalseForUnusedNonce(): void
    {
        // Act
        $result = $this->repository->isUsed($this->testNonce);

        // Assert
        $this->assertFalse($result);
    }

    public function testUsedNonceExpiresAfterTtl(): void
    {
        // Arrange
        $ttl = 1; // 1 second

        // Act
        $this->repository->add($this->testNonce, $ttl);

        // Assert - immediately after adding
        $this->assertTrue($this->repository->isUsed($this->testNonce));

        // Wait for TTL to expire
        sleep(2);

        // Assert - after expiry
        $this->assertFalse($this->repository->isUsed($this->testNonce));
    }
}
