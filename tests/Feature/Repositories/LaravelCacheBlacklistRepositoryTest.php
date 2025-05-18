<?php

declare(strict_types = 1);

namespace JuniorFontenele\LaravelSecureJwt\Tests\Feature\Repositories;

use Illuminate\Support\Facades\Cache;
use JuniorFontenele\LaravelSecureJwt\Repositories\LaravelCacheBlacklistRepository;
use JuniorFontenele\LaravelSecureJwt\Tests\TestCase;

class LaravelCacheBlacklistRepositoryTest extends TestCase
{
    private LaravelCacheBlacklistRepository $repository;

    private string $testJti = 'test-jti-12345';

    private string $cacheKeyPrefix = 'jwt:jti-blacklist:';

    protected function setUp(): void
    {
        parent::setUp();

        $this->repository = new LaravelCacheBlacklistRepository();

        // Clear any existing test data
        Cache::forget($this->cacheKeyPrefix . $this->testJti);
    }

    public function testAddPutsJtiInBlacklist(): void
    {
        // Arrange
        $ttl = 3600; // 1 hour

        // Act
        $this->repository->add($this->testJti, $ttl);

        // Assert
        $this->assertTrue(Cache::has($this->cacheKeyPrefix . $this->testJti));
    }

    public function testIsBlacklistedReturnsTrueForBlacklistedJti(): void
    {
        // Arrange
        $ttl = 3600;
        $this->repository->add($this->testJti, $ttl);

        // Act
        $result = $this->repository->isBlacklisted($this->testJti);

        // Assert
        $this->assertTrue($result);
    }

    public function testIsBlacklistedReturnsFalseForNonBlacklistedJti(): void
    {
        // Act
        $result = $this->repository->isBlacklisted($this->testJti);

        // Assert
        $this->assertFalse($result);
    }

    public function testRemoveDeletesJtiFromBlacklist(): void
    {
        // Arrange
        $ttl = 3600;
        $this->repository->add($this->testJti, $ttl);

        // Act
        $this->repository->remove($this->testJti);

        // Assert
        $this->assertFalse(Cache::has($this->cacheKeyPrefix . $this->testJti));
        $this->assertFalse($this->repository->isBlacklisted($this->testJti));
    }

    public function testBlacklistedJtiExpiresAfterTtl(): void
    {
        // Arrange
        $ttl = 1; // 1 second

        // Act
        $this->repository->add($this->testJti, $ttl);

        // Assert - immediately after adding
        $this->assertTrue($this->repository->isBlacklisted($this->testJti));

        // Wait for TTL to expire
        sleep(2);

        // Assert - after expiry
        $this->assertFalse($this->repository->isBlacklisted($this->testJti));
    }
}
