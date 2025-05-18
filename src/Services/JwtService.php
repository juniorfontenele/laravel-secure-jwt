<?php

declare(strict_types = 1);

namespace JuniorFontenele\LaravelSecureJwt\Services;

use JuniorFontenele\LaravelSecureJwt\Contracts\JwtBlacklistRepositoryInterface;
use JuniorFontenele\LaravelSecureJwt\Contracts\JwtClaimValidatorInterface;
use JuniorFontenele\LaravelSecureJwt\Contracts\JwtDriverInterface;
use JuniorFontenele\LaravelSecureJwt\Contracts\JwtNonceRepositoryInterface;
use JuniorFontenele\LaravelSecureJwt\CustomClaims;
use JuniorFontenele\LaravelSecureJwt\Exceptions\JwtInvalidKidException;
use JuniorFontenele\LaravelSecureJwt\Exceptions\NonceUsedException;
use JuniorFontenele\LaravelSecureJwt\Exceptions\TokenBlacklistedException;
use JuniorFontenele\LaravelSecureJwt\JwtConfig;
use JuniorFontenele\LaravelSecureJwt\JwtKey;
use JuniorFontenele\LaravelSecureJwt\SecureJwt;

class JwtService
{
    public function __construct(
        private JwtConfig $config,
        private JwtClaimValidatorInterface $claimValidator,
        private JwtDriverInterface $provider,
        private JwtBlacklistRepositoryInterface $blacklist,
        private JwtNonceRepositoryInterface $nonce,
    ) {
        //
    }

    public function generateToken(CustomClaims $customClaims, JwtKey $signingKey): string
    {
        return $this->encode($customClaims, $signingKey);
    }

    public function encode(CustomClaims $customClaims, JwtKey $signingKey): string
    {
        $jwt = SecureJwt::createNew(
            iss: $this->config->issuer(),
            kid: $signingKey->id(),
            alg: $signingKey->algorithm(),
            customClaims: $customClaims,
            ttl: $this->config->ttl(),
        );

        $token = $this->provider->encode($jwt, $signingKey);

        return $token;
    }

    /**
     * @throws JwtInvalidKidException
     * @throws TokenBlacklistedException
     * @throws NonceUsedException
     */
    public function decode(string $token, JwtKey $verificationKey): SecureJwt
    {
        if (! $this->provider->isValidKid($token, $verificationKey)) {
            throw new JwtInvalidKidException('Token kid is not valid.');
        }

        $jwt = $this->provider->decode($token, $verificationKey);

        if ($this->blacklist->isBlacklisted($jwt->jti())) {
            throw new TokenBlacklistedException('Token is blacklisted');
        }

        if ($this->nonce->isUsed($jwt->nonce())) {
            throw new NonceUsedException('Token nonce is used');
        }

        $this->nonce->add($jwt->nonce(), $this->config->nonceTtl());

        $this->claimValidator->validate($jwt);

        return $jwt;
    }

    public function blacklist(string $jti): void
    {
        $this->blacklist->add($jti, $this->config->blacklistTtl());
    }

    public function removeFromBlacklist(string $jti): void
    {
        $this->blacklist->remove($jti);
    }

    public function isBlacklisted(string $jti): bool
    {
        return $this->blacklist->isBlacklisted($jti);
    }
}
