<?php

declare(strict_types = 1);

namespace JuniorFontenele\LaravelSecureJwt;

class CustomClaims
{
    /**
     * @param array<string, mixed> $claims
    */
    public function __construct(
        private array $claims = [],
    ) {
        $this->claims = array_filter($claims, function ($value, $key) {
            return ! in_array($key, [
                'iss',
                'exp',
                'nbf',
                'iat',
                'jti',
                'nonce',
                'typ',
                'alg',
                'kid',
            ]);
        }, ARRAY_FILTER_USE_BOTH);
    }

    /**
     * @return array<string, mixed>
     */
    public function claims(): array
    {
        return $this->claims;
    }

    public function get(string $claim): ?string
    {
        return $this->claims[$claim] ?? null;
    }
}
