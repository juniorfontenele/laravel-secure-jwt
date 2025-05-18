<?php

declare(strict_types = 1);

namespace JuniorFontenele\LaravelSecureJwt;

use JuniorFontenele\LaravelSecureJwt\Exceptions\JwtException;

class SecureJwt
{
    public function __construct(
        private string $iss,
        private CustomClaims $customClaims,
        private int $iat,
        private int $nbf,
        private int $exp,
        private Jti $jti,
        private Nonce $nonce,
        private string $alg,
        private string $kid,
        private string $typ = 'JWT',
    ) {
        if ($typ !== 'JWT') {
            throw new JwtException('Invalid type (typ). Only JWT is supported.');
        }

        if ($iat > $nbf) {
            throw new JwtException('Invalid issued at (iat). It must be less than or equal to not before (nbf).');
        }

        if ($nbf > $exp) {
            throw new JwtException('Invalid not before (nbf). It must be less than or equal to expiration (exp).');
        }

        if ($iat > $exp) {
            throw new JwtException('Invalid issued at (iat). It must be less than or equal to expiration (exp).');
        }
    }

    public static function createNew(string $iss, string $kid, string $alg, CustomClaims $customClaims, int $ttl = 60 * 5): self
    {
        $iat = time();
        $nbf = $iat;
        $exp = $iat + $ttl;
        $jti = new Jti();
        $nonce = new Nonce();

        return new self(
            iss: $iss,
            customClaims: $customClaims,
            iat: $iat,
            nbf: $nbf,
            exp: $exp,
            jti: $jti,
            nonce: $nonce,
            alg: $alg,
            kid: $kid
        );
    }

    public function iss(): string
    {
        return $this->iss;
    }

    public function nonce(): string
    {
        return $this->nonce->value();
    }

    /**
     * @return array<string, mixed>
     */
    public function claims(): array
    {
        return $this->customClaims->claims();
    }

    public function claim(string $claim): ?string
    {
        return $this->customClaims->get($claim);
    }

    public function iat(): int
    {
        return $this->iat;
    }

    public function nbf(): int
    {
        return $this->nbf;
    }

    public function exp(): int
    {
        return $this->exp;
    }

    public function jti(): string
    {
        return $this->jti->value();
    }

    public function alg(): string
    {
        return $this->alg;
    }

    public function kid(): string
    {
        return $this->kid;
    }

    public function typ(): string
    {
        return $this->typ;
    }

    /**
     * @return array<string, mixed>
     */
    public function payload(): array
    {
        return [
            'iss' => $this->iss(),
            'iat' => $this->iat(),
            'nbf' => $this->nbf(),
            'exp' => $this->exp(),
            'jti' => $this->jti(),
            'nonce' => $this->nonce(),
            ...$this->claims(),
        ];
    }

    /**
     * @return array<string, mixed>
     */
    public function header(): array
    {
        return [
            'alg' => $this->alg(),
            'kid' => $this->kid(),
            'typ' => $this->typ(),
        ];
    }
}
