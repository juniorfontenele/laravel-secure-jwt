<?php

declare(strict_types = 1);

namespace JuniorFontenele\LaravelSecureJwt\Drivers;

use Firebase\JWT\JWT as FirebaseJWT;
use Firebase\JWT\Key;
use JuniorFontenele\LaravelSecureJwt\Contracts\JwtDriverInterface;
use JuniorFontenele\LaravelSecureJwt\CustomClaims;
use JuniorFontenele\LaravelSecureJwt\Jti;
use JuniorFontenele\LaravelSecureJwt\JwtKey;
use JuniorFontenele\LaravelSecureJwt\Nonce;
use JuniorFontenele\LaravelSecureJwt\SecureJwt;
use stdClass;

class FirebaseJwtDriver implements JwtDriverInterface
{
    public function encode(SecureJwt $jwt, JwtKey $signingKey): string
    {
        return FirebaseJWT::encode($jwt->payload(), $signingKey->key(), $signingKey->algorithm(), $signingKey->id());
    }

    public function decode(string $token, JwtKey $verificationKey): SecureJwt
    {
        $headers = new stdClass();
        $decoded = FirebaseJWT::decode($token, new Key($verificationKey->key(), $verificationKey->algorithm()), $headers);

        return new SecureJwt(
            iss: $decoded->iss,
            customClaims: new CustomClaims((array) $decoded),
            iat: $decoded->iat,
            nbf: $decoded->nbf,
            exp: $decoded->exp,
            jti: new Jti($decoded->jti),
            nonce: new Nonce($decoded->nonce),
            alg: $headers->alg, // @phpstan-ignore-line
            kid: $headers->kid, // @phpstan-ignore-line
            typ: $headers->typ // @phpstan-ignore-line
        );
    }
}
