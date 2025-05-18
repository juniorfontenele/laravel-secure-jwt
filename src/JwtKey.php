<?php

declare(strict_types = 1);

namespace JuniorFontenele\LaravelSecureJwt;

class JwtKey
{
    public function __construct(
        private string $id,
        private string $key,
        private string $algorithm,
    ) {
        //
    }

    public function id(): string
    {
        return $this->id;
    }

    public function key(): string
    {
        return $this->key;
    }

    public function algorithm(): string
    {
        return $this->algorithm;
    }
}
