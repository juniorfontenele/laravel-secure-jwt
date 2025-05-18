<?php

declare(strict_types = 1);

namespace JuniorFontenele\LaravelSecureJwt;

class Nonce
{
    private string $value;

    public function __construct(
        ?string $value = null,
    ) {
        $this->value = $value ?? bin2hex(random_bytes(16));
    }

    public function value(): string
    {
        return $this->value;
    }

    public function __toString(): string
    {
        return $this->value();
    }
}
