<?php

declare(strict_types = 1);

namespace JuniorFontenele\LaravelSecureJwt;

use Ramsey\Uuid\Uuid;

class Jti
{
    private string $value;

    public function __construct(
        ?string $value = null,
    ) {
        $this->value = $value ?? Uuid::uuid7()->toString();
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
