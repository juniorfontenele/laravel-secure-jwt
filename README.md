# Laravel Secure JWT

[![Latest Version on Packagist](https://img.shields.io/packagist/v/juniorfontenele/laravel-secure-jwt.svg?style=flat-square)](https://packagist.org/packages/juniorfontenele/laravel-secure-jwt)
[![Tests](https://img.shields.io/github/actions/workflow/status/juniorfontenele/laravel-secure-jwt/tests.yml?branch=main&label=tests&style=flat-square)](https://github.com/juniorfontenele/laravel-secure-jwt/actions/workflows/tests.yml)
[![Total Downloads](https://img.shields.io/packagist/dt/juniorfontenele/laravel-secure-jwt.svg?style=flat-square)](https://packagist.org/packages/juniorfontenele/laravel-secure-jwt)

A secure and flexible JWT (JSON Web Token) implementation for Laravel applications. This package provides a robust wrapper around firebase/php-jwt with additional security features like nonce validation, blacklisting, and comprehensive claim validation.

## Features

- Secure JWT generation and validation
- Token blacklisting to revoke tokens
- Nonce validation to prevent token replay attacks
- Comprehensive claim validation (expiration, issuance time, not before)
- Custom claims support
- Laravel Cache integration for token storage

## Installation

You can install the package via composer:

```bash
composer require juniorfontenele/laravel-secure-jwt
```

The package will automatically register its service provider if you're using Laravel.

## Configuration

Publish the configuration file:

```bash
php artisan vendor:publish --tag="secure-jwt-config"
```

This will create a `config/secure-jwt.php` file with the following options:

```php
return [
    'issuer' => env('JWT_ISSUER', env('APP_URL')),
    'ttl' => env('JWT_TTL', 300), // 5 minutes
    'nonce_ttl' => env('JWT_NONCE_TTL', 86400), // 24 hours
    'blacklist_ttl' => env('JWT_BLACKLIST_TTL', 2592000), // 30 days
];
```

## Usage

### Creating a JWT

```php
use JuniorFontenele\LaravelSecureJwt\Facades\SecureJwt;
use JuniorFontenele\LaravelSecureJwt\CustomClaims;
use JuniorFontenele\LaravelSecureJwt\JwtKey;

// Create a signing key
$signingKey = new JwtKey(
    id: 'key-1',
    key: 'your-secret-key', // or load from secure storage
    algorithm: 'HS256'
);

// Create custom claims
$customClaims = new CustomClaims([
    'user_id' => 123,
    'email' => 'user@example.com',
    'roles' => ['admin', 'editor']
]);

// Generate JWT token
$token = SecureJwt::generateToken($customClaims, $signingKey);
```

### Validating a JWT

```php
use JuniorFontenele\LaravelSecureJwt\Facades\SecureJwt;
use JuniorFontenele\LaravelSecureJwt\JwtKey;

// Create a verification key (same as signing key for symmetric algorithms)
$verificationKey = new JwtKey(
    id: 'key-1',
    key: 'your-secret-key',
    algorithm: 'HS256'
);

try {
    // Verify and decode the token
    $decodedJwt = SecureJwt::decode($token, $verificationKey);
    
    // Access custom claims
    $userId = $decodedJwt->claim('user_id');
    $email = $decodedJwt->claim('email');
    
    // Access all claims
    $allClaims = $decodedJwt->claims();
} catch (JwtExpiredException $e) {
    // Token has expired
} catch (JwtNotValidYetException $e) {
    // Token not valid yet (nbf claim)
} catch (TokenBlacklistedException $e) {
    // Token has been blacklisted
} catch (NonceUsedException $e) {
    // Token nonce has been used before (replay attack)
} catch (JwtValidationException $e) {
    // Other validation errors
} catch (JwtException $e) {
    // Generic JWT errors
}
```

### Blacklisting a Token

```php
use JuniorFontenele\LaravelSecureJwt\Facades\SecureJwt;

// Blacklist a token using the decoded JWT
SecureJwt::blacklist($decodedJwt->jti());

// Check if a token is blacklisted
$isBlacklisted = SecureJwt::isBlacklisted($decodedJwt->jti());

// Remove a token from the blacklist
SecureJwt::removeFromBlacklist($decodedJwt->jti());
```

## Advanced Usage

### Using Asymmetric Keys (RS256, ES256, etc.)

```php
use JuniorFontenele\LaravelSecureJwt\Facades\SecureJwt;
use JuniorFontenele\LaravelSecureJwt\JwtKey;

// Signing with private key
$signingKey = new JwtKey(
    id: 'key-1',
    key: file_get_contents('/path/to/private.key'),
    algorithm: 'RS256'
);

// Create a token
$token = SecureJwt::generateToken($customClaims, $signingKey);

// Verifying with public key
$verificationKey = new JwtKey(
    id: 'key-1',
    key: file_get_contents('/path/to/public.key'),
    algorithm: 'RS256'
);

$decodedJwt = SecureJwt::decode($token, $verificationKey);
```

## Testing

```bash
composer test
```

## Changelog

Please see [CHANGELOG](CHANGELOG.md) for more information on what has changed recently.

## Contributing

Please see [CONTRIBUTING](CONTRIBUTING.md) for details.

## Security Vulnerabilities

Please review [our security policy](../../security/policy) on how to report security vulnerabilities.

## Credits

- [Junior Fontenele](https://github.com/juniorfontenele)
- [All Contributors](../../contributors)

## License

The MIT License (MIT). Please see [License File](LICENSE.md) for more information.
