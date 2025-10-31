# QUIC TLS Library

[English](README.md) | [中文](README.zh-CN.md)

[![Latest Version](https://img.shields.io/packagist/v/tourze/quic-tls.svg?style=flat-square)](https://packagist.org/packages/tourze/quic-tls)
[![PHP Version](https://img.shields.io/badge/php-%3E%3D8.1-8892BF.svg?style=flat-square)](https://php.net/)
[![License](https://img.shields.io/badge/license-MIT-green.svg?style=flat-square)](LICENSE)
[![Code Coverage](https://img.shields.io/badge/coverage-90%25-brightgreen.svg?style=flat-square)](#)
[![Total Downloads](https://img.shields.io/packagist/dt/tourze/quic-tls.svg?style=flat-square)](https://packagist.org/packages/tourze/quic-tls)

A PHP implementation of TLS 1.3 handshake for QUIC protocol, providing secure cryptographic communication layer for QUIC connections.

## Table of Contents

- [Features](#features)
- [Dependencies](#dependencies)
- [Installation](#installation)
- [Quick Start](#quick-start)
  - [1. Basic Certificate Validation](#1-basic-certificate-validation)
  - [2. Simple TLS Handshake](#2-simple-tls-handshake)
  - [3. Basic Transport Parameters](#3-basic-transport-parameters)
- [Basic Usage](#basic-usage)
  - [Certificate Validation](#certificate-validation)
  - [TLS Handshake](#tls-handshake)
  - [Transport Parameters](#transport-parameters)
- [Advanced Usage](#advanced-usage)
  - [Custom Certificate Validation](#custom-certificate-validation)
  - [Message Handling](#message-handling)
- [Configuration](#configuration)
  - [Certificate Validator Options](#certificate-validator-options)
  - [Transport Parameters Configuration](#transport-parameters-configuration)
- [Error Handling](#error-handling)
- [Testing](#testing)
- [References](#references)
- [License](#license)

## Features

- 🔒 Complete TLS 1.3 handshake implementation
- 📜 X.509 certificate validation and verification
- 🌐 Hostname verification with wildcard support
- 🔑 Certificate chain validation
- ⚙️ Transport parameter negotiation
- 🛡️ Comprehensive error handling
- 🧪 Modular validator architecture
- ✅ Extensive test coverage

## Dependencies

- PHP 8.1 or higher
- ext-openssl: OpenSSL extension
- tourze/quic-core: QUIC core protocol implementation
- tourze/quic-crypto: QUIC cryptographic functions

## Installation

```bash
composer require tourze/quic-tls
```

## Quick Start

Get up and running with QUIC TLS in minutes:

### 1. Basic Certificate Validation

```php
<?php
require_once 'vendor/autoload.php';

use Tourze\QUIC\TLS\CertificateValidator;

// Create a validator with default settings
$validator = new CertificateValidator();

// Validate a certificate (assuming you have certificate data)
try {
    $isValid = $validator->validateCertificate([$certificateData]);
    echo $isValid ? "Certificate is valid" : "Certificate is invalid";
} catch (Exception $e) {
    echo "Validation error: " . $e->getMessage();
}
```

### 2. Simple TLS Handshake

```php
<?php
use Tourze\QUIC\TLS\HandshakeStateMachine;

// Create client handshake
$handshake = new HandshakeStateMachine(false); // false = client mode

// Start the handshake
$clientHello = $handshake->startClientHandshake();

// Send clientHello to server and get serverHello back
// $serverResponse = sendToServer($clientHello);
// $result = $handshake->processMessage($serverResponse);
```

### 3. Basic Transport Parameters

```php
<?php
use Tourze\QUIC\TLS\TransportParameters;

// Create transport parameters with common settings
$params = new TransportParameters([
    TransportParameters::PARAM_MAX_IDLE_TIMEOUT => 30000,      // 30 seconds
    TransportParameters::PARAM_MAX_UDP_PAYLOAD_SIZE => 1200,   // 1.2KB
    TransportParameters::PARAM_INITIAL_MAX_DATA => 1048576,    // 1MB
]);

// Encode for transmission
$encoded = $params->encode();
```

That's it! You're now ready to use QUIC TLS. For more detailed examples, see the sections below.

## Basic Usage

### Certificate Validation

```php
use Tourze\QUIC\TLS\CertificateValidator;

// Create validator with custom options
$validator = new CertificateValidator([
    'verify_peer' => true,
    'verify_peer_name' => true,
    'allow_self_signed' => false,
    'verify_depth' => 7
]);

// Validate certificate chain
$certificates = [$leafCert, $intermediateCert, $rootCert];
$isValid = $validator->validateCertificate($certificates);

// Validate with hostname
$isValid = $validator->validateCertificateChain($certificates, 'example.com');
```

### TLS Handshake

```php
use Tourze\QUIC\TLS\HandshakeStateMachine;

// Initialize handshake state machine
$handshake = new HandshakeStateMachine(false); // false for client

// Start client handshake
$clientHello = $handshake->startClientHandshake();

// Process server messages
$response = $handshake->processMessage($serverMessage);
```

### Transport Parameters

```php
use Tourze\QUIC\TLS\TransportParameters;

// Create transport parameters
$localParams = new TransportParameters([
    TransportParameters::PARAM_MAX_IDLE_TIMEOUT => 30000,
    TransportParameters::PARAM_MAX_UDP_PAYLOAD_SIZE => 1200,
    TransportParameters::PARAM_INITIAL_MAX_DATA => 1048576
]);

// Negotiate with peer parameters
$peerParams = TransportParameters::decode($peerData);
$negotiated = $localParams->negotiate($peerParams);
```

## Advanced Usage

### Custom Certificate Validation

```php
use Tourze\QUIC\TLS\Validator\CertificateChainValidator;
use Tourze\QUIC\TLS\Validator\HostnameValidator;
use Tourze\QUIC\TLS\Validator\CALoader;

// Custom CA loading
$caLoader = new CALoader();
$caLoader->addTrustedCA($customCACert);
$caLoader->loadSystemCAs();

// Custom chain validation
$chainValidator = new CertificateChainValidator(
    $caLoader->getTrustedCAs(),
    true, // allow self-signed
    10    // max depth
);

// Custom hostname validation
$hostnameValidator = new HostnameValidator(true);
$isValidHostname = $hostnameValidator->validateHostname($cert, 'example.com');
```

### Message Handling

```php
use Tourze\QUIC\TLS\Message\ClientHello;
use Tourze\QUIC\TLS\Message\ServerHello;

// Decode messages
$clientHello = ClientHello::decode($binaryData);
$serverHello = ServerHello::decode($binaryData);

// Access message properties
$cipherSuites = $clientHello->getCipherSuites();
$extensions = $serverHello->getExtensions();
```

## Configuration

### Certificate Validator Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `verify_peer` | bool | `true` | Enable peer certificate verification |
| `verify_peer_name` | bool | `true` | Enable hostname verification |
| `allow_self_signed` | bool | `false` | Allow self-signed certificates |
| `verify_depth` | int | `7` | Maximum certificate chain depth |
| `ca_file` | string | auto | Path to CA certificate file |
| `check_revocation` | bool | `false` | Enable certificate revocation checking |

### Transport Parameters Configuration

| Parameter | Description |
|-----------|-------------|
| `PARAM_MAX_IDLE_TIMEOUT` | Maximum idle timeout in milliseconds |
| `PARAM_MAX_UDP_PAYLOAD_SIZE` | Maximum UDP payload size |
| `PARAM_INITIAL_MAX_DATA` | Initial maximum data limit |
| `PARAM_INITIAL_MAX_STREAMS_BIDI` | Initial maximum bidirectional streams |
| `PARAM_INITIAL_MAX_STREAMS_UNI` | Initial maximum unidirectional streams |

## Error Handling

The library provides specific exception types for different error conditions:

```php
use Tourze\QUIC\TLS\Exception\{CertificateValidationException, InvalidCertificateException, TlsProtocolException};

try {
    $validator->validateCertificate($certificates);
} catch (CertificateValidationException $e) {
    // Certificate validation failed
} catch (InvalidCertificateException $e) {
    // Invalid certificate format
} catch (TlsProtocolException $e) {
    // TLS protocol error
}
```

## Testing

```bash
# Run tests
vendor/bin/phpunit packages/quic-tls/tests

# Run with coverage
vendor/bin/phpunit packages/quic-tls/tests --coverage-html coverage

# Static analysis
vendor/bin/phpstan analyse packages/quic-tls
```

## References

- [RFC 9000: QUIC: A UDP-Based Multiplexed and Secure Transport](https://tools.ietf.org/html/rfc9000)
- [RFC 8446: The Transport Layer Security (TLS) Protocol Version 1.3](https://tools.ietf.org/html/rfc8446)
- [RFC 9001: Using TLS to Secure QUIC](https://tools.ietf.org/html/rfc9001)
- [QUIC Transport Parameters](https://www.iana.org/assignments/quic/quic.xhtml)

## Contributing

We welcome contributions! Please follow these guidelines:

1. **Issues**: Use GitHub issues to report bugs or request features
2. **Pull Requests**: 
    - Fork the repository
    - Create a feature branch
    - Write tests for your changes
    - Ensure all tests pass
    - Submit a pull request with a clear description
3. **Code Style**: Follow PSR-12 coding standard
4. **Testing**: All code must be covered by tests

### Development Setup

```bash
# Clone the repository
git clone https://github.com/your-repo/php-monorepo.git
cd php-monorepo

# Install dependencies
composer install

# Run tests
./vendor/bin/phpunit packages/quic-tls/tests

# Run static analysis
./vendor/bin/phpstan analyse packages/quic-tls
```

## Changelog

### [Unreleased]
- Optimized code using PHP 8 readonly property promotion
- Improved type safety and code organization
- Enhanced test coverage

### [0.0.1] - Initial Release
- Complete TLS 1.3 handshake implementation
- X.509 certificate validation
- Hostname verification with wildcard support
- Transport parameter negotiation
- Comprehensive error handling

## License

The MIT License (MIT). Please see [License File](LICENSE) for more information.