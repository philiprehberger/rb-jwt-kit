# Changelog

All notable changes to this gem will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.1] - 2026-03-24

### Changed
- Expand test coverage to 50+ examples covering edge cases and error paths

## [0.1.0] - 2026-03-21

### Added
- JWT encoding with HMAC-SHA256/384/512 signing
- JWT decoding with signature verification
- Automatic claim management (exp, iat, iss, jti)
- Expiration and issuer validation
- Access/refresh token pair generation
- Token refresh from valid refresh tokens
- In-memory token revocation with thread-safe store
- Configurable secret, algorithm, issuer, and expiration
- Zero external dependencies (uses Ruby's built-in OpenSSL)
