# philiprehberger-jwt_kit

[![Tests](https://github.com/philiprehberger/rb-jwt-kit/actions/workflows/ci.yml/badge.svg)](https://github.com/philiprehberger/rb-jwt-kit/actions/workflows/ci.yml)
[![Gem Version](https://badge.fury.io/rb/philiprehberger-jwt_kit.svg)](https://rubygems.org/gems/philiprehberger-jwt_kit)
[![License](https://img.shields.io/github/license/philiprehberger/rb-jwt-kit)](LICENSE)

Opinionated JWT toolkit with encoding, validation, refresh tokens, and revocation

## Requirements

- Ruby >= 3.1

## Installation

Add to your Gemfile:

```ruby
gem "philiprehberger-jwt_kit"
```

Or install directly:

```bash
gem install philiprehberger-jwt_kit
```

## Usage

```ruby
require "philiprehberger/jwt_kit"

Philiprehberger::JwtKit.configure do |c|
  c.secret = "your-secret-key-at-least-32-characters"
  c.issuer = "my-app"
end

token = Philiprehberger::JwtKit.encode(user_id: 42)
payload = Philiprehberger::JwtKit.decode(token)
payload["user_id"] # => 42
```

### Configuration

```ruby
Philiprehberger::JwtKit.configure do |c|
  c.secret = "your-secret-key"          # Required — HMAC signing key
  c.algorithm = :hs256                   # :hs256 (default), :hs384, :hs512
  c.issuer = "my-app"                    # Optional — sets the `iss` claim
  c.expiration = 3600                    # Access token TTL in seconds (default: 1 hour)
  c.refresh_expiration = 86_400 * 7      # Refresh token TTL (default: 1 week)
end
```

### Encoding

```ruby
token = Philiprehberger::JwtKit.encode(user_id: 42, role: "admin")
# => "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHA..."
```

Claims `exp`, `iat`, `iss`, and `jti` are added automatically.

### Decoding

```ruby
payload = Philiprehberger::JwtKit.decode(token)
payload["user_id"] # => 42
payload["exp"]     # => 1711036800
payload["iss"]     # => "my-app"
payload["jti"]     # => "a1b2c3d4-..."
```

Decoding validates the signature, expiration, and issuer automatically.

### Token Pairs

```ruby
access_token, refresh_token = Philiprehberger::JwtKit.token_pair(user_id: 42)
```

The access token uses the standard expiration. The refresh token uses `refresh_expiration` and includes a `type: "refresh"` claim.

### Refresh Tokens

```ruby
new_access_token = Philiprehberger::JwtKit.refresh(refresh_token)
```

Validates the refresh token, verifies it has `type: "refresh"`, and issues a new access token with the original payload.

### Revocation

```ruby
Philiprehberger::JwtKit.revoke(token)
Philiprehberger::JwtKit.revoked?(token)  # => true
Philiprehberger::JwtKit.decode(token)    # => raises RevokedToken
```

Revocation uses an in-memory store keyed by JTI. The store is thread-safe.

## API

| Method | Description |
|--------|-------------|
| `JwtKit.configure { \|c\| ... }` | Configure secret, algorithm, issuer, and expiration |
| `JwtKit.configuration` | Returns the current configuration |
| `JwtKit.reset_configuration!` | Resets configuration to defaults |
| `JwtKit.encode(payload)` | Encodes a payload into a signed JWT token |
| `JwtKit.decode(token)` | Decodes and validates a JWT token |
| `JwtKit.token_pair(payload)` | Generates an access/refresh token pair |
| `JwtKit.refresh(refresh_token)` | Issues a new access token from a refresh token |
| `JwtKit.revoke(token)` | Revokes a token by its JTI |
| `JwtKit.revoked?(token)` | Checks if a token has been revoked |

## Development

```bash
bundle install
bundle exec rspec
bundle exec rubocop
```

## License

MIT
