# philiprehberger-jwt_kit

[![Tests](https://github.com/philiprehberger/rb-jwt-kit/actions/workflows/ci.yml/badge.svg)](https://github.com/philiprehberger/rb-jwt-kit/actions/workflows/ci.yml)
[![Gem Version](https://badge.fury.io/rb/philiprehberger-jwt_kit.svg)](https://rubygems.org/gems/philiprehberger-jwt_kit)
[![GitHub release](https://img.shields.io/github/v/release/philiprehberger/rb-jwt-kit)](https://github.com/philiprehberger/rb-jwt-kit/releases)
[![Last updated](https://img.shields.io/github/last-commit/philiprehberger/rb-jwt-kit)](https://github.com/philiprehberger/rb-jwt-kit/commits/main)
[![License](https://img.shields.io/github/license/philiprehberger/rb-jwt-kit)](LICENSE)
[![Bug Reports](https://img.shields.io/github/issues/philiprehberger/rb-jwt-kit/bug)](https://github.com/philiprehberger/rb-jwt-kit/issues?q=is%3Aissue+is%3Aopen+label%3Abug)
[![Feature Requests](https://img.shields.io/github/issues/philiprehberger/rb-jwt-kit/enhancement)](https://github.com/philiprehberger/rb-jwt-kit/issues?q=is%3Aissue+is%3Aopen+label%3Aenhancement)
[![Sponsor](https://img.shields.io/badge/sponsor-GitHub%20Sponsors-ec6cb9)](https://github.com/sponsors/philiprehberger)

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

### Token Introspection

Decode a token without verifying its signature — useful for inspecting claims or determining which key to use:

```ruby
result = Philiprehberger::JwtKit.peek(token)
result[:header]   # => {"alg"=>"HS256", "typ"=>"JWT"}
result[:payload]  # => {"user_id"=>42, "exp"=>..., "iat"=>..., "jti"=>...}
```

### Audience Validation

```ruby
Philiprehberger::JwtKit.configure do |c|
  c.secret = 'secret'
  c.audience = 'my-api'      # string or array of strings
end

# Tokens automatically include the `aud` claim
token = Philiprehberger::JwtKit.encode(user_id: 42)
# Decoding validates the audience matches configuration
Philiprehberger::JwtKit.decode(token)  # => raises InvalidAudience if mismatch
```

### Custom Revocation Store

Replace the default in-memory store with any object that responds to `#revoke`, `#revoked?`, `#clear`, and `#size`:

```ruby
# Example: plug in a Redis-backed store
Philiprehberger::JwtKit.revocation_store = MyRedisRevocationStore.new
```

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
| `JwtKit.peek(token)` | Decode header and payload without signature verification |
| `JwtKit.revocation_store=` | Set a custom revocation store |

## Development

```bash
bundle install
bundle exec rspec
bundle exec rubocop
```

## Support

If you find this package useful, consider giving it a star on GitHub — it helps motivate continued maintenance and development.

[![LinkedIn](https://img.shields.io/badge/Philip%20Rehberger-LinkedIn-0A66C2?logo=linkedin)](https://www.linkedin.com/in/philiprehberger)
[![More packages](https://img.shields.io/badge/more-open%20source%20packages-blue)](https://philiprehberger.com/open-source-packages)

## License

[MIT](LICENSE)
