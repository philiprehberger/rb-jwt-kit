# frozen_string_literal: true

require_relative 'lib/philiprehberger/jwt_kit/version'

Gem::Specification.new do |spec|
  spec.name          = 'philiprehberger-jwt_kit'
  spec.version       = Philiprehberger::JwtKit::VERSION
  spec.authors       = ['Philip Rehberger']
  spec.email         = ['me@philiprehberger.com']

  spec.summary       = 'Opinionated JWT toolkit with encoding, validation, refresh tokens, and revocation'
  spec.description   = 'A complete JWT toolkit for Ruby. Encode and decode tokens with automatic claim ' \
                       'management (exp, iat, iss, jti), generate access/refresh token pairs, validate ' \
                       'expiration and issuer, and revoke tokens — all without external dependencies.'
  spec.homepage      = 'https://philiprehberger.com/open-source-packages/ruby/philiprehberger-jwt_kit'
  spec.license       = 'MIT'

  spec.required_ruby_version = '>= 3.1.0'

  spec.metadata['homepage_uri']          = spec.homepage
  spec.metadata['source_code_uri']       = 'https://github.com/philiprehberger/rb-jwt-kit'
  spec.metadata['changelog_uri']         = 'https://github.com/philiprehberger/rb-jwt-kit/blob/main/CHANGELOG.md'
  spec.metadata['bug_tracker_uri']       = 'https://github.com/philiprehberger/rb-jwt-kit/issues'
  spec.metadata['rubygems_mfa_required'] = 'true'

  spec.files         = Dir['lib/**/*.rb', 'LICENSE', 'README.md', 'CHANGELOG.md']
  spec.require_paths = ['lib']
end
