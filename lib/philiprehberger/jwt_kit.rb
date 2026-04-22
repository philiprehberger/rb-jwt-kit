# frozen_string_literal: true

require 'openssl'
require 'json'
require 'securerandom'
require 'base64'
require_relative 'jwt_kit/version'
require_relative 'jwt_kit/configuration'
require_relative 'jwt_kit/encoder'
require_relative 'jwt_kit/decoder'
require_relative 'jwt_kit/token_pair'
require_relative 'jwt_kit/revocation'

module Philiprehberger
  module JwtKit
    class Error < StandardError; end
    class DecodeError < Error; end
    class TokenExpired < DecodeError; end
    class InvalidSignature < DecodeError; end
    class InvalidIssuer < DecodeError; end
    class InvalidToken < DecodeError; end
    class InvalidAudience < DecodeError; end
    class TokenNotYetValid < DecodeError; end
    class RevokedToken < DecodeError; end

    class << self
      # Configures JwtKit using a block.
      #
      # @yieldparam config [Configuration] the configuration instance
      # @return [void]
      def configure
        yield(configuration)
      end

      # Returns the current configuration.
      #
      # @return [Configuration]
      def configuration
        @configuration ||= Configuration.new
      end

      # Resets the configuration to defaults.
      #
      # @return [Configuration]
      def reset_configuration!
        @configuration = Configuration.new
      end

      # Validates a token and returns a result hash instead of raising.
      #
      # @param token [String] JWT token
      # @return [Hash] { valid: Boolean, payload: Hash or nil, error: String or nil }
      def validate(token)
        payload = decode(token)
        { valid: true, payload: payload, error: nil }
      rescue DecodeError, RevokedToken => e
        { valid: false, payload: nil, error: e.message }
      end

      # Checks whether a token's `exp` claim is in the past without verifying the signature.
      # Useful for proactive refresh decisions. Returns `true` for malformed tokens or when
      # `exp` is missing.
      #
      # @param token [String] JWT token
      # @return [Boolean]
      def expired?(token)
        payload = peek(token)[:payload]
        exp = payload['exp']
        return true unless exp.is_a?(Numeric)

        Time.now.to_i >= exp
      rescue DecodeError
        true
      end

      # Encodes a payload into a signed JWT token.
      #
      # @param payload [Hash] custom claims
      # @return [String] signed JWT token
      def encode(payload = {})
        Encoder.encode(payload, configuration)
      end

      # Decodes a JWT token and validates its claims.
      #
      # @param token [String] JWT token
      # @return [Hash] decoded payload
      # @raise [RevokedToken] if the token has been revoked
      def decode(token)
        payload = Decoder.decode(token, configuration)
        raise RevokedToken, 'Token has been revoked' if revocation_store.revoked?(token)

        payload
      end

      # Decodes a JWT token WITHOUT verifying the signature.
      # Useful for inspecting the header and payload before choosing a key.
      #
      # @param token [String] JWT token
      # @return [Hash] with :header and :payload keys
      # @raise [DecodeError] if the token format is invalid
      def peek(token)
        Decoder.peek(token)
      end

      # Generates an access/refresh token pair.
      #
      # @param payload [Hash] custom claims
      # @return [Array<String>] `[access_token, refresh_token]`
      def token_pair(payload = {})
        TokenPair.generate(payload, configuration)
      end

      # Generates a new access token from a refresh token.
      #
      # @param refresh_token [String] valid refresh token
      # @return [String] new access token
      def refresh(refresh_token)
        TokenPair.refresh(refresh_token, configuration)
      end

      # Revokes a token.
      #
      # @param token [String] JWT token to revoke
      # @return [void]
      def revoke(token)
        revocation_store.revoke(token)
      end

      # Checks whether a token has been revoked.
      #
      # @param token [String] JWT token
      # @return [Boolean]
      def revoked?(token)
        revocation_store.revoked?(token)
      end

      # Returns the revocation store.
      #
      # @return [#revoke, #revoked?, #clear, #size]
      def revocation_store
        @revocation_store ||= Revocation::MemoryStore.new
      end

      # Sets a custom revocation store (must respond to #revoke, #revoked?, #clear, #size).
      #
      # @param store [#revoke, #revoked?, #clear, #size]
      # @return [void]
      attr_writer :revocation_store

      # Resets the revocation store to the default MemoryStore.
      #
      # @return [Revocation::MemoryStore]
      def reset_revocation_store!
        @revocation_store = Revocation::MemoryStore.new
      end
    end
  end
end
