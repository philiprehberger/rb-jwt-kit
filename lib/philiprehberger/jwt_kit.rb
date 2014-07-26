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
      # @return [Revocation::MemoryStore]
      def revocation_store
        @revocation_store ||= Revocation::MemoryStore.new
      end

      # Resets the revocation store.
      #
      # @return [Revocation::MemoryStore]
      def reset_revocation_store!
        @revocation_store = Revocation::MemoryStore.new
      end
    end
  end
end
