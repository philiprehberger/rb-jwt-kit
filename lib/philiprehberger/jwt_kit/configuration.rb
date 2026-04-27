# frozen_string_literal: true

module Philiprehberger
  module JwtKit
    # Configuration singleton for JWT settings.
    #
    # @example
    #   Philiprehberger::JwtKit.configure do |c|
    #     c.secret = 'my-secret-key'
    #     c.algorithm = :hs256
    #     c.issuer = 'my-app'
    #     c.expiration = 3600
    #   end
    class Configuration
      # @return [String, nil] HMAC secret key (required for HS* algorithms)
      attr_accessor :secret

      # @return [Symbol] signing algorithm (:hs256, :hs384, :hs512)
      attr_accessor :algorithm

      # @return [String, nil] optional issuer for the `iss` claim
      attr_accessor :issuer

      # @return [String, Array<String>, nil] expected audience for the `aud` claim
      attr_accessor :audience

      # @return [Integer] default TTL in seconds for access tokens
      attr_accessor :expiration

      # @return [Integer] default TTL in seconds for refresh tokens
      attr_accessor :refresh_expiration

      # @return [Array<Hash>, nil] array of { kid: String, secret: String } for key rotation
      attr_accessor :secrets

      def initialize
        @secret = nil
        @algorithm = :hs256
        @issuer = nil
        @audience = nil
        @expiration = 3600
        @refresh_expiration = 86_400 * 7
        @secrets = nil
        @on_encode = nil
        @on_decode = nil
        @on_refresh = nil
        @on_revoke = nil
      end

      # Registers a callback fired after a successful encode.
      #
      # @yieldparam token [String] the encoded JWT token
      # @yieldparam payload [Hash] the merged payload that was encoded
      # @return [Proc] the stored callback
      def on_encode(&block)
        @on_encode = block
      end

      # Registers a callback fired after a successful decode.
      #
      # @yieldparam payload [Hash] the decoded payload
      # @return [Proc] the stored callback
      def on_decode(&block)
        @on_decode = block
      end

      # Registers a callback fired after a successful refresh.
      #
      # @yieldparam new_token [String] the newly issued access token
      # @return [Proc] the stored callback
      def on_refresh(&block)
        @on_refresh = block
      end

      # Registers a callback fired after a successful revoke.
      #
      # @yieldparam jti [String, nil] the revoked token's JTI
      # @return [Proc] the stored callback
      def on_revoke(&block)
        @on_revoke = block
      end

      # Invokes the on_encode callback if registered. Errors raised by the callback are swallowed.
      #
      # @param token [String]
      # @param payload [Hash]
      # @return [void]
      def fire_on_encode(token, payload)
        return unless @on_encode

        @on_encode.call(token, payload)
      rescue StandardError
        nil
      end

      # Invokes the on_decode callback if registered. Errors raised by the callback are swallowed.
      #
      # @param payload [Hash]
      # @return [void]
      def fire_on_decode(payload)
        return unless @on_decode

        @on_decode.call(payload)
      rescue StandardError
        nil
      end

      # Invokes the on_refresh callback if registered. Errors raised by the callback are swallowed.
      #
      # @param new_token [String]
      # @return [void]
      def fire_on_refresh(new_token)
        return unless @on_refresh

        @on_refresh.call(new_token)
      rescue StandardError
        nil
      end

      # Invokes the on_revoke callback if registered. Errors raised by the callback are swallowed.
      #
      # @param jti [String, nil]
      # @return [void]
      def fire_on_revoke(jti)
        return unless @on_revoke

        @on_revoke.call(jti)
      rescue StandardError
        nil
      end

      # Returns the OpenSSL digest algorithm name.
      #
      # @return [String] digest name (e.g. 'SHA256')
      # @raise [Error] if the algorithm is unsupported
      def digest_algorithm
        case @algorithm
        when :hs256 then 'SHA256'
        when :hs384 then 'SHA384'
        when :hs512 then 'SHA512'
        else raise Error, "Unsupported algorithm: #{@algorithm}"
        end
      end

      # Returns the JWT algorithm header value.
      #
      # @return [String] algorithm name (e.g. 'HS256')
      def algorithm_name
        @algorithm.to_s.upcase
      end
    end
  end
end
