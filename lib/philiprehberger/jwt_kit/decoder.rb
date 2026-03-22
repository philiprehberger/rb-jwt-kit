# frozen_string_literal: true

module Philiprehberger
  module JwtKit
    # Decodes and validates JWT tokens.
    module Decoder
      module_function

      # Decodes a JWT token and validates its claims.
      #
      # @param token [String] JWT token string
      # @param config [Configuration] JWT configuration
      # @return [Hash] decoded payload with string keys
      # @raise [DecodeError] if the token format is invalid
      # @raise [InvalidSignature] if the signature does not match
      # @raise [TokenExpired] if the token has expired
      # @raise [InvalidIssuer] if the issuer does not match the configuration
      def decode(token, config)
        raise DecodeError, 'Token must be a string' unless token.is_a?(String)

        parts = token.split('.')
        raise DecodeError, 'Invalid token format: expected 3 segments' unless parts.length == 3

        header_segment, payload_segment, signature_segment = parts

        verify_signature!("#{header_segment}.#{payload_segment}", signature_segment, config)

        payload = JSON.parse(base64url_decode(payload_segment))

        validate_expiration!(payload)
        validate_issuer!(payload, config)

        payload
      rescue JSON::ParserError
        raise DecodeError, 'Invalid token: malformed JSON'
      end

      # Base64url-decodes a string.
      #
      # @param data [String] base64url-encoded string
      # @return [String] decoded string
      def base64url_decode(data)
        Base64.urlsafe_decode64(data)
      rescue ArgumentError
        raise DecodeError, 'Invalid token: malformed base64'
      end

      # Verifies the token signature.
      #
      # @param signing_input [String] header.payload string
      # @param signature [String] base64url-encoded signature
      # @param config [Configuration] JWT configuration
      # @raise [InvalidSignature] if the signature does not match
      def verify_signature!(signing_input, signature, config)
        expected = Encoder.sign(signing_input, config)
        raise InvalidSignature, 'Token signature is invalid' unless secure_compare(expected, signature)
      end

      # Validates the expiration claim.
      #
      # @param payload [Hash] decoded payload
      # @raise [TokenExpired] if the token has expired
      def validate_expiration!(payload)
        exp = payload['exp']
        return unless exp

        raise TokenExpired, 'Token has expired' if exp.to_i <= Time.now.to_i
      end

      # Validates the issuer claim.
      #
      # @param payload [Hash] decoded payload
      # @param config [Configuration] JWT configuration
      # @raise [InvalidIssuer] if the issuer does not match
      def validate_issuer!(payload, config)
        return unless config.issuer

        raise InvalidIssuer, "Invalid issuer: expected #{config.issuer}" unless payload['iss'] == config.issuer
      end

      # Constant-time string comparison to prevent timing attacks.
      #
      # @param a [String] first string
      # @param b [String] second string
      # @return [Boolean] true if the strings are equal
      def secure_compare(a, b)
        return false unless a.bytesize == b.bytesize

        left = a.unpack('C*')
        right = b.unpack('C*')
        result = 0
        left.each_with_index { |byte, i| result |= byte ^ right[i] }
        result.zero?
      end
    end
  end
end
