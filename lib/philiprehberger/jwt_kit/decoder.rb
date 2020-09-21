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

        parts = token.split('.', -1)
        raise DecodeError, 'Invalid token format: expected 3 segments' unless parts.length == 3

        header_segment, payload_segment, signature_segment = parts

        verify_signature!("#{header_segment}.#{payload_segment}", signature_segment, config)

        payload = JSON.parse(base64url_decode(payload_segment))

        validate_expiration!(payload)
        validate_not_before!(payload)
        validate_issuer!(payload, config)
        validate_audience!(payload, config)

        payload
      rescue JSON::ParserError
        raise DecodeError, 'Invalid token: malformed JSON'
      end

      # Decodes a JWT token without verifying the signature.
      #
      # @param token [String] JWT token
      # @return [Hash] with :header and :payload keys
      # @raise [DecodeError] if the token format is invalid
      def peek(token)
        raise DecodeError, 'Token must be a string' unless token.is_a?(String)

        parts = token.split('.', -1)
        raise DecodeError, 'Invalid token format: expected 3 segments' unless parts.length == 3

        header = JSON.parse(base64url_decode(parts[0]))
        payload = JSON.parse(base64url_decode(parts[1]))

        { header: header, payload: payload }
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

      # Validates the not-before claim.
      #
      # @param payload [Hash] decoded payload
      # @raise [TokenNotYetValid] if the current time is before nbf
      def validate_not_before!(payload)
        nbf = payload['nbf']
        return unless nbf

        raise TokenNotYetValid, 'Token is not yet valid' if nbf.to_i > Time.now.to_i
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

      # Validates the audience claim.
      #
      # @param payload [Hash] decoded payload
      # @param config [Configuration] JWT configuration
      # @raise [InvalidAudience] if the audience does not match
      def validate_audience!(payload, config)
        return unless config.audience

        token_aud = Array(payload['aud'])
        expected_aud = Array(config.audience)
        return if (expected_aud & token_aud).any?

        raise InvalidAudience, "Invalid audience: expected #{config.audience}"
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
