# frozen_string_literal: true

module Philiprehberger
  module JwtKit
    # Encodes payloads into signed JWT tokens.
    module Encoder
      module_function

      # Encodes a payload into a JWT token string.
      #
      # @param payload [Hash] custom claims to include in the token
      # @param config [Configuration] JWT configuration
      # @return [String] signed JWT token
      # @raise [Error] if no secret is configured
      def encode(payload, config)
        signing_secret = if config.secrets.is_a?(Array) && !config.secrets.empty?
                           config.secrets.first[:secret] || config.secrets.first['secret']
                         else
                           config.secret
                         end
        raise Error, 'Secret is required for encoding' unless signing_secret

        header = { 'alg' => config.algorithm_name, 'typ' => 'JWT' }
        if config.secrets.is_a?(Array) && !config.secrets.empty?
          kid = config.secrets.first[:kid] || config.secrets.first['kid']
          header['kid'] = kid if kid
        end
        now = Time.now.to_i

        claims = {
          'exp' => now + config.expiration,
          'nbf' => now,
          'iat' => now,
          'jti' => SecureRandom.uuid
        }
        claims['iss'] = config.issuer if config.issuer
        claims['aud'] = config.audience if config.audience

        merged = claims.merge(payload.transform_keys(&:to_s))

        header_segment = base64url_encode(JSON.generate(header))
        payload_segment = base64url_encode(JSON.generate(merged))
        signing_input = "#{header_segment}.#{payload_segment}"
        signature = sign(signing_input, config, secret: signing_secret)

        "#{signing_input}.#{signature}"
      end

      # Base64url-encodes a string without padding.
      #
      # @param data [String] data to encode
      # @return [String] base64url-encoded string
      def base64url_encode(data)
        Base64.urlsafe_encode64(data, padding: false)
      end

      # Signs data using HMAC with the configured algorithm.
      #
      # @param data [String] data to sign
      # @param config [Configuration] JWT configuration
      # @param secret [String, nil] optional secret override (defaults to config.secret)
      # @return [String] base64url-encoded signature
      def sign(data, config, secret: nil)
        signing_key = secret || config.secret
        digest = OpenSSL::Digest.new(config.digest_algorithm)
        signature = OpenSSL::HMAC.digest(digest, signing_key, data)
        base64url_encode(signature)
      end
    end
  end
end
