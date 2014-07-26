# frozen_string_literal: true

module Philiprehberger
  module JwtKit
    # Generates and refreshes access/refresh token pairs.
    module TokenPair
      module_function

      # Generates an access token and refresh token pair.
      #
      # @param payload [Hash] custom claims to include in both tokens
      # @param config [Configuration] JWT configuration
      # @return [Array<String>] `[access_token, refresh_token]`
      def generate(payload, config)
        access_token = Encoder.encode(payload, config)

        refresh_payload = payload.merge('type' => 'refresh')
        original_expiration = config.expiration
        config.expiration = config.refresh_expiration
        refresh_token = Encoder.encode(refresh_payload, config)
        config.expiration = original_expiration

        [access_token, refresh_token]
      end

      # Refreshes an access token using a valid refresh token.
      #
      # @param refresh_token [String] a valid refresh token
      # @param config [Configuration] JWT configuration
      # @return [String] new access token
      # @raise [InvalidToken] if the token is not a refresh token
      def refresh(refresh_token, config)
        payload = Decoder.decode(refresh_token, config)
        raise InvalidToken, 'Token is not a refresh token' unless payload['type'] == 'refresh'

        new_payload = payload.reject { |k, _| %w[exp iat jti iss type].include?(k) }
        Encoder.encode(new_payload, config)
      end
    end
  end
end
