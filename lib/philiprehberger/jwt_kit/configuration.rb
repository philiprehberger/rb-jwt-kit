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

      # @return [Integer] default TTL in seconds for access tokens
      attr_accessor :expiration

      # @return [Integer] default TTL in seconds for refresh tokens
      attr_accessor :refresh_expiration

      def initialize
        @secret = nil
        @algorithm = :hs256
        @issuer = nil
        @expiration = 3600
        @refresh_expiration = 86_400 * 7
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
