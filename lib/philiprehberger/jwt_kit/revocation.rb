# frozen_string_literal: true

module Philiprehberger
  module JwtKit
    # Token revocation support with an in-memory store.
    module Revocation
      # Thread-safe in-memory revocation store backed by a Hash.
      class MemoryStore
        def initialize
          @revoked = {}
          @mutex = Mutex.new
        end

        # Revokes a token by extracting and storing its JTI.
        #
        # @param token [String] JWT token to revoke
        # @return [void]
        def revoke(token)
          jti = extract_jti(token)
          return unless jti

          @mutex.synchronize { @revoked[jti] = Time.now.to_i }
        end

        # Checks whether a token has been revoked.
        #
        # @param token [String] JWT token to check
        # @return [Boolean] true if the token has been revoked
        def revoked?(token)
          jti = extract_jti(token)
          return false unless jti

          @mutex.synchronize { @revoked.key?(jti) }
        end

        # Clears all revoked tokens.
        #
        # @return [void]
        def clear
          @mutex.synchronize { @revoked.clear }
        end

        # Returns the number of revoked tokens.
        #
        # @return [Integer]
        def size
          @mutex.synchronize { @revoked.size }
        end

        # Removes revocation entries older than max_age seconds.
        #
        # @param max_age [Integer] maximum age in seconds
        # @return [self]
        def cleanup!(max_age:)
          cutoff = Time.now.to_i - max_age
          @mutex.synchronize { @revoked.reject! { |_jti, ts| ts < cutoff } }
          self
        end

        private

        def extract_jti(token)
          parts = token.split('.')
          return nil unless parts.length == 3

          payload = JSON.parse(Base64.urlsafe_decode64(parts[1]))
          payload['jti']
        rescue JSON::ParserError, ArgumentError
          nil
        end
      end
    end
  end
end
