# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Philiprehberger::JwtKit do
  before do
    described_class.reset_configuration!
    described_class.reset_revocation_store!
    described_class.configure do |c|
      c.secret = 'test-secret-key-at-least-32-chars-long'
      c.algorithm = :hs256
      c.issuer = 'test-app'
      c.expiration = 3600
    end
  end

  describe 'VERSION' do
    it 'has a version number' do
      expect(Philiprehberger::JwtKit::VERSION).not_to be_nil
    end

    it 'follows semantic versioning' do
      expect(Philiprehberger::JwtKit::VERSION).to match(/\A\d+\.\d+\.\d+\z/)
    end
  end

  describe '.configure' do
    it 'sets the secret' do
      expect(described_class.configuration.secret).to eq('test-secret-key-at-least-32-chars-long')
    end

    it 'sets the algorithm' do
      expect(described_class.configuration.algorithm).to eq(:hs256)
    end

    it 'sets the issuer' do
      expect(described_class.configuration.issuer).to eq('test-app')
    end

    it 'sets the expiration' do
      expect(described_class.configuration.expiration).to eq(3600)
    end

    it 'has a default refresh expiration of 1 week' do
      expect(described_class.configuration.refresh_expiration).to eq(86_400 * 7)
    end
  end

  describe '.reset_configuration!' do
    it 'resets to default values' do
      described_class.reset_configuration!
      expect(described_class.configuration.secret).to be_nil
      expect(described_class.configuration.algorithm).to eq(:hs256)
      expect(described_class.configuration.issuer).to be_nil
      expect(described_class.configuration.expiration).to eq(3600)
    end
  end

  describe '.encode' do
    it 'returns a string' do
      token = described_class.encode(user_id: 42)
      expect(token).to be_a(String)
    end

    it 'returns a token with 3 dot-separated parts' do
      token = described_class.encode(user_id: 42)
      expect(token.split('.').length).to eq(3)
    end

    it 'raises an error when no secret is configured' do
      described_class.configuration.secret = nil
      expect { described_class.encode(user_id: 42) }.to raise_error(Philiprehberger::JwtKit::Error)
    end

    it 'encodes an empty payload without error' do
      token = described_class.encode
      payload = described_class.decode(token)
      expect(payload).to include('exp', 'iat', 'jti', 'iss')
    end

    it 'converts symbol keys to string keys in payload' do
      token = described_class.encode(user_id: 42)
      payload = described_class.decode(token)
      expect(payload).to have_key('user_id')
      expect(payload).not_to have_key(:user_id)
    end

    it 'preserves string keys passed directly' do
      token = described_class.encode('email' => 'test@example.com')
      payload = described_class.decode(token)
      expect(payload['email']).to eq('test@example.com')
    end

    it 'includes the algorithm in the JWT header' do
      token = described_class.encode(user_id: 42)
      header_segment = token.split('.').first
      header = JSON.parse(Base64.urlsafe_decode64(header_segment))
      expect(header['alg']).to eq('HS256')
      expect(header['typ']).to eq('JWT')
    end

    it 'generates unique jti for each token' do
      token1 = described_class.encode(user_id: 42)
      token2 = described_class.encode(user_id: 42)
      payload1 = described_class.decode(token1)
      payload2 = described_class.decode(token2)
      expect(payload1['jti']).not_to eq(payload2['jti'])
    end

    it 'encodes payload with special characters' do
      token = described_class.encode(name: "O'Brien & Sons <test>")
      payload = described_class.decode(token)
      expect(payload['name']).to eq("O'Brien & Sons <test>")
    end

    it 'encodes payload with nested hash values' do
      token = described_class.encode(data: { nested: true, count: 5 })
      payload = described_class.decode(token)
      expect(payload['data']).to eq({ 'nested' => true, 'count' => 5 })
    end

    it 'raises Error with a descriptive message when secret is nil' do
      described_class.configuration.secret = nil
      expect { described_class.encode(user_id: 42) }.to raise_error(
        Philiprehberger::JwtKit::Error, 'Secret is required for encoding'
      )
    end
  end

  describe '.decode' do
    it 'extracts the correct payload' do
      token = described_class.encode(user_id: 42, role: 'admin')
      payload = described_class.decode(token)
      expect(payload['user_id']).to eq(42)
      expect(payload['role']).to eq('admin')
    end

    it 'includes auto-generated claims' do
      token = described_class.encode(user_id: 42)
      payload = described_class.decode(token)
      expect(payload).to include('exp', 'iat', 'jti', 'iss')
    end

    it 'sets the correct issuer' do
      token = described_class.encode(user_id: 42)
      payload = described_class.decode(token)
      expect(payload['iss']).to eq('test-app')
    end

    it 'sets a UUID jti' do
      token = described_class.encode(user_id: 42)
      payload = described_class.decode(token)
      expect(payload['jti']).to match(/\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\z/)
    end

    it 'sets an expiration in the future' do
      token = described_class.encode(user_id: 42)
      payload = described_class.decode(token)
      expect(payload['exp']).to be > Time.now.to_i
    end
  end

  describe 'round trip' do
    it 'encodes then decodes returning original payload' do
      original = { 'user_id' => 42, 'role' => 'admin', 'active' => true }
      token = described_class.encode(original)
      payload = described_class.decode(token)
      original.each do |key, value|
        expect(payload[key]).to eq(value)
      end
    end
  end

  describe 'expiration validation' do
    it 'raises TokenExpired for an expired token' do
      described_class.configuration.expiration = -1
      token = described_class.encode(user_id: 42)
      expect { described_class.decode(token) }.to raise_error(Philiprehberger::JwtKit::TokenExpired)
    end
  end

  describe 'signature validation' do
    it 'raises InvalidSignature for a tampered token' do
      token = described_class.encode(user_id: 42)
      parts = token.split('.')
      parts[1] = Base64.urlsafe_encode64('{"user_id":99}', padding: false)
      tampered = parts.join('.')
      expect { described_class.decode(tampered) }.to raise_error(Philiprehberger::JwtKit::InvalidSignature)
    end

    it 'raises DecodeError for an invalid token format' do
      expect { described_class.decode('not.a.valid.token') }.to raise_error(Philiprehberger::JwtKit::DecodeError)
    end

    it 'raises DecodeError for a non-string token' do
      expect { described_class.decode(nil) }.to raise_error(Philiprehberger::JwtKit::DecodeError)
    end

    it 'raises DecodeError for an integer token' do
      expect { described_class.decode(12345) }.to raise_error(
        Philiprehberger::JwtKit::DecodeError, 'Token must be a string'
      )
    end

    it 'raises DecodeError for a token with only 2 segments' do
      expect { described_class.decode('header.payload') }.to raise_error(
        Philiprehberger::JwtKit::DecodeError, 'Invalid token format: expected 3 segments'
      )
    end

    it 'raises DecodeError for an empty string token' do
      expect { described_class.decode('') }.to raise_error(Philiprehberger::JwtKit::DecodeError)
    end

    it 'raises DecodeError for a token with malformed base64' do
      expect { described_class.decode('!!!.@@@.###') }.to raise_error(Philiprehberger::JwtKit::DecodeError)
    end

    it 'raises InvalidSignature when token is signed with a different secret' do
      token = described_class.encode(user_id: 42)
      described_class.configuration.secret = 'completely-different-secret-key!!'
      expect { described_class.decode(token) }.to raise_error(Philiprehberger::JwtKit::InvalidSignature)
    end

    it 'raises InvalidSignature for a tampered header' do
      token = described_class.encode(user_id: 42)
      parts = token.split('.')
      parts[0] = Base64.urlsafe_encode64('{"alg":"HS256","typ":"JWT","extra":true}', padding: false)
      tampered = parts.join('.')
      expect { described_class.decode(tampered) }.to raise_error(Philiprehberger::JwtKit::InvalidSignature)
    end

    it 'raises InvalidSignature for a tampered signature segment' do
      token = described_class.encode(user_id: 42)
      parts = token.split('.')
      parts[2] = Base64.urlsafe_encode64('fake-signature', padding: false)
      tampered = parts.join('.')
      expect { described_class.decode(tampered) }.to raise_error(Philiprehberger::JwtKit::InvalidSignature)
    end
  end

  describe 'issuer validation' do
    it 'raises InvalidIssuer when issuer does not match' do
      token = described_class.encode(user_id: 42)
      described_class.configuration.issuer = 'other-app'
      expect { described_class.decode(token) }.to raise_error(Philiprehberger::JwtKit::InvalidIssuer)
    end

    it 'skips issuer validation when no issuer is configured' do
      described_class.configuration.issuer = nil
      token = described_class.encode(user_id: 42)
      described_class.configuration.issuer = nil
      expect { described_class.decode(token) }.not_to raise_error
    end
  end

  describe 'algorithms' do
    %i[hs256 hs384 hs512].each do |algo|
      it "supports #{algo}" do
        described_class.configuration.algorithm = algo
        token = described_class.encode(user_id: 42)
        payload = described_class.decode(token)
        expect(payload['user_id']).to eq(42)
      end
    end

    it 'raises Error for an unsupported algorithm' do
      described_class.configuration.algorithm = :rs256
      expect { described_class.encode(user_id: 42) }.to raise_error(
        Philiprehberger::JwtKit::Error, /Unsupported algorithm/
      )
    end

    it 'returns correct algorithm_name for each algorithm' do
      { hs256: 'HS256', hs384: 'HS384', hs512: 'HS512' }.each do |algo, name|
        described_class.configuration.algorithm = algo
        expect(described_class.configuration.algorithm_name).to eq(name)
      end
    end

    it 'returns correct digest_algorithm for each algorithm' do
      { hs256: 'SHA256', hs384: 'SHA384', hs512: 'SHA512' }.each do |algo, digest|
        described_class.configuration.algorithm = algo
        expect(described_class.configuration.digest_algorithm).to eq(digest)
      end
    end

    it 'rejects tokens signed with a different algorithm' do
      described_class.configuration.algorithm = :hs256
      token = described_class.encode(user_id: 42)
      described_class.configuration.algorithm = :hs512
      expect { described_class.decode(token) }.to raise_error(Philiprehberger::JwtKit::InvalidSignature)
    end
  end

  describe '.token_pair' do
    it 'returns an array of 2 tokens' do
      result = described_class.token_pair(user_id: 42)
      expect(result).to be_an(Array)
      expect(result.length).to eq(2)
    end

    it 'returns valid access and refresh tokens' do
      access, refresh = described_class.token_pair(user_id: 42)
      access_payload = described_class.decode(access)
      expect(access_payload['user_id']).to eq(42)
      expect(access_payload).not_to include('type')

      # Decode refresh token directly to check type claim
      parts = refresh.split('.')
      refresh_payload = JSON.parse(Base64.urlsafe_decode64(parts[1]))
      expect(refresh_payload['type']).to eq('refresh')
      expect(refresh_payload['user_id']).to eq(42)
    end

    it 'gives the refresh token a longer expiration than the access token' do
      access, refresh = described_class.token_pair(user_id: 42)
      access_payload = described_class.decode(access)
      parts = refresh.split('.')
      refresh_payload = JSON.parse(Base64.urlsafe_decode64(parts[1]))
      expect(refresh_payload['exp']).to be > access_payload['exp']
    end

    it 'restores the original expiration config after generating a pair' do
      original_expiration = described_class.configuration.expiration
      described_class.token_pair(user_id: 42)
      expect(described_class.configuration.expiration).to eq(original_expiration)
    end

    it 'generates a pair with an empty payload' do
      access, refresh = described_class.token_pair
      access_payload = described_class.decode(access)
      expect(access_payload).to include('exp', 'iat', 'jti')
      parts = refresh.split('.')
      refresh_payload = JSON.parse(Base64.urlsafe_decode64(parts[1]))
      expect(refresh_payload['type']).to eq('refresh')
    end
  end

  describe '.refresh' do
    it 'produces a new access token from a refresh token' do
      _access, refresh = described_class.token_pair(user_id: 42)
      new_access = described_class.refresh(refresh)
      payload = described_class.decode(new_access)
      expect(payload['user_id']).to eq(42)
      expect(payload).not_to include('type')
    end

    it 'raises InvalidToken when given a non-refresh token' do
      access, _refresh = described_class.token_pair(user_id: 42)
      expect { described_class.refresh(access) }.to raise_error(Philiprehberger::JwtKit::InvalidToken)
    end
  end

  describe 'revocation' do
    it 'revokes a token' do
      token = described_class.encode(user_id: 42)
      described_class.revoke(token)
      expect(described_class.revoked?(token)).to be true
    end

    it 'raises RevokedToken when decoding a revoked token' do
      token = described_class.encode(user_id: 42)
      described_class.revoke(token)
      expect { described_class.decode(token) }.to raise_error(Philiprehberger::JwtKit::RevokedToken)
    end

    it 'does not affect non-revoked tokens' do
      token1 = described_class.encode(user_id: 1)
      token2 = described_class.encode(user_id: 2)
      described_class.revoke(token1)
      expect { described_class.decode(token2) }.not_to raise_error
    end

    it 'reports a non-revoked token as not revoked' do
      token = described_class.encode(user_id: 42)
      expect(described_class.revoked?(token)).to be false
    end

    it 'raises RevokedToken with a descriptive message' do
      token = described_class.encode(user_id: 42)
      described_class.revoke(token)
      expect { described_class.decode(token) }.to raise_error(
        Philiprehberger::JwtKit::RevokedToken, 'Token has been revoked'
      )
    end
  end

  describe 'Revocation::MemoryStore' do
    let(:store) { Philiprehberger::JwtKit::Revocation::MemoryStore.new }

    it 'starts with a size of 0' do
      expect(store.size).to eq(0)
    end

    it 'increments size when revoking tokens' do
      token1 = described_class.encode(user_id: 1)
      token2 = described_class.encode(user_id: 2)
      store.revoke(token1)
      store.revoke(token2)
      expect(store.size).to eq(2)
    end

    it 'clears all revoked tokens' do
      token = described_class.encode(user_id: 42)
      store.revoke(token)
      expect(store.size).to eq(1)
      store.clear
      expect(store.size).to eq(0)
      expect(store.revoked?(token)).to be false
    end

    it 'handles revoking a malformed token gracefully' do
      store.revoke('not-a-jwt')
      expect(store.size).to eq(0)
    end

    it 'handles checking revocation of a malformed token' do
      expect(store.revoked?('not-a-jwt')).to be false
    end

    it 'does not duplicate jti on repeated revocation of the same token' do
      token = described_class.encode(user_id: 42)
      store.revoke(token)
      store.revoke(token)
      expect(store.size).to eq(1)
    end
  end

  describe '.refresh edge cases' do
    it 'raises InvalidToken with a descriptive message for non-refresh tokens' do
      access, _refresh = described_class.token_pair(user_id: 42)
      expect { described_class.refresh(access) }.to raise_error(
        Philiprehberger::JwtKit::InvalidToken, 'Token is not a refresh token'
      )
    end

    it 'strips meta claims (exp, iat, jti, iss, type) from the refreshed access token' do
      _access, refresh = described_class.token_pair(user_id: 42, role: 'admin')
      new_access = described_class.refresh(refresh)
      payload = described_class.decode(new_access)
      expect(payload['user_id']).to eq(42)
      expect(payload['role']).to eq('admin')
      # The new token gets fresh exp/iat/jti, not the ones from the refresh token
      expect(payload['type']).to be_nil
    end

    it 'generates a new jti for the refreshed access token' do
      _access, refresh = described_class.token_pair(user_id: 42)
      new_access = described_class.refresh(refresh)
      parts = refresh.split('.')
      refresh_payload = JSON.parse(Base64.urlsafe_decode64(parts[1]))
      new_payload = described_class.decode(new_access)
      expect(new_payload['jti']).not_to eq(refresh_payload['jti'])
    end

    it 'raises TokenExpired when refreshing with an expired refresh token' do
      described_class.configuration.refresh_expiration = -1
      _access, refresh = described_class.token_pair(user_id: 42)
      expect { described_class.refresh(refresh) }.to raise_error(Philiprehberger::JwtKit::TokenExpired)
    end
  end

  describe 'decode edge cases' do
    it 'raises DecodeError for a token with malformed JSON payload' do
      header = Base64.urlsafe_encode64('{"alg":"HS256","typ":"JWT"}', padding: false)
      payload = Base64.urlsafe_encode64('not-json', padding: false)
      signing_input = "#{header}.#{payload}"
      signature = Philiprehberger::JwtKit::Encoder.sign(signing_input, described_class.configuration)
      token = "#{signing_input}.#{signature}"
      expect { described_class.decode(token) }.to raise_error(
        Philiprehberger::JwtKit::DecodeError, 'Invalid token: malformed JSON'
      )
    end

    it 'accepts a token without an exp claim when decoded directly' do
      header = Base64.urlsafe_encode64('{"alg":"HS256","typ":"JWT"}', padding: false)
      payload_data = { 'iss' => 'test-app', 'user_id' => 42 }
      payload = Base64.urlsafe_encode64(JSON.generate(payload_data), padding: false)
      signing_input = "#{header}.#{payload}"
      signature = Philiprehberger::JwtKit::Encoder.sign(signing_input, described_class.configuration)
      token = "#{signing_input}.#{signature}"
      decoded = described_class.decode(token)
      expect(decoded['user_id']).to eq(42)
    end

    it 'raises DecodeError for a token with empty segments' do
      expect { described_class.decode('..') }.to raise_error(Philiprehberger::JwtKit::DecodeError)
    end

    it 'raises InvalidSignature when the signature is an empty base64 string' do
      token = described_class.encode(user_id: 42)
      parts = token.split('.')
      parts[2] = ''
      tampered = parts.join('.')
      expect { described_class.decode(tampered) }.to raise_error(Philiprehberger::JwtKit::InvalidSignature)
    end
  end

  describe 'issuer validation edge cases' do
    it 'raises InvalidIssuer with a descriptive message' do
      token = described_class.encode(user_id: 42)
      described_class.configuration.issuer = 'other-app'
      expect { described_class.decode(token) }.to raise_error(
        Philiprehberger::JwtKit::InvalidIssuer, /expected other-app/
      )
    end

    it 'does not include issuer in token when issuer is nil' do
      described_class.configuration.issuer = nil
      token = described_class.encode(user_id: 42)
      described_class.configuration.issuer = nil
      payload = described_class.decode(token)
      expect(payload).not_to have_key('iss')
    end
  end

  describe 'expiration edge cases' do
    it 'raises TokenExpired with a descriptive message' do
      described_class.configuration.expiration = -1
      token = described_class.encode(user_id: 42)
      expect { described_class.decode(token) }.to raise_error(
        Philiprehberger::JwtKit::TokenExpired, 'Token has expired'
      )
    end

    it 'raises TokenExpired for a token that expires at exactly now' do
      # Create a token with exp = now (which is <= Time.now.to_i, so expired)
      header = Base64.urlsafe_encode64('{"alg":"HS256","typ":"JWT"}', padding: false)
      payload_data = { 'exp' => Time.now.to_i, 'iss' => 'test-app', 'user_id' => 42 }
      payload = Base64.urlsafe_encode64(JSON.generate(payload_data), padding: false)
      signing_input = "#{header}.#{payload}"
      signature = Philiprehberger::JwtKit::Encoder.sign(signing_input, described_class.configuration)
      token = "#{signing_input}.#{signature}"
      expect { described_class.decode(token) }.to raise_error(Philiprehberger::JwtKit::TokenExpired)
    end
  end

  describe 'error class hierarchy' do
    it 'DecodeError inherits from Error' do
      expect(Philiprehberger::JwtKit::DecodeError.superclass).to eq(Philiprehberger::JwtKit::Error)
    end

    it 'TokenExpired inherits from DecodeError' do
      expect(Philiprehberger::JwtKit::TokenExpired.superclass).to eq(Philiprehberger::JwtKit::DecodeError)
    end

    it 'InvalidSignature inherits from DecodeError' do
      expect(Philiprehberger::JwtKit::InvalidSignature.superclass).to eq(Philiprehberger::JwtKit::DecodeError)
    end

    it 'InvalidIssuer inherits from DecodeError' do
      expect(Philiprehberger::JwtKit::InvalidIssuer.superclass).to eq(Philiprehberger::JwtKit::DecodeError)
    end

    it 'InvalidToken inherits from DecodeError' do
      expect(Philiprehberger::JwtKit::InvalidToken.superclass).to eq(Philiprehberger::JwtKit::DecodeError)
    end

    it 'RevokedToken inherits from DecodeError' do
      expect(Philiprehberger::JwtKit::RevokedToken.superclass).to eq(Philiprehberger::JwtKit::DecodeError)
    end
  end

  describe 'payload with various data types' do
    it 'encodes and decodes array values' do
      token = described_class.encode(roles: %w[admin editor viewer])
      payload = described_class.decode(token)
      expect(payload['roles']).to eq(%w[admin editor viewer])
    end

    it 'encodes and decodes numeric float values' do
      token = described_class.encode(score: 99.5)
      payload = described_class.decode(token)
      expect(payload['score']).to eq(99.5)
    end

    it 'encodes and decodes null values' do
      token = described_class.encode(optional: nil)
      payload = described_class.decode(token)
      expect(payload).to have_key('optional')
      expect(payload['optional']).to be_nil
    end

    it 'encodes and decodes unicode strings' do
      token = described_class.encode(name: "\u00e9\u00e0\u00fc \u2603 \u{1F600}")
      payload = described_class.decode(token)
      expect(payload['name']).to eq("\u00e9\u00e0\u00fc \u2603 \u{1F600}")
    end
  end
end
