# frozen_string_literal: true

require "spec_helper"

RSpec.describe Philiprehberger::JwtKit do
  before do
    described_class.reset_configuration!
    described_class.reset_revocation_store!
    described_class.configure do |c|
      c.secret = "test-secret-key-at-least-32-chars-long"
      c.algorithm = :hs256
      c.issuer = "test-app"
      c.expiration = 3600
    end
  end

  describe "VERSION" do
    it "has a version number" do
      expect(Philiprehberger::JwtKit::VERSION).not_to be_nil
    end

    it "follows semantic versioning" do
      expect(Philiprehberger::JwtKit::VERSION).to match(/\A\d+\.\d+\.\d+\z/)
    end
  end

  describe ".configure" do
    it "sets the secret" do
      expect(described_class.configuration.secret).to eq("test-secret-key-at-least-32-chars-long")
    end

    it "sets the algorithm" do
      expect(described_class.configuration.algorithm).to eq(:hs256)
    end

    it "sets the issuer" do
      expect(described_class.configuration.issuer).to eq("test-app")
    end

    it "sets the expiration" do
      expect(described_class.configuration.expiration).to eq(3600)
    end

    it "has a default refresh expiration of 1 week" do
      expect(described_class.configuration.refresh_expiration).to eq(86_400 * 7)
    end
  end

  describe ".reset_configuration!" do
    it "resets to default values" do
      described_class.reset_configuration!
      expect(described_class.configuration.secret).to be_nil
      expect(described_class.configuration.algorithm).to eq(:hs256)
      expect(described_class.configuration.issuer).to be_nil
      expect(described_class.configuration.expiration).to eq(3600)
    end
  end

  describe ".encode" do
    it "returns a string" do
      token = described_class.encode(user_id: 42)
      expect(token).to be_a(String)
    end

    it "returns a token with 3 dot-separated parts" do
      token = described_class.encode(user_id: 42)
      expect(token.split(".").length).to eq(3)
    end

    it "raises an error when no secret is configured" do
      described_class.configuration.secret = nil
      expect { described_class.encode(user_id: 42) }.to raise_error(Philiprehberger::JwtKit::Error)
    end
  end

  describe ".decode" do
    it "extracts the correct payload" do
      token = described_class.encode(user_id: 42, role: "admin")
      payload = described_class.decode(token)
      expect(payload["user_id"]).to eq(42)
      expect(payload["role"]).to eq("admin")
    end

    it "includes auto-generated claims" do
      token = described_class.encode(user_id: 42)
      payload = described_class.decode(token)
      expect(payload).to include("exp", "iat", "jti", "iss")
    end

    it "sets the correct issuer" do
      token = described_class.encode(user_id: 42)
      payload = described_class.decode(token)
      expect(payload["iss"]).to eq("test-app")
    end

    it "sets a UUID jti" do
      token = described_class.encode(user_id: 42)
      payload = described_class.decode(token)
      expect(payload["jti"]).to match(/\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\z/)
    end

    it "sets an expiration in the future" do
      token = described_class.encode(user_id: 42)
      payload = described_class.decode(token)
      expect(payload["exp"]).to be > Time.now.to_i
    end
  end

  describe "round trip" do
    it "encodes then decodes returning original payload" do
      original = { "user_id" => 42, "role" => "admin", "active" => true }
      token = described_class.encode(original)
      payload = described_class.decode(token)
      original.each do |key, value|
        expect(payload[key]).to eq(value)
      end
    end
  end

  describe "expiration validation" do
    it "raises TokenExpired for an expired token" do
      described_class.configuration.expiration = -1
      token = described_class.encode(user_id: 42)
      expect { described_class.decode(token) }.to raise_error(Philiprehberger::JwtKit::TokenExpired)
    end
  end

  describe "signature validation" do
    it "raises InvalidSignature for a tampered token" do
      token = described_class.encode(user_id: 42)
      parts = token.split(".")
      parts[1] = Base64.urlsafe_encode64('{"user_id":99}', padding: false)
      tampered = parts.join(".")
      expect { described_class.decode(tampered) }.to raise_error(Philiprehberger::JwtKit::InvalidSignature)
    end

    it "raises DecodeError for an invalid token format" do
      expect { described_class.decode("not.a.valid.token") }.to raise_error(Philiprehberger::JwtKit::DecodeError)
    end

    it "raises DecodeError for a non-string token" do
      expect { described_class.decode(nil) }.to raise_error(Philiprehberger::JwtKit::DecodeError)
    end
  end

  describe "issuer validation" do
    it "raises InvalidIssuer when issuer does not match" do
      token = described_class.encode(user_id: 42)
      described_class.configuration.issuer = "other-app"
      expect { described_class.decode(token) }.to raise_error(Philiprehberger::JwtKit::InvalidIssuer)
    end

    it "skips issuer validation when no issuer is configured" do
      described_class.configuration.issuer = nil
      token = described_class.encode(user_id: 42)
      described_class.configuration.issuer = nil
      expect { described_class.decode(token) }.not_to raise_error
    end
  end

  describe "algorithms" do
    %i[hs256 hs384 hs512].each do |algo|
      it "supports #{algo}" do
        described_class.configuration.algorithm = algo
        token = described_class.encode(user_id: 42)
        payload = described_class.decode(token)
        expect(payload["user_id"]).to eq(42)
      end
    end
  end

  describe ".token_pair" do
    it "returns an array of 2 tokens" do
      result = described_class.token_pair(user_id: 42)
      expect(result).to be_an(Array)
      expect(result.length).to eq(2)
    end

    it "returns valid access and refresh tokens" do
      access, refresh = described_class.token_pair(user_id: 42)
      access_payload = described_class.decode(access)
      expect(access_payload["user_id"]).to eq(42)
      expect(access_payload).not_to include("type")

      # Decode refresh token directly to check type claim
      parts = refresh.split(".")
      refresh_payload = JSON.parse(Base64.urlsafe_decode64(parts[1]))
      expect(refresh_payload["type"]).to eq("refresh")
      expect(refresh_payload["user_id"]).to eq(42)
    end
  end

  describe ".refresh" do
    it "produces a new access token from a refresh token" do
      _access, refresh = described_class.token_pair(user_id: 42)
      new_access = described_class.refresh(refresh)
      payload = described_class.decode(new_access)
      expect(payload["user_id"]).to eq(42)
      expect(payload).not_to include("type")
    end

    it "raises InvalidToken when given a non-refresh token" do
      access, _refresh = described_class.token_pair(user_id: 42)
      expect { described_class.refresh(access) }.to raise_error(Philiprehberger::JwtKit::InvalidToken)
    end
  end

  describe "revocation" do
    it "revokes a token" do
      token = described_class.encode(user_id: 42)
      described_class.revoke(token)
      expect(described_class.revoked?(token)).to be true
    end

    it "raises RevokedToken when decoding a revoked token" do
      token = described_class.encode(user_id: 42)
      described_class.revoke(token)
      expect { described_class.decode(token) }.to raise_error(Philiprehberger::JwtKit::RevokedToken)
    end

    it "does not affect non-revoked tokens" do
      token1 = described_class.encode(user_id: 1)
      token2 = described_class.encode(user_id: 2)
      described_class.revoke(token1)
      expect { described_class.decode(token2) }.not_to raise_error
    end
  end
end
