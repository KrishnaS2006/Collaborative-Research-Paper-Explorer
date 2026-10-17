import { describe, it, before, after, afterEach } from "node:test";
import assert from "node:assert/strict";
import express from "express";
import cookieParser from "cookie-parser";
import crypto from "node:crypto";

import authRoutes from "../routes/auth.routes.js";
import errorHandler from "../middleware/errorHandler.js";
import { env } from "../config/env.js";
import {
  generateSsoAuthorizationUrl,
  verifyGoogleIdToken,
  handleSsoCallback,
  getSsoConfig,
  setCachedJwksForTesting,
  resetCachedJwksForTesting,
} from "../services/sso.service.js";

describe("FR-02: Institutional SSO (OIDC / Google Workspace) Test Suite", () => {
  let app;
  let server;
  let baseUrl;
  const originalEnv = { ...process.env };
  const originalSsoConfig = { ...env.sso };
  const originalAllowedDomains = [...env.allowedEmailDomains];

  // Test RSA Keypair for signing mock OIDC ID tokens
  let testKeyPair;
  let testKid = "test-key-id-12345";

  before(async () => {
    process.env.JWT_SECRET =
      "test-jwt-secret-for-sso-32-chars-long-security-123";
    process.env.NODE_ENV = "test";
    process.env.OIDC_CLIENT_ID = "mock-google-client-id.apps.googleusercontent.com";
    process.env.OIDC_CLIENT_SECRET = "mock-google-client-secret-abc";
    process.env.ALLOWED_EMAIL_DOMAINS = "dau.ac.in,university.edu";

    // Update in-memory env config for test
    env.sso.enabled = true;
    env.sso.clientId = process.env.OIDC_CLIENT_ID;
    env.sso.clientSecret = process.env.OIDC_CLIENT_SECRET;
    env.allowedEmailDomains = ["dau.ac.in", "university.edu"];

    // Generate RSA key pair for cryptographic token tests
    testKeyPair = crypto.generateKeyPairSync("rsa", {
      modulusLength: 2048,
    });

    const jwk = testKeyPair.publicKey.export({ format: "jwk" });
    jwk.kid = testKid;
    setCachedJwksForTesting({
      keys: [jwk],
    });

    app = express();
    app.use(express.json());
    app.use(cookieParser());
    app.use("/api/auth", authRoutes);
    app.use(errorHandler);

    await new Promise((resolve) => {
      server = app.listen(0, () => {
        const port = server.address().port;
        baseUrl = `http://127.0.0.1:${port}`;
        resolve();
      });
    });
  });

  after(async () => {
    process.env = { ...originalEnv };
    env.sso = { ...originalSsoConfig };
    env.allowedEmailDomains = [...originalAllowedDomains];
    resetCachedJwksForTesting();
    if (server) {
      await new Promise((resolve) => server.close(resolve));
    }
  });

  const createMockIdToken = ({
    iss = "https://accounts.google.com",
    aud = env.sso.clientId,
    sub = "google-subject-id-987654321",
    email = "prof@dau.ac.in",
    email_verified = true,
    name = "Dr. Institutional Professor",
    nonce = "test-nonce-123",
    exp = Math.floor(Date.now() / 1000) + 3600,
    kid = testKid,
  } = {}) => {
    const header = {
      alg: "RS256",
      typ: "JWT",
      kid,
    };

    const payload = {
      iss,
      aud,
      sub,
      email,
      email_verified,
      name,
      nonce,
      exp,
      iat: Math.floor(Date.now() / 1000) - 10,
    };

    const headerB64 = Buffer.from(JSON.stringify(header)).toString("base64url");
    const payloadB64 = Buffer.from(JSON.stringify(payload)).toString("base64url");
    const signingInput = `${headerB64}.${payloadB64}`;

    const signer = crypto.createSign("RSA-SHA256");
    signer.update(signingInput);
    const signature = signer.sign(testKeyPair.privateKey, "base64url");

    return `${signingInput}.${signature}`;
  };

  describe("SSO Discovery & Configuration", () => {
    it("should return enabled status and allowed domains via GET /api/auth/sso/config", async () => {
      const res = await fetch(`${baseUrl}/api/auth/sso/config`);
      const data = await res.json();

      assert.equal(res.status, 200);
      assert.equal(data.enabled, true);
      assert.equal(data.provider, "google");
      assert.deepEqual(data.allowedDomains, ["dau.ac.in", "university.edu"]);
    });

    it("should indicate disabled SSO when credentials are absent", () => {
      const prevEnabled = env.sso.enabled;
      env.sso.enabled = false;

      const config = getSsoConfig();
      assert.equal(config.enabled, false);
      assert.equal(config.loginUrl, null);

      env.sso.enabled = prevEnabled;
    });
  });

  describe("Authorization Flow Initiation & PKCE", () => {
    it("generateSsoAuthorizationUrl should create secure state, nonce, and PKCE challenge", () => {
      const auth = generateSsoAuthorizationUrl();

      assert.ok(auth.authUrl.startsWith("https://accounts.google.com/o/oauth2/v2/auth"));
      assert.ok(auth.state && auth.state.length >= 32);
      assert.ok(auth.nonce && auth.nonce.length >= 32);
      assert.ok(auth.codeVerifier && auth.codeVerifier.length >= 43);

      const parsedUrl = new URL(auth.authUrl);
      assert.equal(parsedUrl.searchParams.get("client_id"), env.sso.clientId);
      assert.equal(parsedUrl.searchParams.get("response_type"), "code");
      assert.equal(parsedUrl.searchParams.get("state"), auth.state);
      assert.equal(parsedUrl.searchParams.get("nonce"), auth.nonce);
      assert.equal(parsedUrl.searchParams.get("code_challenge_method"), "S256");
      assert.ok(parsedUrl.searchParams.get("code_challenge"));
    });

    it("GET /api/auth/sso/login should set secure sso_session cookie and redirect to provider", async () => {
      const res = await fetch(`${baseUrl}/api/auth/sso/login`, {
        redirect: "manual",
      });

      assert.equal(res.status, 302);
      const location = res.headers.get("location");
      assert.ok(location.startsWith("https://accounts.google.com/o/oauth2/v2/auth"));

      const setCookie = res.headers.get("set-cookie");
      assert.ok(setCookie);
      assert.match(setCookie, /sso_session=/);
      assert.match(setCookie, /HttpOnly/i);
    });
  });

  describe("OIDC ID Token Validation Protocol Checks", () => {
    it("should accept valid Google ID token with matching nonce and audience", async () => {
      const nonce = "valid-session-nonce-12345";
      const validToken = createMockIdToken({ nonce });

      const payload = await verifyGoogleIdToken(validToken, nonce);
      assert.equal(payload.email, "prof@dau.ac.in");
      assert.equal(payload.sub, "google-subject-id-987654321");
    });

    it("should reject token with invalid issuer", async () => {
      const badIssuerToken = createMockIdToken({ iss: "https://evil-issuer.com" });
      await assert.rejects(
        () => verifyGoogleIdToken(badIssuerToken),
        /Invalid ID token issuer/
      );
    });

    it("should reject token with mismatched audience", async () => {
      const badAudToken = createMockIdToken({ aud: "wrong-client-id.apps.google.com" });
      await assert.rejects(
        () => verifyGoogleIdToken(badAudToken),
        /ID token audience mismatch/
      );
    });

    it("should reject expired ID token", async () => {
      const expiredToken = createMockIdToken({
        exp: Math.floor(Date.now() / 1000) - 300, // 5 minutes ago
      });
      await assert.rejects(
        () => verifyGoogleIdToken(expiredToken),
        /ID token has expired/
      );
    });

    it("should reject token with mismatched nonce (replay attack protection)", async () => {
      const tokenWithNonceA = createMockIdToken({ nonce: "nonce-alpha" });
      await assert.rejects(
        () => verifyGoogleIdToken(tokenWithNonceA, "nonce-beta"),
        /ID token nonce mismatch/
      );
    });

    it("should reject token with tampered signature", async () => {
      const validToken = createMockIdToken();
      const parts = validToken.split(".");
      // Tamper signature byte
      const tamperedToken = `${parts[0]}.${parts[1]}.tamperedsignature123`;

      await assert.rejects(
        () => verifyGoogleIdToken(tamperedToken),
        /signature verification failed/
      );
    });
  });

  describe("SSO Callback & Security Enforcement", () => {
    it("should reject callback when state does not match session (login CSRF protection)", async () => {
      await assert.rejects(
        () =>
          handleSsoCallback({
            code: "test_code",
            state: "attacker_supplied_state",
            sessionState: "genuine_user_state",
            sessionNonce: "nonce",
            sessionCodeVerifier: "verifier",
          }),
        /Login CSRF detected/
      );
    });

    it("should reject callback when session state cookie is missing", async () => {
      await assert.rejects(
        () =>
          handleSsoCallback({
            code: "test_code",
            state: "state123",
            sessionState: null,
            sessionNonce: "nonce",
            sessionCodeVerifier: "verifier",
          }),
        /Login CSRF detected/
      );
    });

    it("should reject callback when provider reports error query param", async () => {
      const res = await fetch(
        `${baseUrl}/api/auth/sso/callback?error=access_denied`,
        { redirect: "manual" }
      );

      assert.equal(res.status, 302);
      const location = res.headers.get("location");
      assert.ok(location.includes("/login?error="));
      assert.match(decodeURIComponent(location), /access_denied/);
    });
  });
});
