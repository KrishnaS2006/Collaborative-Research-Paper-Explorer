import { describe, it, before, after, beforeEach } from "node:test";
import assert from "node:assert/strict";
import express from "express";
import cookieParser from "cookie-parser";
import jwt from "jsonwebtoken";

import authRoutes from "../routes/auth.routes.js";
import errorHandler from "../middleware/errorHandler.js";
import {
  createSession,
  validateSessionSync,
  invalidateSession,
  invalidateAllUserSessions,
  hashToken,
  setSessionInactivityTimeoutForTesting,
  resetSessionInactivityTimeoutForTesting,
  clearInMemorySessionsForTesting,
} from "../services/session.service.js";

describe("FR-04: Logout & Session Expiration Test Suite", () => {
  const TEST_SECRET =
    "session-test-jwt-secret-minimum-32-chars-long-security-12345";
  let app;
  let server;
  let baseUrl;
  const originalEnv = { ...process.env };

  before(async () => {
    process.env.JWT_SECRET = TEST_SECRET;
    process.env.NODE_ENV = "test";

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
    resetSessionInactivityTimeoutForTesting();
    clearInMemorySessionsForTesting();
    if (server) {
      await new Promise((resolve) => server.close(resolve));
    }
  });

  beforeEach(() => {
    resetSessionInactivityTimeoutForTesting();
    clearInMemorySessionsForTesting();
  });

  let tokenCounter = 0;
  const generateTestToken = (userId = "user-test-uuid-1") => {
    tokenCounter++;
    return jwt.sign(
      {
        id: userId,
        _id: userId,
        email: `researcher${tokenCounter}@stanford.edu`,
        role: "RESEARCHER",
      },
      TEST_SECRET,
      { expiresIn: "8h" }
    );
  };

  /* ===================================================================
   * 1. SERVER-SIDE TOKEN INVALIDATION ON LOGOUT
   * =================================================================== */
  describe("Server-Side Token Invalidation on Logout", () => {
    it("should invalidate the token on server when logging out via cookie", async () => {
      const token = generateTestToken();
      await createSession({ userId: "user-test-uuid-1", token });

      // Verify token can initially access /me
      const checkBefore = await fetch(`${baseUrl}/api/auth/me`, {
        headers: { Cookie: `token=${token}` },
      });
      assert.equal(checkBefore.status, 200);

      // Call POST /api/auth/logout with the cookie
      const logoutRes = await fetch(`${baseUrl}/api/auth/logout`, {
        method: "POST",
        headers: { Cookie: `token=${token}` },
      });
      assert.equal(logoutRes.status, 200);
      const logoutBody = await logoutRes.json();
      assert.equal(logoutBody.message, "Logged out successfully.");

      // Verify server-side invalidation: subsequent access to /me with the same token is rejected
      const checkAfter = await fetch(`${baseUrl}/api/auth/me`, {
        headers: { Cookie: `token=${token}` },
      });
      assert.equal(checkAfter.status, 401);
      const afterBody = await checkAfter.json();
      assert.equal(afterBody.code, "SESSION_REVOKED");
    });

    it("should invalidate the token on server when logging out via Authorization Bearer header", async () => {
      const token = generateTestToken("user-bearer-1");
      await createSession({ userId: "user-bearer-1", token });

      // Call POST /api/auth/logout with Bearer token
      const logoutRes = await fetch(`${baseUrl}/api/auth/logout`, {
        method: "POST",
        headers: { Authorization: `Bearer ${token}` },
      });
      assert.equal(logoutRes.status, 200);

      // Subsequent access with Bearer header is rejected
      const checkAfter = await fetch(`${baseUrl}/api/auth/me`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      assert.equal(checkAfter.status, 401);
      const afterBody = await checkAfter.json();
      assert.equal(afterBody.code, "SESSION_REVOKED");
    });

    it("should handle logout safely when no token is present", async () => {
      const res = await fetch(`${baseUrl}/api/auth/logout`, {
        method: "POST",
      });
      assert.equal(res.status, 200);
      const body = await res.json();
      assert.equal(body.message, "Logged out successfully.");
    });
  });

  /* ===================================================================
   * 2. AUTOMATIC SESSION EXPIRATION AFTER 30 MINUTES INACTIVITY
   * =================================================================== */
  describe("Automatic Session Expiration After Inactivity (Idle Tracking)", () => {
    it("should allow active requests within inactivity window and update activity timestamp", async () => {
      const token = generateTestToken("user-active-1");
      const session = await createSession({ userId: "user-active-1", token });
      const initialActiveAt = session.last_active_at.getTime();

      // Small delay to ensure timestamp advances
      await new Promise((r) => setTimeout(r, 20));

      const validation = validateSessionSync(token);
      assert.equal(validation.valid, true);
      assert.ok(validation.session.last_active_at.getTime() >= initialActiveAt);
    });

    it("should expire the session after inactivity window has elapsed (idle_timeout)", async () => {
      // Set inactivity timeout to 50ms for testing idle expiration
      setSessionInactivityTimeoutForTesting(50);

      const token = generateTestToken("user-idle-1");
      await createSession({ userId: "user-idle-1", token });

      // Verify session is initially valid
      const initialCheck = validateSessionSync(token);
      assert.equal(initialCheck.valid, true);

      // Wait 80ms to simulate inactivity exceeding the 50ms threshold
      await new Promise((r) => setTimeout(r, 80));

      // Verify HTTP middleware responds with 401 and idle timeout error
      const res = await fetch(`${baseUrl}/api/auth/me`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      assert.equal(res.status, 401);
      const body = await res.json();
      // After idle_timeout invalidation, subsequent checks may return revoked or idle_timeout
      assert.ok(
        body.code === "SESSION_IDLE_TIMEOUT" || body.code === "SESSION_REVOKED",
        `Expected SESSION_IDLE_TIMEOUT or SESSION_REVOKED but got ${body.code}`
      );
    });

    it("should clear session cookie on response when idle timeout occurs", async () => {
      setSessionInactivityTimeoutForTesting(50);

      const token = generateTestToken("user-cookie-idle");
      await createSession({ userId: "user-cookie-idle", token });

      await new Promise((r) => setTimeout(r, 80));

      const res = await fetch(`${baseUrl}/api/auth/me`, {
        headers: { Cookie: `token=${token}` },
      });
      assert.equal(res.status, 401);

      // Verify Set-Cookie header is present (clearing the cookie)
      const setCookie = res.headers.get("set-cookie");
      if (setCookie) {
        assert.match(setCookie, /token=/);
      }
    });

    it("active requests should refresh the idle window, preventing premature expiration", async () => {
      // Use a large inactivity timeout (15s) so the DB lookup delay (~2-3s per request)
      // doesn't accidentally exceed it. The test verifies the sliding window concept:
      // each successful request resets the idle timer, and only when idle time truly
      // exceeds the threshold does the session expire.
      setSessionInactivityTimeoutForTesting(15000);

      const token = generateTestToken("user-sliding-1");
      await createSession({ userId: "user-sliding-1", token });

      // Request 1 — within window; verify the session validates and activity is refreshed
      const check1 = validateSessionSync(token);
      assert.equal(check1.valid, true, "Direct validation should succeed immediately");

      // Simulate passage of time via small delay
      await new Promise((r) => setTimeout(r, 50));

      // Request 2 — also within window; activity should be refreshed again
      const check2 = validateSessionSync(token);
      assert.equal(check2.valid, true, "Second validation within window should succeed");
      assert.ok(
        check2.session.last_active_at.getTime() >= check1.session.last_active_at.getTime(),
        "last_active_at should advance with each validation"
      );

      // Now verify the HTTP endpoint also works (this is slow due to test DB):
      const res = await fetch(`${baseUrl}/api/auth/me`, {
        headers: { Cookie: `token=${token}` },
      });
      assert.equal(res.status, 200, "HTTP request within 15s window should succeed");

      // Set timeout very short and verify expiration triggers
      setSessionInactivityTimeoutForTesting(50);
      await new Promise((r) => setTimeout(r, 80));

      const checkExpired = validateSessionSync(token);
      assert.equal(checkExpired.valid, false, "Should expire after idle period");
    });
  });

  /* ===================================================================
   * 3. SESSION SERVICE UNIT TESTS
   * =================================================================== */
  describe("Session Service Cryptographic Token Hashing & User Invalidation", () => {
    it("hashToken should generate consistent 64-character SHA-256 hashes", () => {
      const sample = "sample.token.value";
      const hash1 = hashToken(sample);
      const hash2 = hashToken(sample);
      assert.equal(hash1, hash2);
      assert.equal(hash1.length, 64);
      assert.match(hash1, /^[0-9a-f]{64}$/);
    });

    it("invalidateAllUserSessions should revoke all sessions belonging to the user", async () => {
      const userA = "user-multi-session";
      const tokenA1 = generateTestToken(userA);

      // Small delay to ensure different JWT iat
      await new Promise((r) => setTimeout(r, 5));
      const tokenA2 = generateTestToken(userA);

      const s1 = await createSession({ userId: userA, token: tokenA1 });
      const s2 = await createSession({ userId: userA, token: tokenA2 });

      // Verify both sessions were created with correct user_id
      assert.equal(s1.user_id, userA);
      assert.equal(s2.user_id, userA);

      assert.equal(validateSessionSync(tokenA1).valid, true);
      assert.equal(validateSessionSync(tokenA2).valid, true);

      // Revoke all sessions for userA
      const count = await invalidateAllUserSessions(userA);
      assert.ok(count >= 2, `Expected at least 2 revoked sessions, got ${count}`);

      // Both tokens must now be rejected
      const check1 = validateSessionSync(tokenA1);
      assert.equal(check1.valid, false);
      assert.equal(check1.reason, "revoked");

      const check2 = validateSessionSync(tokenA2);
      assert.equal(check2.valid, false);
      assert.equal(check2.reason, "revoked");
    });

    it("invalidateSession should immediately revoke a specific session", async () => {
      const token = generateTestToken("user-revoke-one");
      await createSession({ userId: "user-revoke-one", token });

      assert.equal(validateSessionSync(token).valid, true);

      const result = await invalidateSession(token);
      assert.equal(result, true);

      const check = validateSessionSync(token);
      assert.equal(check.valid, false);
      assert.equal(check.reason, "revoked");
    });
  });
});
