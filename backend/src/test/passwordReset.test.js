import './setup.js';
import { describe, it, before, after, afterEach, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import cookieParser from 'cookie-parser';
import crypto from 'node:crypto';
import bcrypt from 'bcryptjs';

import pool from '../config/database.js';
import authRoutes from '../routes/auth.routes.js';
import errorHandler from '../middleware/errorHandler.js';
import {
  forgotPasswordRateLimiter,
  resetPasswordRateLimiter,
  loginRateLimiter,
} from '../middleware/rateLimiter.js';
import {
  validateForgotPasswordPayload,
  validateResetPasswordPayload,
} from '../utils/validation.js';
import {
  sendPasswordResetEmail,
  createSmtpTransporter,
  _setTransporterForTesting,
  _resetTransporterForTesting,
} from '../utils/emailService.js';
import {
  createSession,
  validateSessionSync,
  clearInMemorySessionsForTesting,
  invalidateAllUserSessions,
  setInvalidateAllUserSessionsForTesting,
  resetInvalidateAllUserSessionsForTesting,
} from '../services/session.service.js';
import { resetUserPassword } from '../services/auth.service.js';
import {
  _setConsumePasswordResetTokenForTesting,
  _resetConsumePasswordResetTokenForTesting,
  _setFindUserByEmailForTesting,
  _resetFindUserByEmailForTesting,
  _setCreatePasswordResetTokenForTesting,
  _resetCreatePasswordResetTokenForTesting,
  _setInvalidateResetTokensForTesting,
  _resetInvalidateResetTokensForTesting,
} from '../repositories/auth.repository.js';
import * as sessionService from '../services/session.service.js';

describe('Password Reset Feature Test Suite', () => {
  let app;
  let server;
  let baseUrl;

  const testEmail = `pwreset_${Date.now()}@testuniv.edu`;
  const initialPassword = 'OldPassword123!';
  const newPassword = 'NewSecretP@ssword2026!';
  let testUserId;

  before(async () => {
    app = express();
    app.use(express.json());
    app.use(cookieParser());
    app.use('/api/auth', authRoutes);
    app.use(errorHandler);

    await new Promise((resolve) => {
      server = app.listen(0, () => {
        const port = server.address().port;
        baseUrl = `http://127.0.0.1:${port}`;
        resolve();
      });
    });

    // Attempt to create test user in DB for full lifecycle test if live DB is available
    try {
      const salt = await bcrypt.genSalt(10);
      const hash = await bcrypt.hash(initialPassword, salt);
      const res = await pool.query(
        `INSERT INTO users (email, password_hash, full_name, role)
         VALUES ($1, $2, $3, $4)
         RETURNING id`,
        [testEmail, hash, 'Test User Reset', 'STUDENT']
      );
      testUserId = res.rows[0]?.id;
    } catch {
      // Running without live DB - integration tests requiring PostgreSQL will be skipped cleanly
    }
  });

  after(async () => {
    // Clean up test records if live DB was connected
    if (testUserId) {
      try {
        await pool.query('DELETE FROM password_reset_tokens WHERE user_id = $1', [testUserId]);
        await pool.query('DELETE FROM users WHERE id = $1', [testUserId]);
      } catch {
        // ignore cleanup errors
      }
    }

    if (server) {
      await new Promise((resolve) => server.close(resolve));
    }
  });

  afterEach(() => {
    _resetConsumePasswordResetTokenForTesting();
    _resetFindUserByEmailForTesting();
    _resetCreatePasswordResetTokenForTesting();
    _resetInvalidateResetTokensForTesting();
    _resetTransporterForTesting();
    resetInvalidateAllUserSessionsForTesting();
  });

  describe('Validation Functions', () => {
    it('validateForgotPasswordPayload should accept valid email', () => {
      const res = validateForgotPasswordPayload({ email: 'Student@Univ.Edu ' });
      assert.equal(res.valid, true);
      assert.equal(res.sanitized.email, 'student@univ.edu');
    });

    it('validateForgotPasswordPayload should reject missing or invalid email', () => {
      assert.equal(validateForgotPasswordPayload({}).valid, false);
      assert.equal(validateForgotPasswordPayload({ email: 'notanemail' }).valid, false);
      assert.equal(validateForgotPasswordPayload(null).valid, false);
      assert.equal(validateForgotPasswordPayload([]).valid, false);
    });

    it('validateResetPasswordPayload should accept valid token and strong password', () => {
      const res = validateResetPasswordPayload({
        token: 'a'.repeat(64),
        password: 'StrongPassword1!',
      });
      assert.equal(res.valid, true);
      assert.equal(res.sanitized.token, 'a'.repeat(64));
      assert.equal(res.sanitized.password, 'StrongPassword1!');
    });

    it('validateResetPasswordPayload should reject missing token or weak password', () => {
      assert.equal(validateResetPasswordPayload({ password: 'StrongPassword1!' }).valid, false);
      assert.equal(validateResetPasswordPayload({ token: 'abc', password: 'weak' }).valid, false);
      assert.equal(validateResetPasswordPayload(null).valid, false);
    });
  });

  describe('POST /api/auth/forgot-password (HTTP & Security)', () => {
    it('should return 400 for invalid email input', async () => {
      const res = await fetch(`${baseUrl}/api/auth/forgot-password`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: 'bad-email' }),
      });
      const data = await res.json();
      assert.equal(res.status, 400);
      assert.match(data.error, /valid email/i);
    });

    it('should return generic success response for unregistered email (no enumeration)', async () => {
      _setFindUserByEmailForTesting(async () => null);

      const res = await fetch(`${baseUrl}/api/auth/forgot-password`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: 'unregistered_nonexistent_user@example.com' }),
      });
      const data = await res.json();
      assert.equal(res.status, 200);
      assert.match(data.message, /If an account with that email exists/i);
    });

    it('should enforce rate limiting on forgot-password endpoint (429)', async () => {
      forgotPasswordRateLimiter.reset();

      // Send 5 rapid requests
      for (let i = 0; i < 5; i++) {
        await fetch(`${baseUrl}/api/auth/forgot-password`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email: `test_${i}@example.com` }),
        });
      }

      // 6th request should be blocked
      const res = await fetch(`${baseUrl}/api/auth/forgot-password`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: 'test_blocked@example.com' }),
      });
      const data = await res.json();
      assert.equal(res.status, 429);
      assert.match(data.error, /Too many password reset requests/i);

      forgotPasswordRateLimiter.reset();
    });
  });

  describe('POST /api/auth/reset-password (HTTP & Security)', () => {
    it('should return 400 when token is missing', async () => {
      const res = await fetch(`${baseUrl}/api/auth/reset-password`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password: 'StrongPassword1!' }),
      });
      const data = await res.json();
      assert.equal(res.status, 400);
      assert.match(data.error, /Reset token is required/i);
    });

    it('should return 400 when new password fails strong password policy', async () => {
      const res = await fetch(`${baseUrl}/api/auth/reset-password`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token: 'dummy_token', password: 'weak' }),
      });
      const data = await res.json();
      assert.equal(res.status, 400);
      assert.match(data.error, /at least 8 characters/i);
    });

    it('should return 400 for a nonexistent/invalid token', async () => {
      _setConsumePasswordResetTokenForTesting(async () => ({
        success: false,
        reason: 'invalid',
      }));

      const res = await fetch(`${baseUrl}/api/auth/reset-password`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          token: crypto.randomBytes(32).toString('hex'),
          password: 'StrongPassword1!',
        }),
      });
      const data = await res.json();
      assert.equal(res.status, 400);
      assert.match(data.error, /Invalid or expired/i);
    });

    it('should enforce rate limiting on reset-password endpoint (429)', async () => {
      resetPasswordRateLimiter.reset();

      for (let i = 0; i < 5; i++) {
        await fetch(`${baseUrl}/api/auth/reset-password`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ token: 't'.repeat(32), password: 'weak' }),
        });
      }

      const res = await fetch(`${baseUrl}/api/auth/reset-password`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token: 't'.repeat(32), password: 'ValidPassword1!' }),
      });
      const data = await res.json();
      assert.equal(res.status, 429);
      assert.match(data.error, /Too many password reset attempts/i);

      resetPasswordRateLimiter.reset();
    });
  });

  describe('Active Session Revocation After Password Reset', () => {
    beforeEach(() => {
      clearInMemorySessionsForTesting();
    });

    it('should revoke all active user sessions upon successful password reset', async () => {
      const targetUserId = 'target-user-uuid-1111';
      const otherUserId = 'other-user-uuid-2222';

      // Register two active sessions for target user and one for another user
      const session1Token = 'session_jwt_target_1';
      const session2Token = 'session_jwt_target_2';
      const otherToken = 'session_jwt_other_user';

      await createSession({ userId: targetUserId, token: session1Token });
      await createSession({ userId: targetUserId, token: session2Token });
      await createSession({ userId: otherUserId, token: otherToken });

      // Verify all three sessions are active initially
      assert.equal(validateSessionSync(session1Token).valid, true);
      assert.equal(validateSessionSync(session2Token).valid, true);
      assert.equal(validateSessionSync(otherToken).valid, true);

      // Mock repository to return success and target user id
      _setConsumePasswordResetTokenForTesting(async () => ({
        success: true,
        userId: targetUserId,
      }));

      const result = await resetUserPassword({
        token: 'mock_valid_token_32_characters_1234',
        password: 'NewStrongPassword1!',
      });

      assert.ok(result.message);
      assert.match(result.message, /Password has been reset successfully/i);

      // Verify target user's sessions are now revoked
      const check1 = validateSessionSync(session1Token);
      const check2 = validateSessionSync(session2Token);
      assert.equal(check1.valid, false, 'Session 1 must be revoked');
      assert.equal(check1.reason, 'revoked');
      assert.equal(check2.valid, false, 'Session 2 must be revoked');
      assert.equal(check2.reason, 'revoked');

      // Verify other user's session remains untouched and valid
      const checkOther = validateSessionSync(otherToken);
      assert.equal(checkOther.valid, true, "Other user's session must not be affected");
    });

    it('should reject reset and not revoke sessions when token is already used', async () => {
      const targetUserId = 'target-user-already-used';
      const activeToken = 'session_token_should_stay_active';
      await createSession({ userId: targetUserId, token: activeToken });

      _setConsumePasswordResetTokenForTesting(async () => ({
        success: false,
        reason: 'already_used',
      }));

      await assert.rejects(
        async () => {
          await resetUserPassword({
            token: 'reused_token_123',
            password: 'NewStrongPassword1!',
          });
        },
        (err) => {
          assert.equal(err.statusCode, 400);
          assert.match(err.message, /already been used/i);
          return true;
        }
      );

      // Session must remain active since reset was rejected
      assert.equal(validateSessionSync(activeToken).valid, true);
    });

    it('should reject reset and not revoke sessions when token is expired', async () => {
      const targetUserId = 'target-user-expired';
      const activeToken = 'session_token_expired_stay_active';
      await createSession({ userId: targetUserId, token: activeToken });

      _setConsumePasswordResetTokenForTesting(async () => ({
        success: false,
        reason: 'expired',
      }));

      await assert.rejects(
        async () => {
          await resetUserPassword({
            token: 'expired_token_123',
            password: 'NewStrongPassword1!',
          });
        },
        (err) => {
          assert.equal(err.statusCode, 400);
          assert.match(err.message, /expired/i);
          return true;
        }
      );

      assert.equal(validateSessionSync(activeToken).valid, true);
    });

    it('should reject reset when token is invalid or non-existent', async () => {
      _setConsumePasswordResetTokenForTesting(async () => ({
        success: false,
        reason: 'invalid',
      }));

      await assert.rejects(
        async () => {
          await resetUserPassword({
            token: 'invalid_token_123',
            password: 'NewStrongPassword1!',
          });
        },
        (err) => {
          assert.equal(err.statusCode, 400);
          assert.match(err.message, /Invalid or expired/i);
          return true;
        }
      );
    });

    it('should securely handle session invalidation failure by throwing error instead of reporting false success', async () => {
      const targetUserId = 'target-user-invalidation-failure';

      _setConsumePasswordResetTokenForTesting(async () => ({
        success: true,
        userId: targetUserId,
      }));

      // Create active session for the target user to ensure defense-in-depth cutoff
      const session1Token = 'session_jwt_target_1_fail';
      const session2Token = 'session_jwt_target_2_fail';
      await createSession({ userId: targetUserId, token: session1Token });
      await createSession({ userId: targetUserId, token: session2Token });

      // Simulate unexpected error during session invalidation
      setInvalidateAllUserSessionsForTesting(async () => {
        throw new Error('Redis/DB connection failed during session invalidation');
      });

      await assert.rejects(
        async () => {
          await resetUserPassword({
            token: 'mock_valid_token_32_characters_1234',
            password: 'NewStrongPassword1!',
          });
        },
        (err) => {
          assert.equal(err.statusCode, 500);
          assert.match(
            err.message,
            /Password has been reset, but revoking existing sessions encountered an error/i
          );
          return true;
        }
      );

      // After failure, ensure sessions are still revoked via in-memory cutoff
      const postFailureCheck1 = validateSessionSync(session1Token);
      const postFailureCheck2 = validateSessionSync(session2Token);
      assert.equal(postFailureCheck1.valid, false, 'Session 1 must be revoked via cutoff even if DB revocation fails');
      assert.equal(postFailureCheck1.reason, 'revoked');
      assert.equal(postFailureCheck2.valid, false, 'Session 2 must be revoked via cutoff even if DB revocation fails');
      assert.equal(postFailureCheck2.reason, 'revoked');
    });
  });

  describe('End-to-End Forgot & Reset Password Lifecycle (Database Verified)', () => {
    it('should complete the full reset lifecycle: request, token hash in DB, reset, single-use, and login verification', async () => {
      if (!testUserId) {
        console.log('Skipping live DB lifecycle test because PostgreSQL is not connected (expected in unit test environment).');
        return;
      }

      // Step 1: Request reset
      forgotPasswordRateLimiter.reset();
      const forgotRes = await fetch(`${baseUrl}/api/auth/forgot-password`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: testEmail }),
      });
      const forgotData = await forgotRes.json();
      assert.equal(forgotRes.status, 200);
      assert.match(forgotData.message, /If an account with that email exists/i);
      assert.ok(forgotData.devResetToken, 'Expected devResetToken in test environment');

      const rawToken = forgotData.devResetToken;
      const tokenHash = crypto.createHash('sha256').update(rawToken).digest('hex');

      // Step 2: Verify database stored token hash, NOT plaintext token
      const dbToken = await pool.query(
        'SELECT * FROM password_reset_tokens WHERE user_id = $1 AND token_hash = $2',
        [testUserId, tokenHash]
      );
      assert.equal(dbToken.rows.length, 1);
      assert.equal(dbToken.rows[0].used_at, null);
      assert.ok(new Date(dbToken.rows[0].expires_at) > new Date());

      // Step 3: Test expired token rejection
      const expiredRawToken = crypto.randomBytes(32).toString('hex');
      const expiredHash = crypto.createHash('sha256').update(expiredRawToken).digest('hex');
      await pool.query(
        `INSERT INTO password_reset_tokens (user_id, token_hash, expires_at)
         VALUES ($1, $2, CURRENT_TIMESTAMP - INTERVAL '5 minutes')`,
        [testUserId, expiredHash]
      );

      const expiredRes = await fetch(`${baseUrl}/api/auth/reset-password`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token: expiredRawToken, password: newPassword }),
      });
      const expiredData = await expiredRes.json();
      assert.equal(expiredRes.status, 400);
      assert.match(expiredData.error, /expired/i);

      // Step 4: Perform successful reset with valid token
      resetPasswordRateLimiter.reset();
      const resetRes = await fetch(`${baseUrl}/api/auth/reset-password`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token: rawToken, password: newPassword }),
      });
      const resetData = await resetRes.json();
      assert.equal(resetRes.status, 200);
      assert.match(resetData.message, /Password has been reset successfully/i);

      // Step 5: Verify token is now marked as used in database (single-use)
      const usedCheck = await pool.query(
        'SELECT used_at FROM password_reset_tokens WHERE token_hash = $1',
        [tokenHash]
      );
      assert.ok(usedCheck.rows[0].used_at !== null, 'used_at should be populated');

      // Step 6: Attempting to reuse the same token should fail
      const reuseRes = await fetch(`${baseUrl}/api/auth/reset-password`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token: rawToken, password: 'AnotherPassword1!' }),
      });
      const reuseData = await reuseRes.json();
      assert.equal(reuseRes.status, 400);
      assert.match(reuseData.error, /already been used/i);

      // Step 7: Verify login with old password fails (401)
      loginRateLimiter.reset();
      const oldLoginRes = await fetch(`${baseUrl}/api/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: testEmail, password: initialPassword }),
      });
      assert.equal(oldLoginRes.status, 401);

      // Step 8: Verify login with new password succeeds (200)
      const newLoginRes = await fetch(`${baseUrl}/api/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: testEmail, password: newPassword }),
      });
      assert.equal(newLoginRes.status, 200);
      const newLoginData = await newLoginRes.json();
      assert.equal(newLoginData.user.email, testEmail);
    });
  });

  describe('Email Service & Gmail SMTP Configuration', () => {
    const originalEnv = { ...process.env };

    afterEach(() => {
      _resetTransporterForTesting();
      process.env = { ...originalEnv };
    });

    it('createSmtpTransporter should throw error if credentials are missing', () => {
      delete process.env.SMTP_USER;
      delete process.env.SMTP_PASS;
      assert.throws(
        () => createSmtpTransporter(),
        /SMTP_USER or SMTP_PASS environment variable is missing/
      );
    });

    it('createSmtpTransporter should create transporter when credentials are provided', () => {
      process.env.SMTP_USER = 'test@gmail.com';
      process.env.SMTP_PASS = '16characterapppwd';
      process.env.SMTP_HOST = 'smtp.gmail.com';
      process.env.SMTP_PORT = '587';

      const transporter = createSmtpTransporter();
      assert.ok(transporter, 'Transporter should be created');
      assert.equal(typeof transporter.sendMail, 'function');
      assert.equal(transporter.options.host, 'smtp.gmail.com');
      assert.equal(transporter.options.port, 587);
      assert.equal(transporter.options.secure, false, 'Port 587 should use STARTTLS (secure: false)');
    });

    it('createSmtpTransporter should use secure: true for port 465 (SSL)', () => {
      process.env.SMTP_USER = 'test@gmail.com';
      process.env.SMTP_PASS = '16characterapppwd';
      process.env.SMTP_PORT = '465';

      const transporter = createSmtpTransporter();
      assert.equal(transporter.options.port, 465);
      assert.equal(transporter.options.secure, true, 'Port 465 should use SSL (secure: true)');
    });

    it('sendPasswordResetEmail should format console delivery correctly in dev mode', async () => {
      process.env.EMAIL_SERVICE_MODE = 'console';
      process.env.FRONTEND_URL = 'http://localhost:5173';

      const result = await sendPasswordResetEmail({
        to: 'researcher@univ.edu',
        name: 'Dr. Researcher',
        resetToken: 'mocktoken123',
      });

      assert.equal(result.success, true);
      assert.equal(result.mode, 'console');
      assert.equal(
        result.targetUrl,
        'http://localhost:5173/reset-password?token=mocktoken123'
      );
    });

    it('sendPasswordResetEmail should send email successfully using mocked SMTP transporter', async () => {
      process.env.EMAIL_SERVICE_MODE = 'smtp';
      process.env.SMTP_USER = 'test@gmail.com';
      process.env.SMTP_PASS = 'mockpassword';

      let capturedMailOptions = null;
      _setTransporterForTesting({
        sendMail: async (mailOptions) => {
          capturedMailOptions = mailOptions;
          return { messageId: '<test-message-id-999@gmail.com>' };
        },
      });

      const result = await sendPasswordResetEmail({
        to: 'user@example.com',
        name: 'Jane Doe',
        resetToken: 'securetokenabc',
      });

      assert.equal(result.success, true);
      assert.equal(result.mode, 'smtp');
      assert.equal(result.messageId, '<test-message-id-999@gmail.com>');
      assert.ok(capturedMailOptions, 'Mail options should be passed to sendMail');
      assert.equal(capturedMailOptions.to, 'user@example.com');
      assert.match(capturedMailOptions.text, /securetokenabc/);
      assert.match(capturedMailOptions.html, /Reset My Password/);
      assert.match(capturedMailOptions.from, /Collaborative Research Paper Explorer/);
    });

    it('sendPasswordResetEmail should safely catch and return SMTP errors without crashing', async () => {
      process.env.EMAIL_SERVICE_MODE = 'smtp';
      process.env.SMTP_USER = 'test@gmail.com';
      process.env.SMTP_PASS = 'mockpassword';

      _setTransporterForTesting({
        sendMail: async () => {
          throw new Error('Invalid login: 535-5.7.8 Username and Password not accepted');
        },
      });

      const result = await sendPasswordResetEmail({
        to: 'user@example.com',
        name: 'Jane Doe',
        resetToken: 'securetokenabc',
      });

      assert.equal(result.success, false);
      assert.equal(result.mode, 'smtp');
      assert.match(result.error, /Username and Password not accepted/);
    });

    it('POST /api/auth/forgot-password should return generic 200 response even when SMTP transport fails', async () => {
      forgotPasswordRateLimiter.reset();
      process.env.EMAIL_SERVICE_MODE = 'smtp';
      process.env.SMTP_USER = 'test@gmail.com';
      process.env.SMTP_PASS = 'mockpassword';

      _setFindUserByEmailForTesting(async () => ({
        id: 'mock-test-id-1234',
        email: testEmail,
        full_name: 'Dr. Researcher',
      }));
      _setInvalidateResetTokensForTesting(async () => {});
      _setCreatePasswordResetTokenForTesting(async () => ({ id: 'token-uuid' }));

      _setTransporterForTesting({
        sendMail: async () => {
          throw new Error('Connection timeout to smtp.gmail.com');
        },
      });

      const res = await fetch(`${baseUrl}/api/auth/forgot-password`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: testEmail }),
      });
      const data = await res.json();

      assert.equal(res.status, 200);
      assert.match(data.message, /If an account with that email exists/i);
    });
  });
});
