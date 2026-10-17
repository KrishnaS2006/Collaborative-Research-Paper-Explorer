import { describe, it, before, after, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import cookieParser from 'cookie-parser';
import crypto from 'crypto';
import bcrypt from 'bcryptjs';
import pool from '../src/config/database.js';
import authRoutes from '../src/routes/auth.routes.js';
import errorHandler from '../src/middleware/errorHandler.js';
import {
  forgotPasswordRateLimiter,
  resetPasswordRateLimiter,
  loginRateLimiter,
} from '../src/middleware/rateLimiter.js';
import {
  validateForgotPasswordPayload,
  validateResetPasswordPayload,
} from '../src/utils/validation.js';
import {
  sendPasswordResetEmail,
  createSmtpTransporter,
  _setTransporterForTesting,
  _resetTransporterForTesting,
} from '../src/utils/emailService.js';

describe('Password Reset Feature Test Suite', () => {
  let app;
  let server;
  let baseUrl;

  const testEmail = `pwreset_${Date.now()}@testuniv.edu`;
  const initialPassword = 'OldPassword123!';
  const newPassword = 'NewSecretP@ssword2026!';
  let testUserId;

  before(async () => {
    process.env.JWT_SECRET = 'super_secure_test_jwt_secret_with_32_characters_12345';
    process.env.NODE_ENV = 'test';
    process.env.EXPOSE_DEV_RESET_TOKEN = 'true';

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

    // Create test user in DB for full lifecycle test if DB is available
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
    } catch (e) {
      console.warn('DB user setup skipped (running without live DB):', e.message);
    }
  });

  after(async () => {
    // Clean up test records
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

  describe('End-to-End Forgot & Reset Password Lifecycle (Database Verified)', () => {
    it('should complete the full reset lifecycle: request, token hash in DB, reset, single-use, and login verification', async () => {
      if (!testUserId) {
        console.log('Skipping DB lifecycle test because database is not connected.');
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
