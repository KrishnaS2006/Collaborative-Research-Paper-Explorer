import { describe, it, before, after, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import cookieParser from 'cookie-parser';
import authRoutes from '../routes/auth.routes.js';
import errorHandler from '../middleware/errorHandler.js';
import { loginRateLimiter } from '../middleware/rateLimiter.js';
import bcrypt from 'bcryptjs';
import {
  _setFindUserByEmailForTesting,
  _resetFindUserByEmailForTesting,
} from '../repositories/auth.repository.js';

describe('Auth Router Integration (HTTP Endpoints)', () => {
  let app;
  let server;
  let baseUrl;
  const originalEnv = { ...process.env };

  before(async () => {
    process.env.JWT_SECRET = 'route-test-jwt-secret-minimum-32-chars-long-12345';
    process.env.NODE_ENV = 'test';

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
  });

  after(async () => {
    process.env = { ...originalEnv };
    if (server) {
      await new Promise((resolve) => server.close(resolve));
    }
  });

  afterEach(() => {
    _resetFindUserByEmailForTesting();
    loginRateLimiter.reset();
  });

  describe('POST /api/auth/register (Validation)', () => {
    it('should return 400 when full_name is missing', async () => {
      const res = await fetch(`${baseUrl}/api/auth/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: 'valid@example.com',
          password: 'ValidPassword1!',
          role: 'STUDENT',
        }),
      });

      const body = await res.json();
      assert.equal(res.status, 400);
      assert.match(body.error, /Full name is required/);
    });

    it('should return 400 when email format is invalid', async () => {
      const res = await fetch(`${baseUrl}/api/auth/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          full_name: 'Test User',
          email: 'invalid-email-address',
          password: 'ValidPassword1!',
          role: 'STUDENT',
        }),
      });

      const body = await res.json();
      assert.equal(res.status, 400);
      assert.match(body.error, /valid email/);
    });

    it('should return 400 when password does not meet strong-password policy', async () => {
      const res = await fetch(`${baseUrl}/api/auth/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          full_name: 'Test User',
          email: 'user@example.com',
          password: 'weak',
          role: 'STUDENT',
        }),
      });

      const body = await res.json();
      assert.equal(res.status, 400);
      assert.match(body.error, /at least 8 characters/);
    });

    it('should return 400 when role is disallowed (e.g., SYSTEM_ADMIN)', async () => {
      const res = await fetch(`${baseUrl}/api/auth/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          full_name: 'Admin Attempt',
          email: 'admin@example.com',
          password: 'ValidPassword1!',
          role: 'SYSTEM_ADMIN',
        }),
      });

      const body = await res.json();
      assert.equal(res.status, 400);
      assert.match(body.error, /Only STUDENT or RESEARCHER/);
    });

    it('should return 400 when request body is an array instead of object', async () => {
      const res = await fetch(`${baseUrl}/api/auth/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify([]),
      });

      const body = await res.json();
      assert.equal(res.status, 400);
      assert.match(body.error, /Invalid request body/);
    });
  });

  describe('POST /api/auth/login (Validation & Rate Limiting)', () => {
    it('should return 400 when email or password is missing', async () => {
      const res = await fetch(`${baseUrl}/api/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: 'user@example.com' }),
      });

      const body = await res.json();
      assert.equal(res.status, 400);
      assert.match(body.error, /Password is required/);
    });

    it('should return 400 when request body is non-object', async () => {
      const res = await fetch(`${baseUrl}/api/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify([1, 2, 3]),
      });

      const body = await res.json();
      assert.equal(res.status, 400);
      assert.match(body.error, /Invalid request body/);
    });

    it('should return 429 when login rate limit is exceeded', async () => {
      // Reset rate limiter hits first
      loginRateLimiter.reset();

      // Send 5 rapid login requests
      for (let i = 0; i < 5; i++) {
        await fetch(`${baseUrl}/api/auth/login`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email: '', password: '' }),
        });
      }

      // 6th request should hit rate limit
      const res = await fetch(`${baseUrl}/api/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: 'user@example.com', password: 'Password1!' }),
      });

      const body = await res.json();
      assert.equal(res.status, 429);
      assert.match(body.error, /Too many login attempts/);
      assert.ok(res.headers.get('retry-after'));

      // Clean up for subsequent tests
      loginRateLimiter.reset();
    });

    it('should successfully log in with valid credentials, returning user and setting session cookie', async () => {
      const passwordHash = await bcrypt.hash('CorrectPassword1!', 10);
      _setFindUserByEmailForTesting(async (email) => ({
        id: 'user-login-test-id',
        email: email.toLowerCase(),
        password_hash: passwordHash,
        full_name: 'Verified User',
        role: 'RESEARCHER',
        affiliation: 'Science Dept',
        research_interests: ['Genetics'],
        email_verified: true,
      }));

      const res = await fetch(`${baseUrl}/api/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: 'verified@university.edu',
          password: 'CorrectPassword1!',
        }),
      });

      assert.equal(res.status, 200);
      const data = await res.json();
      assert.equal(data.message, 'Logged in successfully.');
      assert.ok(data.user);
      assert.equal(data.user.email, 'verified@university.edu');
      assert.equal(data.user.role, 'RESEARCHER');

      // Verify Set-Cookie header contains token
      const cookieHeader = res.headers.get('set-cookie');
      assert.ok(cookieHeader);
      assert.match(cookieHeader, /token=/);
      assert.match(cookieHeader, /HttpOnly/i);
    });

    it('should return 401 with generic error for nonexistent account (enumeration prevention)', async () => {
      _setFindUserByEmailForTesting(async () => null);

      const res = await fetch(`${baseUrl}/api/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: 'nonexistent@university.edu',
          password: 'Password123!',
        }),
      });

      assert.equal(res.status, 401);
      const data = await res.json();
      assert.equal(data.error, 'Invalid email or password.');
    });

    it('should return 401 with generic error for incorrect password', async () => {
      const passwordHash = await bcrypt.hash('RealPassword123!', 10);
      _setFindUserByEmailForTesting(async (email) => ({
        id: 'user-id-wrong-pwd',
        email: email.toLowerCase(),
        password_hash: passwordHash,
        full_name: 'Real User',
        role: 'STUDENT',
        email_verified: true,
      }));

      const res = await fetch(`${baseUrl}/api/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: 'real@university.edu',
          password: 'WrongPassword123!',
        }),
      });

      assert.equal(res.status, 401);
      const data = await res.json();
      assert.equal(data.error, 'Invalid email or password.');
    });

    it('should return 403 when unverified user attempts to log in', async () => {
      const passwordHash = await bcrypt.hash('CorrectPassword1!', 10);
      _setFindUserByEmailForTesting(async (email) => ({
        id: 'unverified-user-id',
        email: email.toLowerCase(),
        password_hash: passwordHash,
        full_name: 'Unverified User',
        role: 'STUDENT',
        email_verified: false,
      }));

      const res = await fetch(`${baseUrl}/api/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: 'unverified@university.edu',
          password: 'CorrectPassword1!',
        }),
      });

      assert.equal(res.status, 403);
      const data = await res.json();
      assert.match(data.error, /verify your email address/);
    });
  });

  describe('GET /api/auth/me (Protected Route Verification)', () => {
    it('should return 401 when accessing /me without token', async () => {
      const res = await fetch(`${baseUrl}/api/auth/me`);
      const body = await res.json();
      assert.equal(res.status, 401);
      assert.match(body.error, /No authentication token provided/);
    });

    it('should return 401 when accessing /me with tampered Bearer token', async () => {
      const res = await fetch(`${baseUrl}/api/auth/me`, {
        headers: {
          Authorization: 'Bearer invalid.token.payload',
        },
      });
      const body = await res.json();
      assert.equal(res.status, 401);
      assert.match(body.error, /Invalid or expired token/);
    });
  });
});
