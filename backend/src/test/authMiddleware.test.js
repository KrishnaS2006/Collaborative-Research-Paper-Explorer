import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import jwt from 'jsonwebtoken';
import { authenticateToken } from '../middleware/authenticate.js';

describe('Authentication Middleware (authenticateToken)', () => {
  const TEST_SECRET = 'a_very_secure_test_jwt_secret_with_at_least_32_characters_123!';
  const originalEnv = { ...process.env };

  beforeEach(() => {
    process.env.JWT_SECRET = TEST_SECRET;
    process.env.NODE_ENV = 'test';
  });

  afterEach(() => {
    process.env = { ...originalEnv };
  });

  const createMockReqRes = ({ cookies = {}, headers = {} } = {}) => {
    const req = {
      cookies,
      headers,
    };
    const res = {
      statusCode: 200,
      body: null,
      status(code) {
        this.statusCode = code;
        return this;
      },
      json(data) {
        this.body = data;
        return this;
      },
    };
    return { req, res };
  };

  it('should return 500 when JWT_SECRET is missing or empty in environment', () => {
    delete process.env.JWT_SECRET;
    let nextCalled = false;
    const { req, res } = createMockReqRes({ cookies: { token: 'some.valid.looking.jwt' } });

    authenticateToken(req, res, () => { nextCalled = true; });

    assert.equal(res.statusCode, 500);
    assert.match(res.body?.error, /Server authentication configuration error/);
    assert.equal(nextCalled, false);
  });

  it('should return 500 in production if JWT_SECRET is shorter than 32 characters', () => {
    process.env.JWT_SECRET = 'short_secret';
    process.env.NODE_ENV = 'production';
    let nextCalled = false;
    const { req, res } = createMockReqRes({ cookies: { token: 'some.jwt.token' } });

    authenticateToken(req, res, () => { nextCalled = true; });

    assert.equal(res.statusCode, 500);
    assert.match(res.body?.error, /Server authentication configuration error/);
    assert.equal(nextCalled, false);
  });

  it('should return 401 when neither cookie nor Authorization header is present', () => {
    let nextCalled = false;
    const { req, res } = createMockReqRes();

    authenticateToken(req, res, () => { nextCalled = true; });

    assert.equal(res.statusCode, 401);
    assert.match(res.body?.error, /No authentication token provided/);
    assert.equal(nextCalled, false);
  });

  it('should return 401 for an invalid or tampered token', () => {
    let nextCalled = false;
    const { req, res } = createMockReqRes({ cookies: { token: 'invalid.jwt.token' } });

    authenticateToken(req, res, () => { nextCalled = true; });

    assert.equal(res.statusCode, 401);
    assert.match(res.body?.error, /Invalid or expired token/);
    assert.equal(nextCalled, false);
  });

  it('should return 401 for an expired token', () => {
    let nextCalled = false;
    const expiredToken = jwt.sign(
      { id: 'user-1', email: 'test@univ.edu', role: 'STUDENT' },
      TEST_SECRET,
      { expiresIn: '-1s' }
    );
    const { req, res } = createMockReqRes({ cookies: { token: expiredToken } });

    authenticateToken(req, res, () => { nextCalled = true; });

    assert.equal(res.statusCode, 401);
    assert.match(res.body?.error, /Invalid or expired token/);
    assert.equal(nextCalled, false);
  });

  it('should return 401 if token payload has no user id', () => {
    let nextCalled = false;
    const invalidPayloadToken = jwt.sign({ foo: 'bar' }, TEST_SECRET, { expiresIn: '1h' });
    const { req, res } = createMockReqRes({ cookies: { token: invalidPayloadToken } });

    authenticateToken(req, res, () => { nextCalled = true; });

    assert.equal(res.statusCode, 401);
    assert.match(res.body?.error, /Invalid token payload/);
    assert.equal(nextCalled, false);
  });

  it('should authenticate successfully with a valid token from cookie', () => {
    let nextCalled = false;
    const payload = { id: 'user-123', email: 'student@example.edu', role: 'STUDENT' };
    const validToken = jwt.sign(payload, TEST_SECRET, { expiresIn: '1h' });

    const { req, res } = createMockReqRes({ cookies: { token: validToken } });

    authenticateToken(req, res, () => { nextCalled = true; });

    assert.equal(res.statusCode, 200);
    assert.equal(nextCalled, true);
    assert.equal(req.user.id, payload.id);
    assert.equal(req.user.email, payload.email);
    assert.equal(req.user.role, payload.role);
  });

  it('should authenticate successfully with a valid token from Authorization Bearer header', () => {
    let nextCalled = false;
    const payload = { id: 'prof-456', email: 'prof@example.edu', role: 'RESEARCHER' };
    const validToken = jwt.sign(payload, TEST_SECRET, { expiresIn: '1h' });

    const { req, res } = createMockReqRes({
      headers: { authorization: `Bearer ${validToken}` },
    });

    authenticateToken(req, res, () => { nextCalled = true; });

    assert.equal(res.statusCode, 200);
    assert.equal(nextCalled, true);
    assert.equal(req.user.id, payload.id);
    assert.equal(req.user.email, payload.email);
    assert.equal(req.user.role, payload.role);
  });
});
