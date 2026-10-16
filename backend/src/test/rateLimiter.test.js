import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { createRateLimiter } from '../middleware/rateLimiter.js';

describe('Rate Limiter Middleware', () => {
  let limiter;

  beforeEach(() => {
    limiter = createRateLimiter({
      windowMs: 1000, // 1 second for test
      max: 3,         // 3 allowed
      message: 'Rate limit test reached.',
    });
  });

  const createMockReqRes = (ip = '127.0.0.1', headers = {}) => {
    const req = {
      ip,
      headers,
      socket: { remoteAddress: ip },
    };
    const res = {
      statusCode: 200,
      headers: {},
      body: null,
      setHeader(name, val) {
        this.headers[name] = val;
      },
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

  it('should allow requests within the limit', () => {
    let nextCalledCount = 0;
    const next = () => { nextCalledCount++; };

    for (let i = 0; i < 3; i++) {
      const { req, res } = createMockReqRes('192.168.1.10');
      limiter(req, res, next);
      assert.equal(res.statusCode, 200);
    }

    assert.equal(nextCalledCount, 3);
  });

  it('should block requests exceeding the maximum limit with 429 and Retry-After', () => {
    let nextCalledCount = 0;
    const next = () => { nextCalledCount++; };

    const ip = '10.0.0.1';

    // First 3 requests should pass
    for (let i = 0; i < 3; i++) {
      const { req, res } = createMockReqRes(ip);
      limiter(req, res, next);
      assert.equal(res.statusCode, 200);
    }
    assert.equal(nextCalledCount, 3);

    // 4th request should be blocked
    const { req: req4, res: res4 } = createMockReqRes(ip);
    limiter(req4, res4, next);

    assert.equal(res4.statusCode, 429);
    assert.equal(res4.body?.error, 'Rate limit test reached.');
    assert.ok(res4.headers['Retry-After']);
    // next should not have been called for 4th request
    assert.equal(nextCalledCount, 3);
  });

  it('should not be bypassed by spoofed x-forwarded-for headers when remote address is identical', () => {
    let nextCalledCount = 0;
    const next = () => { nextCalledCount++; };
    const realIp = '198.51.100.5';

    // Send 3 requests with changing forwarded IPs but same real TCP socket IP
    for (let i = 0; i < 3; i++) {
      const { req, res } = createMockReqRes(realIp, { 'x-forwarded-for': `203.0.113.${i}` });
      limiter(req, res, next);
      assert.equal(res.statusCode, 200);
    }

    // 4th request with another spoofed IP should still be blocked based on real IP
    const { req: reqBlocked, res: resBlocked } = createMockReqRes(realIp, {
      'x-forwarded-for': '203.0.113.99',
    });
    limiter(reqBlocked, resBlocked, next);
    assert.equal(resBlocked.statusCode, 429);
  });

  it('should track distinct IP addresses separately', () => {
    let nextCalledCount = 0;
    const next = () => { nextCalledCount++; };

    // Max out IP 1
    for (let i = 0; i < 3; i++) {
      const { req, res } = createMockReqRes('1.1.1.1');
      limiter(req, res, next);
    }

    // IP 1 should be blocked
    const { req: reqBlocked, res: resBlocked } = createMockReqRes('1.1.1.1');
    limiter(reqBlocked, resBlocked, next);
    assert.equal(resBlocked.statusCode, 429);

    // IP 2 should still be allowed
    const { req: reqAllowed, res: resAllowed } = createMockReqRes('2.2.2.2');
    limiter(reqAllowed, resAllowed, next);
    assert.equal(resAllowed.statusCode, 200);
  });

  it('should reset counts when reset() is invoked', () => {
    const next = () => {};
    const ip = '5.5.5.5';

    for (let i = 0; i < 3; i++) {
      const { req, res } = createMockReqRes(ip);
      limiter(req, res, next);
    }

    // Confirm blocked
    const { req: r1, res: blockedRes } = createMockReqRes(ip);
    limiter(r1, blockedRes, next);
    assert.equal(blockedRes.statusCode, 429);

    // Reset
    limiter.reset();

    // Now should pass again
    const { req: r2, res: freshRes } = createMockReqRes(ip);
    limiter(r2, freshRes, next);
    assert.equal(freshRes.statusCode, 200);
  });
});
