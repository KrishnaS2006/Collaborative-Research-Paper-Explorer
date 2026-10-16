
/**
 * In-memory rate limiter for authentication endpoints.
 *
 * Note: Counters are local to this Node.js process.
 * Use Redis for shared rate limiting across multiple instances.
 */

const DEFAULT_WINDOW_MS = 15 * 60 * 1000;
const DEFAULT_MAX_ATTEMPTS = 5;
const CLEANUP_INTERVAL_MS = 5 * 60 * 1000;

export const createRateLimiter = (options = {}) => {
  const windowMs =
    Number(options.windowMs) ||
    DEFAULT_WINDOW_MS;

  const max =
    Number(options.max) ||
    DEFAULT_MAX_ATTEMPTS;

  const message =
    options.message ||
    "Too many requests. Please try again later.";

  const keyGenerator =
    options.keyGenerator ||
    ((req) =>
      String(req.ip || req.socket?.remoteAddress || "unknown-client"));

  const hits = new Map();

  const cleanupInterval = setInterval(() => {
    const now = Date.now();

    for (const [key, record] of hits.entries()) {
      if (now >= record.resetTime) {
        hits.delete(key);
      }
    }
  }, CLEANUP_INTERVAL_MS);

  cleanupInterval.unref?.();

  const limiterMiddleware = (req, res, next) => {
    const key = keyGenerator(req);
    const now = Date.now();

    let record = hits.get(key);

    if (!record || now >= record.resetTime) {
      record = {
        count: 1,
        resetTime: now + windowMs,
      };

      hits.set(key, record);
      return next();
    }

    record.count += 1;

    if (record.count > max) {
      const retryAfterSeconds = Math.max(
        1,
        Math.ceil((record.resetTime - now) / 1000)
      );

      res.setHeader("Retry-After", String(retryAfterSeconds));

      return res.status(429).json({
        error: message,
        retryAfterSeconds,
      });
    }

    return next();
  };

  // Helpers for automated tests.
  limiterMiddleware.reset = () => hits.clear();
  limiterMiddleware.getHits = (key) => hits.get(key);

  return limiterMiddleware;
};

// Login endpoint limiter.
export const loginRateLimiter = createRateLimiter({
  windowMs: process.env.LOGIN_RATE_LIMIT_WINDOW_MS,
  max: process.env.LOGIN_RATE_LIMIT_MAX_ATTEMPTS,
  message: "Too many login attempts. Please try again later.",
});

// Forgot-password endpoint limiter.
export const forgotPasswordRateLimiter = createRateLimiter({
  windowMs: process.env.FORGOT_PASSWORD_RATE_LIMIT_WINDOW_MS,
  max: process.env.FORGOT_PASSWORD_RATE_LIMIT_MAX_ATTEMPTS,
  message: "Too many password reset requests. Please try again later.",
});

// Reset-password endpoint limiter.
export const resetPasswordRateLimiter = createRateLimiter({
  windowMs: process.env.RESET_PASSWORD_RATE_LIMIT_WINDOW_MS,
  max: process.env.RESET_PASSWORD_RATE_LIMIT_MAX_ATTEMPTS,
  message: "Too many password reset attempts. Please try again later.",
});

export default createRateLimiter;
