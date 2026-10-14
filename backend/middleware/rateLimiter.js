// In-memory configurable rate limiter middleware for sensitive endpoints like login

/**
 * ARCHITECTURAL NOTES & LIMITATIONS:
 * ---------------------------------
 * 1. Process Restarts: In-memory state is stored in a Node.js process Map.
 *    Restarting or redeploying the server will clear the rate limiter counters.
 * 2. Horizontal Scaling / Clustering: If running multiple Node.js instances behind
 *    a load balancer, each instance maintains its own in-memory state. For production
 *    clustering, a distributed shared store (e.g. Redis via rate-limit-redis) is recommended.
 * 3. Proxy Spoofing Defense: Client IP is determined via `req.ip` or `req.socket.remoteAddress`.
 *    Raw `X-Forwarded-For` headers are intentionally NOT trusted directly to prevent
 *    malicious clients from bypassing rate limits with spoofed headers. If behind a reverse proxy,
 *    configure `app.set('trust proxy', 1)` on the Express application so Express parses it safely.
 */

/**
 * Creates an in-memory rate limiting middleware.
 * @param {object} options
 * @param {number} [options.windowMs] - Time window in milliseconds
 * @param {number} [options.max] - Max requests allowed within windowMs
 * @param {string} [options.message] - Custom error message
 * @param {Function} [options.keyGenerator] - Custom key generator function
 */
export const createRateLimiter = (options = {}) => {
  const windowMs = Number(options.windowMs) || 
    Number(process.env.LOGIN_RATE_LIMIT_WINDOW_MS) || 
    15 * 60 * 1000; // default 15 minutes

  const max = Number(options.max) || 
    Number(process.env.LOGIN_RATE_LIMIT_MAX_ATTEMPTS) || 
    5; // default 5 attempts

  const message = options.message || 'Too many login attempts. Please try again later.';

  const keyGenerator = options.keyGenerator || ((req) => {
    // Rely on Express req.ip (which respects trust proxy settings) or remote TCP socket.
    // Do NOT blindly trust req.headers['x-forwarded-for'] directly as attackers can forge it.
    const ip = req.ip || (req.socket && req.socket.remoteAddress) || 'unknown-client';
    return String(ip);
  });

  const hits = new Map();

  // Periodic cleanup of expired entries every 5 minutes to avoid memory leak
  const cleanupInterval = setInterval(() => {
    const now = Date.now();
    for (const [key, record] of hits.entries()) {
      if (now > record.resetTime) {
        hits.delete(key);
      }
    }
  }, 5 * 60 * 1000);

  // Do not hold Node process open for cleanup timer
  if (cleanupInterval.unref) {
    cleanupInterval.unref();
  }

  const limiterMiddleware = (req, res, next) => {
    const key = keyGenerator(req);
    const now = Date.now();

    let record = hits.get(key);

    if (!record || now > record.resetTime) {
      record = {
        count: 1,
        resetTime: now + windowMs
      };
      hits.set(key, record);
      return next();
    }

    record.count += 1;

    if (record.count > max) {
      const retryAfterSeconds = Math.max(1, Math.ceil((record.resetTime - now) / 1000));
      res.setHeader('Retry-After', String(retryAfterSeconds));
      return res.status(429).json({
        error: message,
        retryAfterSeconds
      });
    }

    return next();
  };

  // Helper methods for testing and manual resets
  limiterMiddleware.reset = () => {
    hits.clear();
  };

  limiterMiddleware.getHits = (key) => {
    return hits.get(key);
  };

  return limiterMiddleware;
};

// Default export configured for login endpoint
export const loginRateLimiter = createRateLimiter();
