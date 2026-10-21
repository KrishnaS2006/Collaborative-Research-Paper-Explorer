import jwt from "jsonwebtoken";
import { getValidatedJwtSecret } from "../utils/jwt.js";
import { validateSessionSync } from "../services/session.service.js";

/**
 * JWT authentication middleware with FR-04 Session Validation & Idle Tracking.
 *
 * Supports:
 * 1. HTTP-only cookie
 * 2. Authorization: Bearer <token>
 *
 * Attaches the verified JWT payload to req.user and active session to req.session.
 * Enforces server-side token revocation and 30-minute inactivity expiration.
 */
export const authenticateToken = (req, res, next) => {
  let token = req.cookies?.token;

  // Fallback to the Authorization header.
  if (!token && req.headers?.authorization) {
    const authHeader = req.headers.authorization;

    if (authHeader.startsWith("Bearer ")) {
      token = authHeader.substring(7).trim();
    }
  }

  if (!token) {
    return res.status(401).json({
      error: "Access denied. No authentication token provided.",
    });
  }

  let secret;

  try {
    secret = getValidatedJwtSecret();
  } catch (error) {
    console.error(
      "Authentication configuration error:",
      error.message
    );

    return res.status(500).json({
      error: "Server authentication configuration error.",
    });
  }

  let decoded;
  try {
    decoded = jwt.verify(token, secret);

    if (
      !decoded ||
      typeof decoded !== "object" ||
      (!decoded._id && !decoded.id)
    ) {
      return res.status(401).json({
        error: "Invalid token payload.",
      });
    }
  } catch {
    return res.status(401).json({
      error: "Invalid or expired token.",
    });
  }

  // FR-04: Server-side token invalidation and 30-minute inactivity checking
  const sessionCheck = validateSessionSync(token);
  if (!sessionCheck.valid) {
    if (typeof res.clearCookie === "function") {
      res.clearCookie("token", {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "lax",
      });
    }

    if (sessionCheck.reason === "idle_timeout") {
      return res.status(401).json({
        error: "Session expired due to 30 minutes of inactivity. Please log in again.",
        code: "SESSION_IDLE_TIMEOUT",
      });
    }

    if (sessionCheck.reason === "revoked") {
      return res.status(401).json({
        error: "Session has been invalidated. Please log in again.",
        code: "SESSION_REVOKED",
      });
    }

    return res.status(401).json({
      error: "Invalid or expired token.",
    });
  }

  // Rolling cookie refresh for active sessions (30 minutes sliding window)
  if (req.cookies?.token && typeof res.cookie === "function") {
    res.cookie("token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      maxAge: 30 * 60 * 1000,
    });
  }

  req.user = decoded;
  if (!req.user.id && req.user._id) req.user.id = req.user._id;
  if (!req.user._id && req.user.id) req.user._id = req.user.id;
  if (sessionCheck.session) {
    req.session = sessionCheck.session;
  }

  return next();
};

export default authenticateToken;
