
import jwt from "jsonwebtoken";
import { getValidatedJwtSecret } from "../utils/jwt.js";

/**
 * JWT authentication middleware.
 *
 * Supports:
 * 1. HTTP-only cookie
 * 2. Authorization: Bearer <token>
 *
 * Attaches the verified JWT payload to req.user.
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

  try {
    const decoded = jwt.verify(token, secret);

    if (
      !decoded ||
      typeof decoded !== "object" ||
      (!decoded._id && !decoded.id)
    ) {
      return res.status(401).json({
        error: "Invalid token payload.",
      });
    }

    req.user = decoded;
    if (!req.user.id && req.user._id) req.user.id = req.user._id;
    if (!req.user._id && req.user.id) req.user._id = req.user.id;

    return next();
  } catch {
    return res.status(401).json({
      error: "Invalid or expired token.",
    });
  }
};

export default authenticateToken;
