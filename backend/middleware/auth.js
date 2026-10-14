import jwt from 'jsonwebtoken';
import { getValidatedJwtSecret } from '../utils/jwt.js';

/**
 * Reusable JWT authentication middleware.
 * Inspects both HTTP-only cookie and Authorization Bearer header.
 * Populates req.user upon successful verification.
 */
export const authenticateToken = (req, res, next) => {
  let token = req.cookies?.token;

  if (!token && req.headers?.authorization) {
    const authHeader = req.headers.authorization;
    if (authHeader.startsWith('Bearer ')) {
      token = authHeader.substring(7).trim();
    }
  }

  if (!token) {
    return res.status(401).json({ error: 'Access denied. No authentication token provided.' });
  }

  let secret;
  try {
    secret = getValidatedJwtSecret();
  } catch (configErr) {
    console.error('Authentication configuration error:', configErr.message);
    return res.status(500).json({ error: 'Server authentication configuration error.' });
  }

  try {
    const decoded = jwt.verify(token, secret);
    if (!decoded || typeof decoded !== 'object' || !decoded.id) {
      return res.status(401).json({ error: 'Invalid token payload.' });
    }
    req.user = decoded;
    return next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired token.' });
  }
};
