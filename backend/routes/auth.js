import express from 'express';
import bcrypt from 'bcryptjs';
import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import pool from '../db.js';
import {
  validateRegisterPayload,
  validateLoginPayload,
  validateForgotPasswordPayload,
  validateResetPasswordPayload,
} from '../utils/validation.js';
import {
  loginRateLimiter,
  forgotPasswordRateLimiter,
  resetPasswordRateLimiter,
} from '../middleware/rateLimiter.js';
import { authenticateToken } from '../middleware/auth.js';
import { getValidatedJwtSecret } from '../utils/jwt.js';
import { sendPasswordResetEmail } from '../utils/emailService.js';

const router = express.Router();

// Generic response message to prevent email enumeration
const GENERIC_PASSWORD_RESET_MESSAGE =
  'If an account with that email exists, a password reset link has been sent.';

// --- REGISTER ---
router.post('/register', async (req, res) => {
  const validation = validateRegisterPayload(req.body);
  if (!validation.valid) {
    return res.status(400).json({ error: validation.error });
  }

  const { full_name, email, password, role } = validation.sanitized;

  try {
    const userExists = await pool.query(
      'SELECT id FROM users WHERE LOWER(email) = LOWER($1)',
      [email]
    );
    if (userExists.rows.length > 0) {
      return res.status(400).json({ error: 'Email already in use.' });
    }

    const salt = await bcrypt.genSalt(10);
    const password_hash = await bcrypt.hash(password, salt);

    const newUser = await pool.query(
      `INSERT INTO users (email, password_hash, full_name, role) 
       VALUES ($1, $2, $3, $4) RETURNING id, email, full_name, role`,
      [email, password_hash, full_name, role]
    );

    return res.status(201).json({
      message: 'User registered successfully',
      user: newUser.rows[0],
    });
  } catch (err) {
    console.error('Registration error:', err.message);
    return res.status(500).json({ error: 'Server error' });
  }
});

// --- LOGIN (Rate Limited) ---
router.post('/login', loginRateLimiter, async (req, res) => {
  const validation = validateLoginPayload(req.body);
  if (!validation.valid) {
    return res.status(400).json({ error: validation.error });
  }

  const { email, password } = validation.sanitized;

  try {
    const result = await pool.query(
      'SELECT * FROM users WHERE LOWER(email) = LOWER($1)',
      [email]
    );
    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const user = result.rows[0];
    const validPassword = await bcrypt.compare(password, user.password_hash);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    let secret;
    try {
      secret = getValidatedJwtSecret();
    } catch (configErr) {
      console.error('Authentication configuration error:', configErr.message);
      return res.status(500).json({ error: 'Server authentication configuration error.' });
    }

    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role },
      secret,
      { expiresIn: '8h' }
    );

    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 8 * 60 * 60 * 1000,
    });

    return res.json({
      message: 'Logged in successfully',
      user: {
        id: user.id,
        email: user.email,
        full_name: user.full_name,
        role: user.role,
      },
    });
  } catch (err) {
    console.error('Login error:', err.message);
    return res.status(500).json({ error: 'Server error' });
  }
});

// --- FORGOT PASSWORD (Rate Limited & Enumeration Safe) ---
router.post('/forgot-password', forgotPasswordRateLimiter, async (req, res) => {
  const validation = validateForgotPasswordPayload(req.body);
  if (!validation.valid) {
    return res.status(400).json({ error: validation.error });
  }

  const { email } = validation.sanitized;

  try {
    const result = await pool.query(
      'SELECT id, email, full_name FROM users WHERE LOWER(email) = LOWER($1)',
      [email]
    );

    // If user does not exist, return generic success response immediately (prevents enumeration)
    if (result.rows.length === 0) {
      return res.json({ message: GENERIC_PASSWORD_RESET_MESSAGE });
    }

    const user = result.rows[0];

    // Invalidate any existing unused reset tokens for this user
    await pool.query(
      'UPDATE password_reset_tokens SET used_at = CURRENT_TIMESTAMP WHERE user_id = $1 AND used_at IS NULL',
      [user.id]
    );

    // Generate cryptographically secure random token (32 bytes = 64 hex characters)
    const rawToken = crypto.randomBytes(32).toString('hex');
    // Store ONLY a SHA-256 hash of the token in the database
    const tokenHash = crypto.createHash('sha256').update(rawToken).digest('hex');
    // Expiration: 15 minutes TTL
    const expiresAt = new Date(Date.now() + 15 * 60 * 1000);

    await pool.query(
      `INSERT INTO password_reset_tokens (user_id, token_hash, expires_at)
       VALUES ($1, $2, $3)`,
      [user.id, tokenHash, expiresAt]
    );

    // Send email via email service abstraction
    await sendPasswordResetEmail({
      to: user.email,
      name: user.full_name,
      resetToken: rawToken,
    });

    const responseData = { message: GENERIC_PASSWORD_RESET_MESSAGE };

    // In development ONLY: if explicitly requested via environment variable, provide dev token for local testing
    if (process.env.NODE_ENV !== 'production' && process.env.EXPOSE_DEV_RESET_TOKEN === 'true') {
      responseData.devResetToken = rawToken;
    }

    return res.json(responseData);
  } catch (err) {
    console.error('Forgot password error:', err.message);
    return res.status(500).json({ error: 'Server error' });
  }
});

// --- RESET PASSWORD (Rate Limited & Single-Use Enforcement) ---
router.post('/reset-password', resetPasswordRateLimiter, async (req, res) => {
  const validation = validateResetPasswordPayload(req.body);
  if (!validation.valid) {
    return res.status(400).json({ error: validation.error });
  }

  const { token, password } = validation.sanitized;

  try {
    // Hash incoming token to look up in DB
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');

    const tokenResult = await pool.query(
      `SELECT id, user_id, expires_at, used_at
       FROM password_reset_tokens
       WHERE token_hash = $1`,
      [tokenHash]
    );

    if (tokenResult.rows.length === 0) {
      return res.status(400).json({ error: 'Invalid or expired password reset token.' });
    }

    const resetRecord = tokenResult.rows[0];

    // Check single-use
    if (resetRecord.used_at !== null) {
      return res.status(400).json({
        error: 'This password reset token has already been used. Please request a new one.'
      });
    }

    // Check expiration (15-minute window)
    if (new Date() > new Date(resetRecord.expires_at)) {
      return res.status(400).json({
        error: 'This password reset token has expired. Please request a new one.'
      });
    }

    // Mark token as used immediately to prevent reuse
    await pool.query(
      'UPDATE password_reset_tokens SET used_at = CURRENT_TIMESTAMP WHERE id = $1',
      [resetRecord.id]
    );

    // Hash the new password with bcrypt
    const salt = await bcrypt.genSalt(10);
    const password_hash = await bcrypt.hash(password, salt);

    // Update user's password in database
    await pool.query(
      'UPDATE users SET password_hash = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2',
      [password_hash, resetRecord.user_id]
    );

    return res.json({
      message: 'Password has been reset successfully. You can now sign in with your new password.'
    });
  } catch (err) {
    console.error('Reset password error:', err.message);
    return res.status(500).json({ error: 'Server error' });
  }
});

// --- LOGOUT ---
router.post('/logout', (req, res) => {
  res.clearCookie('token', {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
  });
  return res.json({ message: 'Logged out successfully' });
});

// --- CURRENT USER (Protected with reusable authenticateToken middleware) ---
router.get('/me', authenticateToken, async (req, res) => {
  try {
    const user = await pool.query(
      'SELECT id, email, full_name, role FROM users WHERE id = $1',
      [req.user.id]
    );
    if (user.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    return res.json({ user: user.rows[0] });
  } catch (err) {
    console.error('Fetch current user error:', err.message);
    return res.status(500).json({ error: 'Server error' });
  }
});

export default router;