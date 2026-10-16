import express from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import pool from '../db.js';
import { validateRegisterPayload, validateLoginPayload } from '../utils/validation.js';
import { loginRateLimiter } from '../middleware/rateLimiter.js';
import { authenticateToken } from '../middleware/auth.js';
import { getValidatedJwtSecret } from '../utils/jwt.js';

const router = express.Router();

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