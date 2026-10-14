import express from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import pool from '../db.js';

const router = express.Router();

// --- REGISTER ---
// --- REGISTER ---
router.post('/register', async (req, res) => {
  const { email, password, full_name, role } = req.body;

  // Role validation — sirf STUDENT ya RESEARCHER allow karein
  // SYSTEM_ADMIN ko database trigger bhi block karega, lekin backend par bhi guard rakhein
  const ALLOWED_ROLES = ['STUDENT', 'RESEARCHER'];
  const userRole = role || 'STUDENT';

  if (!ALLOWED_ROLES.includes(userRole)) {
    return res.status(400).json({ 
      error: 'Invalid role. Only STUDENT or RESEARCHER can be selected during registration.' 
    });
  }

  try {
    const userExists = await pool.query(
      'SELECT * FROM users WHERE LOWER(email) = LOWER($1)',
      [email]
    );
    if (userExists.rows.length > 0) {
      return res.status(400).json({ error: 'Email already in use.' });
    }

    const salt = await bcrypt.genSalt(10);
    const password_hash = await bcrypt.hash(password, salt);

    // Role explicitly pass kar rahe hain
    const newUser = await pool.query(
      `INSERT INTO users (email, password_hash, full_name, role) 
       VALUES ($1, $2, $3, $4) RETURNING id, email, full_name, role`,
      [email, password_hash, full_name, userRole]
    );

    res.status(201).json({
      message: 'User registered successfully',
      user: newUser.rows[0],
    });
  } catch (err) {
    console.error(err.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// --- LOGIN ---
router.post('/login', async (req, res) => {
  const { email, password } = req.body;
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

    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '8h' }
    );

    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 8 * 60 * 60 * 1000,
    });

    res.json({
      message: 'Logged in successfully',
      user: {
        id: user.id,
        email: user.email,
        full_name: user.full_name,
        role: user.role,
      },
    });
  } catch (err) {
    console.error(err.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// --- LOGOUT ---
router.post('/logout', (req, res) => {
  res.clearCookie('token', {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
  });
  res.json({ message: 'Logged out successfully' });
});

// --- CURRENT USER ---
router.get('/me', async (req, res) => {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ error: 'Not authenticated' });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await pool.query(
      'SELECT id, email, full_name, role FROM users WHERE id = $1',
      [decoded.id]
    );
    res.json({ user: user.rows[0] });
  } catch (err) {
    res.status(401).json({ error: 'Invalid token' });
  }
});

export default router;