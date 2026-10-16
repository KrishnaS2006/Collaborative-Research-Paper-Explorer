
import express from "express";

import {
  register,
  login,
  logout,
  getCurrentUser,
  forgotPassword,
  resetPassword,
} from "../controllers/auth.controller.js";

import { authenticateToken } from "../middleware/authenticate.js";

import {
  loginRateLimiter,
  forgotPasswordRateLimiter,
  resetPasswordRateLimiter,
} from "../middleware/rateLimiter.js";

const router = express.Router();

// Register a new user
router.post("/register", register);

// Login with rate limiting
router.post("/login", loginRateLimiter, login);

// Logout
router.post("/logout", logout);

// Get current authenticated user
router.get("/me", authenticateToken, getCurrentUser);

// Request a password reset email
router.post(
  "/forgot-password",
  forgotPasswordRateLimiter,
  forgotPassword
);

// Reset password using a valid reset token
router.post(
  "/reset-password",
  resetPasswordRateLimiter,
  resetPassword
);

export default router;
