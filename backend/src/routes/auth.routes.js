import express from "express";

import {
  register,
  verifyEmail,
  resendVerification,
  login,
  logout,
  getCurrentUser,
  forgotPassword,
  resetPassword,
  getSsoConfig,
  initiateSso,
  handleSsoCallback,
} from "../controllers/auth.controller.js";

import { authenticateToken } from "../middleware/authenticate.js";

import {
  loginRateLimiter,
  forgotPasswordRateLimiter,
  resetPasswordRateLimiter,
  resendVerificationRateLimiter,
  ssoCallbackRateLimiter,
} from "../middleware/rateLimiter.js";

const router = express.Router();

// Register a new user
router.post("/register", register);

// Email verification endpoints
router.post("/verify-email", verifyEmail);
router.get("/verify-email", verifyEmail);
router.post(
  "/resend-verification",
  resendVerificationRateLimiter,
  resendVerification
);

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

// Institutional SSO endpoints
router.get("/sso/config", getSsoConfig);
router.get("/sso/login", initiateSso);
router.get("/sso/google", initiateSso);
router.get("/sso/callback", ssoCallbackRateLimiter, handleSsoCallback);
router.get("/google/callback", ssoCallbackRateLimiter, handleSsoCallback);

export default router;
