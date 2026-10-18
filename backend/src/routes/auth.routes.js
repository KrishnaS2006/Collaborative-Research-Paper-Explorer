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
  updateUserRoleController,
  adminOnly,
  researcherOnly,
  checkUploadPermission,
} from "../controllers/auth.controller.js";

import { authenticateToken } from "../middleware/authenticate.js";
import {
  authorize,
  requirePermission,
  requireAdmin,
  requireResearcher,
} from "../middleware/authorize.js";
import { ROLES, PERMISSIONS } from "../utils/roles.js";

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

// Role-based authorization & permission verification endpoints
router.get(
  "/admin-only",
  authenticateToken,
  authorize(ROLES.SYSTEM_ADMIN),
  adminOnly
);
router.get(
  "/researcher-only",
  authenticateToken,
  authorize(ROLES.RESEARCHER, ROLES.SYSTEM_ADMIN),
  researcherOnly
);
router.post(
  "/papers/check-upload-permission",
  authenticateToken,
  requirePermission(PERMISSIONS.PAPERS_UPLOAD),
  checkUploadPermission
);
router.put(
  "/users/:id/role",
  authenticateToken,
  authorize(ROLES.SYSTEM_ADMIN),
  updateUserRoleController
);

export default router;
