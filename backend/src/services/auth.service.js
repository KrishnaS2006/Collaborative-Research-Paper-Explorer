import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import crypto from "node:crypto";
import { env } from "../config/env.js";
import {
  findUserByEmail,
  createUser,
  findUserById,
  invalidateUnusedPasswordResetTokens,
  createPasswordResetToken,
  consumePasswordResetTokenAndUpdatePassword,
  createEmailVerificationToken,
  invalidateUnusedEmailVerificationTokens,
  consumeEmailVerificationToken,
  checkEmailVerifiedColumn,
  updateUserProfile,
} from "../repositories/auth.repository.js";

import { getValidatedJwtSecret } from "../utils/jwt.js";
import {
  createSession,
  invalidateAllUserSessions,
  recordUserPasswordReset,
} from "./session.service.js";
import {
  sendPasswordResetEmail,
  sendEmailVerificationEmail,
} from "../utils/emailService.js";
import {
  validateRegisterPayload,
  validateLoginPayload,
  validateVerifyEmailPayload,
  validateResendVerificationPayload,
  validateForgotPasswordPayload,
  validateResetPasswordPayload,
  isAllowedInstitutionalEmail,
} from "../utils/validation.js";

const GENERIC_PASSWORD_RESET_MESSAGE =
  "If an account with that email exists, a password reset link has been sent.";

const GENERIC_RESEND_VERIFICATION_MESSAGE =
  "If an unverified account with that email exists, a new verification link has been sent.";

const createError = (message, statusCode) => {
  const error = new Error(message);
  error.statusCode = statusCode;
  return error;
};

export const registerUser = async (payload = {}) => {
  const validation = validateRegisterPayload(payload);
  if (!validation.valid) {
    throw createError(validation.error, 400);
  }

  const {
    full_name,
    email,
    password,
    role,
    affiliation,
    research_interests,
  } = validation.sanitized;

  if (!affiliation) {
    throw createError("Affiliation is required.", 400);
  }

  // Institutional email validation for RESEARCHER role
  if (role === "RESEARCHER") {
    const isAllowed = isAllowedInstitutionalEmail(
      email,
      env.allowedEmailDomains
    );

    if (!isAllowed) {
      throw createError(
        "Researchers must use an approved institutional email address.",
        403
      );
    }
  }

  const existingUser = await findUserByEmail(email);
  if (existingUser) {
    throw createError("Email already in use.", 409);
  }

  const passwordHash = await bcrypt.hash(password, 12);

  let newUser;
  try {
    newUser = await createUser({
      email,
      passwordHash,
      fullName: full_name,
      role,
      affiliation,
      researchInterests: research_interests,
      emailVerified: false,
    });
  } catch (error) {
    if (error.code === "23505") {
      throw createError("Email already in use.", 409);
    }
    throw error;
  }

  // Generate verification token (cryptographically secure random 32-byte hex)
  const rawVerificationToken = crypto.randomBytes(32).toString("hex");
  const tokenHash = crypto
    .createHash("sha256")
    .update(rawVerificationToken)
    .digest("hex");
  const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours

  // Store the token hash in the database FIRST.
  // If this fails, throw immediately — do NOT send an email with a token
  // that was never stored, as that produces an unverifiable link.
  await createEmailVerificationToken({
    userId: newUser.id,
    tokenHash,
    expiresAt,
  });

  // Token is confirmed stored. Now attempt to send the email.
  // A delivery failure here is non-fatal: the user can request a resend.
  try {
    await sendEmailVerificationEmail({
      to: newUser.email,
      name: newUser.full_name,
      verificationToken: rawVerificationToken,
    });
  } catch (err) {
    console.error("Email verification delivery error (token stored, resend available):", err.message);
  }

  const responseUser = {
  id: newUser.id,
  email: newUser.email,
  full_name: newUser.full_name,
  role: newUser.role,
  affiliation: newUser.affiliation,
  research_interests: newUser.research_interests,
  email_verified: newUser.email_verified,
};

  if (process.env.NODE_ENV !== "production") {
    responseUser.devVerificationToken = rawVerificationToken;
  }

  return responseUser;
};

export const verifyEmail = async (payload = {}) => {
  const validation = validateVerifyEmailPayload(payload);
  if (!validation.valid) {
    throw createError(validation.error, 400);
  }

  const { token } = validation.sanitized;
  const tokenHash = crypto.createHash("sha256").update(token).digest("hex");

  const result = await consumeEmailVerificationToken(tokenHash);

  if (!result.success) {
    if (result.reason === "already_used") {
      throw createError(
        "This verification token has already been used. Please sign in or request a new one.",
        400
      );
    }
    if (result.reason === "expired") {
      throw createError(
        "Verification token has expired. Please request a new verification link.",
        400
      );
    }
    throw createError(
      "Invalid or non-existent verification token. Please request a new verification link.",
      400
    );
  }

  return {
    message: "Email verified successfully. You can now sign in.",
    user: result.user,
  };
};

export const resendVerificationEmail = async (payload = {}) => {
  const validation = validateResendVerificationPayload(payload);
  if (!validation.valid) {
    throw createError(validation.error, 400);
  }

  const { email } = validation.sanitized;
  const user = await findUserByEmail(email);

  // Avoid account enumeration: return same generic response if user doesn't exist
  if (!user) {
    return { message: GENERIC_RESEND_VERIFICATION_MESSAGE };
  }

  // If user is already verified, do not send verification token
  if (user.email_verified) {
    return { message: GENERIC_RESEND_VERIFICATION_MESSAGE };
  }

  // Invalidate older unused tokens before issuing a fresh one
  await invalidateUnusedEmailVerificationTokens(user.id);

  const rawVerificationToken = crypto.randomBytes(32).toString("hex");
  const tokenHash = crypto
    .createHash("sha256")
    .update(rawVerificationToken)
    .digest("hex");
  const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours

  // Store the new token hash first — fail loudly if this doesn't succeed.
  await createEmailVerificationToken({
    userId: user.id,
    tokenHash,
    expiresAt,
  });

  // Token stored — attempt delivery. Non-fatal if SMTP fails.
  try {
    await sendEmailVerificationEmail({
      to: user.email,
      name: user.full_name,
      verificationToken: rawVerificationToken,
    });
  } catch (err) {
    console.error("Resend verification delivery failed:", err.message);
  }

  const result = {
    message: GENERIC_RESEND_VERIFICATION_MESSAGE,
  };

  if (process.env.NODE_ENV !== "production") {
    result.devVerificationToken = rawVerificationToken;
  }

  return result;
};

export const loginUser = async (payload = {}) => {
  const validation = validateLoginPayload(payload);
  if (!validation.valid) {
    throw createError(validation.error, 400);
  }

  const { email, password } = validation.sanitized;
  const user = await findUserByEmail(email);

  if (!user) {
    throw createError("Invalid email or password.", 401);
  }

  const passwordMatches = await bcrypt.compare(
    password,
    user.password_hash
  );

  if (!passwordMatches) {
    throw createError("Invalid email or password.", 401);
  }

  // Prevent unverified password-based accounts from logging in
  if (user.email_verified === false) {
    const error = createError(
      "Please verify your email address before logging in.",
      403
    );
    error.unverified = true;
    throw error;
  }

  const token = jwt.sign(
    {
       _id: user.id,
  id: user.id,
  email: user.email,
  role: user.role,
  affiliation: user.affiliation,
    },
    getValidatedJwtSecret(),
    { expiresIn: "8h" }
  );

  // FR-04: Register server-side session for idle tracking and revocation
  await createSession({
    userId: user.id,
    token,
  });

  return {
    token,
    user: {
      id: user.id,
      email: user.email,
      full_name: user.full_name,
      role: user.role,
      affiliation: user.affiliation,
      research_interests: user.research_interests,
      email_verified: user.email_verified,
    },
  };
};

export const getCurrentUserById = async (id) => {
  const user = await findUserById(id);

  if (!user) {
    throw createError("User no longer exists.", 401);
  }

  return {
    id: user.id,
    email: user.email,
    full_name: user.full_name,
    role: user.role,
    affiliation: user.affiliation,
    research_interests: user.research_interests,
    email_verified: user.email_verified,
  };
};

// Forgot Password
export const requestPasswordReset = async ({ email } = {}) => {
  if (typeof email !== "string" || !email.trim()) {
    throw createError("Email is required.", 400);
  }

  const normalizedEmail = email.trim().toLowerCase();

  const emailResult = validateRegisterPayload({ email: normalizedEmail });
  // Fallback simple email regex if needed
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalizedEmail)) {
    throw createError("Please provide a valid email address.", 400);
  }

  const user = await findUserByEmail(normalizedEmail);

  // Generic message prevents account enumeration
  if (!user) {
    return { message: GENERIC_PASSWORD_RESET_MESSAGE };
  }

  // Invalidate older unused tokens before creating a new one
  await invalidateUnusedPasswordResetTokens(user.id);

  const rawToken = crypto.randomBytes(32).toString("hex");
  const tokenHash = crypto
    .createHash("sha256")
    .update(rawToken)
    .digest("hex");

  const expiresAt = new Date(Date.now() + 15 * 60 * 1000);

  await createPasswordResetToken({
    userId: user.id,
    tokenHash,
    expiresAt,
  });

  try {
    await sendPasswordResetEmail({
      to: user.email,
      name: user.full_name,
      resetToken: rawToken,
    });
  } catch (error) {
    console.error("Password reset email delivery failed:", error.message);
  }

  const result = { message: GENERIC_PASSWORD_RESET_MESSAGE };
  if (process.env.EXPOSE_DEV_RESET_TOKEN === "true") {
    result.devResetToken = rawToken;
  }
  return result;
};

// Reset Password
export const resetUserPassword = async (payload = {}) => {
  const validation = validateResetPasswordPayload(payload);
  if (!validation.valid) {
    throw createError(validation.error, 400);
  }

  const { token, password } = validation.sanitized;

  const tokenHash = crypto
    .createHash("sha256")
    .update(token.trim())
    .digest("hex");

  const passwordHash = await bcrypt.hash(password, 12);

  const result = await consumePasswordResetTokenAndUpdatePassword({
    tokenHash,
    passwordHash,
  });

  if (!result.success) {
    if (result.reason === "already_used") {
      throw createError(
        "This password reset token has already been used. Please request a new one.",
        400
      );
    }
    if (result.reason === "expired") {
      throw createError(
        "This password reset token has expired. Please request a new one.",
        400
      );
    }
    throw createError(
      "Invalid or expired password reset token. Please request a new one.",
      400
    );
  }

  // Guaranteed immediate in-memory cutoff: makes all pre-existing sessions unusable
  if (result.userId) {
    recordUserPasswordReset(result.userId);
  }

  // Revoke all active sessions for this user across memory and database
  if (result.userId) {
    try {
      await invalidateAllUserSessions(result.userId);
    } catch (sessionError) {
      console.error(
        "Failed to revoke active user sessions after password reset:",
        sessionError.message
      );
      throw createError(
        "Password has been reset, but revoking existing sessions encountered an error.",
        500
      );
    }
  }

  return {
    message:
      "Password has been reset successfully. You can now sign in with your new password.",
  };
};

export const updateUserProfileService = async ({
  userId,
  currentUserRole,
  payload = {},
}) => {
  if (!userId) {
    throw createError("User identifier is required.", 400);
  }

  // FR-05: Prevent users from changing their own roles through profile updates
  if (payload.role !== undefined || payload.access_role !== undefined) {
    throw createError(
      "Changing user roles through profile update is forbidden. Role assignments require administrator privileges.",
      403
    );
  }

  const { full_name, affiliation, research_interests } = payload;
  const updateData = { userId };

  if (full_name !== undefined) {
    if (typeof full_name !== "string" || !full_name.trim()) {
      throw createError("Full name cannot be empty.", 400);
    }
    if (full_name.trim().length > 150) {
      throw createError("Full name cannot exceed 150 characters.", 400);
    }
    updateData.fullName = full_name.trim();
  }

  if (affiliation !== undefined) {
    if (typeof affiliation !== "string") {
      throw createError("Affiliation must be a string.", 400);
    }
    if (affiliation.trim().length > 255) {
      throw createError("Affiliation cannot exceed 255 characters.", 400);
    }
    updateData.affiliation = affiliation.trim() || null;
  }

  if (research_interests !== undefined) {
    if (!Array.isArray(research_interests)) {
      throw createError("Research interests must be a list.", 400);
    }
    if (
      research_interests.some(
        (interest) => typeof interest !== "string" || !interest.trim()
      )
    ) {
      throw createError("Each research interest must be a non-empty string.", 400);
    }
    const deduplicated = [
      ...new Set(
        research_interests.map((i) => i.trim()).filter(Boolean)
      ),
    ];
    if (deduplicated.length > 20) {
      throw createError("You can select up to 20 research interests.", 400);
    }
    updateData.researchInterests = deduplicated;
  }

  const updatedUser = await updateUserProfile(updateData);
  if (!updatedUser) {
    throw createError("User account not found.", 404);
  }

  return {
    id: updatedUser.id,
    email: updatedUser.email,
    full_name: updatedUser.full_name,
    role: updatedUser.role,
    affiliation: updatedUser.affiliation,
    research_interests: updatedUser.research_interests,
    email_verified: updatedUser.email_verified,
  };
};

export default {
  registerUser,
  verifyEmail,
  resendVerificationEmail,
  loginUser,
  getCurrentUserById,
  requestPasswordReset,
  resetUserPassword,
  updateUserProfileService,
};
