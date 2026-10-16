
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import crypto from "node:crypto";

import {
  findUserByEmail,
  createUser,
  findUserById,
  invalidateUnusedPasswordResetTokens,
  createPasswordResetToken,
  consumePasswordResetTokenAndUpdatePassword,
} from "../repositories/auth.repository.js";

import { getValidatedJwtSecret } from "../utils/jwt.js";
import { sendPasswordResetEmail } from "../utils/emailService.js";

const ALLOWED_ROLES = ["STUDENT", "RESEARCHER"];

const GENERIC_PASSWORD_RESET_MESSAGE =
  "If an account with that email exists, a password reset link has been sent.";

const createError = (message, statusCode) => {
  const error = new Error(message);
  error.statusCode = statusCode;
  return error;
};

const isValidEmail = (email) =>
  /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);

export const registerUser = async ({
  email,
  password,
  full_name,
  role = "STUDENT",
} = {}) => {
  if (
    typeof email !== "string" ||
    typeof password !== "string" ||
    typeof full_name !== "string" ||
    !email.trim() ||
    !password ||
    !full_name.trim()
  ) {
    throw createError(
      "Email, password, and full name are required.",
      400
    );
  }

  const normalizedEmail = email.trim().toLowerCase();
  const normalizedName = full_name.trim();
  const normalizedRole = String(role).trim().toUpperCase();

  if (!isValidEmail(normalizedEmail)) {
    throw createError("Please provide a valid email address.", 400);
  }

  if (password.length < 8) {
    throw createError("Password must be at least 8 characters long.", 400);
  }

  if (!ALLOWED_ROLES.includes(normalizedRole)) {
    throw createError("Only STUDENT or RESEARCHER can register.", 400);
  }

  const existingUser = await findUserByEmail(normalizedEmail);

  if (existingUser) {
    throw createError("Email already in use.", 409);
  }

  const passwordHash = await bcrypt.hash(password, 12);

  try {
    return await createUser({
      email: normalizedEmail,
      passwordHash,
      fullName: normalizedName,
      role: normalizedRole,
    });
  } catch (error) {
    if (error.code === "23505") {
      throw createError("Email already in use.", 409);
    }

    throw error;
  }
};

export const loginUser = async ({ email, password } = {}) => {
  if (
    typeof email !== "string" ||
    typeof password !== "string" ||
    !email.trim() ||
    !password
  ) {
    throw createError("Email and password are required.", 400);
  }

  const user = await findUserByEmail(email.trim().toLowerCase());

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

  const token = jwt.sign(
    {
      _id: user.id,
      id: user.id,
      email: user.email,
      role: user.role,
    },
    getValidatedJwtSecret(),
    { expiresIn: "8h" }
  );

  return {
    token,
    user: {
      id: user.id,
      email: user.email,
      full_name: user.full_name,
      role: user.role,
    },
  };
};

export const getCurrentUserById = async (id) => {
  const user = await findUserById(id);

  if (!user) {
    throw createError("User no longer exists.", 401);
  }

  return user;
};

// Forgot Password
export const requestPasswordReset = async ({ email } = {}) => {
  if (typeof email !== "string" || !email.trim()) {
    throw createError("Email is required.", 400);
  }

  const normalizedEmail = email.trim().toLowerCase();

  if (!isValidEmail(normalizedEmail)) {
    throw createError("Please provide a valid email address.", 400);
  }

  const user = await findUserByEmail(normalizedEmail);

  // Don't reveal whether an account exists.
  if (!user) {
    return { message: GENERIC_PASSWORD_RESET_MESSAGE };
  }

  // Invalidate older unused tokens before creating a new one.
  await invalidateUnusedPasswordResetTokens(user.id);

  // The raw token is emailed; only its hash is stored in PostgreSQL.
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
    // Do not expose email-provider details to the client.
    // Log the failure on the server for troubleshooting.
    console.error("Password reset email delivery failed:", error.message);
    throw createError("Unable to send password reset email. Please try again.", 503);
  }

  return { message: GENERIC_PASSWORD_RESET_MESSAGE };
};

// Reset Password
export const resetUserPassword = async ({ token, password } = {}) => {
  if (
    typeof token !== "string" ||
    !/^[a-f0-9]{64}$/i.test(token) ||
    typeof password !== "string" ||
    !password
  ) {
    throw createError("A valid token and new password are required.", 400);
  }

  if (password.length < 8) {
    throw createError("Password must be at least 8 characters long.", 400);
  }

  const tokenHash = crypto
    .createHash("sha256")
    .update(token)
    .digest("hex");

  const passwordHash = await bcrypt.hash(password, 12);

  // This repository method must validate, consume the token, and update
  // the password in ONE database transaction.
  const updated = await consumePasswordResetTokenAndUpdatePassword({
    tokenHash,
    passwordHash,
  });

  if (!updated) {
    throw createError(
      "Invalid, expired, or already-used password reset token. Please request a new one.",
      400
    );
  }

  return {
    message:
      "Password has been reset successfully. You can now sign in with your new password.",
  };
};


export default {
  registerUser,
  loginUser,
  getCurrentUserById,
  requestPasswordReset,
  resetUserPassword,
};
