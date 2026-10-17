/**
 * Validates and retrieves the JWT secret from environment variables.
 * Guarantees that the application refuses to issue or verify tokens if JWT_SECRET
 * is missing or inadequate, especially in production.
 * @returns {string}
 * @throws {Error} When JWT_SECRET is missing or too weak in production
 */
import { env } from "../config/env.js";

export const getValidatedJwtSecret = () => {
  const secret = process.env.JWT_SECRET;

  if (!secret || typeof secret !== 'string' || secret.trim().length === 0) {
    throw new Error('JWT_SECRET environment variable is missing or empty.');
  }

  if (process.env.NODE_ENV === 'production' && secret.trim().length < 32) {
    throw new Error('JWT_SECRET must be at least 32 characters long in production.');
  }
  return secret.trim();
};

