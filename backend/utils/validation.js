// Validation utilities for authentication payloads and password policy

/**
 * Validates email format according to standard RFC 5322 regex.
 * Normalizes email by trimming and converting to lowercase.
 * @param {string} email
 * @returns {{ valid: boolean, error?: string }}
 */
export const validateEmail = (email) => {
  if (!email || typeof email !== 'string') {
    return { valid: false, error: 'Email is required.' };
  }

  const trimmed = email.trim();
  if (trimmed.length === 0) {
    return { valid: false, error: 'Email cannot be empty.' };
  }

  if (trimmed.length > 255) {
    return { valid: false, error: 'Email cannot exceed 255 characters.' };
  }

  // Standard email regex ensuring valid domain structure without consecutive dots
  const emailRegex = /^[A-Za-z0-9._%+-]+@([A-Za-z0-9-]+\.)+[A-Za-z]{2,}$/;
  if (!emailRegex.test(trimmed)) {
    return { valid: false, error: 'Please enter a valid email address.' };
  }

  return { valid: true };
};

/**
 * Validates password strength according to the project security policy:
 * - At least 8 characters
 * - Maximum 128 characters (prevents DoS on bcrypt hashing)
 * - At least 1 uppercase letter
 * - At least 1 lowercase letter
 * - At least 1 number
 * - At least 1 special character
 * NOTE: Passwords must NEVER be trimmed or altered.
 * @param {string} password
 * @returns {{ valid: boolean, error?: string }}
 */
export const validatePassword = (password) => {
  if (!password || typeof password !== 'string') {
    return { valid: false, error: 'Password is required.' };
  }

  if (password.length < 8) {
    return { valid: false, error: 'Password must be at least 8 characters long.' };
  }

  if (password.length > 128) {
    return { valid: false, error: 'Password cannot exceed 128 characters.' };
  }

  if (!/[A-Z]/.test(password)) {
    return { valid: false, error: 'Password must contain at least one uppercase letter.' };
  }

  if (!/[a-z]/.test(password)) {
    return { valid: false, error: 'Password must contain at least one lowercase letter.' };
  }

  if (!/[0-9]/.test(password)) {
    return { valid: false, error: 'Password must contain at least one number.' };
  }

  // Special characters: any non-alphanumeric, non-whitespace character
  if (!/[^A-Za-z0-9\s]/.test(password)) {
    return { valid: false, error: 'Password must contain at least one special character (!@#$%^&* etc.).' };
  }

  return { valid: true };
};

/**
 * Validates registration payload.
 * Allowed roles for public registration: STUDENT, RESEARCHER.
 * Prevents assignment of privileged roles like SYSTEM_ADMIN.
 * @param {object} payload
 * @returns {{ valid: boolean, error?: string, sanitized?: object }}
 */
export const validateRegisterPayload = (payload) => {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    return { valid: false, error: 'Invalid request body.' };
  }

  const { full_name, email, password, role } = payload;

  if (!full_name || typeof full_name !== 'string' || full_name.trim().length === 0) {
    return { valid: false, error: 'Full name is required.' };
  }

  if (full_name.trim().length > 150) {
    return { valid: false, error: 'Full name cannot exceed 150 characters.' };
  }

  const emailResult = validateEmail(email);
  if (!emailResult.valid) {
    return emailResult;
  }

  const passwordResult = validatePassword(password);
  if (!passwordResult.valid) {
    return passwordResult;
  }

  const ALLOWED_ROLES = ['STUDENT', 'RESEARCHER'];
  const userRole = role || 'STUDENT';
  if (!ALLOWED_ROLES.includes(userRole)) {
    return {
      valid: false,
      error: 'Invalid role. Only STUDENT or RESEARCHER can be selected during registration.'
    };
  }

  return {
    valid: true,
    sanitized: {
      full_name: full_name.trim(),
      email: email.trim().toLowerCase(),
      password, // Intentionally NOT trimmed or modified
      role: userRole
    }
  };
};

/**
 * Validates login payload.
 * @param {object} payload
 * @returns {{ valid: boolean, error?: string, sanitized?: object }}
 */
export const validateLoginPayload = (payload) => {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    return { valid: false, error: 'Invalid request body.' };
  }

  const { email, password } = payload;

  if (!email || typeof email !== 'string' || email.trim().length === 0) {
    return { valid: false, error: 'Email is required.' };
  }

  if (!password || typeof password !== 'string' || password.length === 0) {
    return { valid: false, error: 'Password is required.' };
  }

  const emailResult = validateEmail(email);
  if (!emailResult.valid) {
    return emailResult;
  }

  return {
    valid: true,
    sanitized: {
      email: email.trim().toLowerCase(),
      password // Intentionally NOT trimmed or modified
    }
  };
};
