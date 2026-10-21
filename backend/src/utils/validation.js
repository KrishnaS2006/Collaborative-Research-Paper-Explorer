
// backend/src/utils/validation.js
import { ROLES, normalizeRole } from "./roles.js";

export const validateEmail = (email) => {
  if (!email || typeof email !== "string") {
    return { valid: false, error: "Email is required." };
  }

  const trimmed = email.trim();

  if (!trimmed) {
    return { valid: false, error: "Email cannot be empty." };
  }

  if (trimmed.length > 255) {
    return {
      valid: false,
      error: "Email cannot exceed 255 characters.",
    };
  }

  const emailRegex =
    /^[A-Za-z0-9._%+-]+@([A-Za-z0-9-]+\.)+[A-Za-z]{2,}$/;

  if (!emailRegex.test(trimmed)) {
    return {
      valid: false,
      error: "Please enter a valid email address.",
    };
  }

  return { valid: true };
};

export const validatePassword = (password) => {
  if (typeof password !== "string" || password.length === 0) {
    return { valid: false, error: "Password is required." };
  }

  if (password.length < 8) {
    return {
      valid: false,
      error: "Password must be at least 8 characters long.",
    };
  }

  if (password.length > 128) {
    return {
      valid: false,
      error: "Password cannot exceed 128 characters.",
    };
  }

  if (!/[A-Z]/.test(password)) {
    return {
      valid: false,
      error: "Password must contain at least one uppercase letter.",
    };
  }

  if (!/[a-z]/.test(password)) {
    return {
      valid: false,
      error: "Password must contain at least one lowercase letter.",
    };
  }

  if (!/[0-9]/.test(password)) {
    return {
      valid: false,
      error: "Password must contain at least one number.",
    };
  }

  if (!/[^A-Za-z0-9\s]/.test(password)) {
    return {
      valid: false,
      error: "Password must contain at least one special character.",
    };
  }

  return { valid: true };
};

export const validateRegisterPayload = (payload) => {
  if (
    !payload ||
    typeof payload !== "object" ||
    Array.isArray(payload)
  ) {
    return { valid: false, error: "Invalid request body." };
  }

  const {
    full_name,
    email,
    password,
    role,
    affiliation,
    research_interests,
  } = payload;

  if (
    typeof full_name !== "string" ||
    !full_name.trim()
  ) {
    return { valid: false, error: "Full name is required." };
  }

  if (full_name.trim().length > 150) {
    return {
      valid: false,
      error: "Full name cannot exceed 150 characters.",
    };
  }

  const emailResult = validateEmail(email);
  if (!emailResult.valid) return emailResult;

  const passwordResult = validatePassword(password);
  if (!passwordResult.valid) return passwordResult;

  const rawRole = role ?? ROLES.STUDENT;
  const userRole = normalizeRole(rawRole);
  const allowedPublicRoles = [ROLES.STUDENT, ROLES.RESEARCHER];

  if (
    !userRole ||
    !allowedPublicRoles.includes(userRole)
  ) {
    return {
      valid: false,
      error:
        "Invalid role. Only STUDENT or RESEARCHER can be selected during registration.",
    };
  }

  if (affiliation !== undefined) {
    if (typeof affiliation !== "string" || !affiliation.trim()) {
      return { valid: false, error: "Affiliation is required." };
    }
    if (affiliation.trim().length > 255) {
      return {
        valid: false,
        error: "Affiliation cannot exceed 255 characters.",
      };
    }
  }

  let normalizedInterests = [];
  if (research_interests !== undefined) {
    if (!Array.isArray(research_interests)) {
      return {
        valid: false,
        error: "Research interests must be a list.",
      };
    }

    if (
      research_interests.some(
        (interest) => typeof interest !== "string" || !interest.trim()
      )
    ) {
      return {
        valid: false,
        error: "Each research interest must be a non-empty string.",
      };
    }

    normalizedInterests = [
      ...new Set(
        research_interests
          .map((interest) => interest.trim())
          .filter(Boolean)
      ),
    ];

    if (normalizedInterests.length > 20) {
      return {
        valid: false,
        error: "You can select up to 20 research interests.",
      };
    }
  }

  return {
    valid: true,
    sanitized: {
      full_name: full_name.trim(),
      email: email.trim().toLowerCase(),
      password, // Never trim or alter passwords.
      role: userRole,
      affiliation: affiliation ? affiliation.trim() : null,
      research_interests: normalizedInterests,
    },
  };
};

export const isAllowedInstitutionalEmail = (email, allowedDomains = []) => {
  if (typeof email !== "string" || !email.includes("@")) return false;
  const domain = email.trim().toLowerCase().split("@").pop();
  if (!allowedDomains || allowedDomains.length === 0) return false;
  return allowedDomains.some(
    (allowedDomain) =>
      domain === allowedDomain || domain.endsWith(`.${allowedDomain}`)
  );
};

export const validateVerifyEmailPayload = (payload) => {
  if (
    !payload ||
    typeof payload !== "object" ||
    Array.isArray(payload)
  ) {
    return { valid: false, error: "Invalid request body." };
  }

  const { token } = payload;

  if (typeof token !== "string" || !/^[a-f0-9]{64}$/i.test(token.trim())) {
    return {
      valid: false,
      error: "A valid 64-character verification token is required.",
    };
  }

  return {
    valid: true,
    sanitized: {
      token: token.trim().toLowerCase(),
    },
  };
};

export const validateResendVerificationPayload = (payload) => {
  if (
    !payload ||
    typeof payload !== "object" ||
    Array.isArray(payload)
  ) {
    return { valid: false, error: "Invalid request body." };
  }

  const { email } = payload;

  if (typeof email !== "string" || !email.trim()) {
    return { valid: false, error: "Email is required." };
  }

  const emailResult = validateEmail(email);
  if (!emailResult.valid) return emailResult;

  return {
    valid: true,
    sanitized: {
      email: email.trim().toLowerCase(),
    },
  };
};

export const validateLoginPayload = (payload) => {
  if (
    !payload ||
    typeof payload !== "object" ||
    Array.isArray(payload)
  ) {
    return { valid: false, error: "Invalid request body." };
  }

  const { email, password } = payload;

  if (typeof email !== "string" || !email.trim()) {
    return { valid: false, error: "Email is required." };
  }

  if (typeof password !== "string" || !password) {
    return { valid: false, error: "Password is required." };
  }

  const emailResult = validateEmail(email);
  if (!emailResult.valid) return emailResult;

  return {
    valid: true,
    sanitized: {
      email: email.trim().toLowerCase(),
      password, // Never trim or alter passwords.
    },
  };
};

export const validateForgotPasswordPayload = (payload) => {
  if (
    !payload ||
    typeof payload !== "object" ||
    Array.isArray(payload)
  ) {
    return { valid: false, error: "Invalid request body." };
  }

  const { email } = payload;

  if (typeof email !== "string" || !email.trim()) {
    return { valid: false, error: "Email is required." };
  }

  const emailResult = validateEmail(email);
  if (!emailResult.valid) return emailResult;

  return {
    valid: true,
    sanitized: {
      email: email.trim().toLowerCase(),
    },
  };
};

export const validateResetPasswordPayload = (payload) => {
  if (
    !payload ||
    typeof payload !== "object" ||
    Array.isArray(payload)
  ) {
    return { valid: false, error: "Invalid request body." };
  }

  const { token, password } = payload;

  if (typeof token !== "string" || !token.trim()) {
    return { valid: false, error: "Reset token is required." };
  }

  const passwordResult = validatePassword(password);
  if (!passwordResult.valid) return passwordResult;

  return {
    valid: true,
    sanitized: {
      token: token.trim(),
      password, // Never trim or alter passwords.
    },
  };
};
