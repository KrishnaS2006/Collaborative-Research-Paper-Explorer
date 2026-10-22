


import { findUserById } from "../repositories/auth.repository.js";

const VALID_ACCESS_ROLES = [
  "SYSTEM_ADMIN",
  "LAB_ANNOTATOR",
  "READ_ONLY_VIEWER",
];

export const createAuthorizeRoles = (findUser = findUserById) => {
  return (...allowedRoles) => {
    return async (req, res, next) => {
      if (!req.user) {
        return res.status(401).json({
          error: "Authentication required.",
        });
      }

      try {
        const user = await findUser(req.user.id);

        if (!user) {
          return res.status(401).json({
            error: "User account not found.",
          });
        }

        const accessRole = user.access_role;

        if (!VALID_ACCESS_ROLES.includes(accessRole)) {
          return res.status(403).json({
            error: "Access denied. Invalid or missing access role.",
          });
        }

        req.user.access_role = accessRole;
        req.user.role = user.role;

        if (!allowedRoles.includes(accessRole)) {
          return res.status(403).json({
            error: "Forbidden. You do not have permission to perform this action.",
          });
        }

        return next();
      } catch (error) {
        console.error("Authorization role lookup failed:", error.message);

        return res.status(500).json({
          error: "Unable to verify permissions.",
        });
      }
    };
  };
};

// Production middleware uses the real repository function.
export const authorizeRoles = createAuthorizeRoles();

import {
  ROLES,
  normalizeRole,
  isRoleMatch,
  hasPermission,
} from "../utils/roles.js";

/**
 * Role-Based Access Control (RBAC) authorization middleware.
 */
export const authorize = (...allowedRoles) => {
  const flattened = allowedRoles.flat();

  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        error: "Access denied. Authentication required.",
        code: "UNAUTHENTICATED",
      });
    }

    const userRole = req.user.role;
    const normalizedUser = normalizeRole(userRole);

    if (!normalizedUser) {
      return res.status(403).json({
        error: "Forbidden: User has invalid or unassigned role.",
        code: "INVALID_ROLE",
      });
    }

    const authorized = isRoleMatch(normalizedUser, flattened);

    if (!authorized) {
      return res.status(403).json({
        error: "Forbidden: You do not have permission to access this resource.",
        code: "FORBIDDEN",
        userRole,
        requiredRoles: flattened,
      });
    }

    return next();
  };
};

/**
 * Permission-based authorization middleware.
 */
export const requirePermission = (...requiredPermissions) => {
  const permissions = requiredPermissions.flat();

  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        error: "Access denied. Authentication required.",
        code: "UNAUTHENTICATED",
      });
    }

    const userRole = req.user.role;
    const missingPermissions = permissions.filter(
      (perm) => !hasPermission(userRole, perm)
    );

    if (missingPermissions.length > 0) {
      return res.status(403).json({
        error: "Forbidden: Insufficient permissions to perform this action.",
        code: "FORBIDDEN",
        userRole,
        missingPermissions,
      });
    }

    return next();
  };
};

export const requireAdmin = authorize(ROLES.SYSTEM_ADMIN);
export const requireResearcher = authorize(ROLES.RESEARCHER, ROLES.SYSTEM_ADMIN);
export const requireAnyRole = authorize(
  ROLES.STUDENT,
  ROLES.RESEARCHER,
  ROLES.SYSTEM_ADMIN
);

export default authorizeRoles;
