import { findUserById } from "../repositories/auth.repository.js";
import {
  ROLES,
  normalizeRole,
  isRoleMatch,
  hasPermission,
} from "../utils/roles.js";

const VALID_ROLES = [
  ROLES.SYSTEM_ADMIN,
  ROLES.RESEARCHER,
  ROLES.STUDENT,
];

export const createAuthorizeRoles = (findUser = findUserById) => {
  return (...allowedRoles) => {
    const flattened = allowedRoles.flat();

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

        const normalizedRole = normalizeRole(user.role);

        if (!normalizedRole || !VALID_ROLES.includes(normalizedRole)) {
          return res.status(403).json({
            error: "Access denied. Invalid or missing user role.",
          });
        }

        // Current database role overrides any stale token role
        req.user.role = normalizedRole;

        const isAllowed = isRoleMatch(normalizedRole, flattened);

        if (!isAllowed) {
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

    if (!normalizedUser || !VALID_ROLES.includes(normalizedUser)) {
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
