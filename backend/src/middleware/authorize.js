import {
  ROLES,
  normalizeRole,
  isRoleMatch,
  hasPermission,
} from "../utils/roles.js";

/**
 * Role-Based Access Control (RBAC) authorization middleware.
 *
 * Verifies that the authenticated user (req.user) possesses one of the required roles.
 * Supports flexible role aliases, including both "SYSTEM ADMIN" and "SYSTEM_ADMIN".
 *
 * Usage:
 *   router.get("/admin", authenticateToken, authorize(ROLES.SYSTEM_ADMIN), handler);
 *   router.post("/papers", authenticateToken, authorize("RESEARCHER", "SYSTEM_ADMIN"), handler);
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
 *
 * Checks if the authenticated user's role has all specified permissions.
 *
 * Usage:
 *   router.post("/papers", authenticateToken, requirePermission("papers:upload"), handler);
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

/**
 * Pre-configured helpers for standard role checks
 */
export const requireAdmin = authorize(ROLES.SYSTEM_ADMIN);
export const requireResearcher = authorize(ROLES.RESEARCHER, ROLES.SYSTEM_ADMIN);
export const requireAnyRole = authorize(
  ROLES.STUDENT,
  ROLES.RESEARCHER,
  ROLES.SYSTEM_ADMIN
);

export default {
  authorize,
  requirePermission,
  requireAdmin,
  requireResearcher,
  requireAnyRole,
};
