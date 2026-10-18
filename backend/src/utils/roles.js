/**
 * ==============================================================================
 * Role-Based Access Control (RBAC) & Permission Definitions
 * Supports: STUDENT, RESEARCHER, SYSTEM ADMIN / SYSTEM_ADMIN
 * ==============================================================================
 */

export const ROLES = Object.freeze({
  STUDENT: "STUDENT",
  RESEARCHER: "RESEARCHER",
  SYSTEM_ADMIN: "SYSTEM_ADMIN",
});

// Human-readable and alternate representation mappings
export const ROLE_DISPLAY_NAMES = Object.freeze({
  [ROLES.STUDENT]: "Student",
  [ROLES.RESEARCHER]: "Researcher",
  [ROLES.SYSTEM_ADMIN]: "System Admin",
});

// Canonical permissions across the Collaborative Research Paper Explorer
export const PERMISSIONS = Object.freeze({
  // Paper permissions
  PAPERS_READ: "papers:read",
  PAPERS_UPLOAD: "papers:upload",
  PAPERS_DELETE: "papers:delete",

  // Summary permissions
  SUMMARIES_GENERATE: "summaries:generate",

  // Collection permissions
  COLLECTIONS_CREATE: "collections:create",
  COLLECTIONS_MANAGE: "collections:manage",

  // Administration permissions
  USERS_READ: "users:read",
  USERS_MANAGE: "users:manage",
  ROLE_ASSIGN: "role:assign",
  ADMIN_ACCESS: "admin:access",
});

// Role-to-Permissions Matrix
export const ROLE_PERMISSIONS = Object.freeze({
  [ROLES.STUDENT]: Object.freeze([
    PERMISSIONS.PAPERS_READ,
    PERMISSIONS.SUMMARIES_GENERATE,
    PERMISSIONS.COLLECTIONS_CREATE,
  ]),
  [ROLES.RESEARCHER]: Object.freeze([
    PERMISSIONS.PAPERS_READ,
    PERMISSIONS.PAPERS_UPLOAD,
    PERMISSIONS.SUMMARIES_GENERATE,
    PERMISSIONS.COLLECTIONS_CREATE,
    PERMISSIONS.COLLECTIONS_MANAGE,
  ]),
  [ROLES.SYSTEM_ADMIN]: Object.freeze([
    PERMISSIONS.PAPERS_READ,
    PERMISSIONS.PAPERS_UPLOAD,
    PERMISSIONS.PAPERS_DELETE,
    PERMISSIONS.SUMMARIES_GENERATE,
    PERMISSIONS.COLLECTIONS_CREATE,
    PERMISSIONS.COLLECTIONS_MANAGE,
    PERMISSIONS.USERS_READ,
    PERMISSIONS.USERS_MANAGE,
    PERMISSIONS.ROLE_ASSIGN,
    PERMISSIONS.ADMIN_ACCESS,
  ]),
});

/**
 * Normalizes any role string into canonical representation (e.g. "SYSTEM ADMIN" -> "SYSTEM_ADMIN").
 * Handles case-insensitivity, spaces, dashes, and underscores.
 */
export const normalizeRole = (role) => {
  if (!role || typeof role !== "string") return null;

  const sanitized = role.trim().toUpperCase().replace(/[\s\-]+/g, "_");

  if (
    sanitized === "SYSTEM_ADMIN" ||
    sanitized === "SYSTEMADMIN" ||
    sanitized === "ADMIN"
  ) {
    return ROLES.SYSTEM_ADMIN;
  }

  if (sanitized === "RESEARCHER") {
    return ROLES.RESEARCHER;
  }

  if (sanitized === "STUDENT") {
    return ROLES.STUDENT;
  }

  return null;
};

/**
 * Checks if a given role matches any of the required roles.
 */
export const isRoleMatch = (userRole, ...allowedRoles) => {
  const normalizedUserRole = normalizeRole(userRole);
  if (!normalizedUserRole) return false;

  const flattened = allowedRoles.flat();
  for (const allowed of flattened) {
    const normalizedAllowed = normalizeRole(allowed);
    if (normalizedAllowed && normalizedAllowed === normalizedUserRole) {
      return true;
    }
  }

  return false;
};

/**
 * Returns all permissions assigned to a role.
 */
export const getPermissionsForRole = (role) => {
  const normalized = normalizeRole(role);
  if (!normalized) return [];
  return ROLE_PERMISSIONS[normalized] || [];
};

/**
 * Checks if a given role has a specific permission.
 */
export const hasPermission = (role, permission) => {
  const permissions = getPermissionsForRole(role);
  return permissions.includes(permission);
};

export default {
  ROLES,
  ROLE_DISPLAY_NAMES,
  PERMISSIONS,
  ROLE_PERMISSIONS,
  normalizeRole,
  isRoleMatch,
  getPermissionsForRole,
  hasPermission,
};
