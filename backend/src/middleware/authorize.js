


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

export default authorizeRoles;
