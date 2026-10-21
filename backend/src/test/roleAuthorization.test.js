import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import express from "express";
import cookieParser from "cookie-parser";
import jwt from "jsonwebtoken";

import authRoutes from "../routes/auth.routes.js";
import errorHandler from "../middleware/errorHandler.js";
import {
  authorize,
  requirePermission,
  requireAdmin,
  requireResearcher,
} from "../middleware/authorize.js";
import {
  ROLES,
  PERMISSIONS,
  normalizeRole,
  isRoleMatch,
  hasPermission,
  getPermissionsForRole,
} from "../utils/roles.js";

describe("Role-Based Authorization & Permission Enforcement Test Suite", () => {
  const TEST_SECRET =
    "rbac-test-jwt-secret-minimum-32-chars-long-security-12345";
  let app;
  let server;
  let baseUrl;
  const originalEnv = { ...process.env };

  before(async () => {
    process.env.JWT_SECRET = TEST_SECRET;
    process.env.NODE_ENV = "test";

    app = express();
    app.use(express.json());
    app.use(cookieParser());
    app.use("/api/auth", authRoutes);
    app.use(errorHandler);

    await new Promise((resolve) => {
      server = app.listen(0, () => {
        const port = server.address().port;
        baseUrl = `http://127.0.0.1:${port}`;
        resolve();
      });
    });
  });

  after(async () => {
    process.env = { ...originalEnv };
    if (server) {
      await new Promise((resolve) => server.close(resolve));
    }
  });

  const createToken = (role, id = "test-user-id") => {
    return jwt.sign(
      {
        id,
        _id: id,
        email: `${role.toLowerCase()}@example.edu`,
        role,
      },
      TEST_SECRET,
      { expiresIn: "8h" }
    );
  };

  /* ===================================================================
   * 1. ROLE NORMALIZATION & ALIGNMENT (SYSTEM ADMIN vs SYSTEM_ADMIN)
   * =================================================================== */
  describe("Role Normalization & Alignment", () => {
    it("should normalize both 'SYSTEM ADMIN' and 'SYSTEM_ADMIN' to canonical SYSTEM_ADMIN", () => {
      assert.equal(normalizeRole("SYSTEM ADMIN"), ROLES.SYSTEM_ADMIN);
      assert.equal(normalizeRole("SYSTEM_ADMIN"), ROLES.SYSTEM_ADMIN);
      assert.equal(normalizeRole("system admin"), ROLES.SYSTEM_ADMIN);
      assert.equal(normalizeRole("system_admin"), ROLES.SYSTEM_ADMIN);
      assert.equal(normalizeRole("ADMIN"), ROLES.SYSTEM_ADMIN);
    });

    it("should normalize RESEARCHER and STUDENT correctly", () => {
      assert.equal(normalizeRole("RESEARCHER"), ROLES.RESEARCHER);
      assert.equal(normalizeRole("researcher"), ROLES.RESEARCHER);
      assert.equal(normalizeRole("STUDENT"), ROLES.STUDENT);
      assert.equal(normalizeRole("student"), ROLES.STUDENT);
    });

    it("should return null for invalid roles", () => {
      assert.equal(normalizeRole("SUPERUSER"), null);
      assert.equal(normalizeRole("GUEST"), null);
      assert.equal(normalizeRole(""), null);
      assert.equal(normalizeRole(null), null);
    });

    it("isRoleMatch should match aliases seamlessly", () => {
      assert.equal(isRoleMatch("SYSTEM ADMIN", "SYSTEM_ADMIN"), true);
      assert.equal(isRoleMatch("SYSTEM_ADMIN", "SYSTEM ADMIN"), true);
      assert.equal(isRoleMatch("RESEARCHER", "RESEARCHER"), true);
      assert.equal(isRoleMatch("STUDENT", "STUDENT"), true);
      assert.equal(isRoleMatch("STUDENT", "RESEARCHER", "SYSTEM_ADMIN"), false);
      assert.equal(isRoleMatch("RESEARCHER", ["STUDENT", "RESEARCHER"]), true);
    });
  });

  /* ===================================================================
   * 2. PERMISSION MATRIX ENFORCEMENT
   * =================================================================== */
  describe("Permission Matrix Enforcement", () => {
    it("STUDENT should have read, summary, and collection permissions but NOT upload or manage users", () => {
      assert.equal(hasPermission(ROLES.STUDENT, PERMISSIONS.PAPERS_READ), true);
      assert.equal(hasPermission(ROLES.STUDENT, PERMISSIONS.SUMMARIES_GENERATE), true);
      assert.equal(hasPermission(ROLES.STUDENT, PERMISSIONS.COLLECTIONS_CREATE), true);
      assert.equal(hasPermission(ROLES.STUDENT, PERMISSIONS.PAPERS_UPLOAD), false);
      assert.equal(hasPermission(ROLES.STUDENT, PERMISSIONS.PAPERS_DELETE), false);
      assert.equal(hasPermission(ROLES.STUDENT, PERMISSIONS.USERS_MANAGE), false);
    });

    it("RESEARCHER should have upload and collection management permissions but NOT user administration", () => {
      assert.equal(hasPermission(ROLES.RESEARCHER, PERMISSIONS.PAPERS_READ), true);
      assert.equal(hasPermission(ROLES.RESEARCHER, PERMISSIONS.PAPERS_UPLOAD), true);
      assert.equal(hasPermission(ROLES.RESEARCHER, PERMISSIONS.COLLECTIONS_MANAGE), true);
      assert.equal(hasPermission(ROLES.RESEARCHER, PERMISSIONS.PAPERS_DELETE), false);
      assert.equal(hasPermission(ROLES.RESEARCHER, PERMISSIONS.USERS_MANAGE), false);
    });

    it("SYSTEM_ADMIN and 'SYSTEM ADMIN' should possess all administrative and deletion permissions", () => {
      const perms = getPermissionsForRole("SYSTEM ADMIN");
      assert.ok(perms.includes(PERMISSIONS.PAPERS_UPLOAD));
      assert.ok(perms.includes(PERMISSIONS.PAPERS_DELETE));
      assert.ok(perms.includes(PERMISSIONS.USERS_MANAGE));
      assert.ok(perms.includes(PERMISSIONS.ROLE_ASSIGN));
      assert.ok(perms.includes(PERMISSIONS.ADMIN_ACCESS));
    });
  });

  /* ===================================================================
   * 3. ROLE-BASED AUTHORIZATION MIDDLEWARE (HTTP ENDPOINTS)
   * =================================================================== */
  describe("Role-Based Authorization Middleware (authorize)", () => {
    it("should return 401 when accessing protected role endpoint without token", async () => {
      const res = await fetch(`${baseUrl}/api/auth/admin-only`);
      assert.equal(res.status, 401);
      const body = await res.json();
      assert.match(body.error, /No authentication token provided/);
    });

    it("should return 403 Forbidden when STUDENT attempts to access researcher-only endpoint", async () => {
      const studentToken = createToken("STUDENT");
      const res = await fetch(`${baseUrl}/api/auth/researcher-only`, {
        headers: { Authorization: `Bearer ${studentToken}` },
      });

      assert.equal(res.status, 403);
      const body = await res.json();
      assert.equal(body.code, "FORBIDDEN");
      assert.match(body.error, /Forbidden/i);
    });

    it("should return 403 Forbidden when STUDENT attempts to access admin-only endpoint", async () => {
      const studentToken = createToken("STUDENT");
      const res = await fetch(`${baseUrl}/api/auth/admin-only`, {
        headers: { Authorization: `Bearer ${studentToken}` },
      });

      assert.equal(res.status, 403);
      const body = await res.json();
      assert.equal(body.code, "FORBIDDEN");
    });

    it("should return 403 Forbidden when RESEARCHER attempts to access admin-only endpoint", async () => {
      const researcherToken = createToken("RESEARCHER");
      const res = await fetch(`${baseUrl}/api/auth/admin-only`, {
        headers: { Authorization: `Bearer ${researcherToken}` },
      });

      assert.equal(res.status, 403);
      const body = await res.json();
      assert.equal(body.code, "FORBIDDEN");
    });

    it("should return 200 OK when RESEARCHER accesses researcher-only endpoint", async () => {
      const researcherToken = createToken("RESEARCHER");
      const res = await fetch(`${baseUrl}/api/auth/researcher-only`, {
        headers: { Authorization: `Bearer ${researcherToken}` },
      });

      assert.equal(res.status, 200);
      const body = await res.json();
      assert.equal(body.message, "Researcher access granted.");
    });

    it("should return 200 OK when SYSTEM_ADMIN accesses admin-only endpoint", async () => {
      const adminToken = createToken("SYSTEM_ADMIN");
      const res = await fetch(`${baseUrl}/api/auth/admin-only`, {
        headers: { Authorization: `Bearer ${adminToken}` },
      });

      assert.equal(res.status, 200);
      const body = await res.json();
      assert.equal(body.message, "Admin access granted.");
    });

    it("should return 200 OK when SYSTEM ADMIN (with space) accesses admin-only endpoint", async () => {
      const adminToken = createToken("SYSTEM ADMIN");
      const res = await fetch(`${baseUrl}/api/auth/admin-only`, {
        headers: { Authorization: `Bearer ${adminToken}` },
      });

      assert.equal(res.status, 200);
      const body = await res.json();
      assert.equal(body.message, "Admin access granted.");
    });

    it("SYSTEM_ADMIN should have access to researcher endpoints as well", async () => {
      const adminToken = createToken("SYSTEM_ADMIN");
      const res = await fetch(`${baseUrl}/api/auth/researcher-only`, {
        headers: { Authorization: `Bearer ${adminToken}` },
      });

      assert.equal(res.status, 200);
      const body = await res.json();
      assert.equal(body.message, "Researcher access granted.");
    });
  });

  /* ===================================================================
   * 4. PERMISSION ENFORCEMENT MIDDLEWARE (requirePermission)
   * =================================================================== */
  describe("Permission Enforcement Middleware (requirePermission)", () => {
    it("should return 403 when STUDENT attempts paper upload permission endpoint", async () => {
      const studentToken = createToken("STUDENT");
      const res = await fetch(`${baseUrl}/api/auth/papers/check-upload-permission`, {
        method: "POST",
        headers: { Authorization: `Bearer ${studentToken}` },
      });

      assert.equal(res.status, 403);
      const body = await res.json();
      assert.equal(body.code, "FORBIDDEN");
      assert.match(body.error, /Insufficient permissions/i);
    });

    it("should return 200 OK when RESEARCHER accesses paper upload permission endpoint", async () => {
      const researcherToken = createToken("RESEARCHER");
      const res = await fetch(`${baseUrl}/api/auth/papers/check-upload-permission`, {
        method: "POST",
        headers: { Authorization: `Bearer ${researcherToken}` },
      });

      assert.equal(res.status, 200);
      const body = await res.json();
      assert.equal(body.message, "Upload permission verified.");
    });

    it("should return 200 OK when SYSTEM_ADMIN accesses paper upload permission endpoint", async () => {
      const adminToken = createToken("SYSTEM_ADMIN");
      const res = await fetch(`${baseUrl}/api/auth/papers/check-upload-permission`, {
        method: "POST",
        headers: { Authorization: `Bearer ${adminToken}` },
      });

      assert.equal(res.status, 200);
      const body = await res.json();
      assert.equal(body.message, "Upload permission verified.");
    });
  });

  /* ===================================================================
   * 5. PRIVILEGED ROLE ASSIGNMENT ENDPOINT (PUT /api/auth/users/:id/role)
   * =================================================================== */
  describe("Privileged Role Assignment Endpoint", () => {
    it("should return 403 when STUDENT attempts to update user role", async () => {
      const studentToken = createToken("STUDENT");
      const res = await fetch(`${baseUrl}/api/auth/users/target-user-123/role`, {
        method: "PUT",
        headers: {
          Authorization: `Bearer ${studentToken}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ role: "RESEARCHER" }),
      });

      assert.equal(res.status, 403);
    });

    it("should return 403 when RESEARCHER attempts to promote themselves or others to SYSTEM_ADMIN", async () => {
      const researcherToken = createToken("RESEARCHER");
      const res = await fetch(`${baseUrl}/api/auth/users/target-user-123/role`, {
        method: "PUT",
        headers: {
          Authorization: `Bearer ${researcherToken}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ role: "SYSTEM_ADMIN" }),
      });

      assert.equal(res.status, 403);
    });

    it("should return 400 when admin provides an invalid role", async () => {
      const adminToken = createToken("SYSTEM_ADMIN");
      const res = await fetch(`${baseUrl}/api/auth/users/target-user-123/role`, {
        method: "PUT",
        headers: {
          Authorization: `Bearer ${adminToken}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ role: "INVALID_ROLE" }),
      });

      assert.equal(res.status, 400);
      const body = await res.json();
      assert.match(body.error, /Invalid role/);
    });

    it("should return 200 OK and update role when authorized SYSTEM_ADMIN updates a role", async () => {
      const adminToken = createToken("SYSTEM_ADMIN");
      const res = await fetch(`${baseUrl}/api/auth/users/target-user-123/role`, {
        method: "PUT",
        headers: {
          Authorization: `Bearer ${adminToken}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ role: "RESEARCHER" }),
      });

      assert.equal(res.status, 200);
      const body = await res.json();
      assert.equal(body.message, "User role updated successfully.");
      assert.equal(body.user.role, "RESEARCHER");
    });

    it("should accept 'SYSTEM ADMIN' (with space) when admin updates role", async () => {
      const adminToken = createToken("SYSTEM_ADMIN");
      const res = await fetch(`${baseUrl}/api/auth/users/target-user-456/role`, {
        method: "PUT",
        headers: {
          Authorization: `Bearer ${adminToken}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ role: "SYSTEM ADMIN" }),
      });

      assert.equal(res.status, 200);
      const body = await res.json();
      assert.equal(body.message, "User role updated successfully.");
      assert.equal(body.user.role, "SYSTEM_ADMIN");
    });
  });
});
