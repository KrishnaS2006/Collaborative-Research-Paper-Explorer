import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

import app from "../app.js";
import pool from "../config/database.js";
import { ROLES } from "../utils/roles.js";
import {
  _setFindUserByEmailForTesting,
  _resetFindUserByEmailForTesting,
  _setCreateUserForTesting,
  _resetCreateUserForTesting,
  _setCreateEmailVerificationTokenForTesting,
  _resetCreateEmailVerificationTokenForTesting,
  _setUpdateUserProfileForTesting,
  _resetUpdateUserProfileForTesting,
} from "../repositories/auth.repository.js";
import { setTransporterForTesting, resetTransporterForTesting } from "../utils/emailService.js";

describe("Comprehensive End-to-End System Verification (FR-01 to FR-05 & Workflows)", () => {
  let server;
  let baseUrl;
  const originalQuery = pool.query;
  const JWT_SECRET = process.env.JWT_SECRET || "e2e-test-jwt-secret-minimum-32-chars-long-abc123";

  before(async () => {
    process.env.JWT_SECRET = JWT_SECRET;
    process.env.NODE_ENV = "test";

    // Set transporter mock so email send doesn't fail
    setTransporterForTesting({
      sendMail: async () => ({ messageId: "<e2e-test-id@domain.com>" }),
    });

    _setCreateEmailVerificationTokenForTesting(async (t) => ({
      id: "token-uuid-123",
      user_id: t.userId,
      expires_at: t.expiresAt,
    }));

    // Mock pool.query for sessions and papers
    pool.query = async (sql, params) => {
      const text = String(sql);

      // Session creation
      if (text.includes("INSERT INTO user_sessions") || text.includes("INSERT INTO sessions")) {
        return {
          rows: [{
            id: "session-123",
            user_id: params?.[0] || "e2e-user-id",
            token_hash: "mockhash",
            last_active_at: new Date(),
            revoked_at: null,
          }],
        };
      }

      // Check revoked token
      if (text.includes("FROM user_sessions") || text.includes("FROM sessions")) {
        return {
          rows: [{
            id: "session-123",
            user_id: params?.[0] || "e2e-user-id",
            last_active_at: new Date(),
            revoked_at: null,
          }],
        };
      }

      // findUserById for authorizeRoles middleware
      if (text.includes("FROM users") && text.includes("WHERE id = $1")) {
        const id = params?.[0];
        let role = ROLES.STUDENT;
        if (id === "admin-user") role = ROLES.SYSTEM_ADMIN;
        if (id === "researcher-user") role = ROLES.RESEARCHER;
        if (id === "student-user") role = ROLES.STUDENT;
        return {
          rows: [{
            id,
            email: "test@university.edu",
            full_name: "Test User",
            role,
          }],
        };
      }

      if (text.includes("FROM papers")) {
        return {
          rows: [{
            id: "paper-123",
            title: "Quantum Entanglement Analysis",
            abstract: "A study on qubits...",
            authors: ["Dr. Smith"],
          }],
        };
      }

      if (text.includes("FROM annotations")) {
        return {
          rows: [{
            id: "annotation-123",
            paper_id: "paper-123",
            created_by: "researcher-user",
            content: "Key finding here",
          }],
        };
      }

      return { rows: [] };
    };

    await new Promise((resolve) => {
      server = http.createServer(app);
      server.listen(0, () => {
        const port = server.address().port;
        baseUrl = `http://127.0.0.1:${port}`;
        resolve();
      });
    });
  });

  after(async () => {
    pool.query = originalQuery;
    resetTransporterForTesting();
    _resetFindUserByEmailForTesting();
    _resetCreateUserForTesting();
    _resetCreateEmailVerificationTokenForTesting();
    _resetUpdateUserProfileForTesting();
    if (server) {
      await new Promise((resolve) => server.close(resolve));
    }
  });

  const createToken = (role, id = "e2e-user-id", email = "test@university.edu") => {
    return jwt.sign(
      { id, _id: id, role, email },
      JWT_SECRET,
      { expiresIn: "8h" }
    );
  };

  /* ===================================================================
   * 1. FR-01: USER REGISTRATION & ROLE SANITIZATION
   * =================================================================== */
  describe("FR-01: Registration and Role Validation", () => {
    it("should successfully register a student with password hashing", async () => {
      let savedUser = null;
      _setFindUserByEmailForTesting(async () => null);
      _setCreateUserForTesting(async (u) => {
        savedUser = {
          id: "student-123",
          email: u.email,
          full_name: u.fullName,
          role: u.role,
          affiliation: u.affiliation,
          research_interests: u.researchInterests,
          email_verified: false,
          password_hash: u.passwordHash,
        };
        return savedUser;
      });

      const res = await fetch(`${baseUrl}/api/auth/register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          full_name: "Alice Student",
          email: "alice@university.edu",
          password: "SecurePassword123!",
          role: "STUDENT",
          affiliation: "Dept of Physics",
          research_interests: ["Astrophysics"],
        }),
      });

      assert.equal(res.status, 201);
      const data = await res.json();
      assert.equal(data.user.email, "alice@university.edu");
      assert.equal(data.user.role, ROLES.STUDENT);
      assert.equal(data.user.access_role, undefined, "access_role must not exist in response");

      // Verify bcrypt hashing cost factor
      assert.ok(savedUser.password_hash);
      const isMatch = await bcrypt.compare("SecurePassword123!", savedUser.password_hash);
      assert.equal(isMatch, true);
    });

    it("should reject registration attempts with obsolete role LAB_ANNOTATOR (400)", async () => {
      const res = await fetch(`${baseUrl}/api/auth/register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          full_name: "Test Person",
          email: "test@university.edu",
          password: "SecurePassword123!",
          role: "LAB_ANNOTATOR",
        }),
      });

      assert.equal(res.status, 400);
      const data = await res.json();
      assert.match(data.error, /Only STUDENT or RESEARCHER/);
    });

    it("should reject registration attempts with obsolete role READ_ONLY_VIEWER (400)", async () => {
      const res = await fetch(`${baseUrl}/api/auth/register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          full_name: "Test Person",
          email: "test@university.edu",
          password: "SecurePassword123!",
          role: "READ_ONLY_VIEWER",
        }),
      });

      assert.equal(res.status, 400);
      const data = await res.json();
      assert.match(data.error, /Only STUDENT or RESEARCHER/);
    });

    it("should reject duplicate email registrations (409)", async () => {
      _setFindUserByEmailForTesting(async () => ({
        id: "existing-user",
        email: "alice@university.edu",
        role: "STUDENT",
      }));

      const res = await fetch(`${baseUrl}/api/auth/register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          full_name: "Duplicate Alice",
          email: "alice@university.edu",
          password: "SecurePassword123!",
          role: "STUDENT",
          affiliation: "State University",
          research_interests: ["Databases"],
        }),
      });

      assert.equal(res.status, 409);
    });
  });

  /* ===================================================================
   * 2. FR-02: SECURE AUTHENTICATION & SSO
   * =================================================================== */
  describe("FR-02: Authentication & SSO Config", () => {
    it("should reject login with nonexistent email (401 without user enumeration)", async () => {
      _setFindUserByEmailForTesting(async () => null);

      const res = await fetch(`${baseUrl}/api/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          email: "nonexistent@university.edu",
          password: "AnyPassword123!",
        }),
      });

      assert.equal(res.status, 401);
      const data = await res.json();
      assert.match(data.error, /Invalid email or password/);
    });

    it("should reject login with incorrect password (401)", async () => {
      const hash = await bcrypt.hash("RealPassword123!", 10);
      _setFindUserByEmailForTesting(async () => ({
        id: "user-1",
        email: "real@university.edu",
        password_hash: hash,
        full_name: "Real User",
        role: "RESEARCHER",
        email_verified: true,
      }));

      const res = await fetch(`${baseUrl}/api/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          email: "real@university.edu",
          password: "WrongPassword123!",
        }),
      });

      assert.equal(res.status, 401);
      const data = await res.json();
      assert.match(data.error, /Invalid email or password/);
    });

    it("should successfully log in verified user and set JWT cookie, return clean user payload", async () => {
      const hash = await bcrypt.hash("RealPassword123!", 10);
      _setFindUserByEmailForTesting(async () => ({
        id: "user-1",
        email: "real@university.edu",
        password_hash: hash,
        full_name: "Real User",
        role: "RESEARCHER",
        email_verified: true,
      }));

      const res = await fetch(`${baseUrl}/api/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          email: "real@university.edu",
          password: "RealPassword123!",
        }),
      });

      assert.equal(res.status, 200);
      // Token is delivered via HTTP-only cookie, not in JSON body
      const setCookieHeader = res.headers.get("set-cookie");
      assert.ok(setCookieHeader && setCookieHeader.includes("token="), "JWT cookie must be set");

      const data = await res.json();
      assert.equal(data.message, "Logged in successfully.");
      assert.equal(data.user.role, "RESEARCHER");
      assert.equal(data.user.access_role, undefined, "access_role must not be present");
    });

    it("should return safe SSO configuration via GET /api/auth/sso/config", async () => {
      const res = await fetch(`${baseUrl}/api/auth/sso/config`);
      assert.equal(res.status, 200);
      const data = await res.json();
      assert.ok(typeof data.enabled === "boolean");
    });
  });

  /* ===================================================================
   * 3. FR-05: ROLE-BASED ACCESS CONTROL (ONLY 3 ROLES)
   * =================================================================== */
  describe("FR-05: RBAC & Elimination of Obsolete Roles", () => {
    it("SYSTEM_ADMIN can access admin routes", async () => {
      const adminToken = createToken(ROLES.SYSTEM_ADMIN);
      const res = await fetch(`${baseUrl}/api/auth/admin-only`, {
        headers: { Authorization: `Bearer ${adminToken}` },
      });
      assert.equal(res.status, 200);
    });

    it("RESEARCHER cannot access admin-only routes (403)", async () => {
      const researcherToken = createToken(ROLES.RESEARCHER);
      const res = await fetch(`${baseUrl}/api/auth/admin-only`, {
        headers: { Authorization: `Bearer ${researcherToken}` },
      });
      assert.equal(res.status, 403);
    });

    it("STUDENT cannot access admin-only routes (403)", async () => {
      const studentToken = createToken(ROLES.STUDENT);
      const res = await fetch(`${baseUrl}/api/auth/admin-only`, {
        headers: { Authorization: `Bearer ${studentToken}` },
      });
      assert.equal(res.status, 403);
    });

    it("RESEARCHER can check paper upload permission (200)", async () => {
      const researcherToken = createToken(ROLES.RESEARCHER);
      const res = await fetch(`${baseUrl}/api/auth/papers/check-upload-permission`, {
        method: "POST",
        headers: { Authorization: `Bearer ${researcherToken}` },
      });
      assert.equal(res.status, 200);
    });

    it("STUDENT cannot check paper upload permission (403)", async () => {
      const studentToken = createToken(ROLES.STUDENT);
      const res = await fetch(`${baseUrl}/api/auth/papers/check-upload-permission`, {
        method: "POST",
        headers: { Authorization: `Bearer ${studentToken}` },
      });
      assert.equal(res.status, 403);
    });

    it("rejects profile update attempt to modify role (403)", async () => {
      const studentToken = createToken(ROLES.STUDENT);
      const res = await fetch(`${baseUrl}/api/auth/profile`, {
        method: "PUT",
        headers: {
          Authorization: `Bearer ${studentToken}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ role: "SYSTEM_ADMIN" }),
      });
      assert.equal(res.status, 403);
    });

    it("rejects profile update attempt supplying access_role (403)", async () => {
      const studentToken = createToken(ROLES.STUDENT);
      const res = await fetch(`${baseUrl}/api/auth/profile`, {
        method: "PUT",
        headers: {
          Authorization: `Bearer ${studentToken}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ access_role: "LAB_ANNOTATOR" }),
      });
      assert.equal(res.status, 403);
    });

    it("rejects administrative assignment of obsolete roles LAB_ANNOTATOR or READ_ONLY_VIEWER (400)", async () => {
      const adminToken = createToken(ROLES.SYSTEM_ADMIN);

      const res1 = await fetch(`${baseUrl}/api/auth/users/target-id/role`, {
        method: "PUT",
        headers: {
          Authorization: `Bearer ${adminToken}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ role: "LAB_ANNOTATOR" }),
      });
      assert.equal(res1.status, 400);

      const res2 = await fetch(`${baseUrl}/api/auth/users/target-id/role`, {
        method: "PUT",
        headers: {
          Authorization: `Bearer ${adminToken}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ role: "READ_ONLY_VIEWER" }),
      });
      assert.equal(res2.status, 400);
    });
  });

  /* ===================================================================
   * 4. RESEARCH PAPERS & ANNOTATIONS WORKFLOW VERIFICATION
   * =================================================================== */
  describe("Research Papers & Annotations Collaboration Workflows", () => {
    it("STUDENT can view papers (/api/papers)", async () => {
      const studentToken = createToken(ROLES.STUDENT, "student-user");
      const res = await fetch(`${baseUrl}/api/papers`, {
        headers: { Authorization: `Bearer ${studentToken}` },
      });
      assert.equal(res.status, 200);
      const data = await res.json();
      assert.ok(Array.isArray(data.papers));
      assert.equal(data.papers.length, 1);
    });

    it("RESEARCHER can view papers (/api/papers)", async () => {
      const researcherToken = createToken(ROLES.RESEARCHER, "researcher-user");
      const res = await fetch(`${baseUrl}/api/papers`, {
        headers: { Authorization: `Bearer ${researcherToken}` },
      });
      assert.equal(res.status, 200);
    });

    it("SYSTEM_ADMIN can view papers (/api/papers)", async () => {
      const adminToken = createToken(ROLES.SYSTEM_ADMIN, "admin-user");
      const res = await fetch(`${baseUrl}/api/papers`, {
        headers: { Authorization: `Bearer ${adminToken}` },
      });
      assert.equal(res.status, 200);
    });

    it("STUDENT can view annotations (/api/annotations)", async () => {
      const studentToken = createToken(ROLES.STUDENT, "student-user");
      const res = await fetch(`${baseUrl}/api/annotations`, {
        headers: { Authorization: `Bearer ${studentToken}` },
      });
      assert.equal(res.status, 200);
      const data = await res.json();
      assert.ok(Array.isArray(data.annotations));
    });

    it("STUDENT cannot create annotations (403)", async () => {
      const studentToken = createToken(ROLES.STUDENT, "student-user");
      const res = await fetch(`${baseUrl}/api/annotations`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${studentToken}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          paper_id: "11111111-1111-4111-8111-111111111111",
          page_number: 1,
          content: "Student annotation",
        }),
      });
      assert.equal(res.status, 403);
    });

    it("RESEARCHER cannot delete annotations (403)", async () => {
      const researcherToken = createToken(ROLES.RESEARCHER, "researcher-user");
      const res = await fetch(`${baseUrl}/api/annotations/11111111-1111-4111-8111-111111111111`, {
        method: "DELETE",
        headers: { Authorization: `Bearer ${researcherToken}` },
      });
      assert.equal(res.status, 403);
    });
  });
});
