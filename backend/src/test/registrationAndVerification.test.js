import './setup.js';
import { describe, it, before, after, afterEach } from "node:test";
import assert from "node:assert/strict";
import express from "express";
import cookieParser from "cookie-parser";
import crypto from "node:crypto";
import bcrypt from "bcryptjs";

import authRoutes from "../routes/auth.routes.js";
import errorHandler from "../middleware/errorHandler.js";
import { env } from "../config/env.js";
import {
  resendVerificationRateLimiter,
  loginRateLimiter,
} from "../middleware/rateLimiter.js";
import {
  sendEmailVerificationEmail,
  setTransporterForTesting,
  resetTransporterForTesting,
} from "../utils/emailService.js";
import {
  isAllowedInstitutionalEmail,
  validateRegisterPayload,
} from "../utils/validation.js";
import {
  _setFindUserByEmailForTesting,
  _resetFindUserByEmailForTesting,
  _setCreateUserForTesting,
  _resetCreateUserForTesting,
  _setCreateEmailVerificationTokenForTesting,
  _resetCreateEmailVerificationTokenForTesting,
  _setConsumeEmailVerificationTokenForTesting,
  _resetConsumeEmailVerificationTokenForTesting,
} from "../repositories/auth.repository.js";

describe("FR-01: User Registration & Email Verification Suite", () => {
  let app;
  let server;
  let baseUrl;
  const originalEnv = { ...process.env };
  const originalAllowedDomains = [...env.allowedEmailDomains];

  before(async () => {
    process.env.JWT_SECRET =
      "test-jwt-secret-min-32-chars-long-security-123456";
    process.env.NODE_ENV = "test";
    process.env.ALLOWED_EMAIL_DOMAINS = "dau.ac.in,university.edu";
    env.allowedEmailDomains = ["dau.ac.in", "university.edu"];

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
    env.allowedEmailDomains = [...originalAllowedDomains];
    if (server) {
      await new Promise((resolve) => server.close(resolve));
    }
  });

  afterEach(() => {
    resetTransporterForTesting();
    resendVerificationRateLimiter.reset();
    loginRateLimiter.reset();
    _resetFindUserByEmailForTesting();
    _resetCreateUserForTesting();
    _resetCreateEmailVerificationTokenForTesting();
    _resetConsumeEmailVerificationTokenForTesting();
  });

  describe("Institutional Email Domain Matching Logic", () => {
    const allowed = ["dau.ac.in", "university.edu"];

    it("should accept valid exact institutional domain", () => {
      assert.equal(
        isAllowedInstitutionalEmail("researcher@dau.ac.in", allowed),
        true
      );
      assert.equal(
        isAllowedInstitutionalEmail("prof@university.edu", allowed),
        true
      );
    });

    it("should accept valid subdomains of allowed institutional domains", () => {
      assert.equal(
        isAllowedInstitutionalEmail("lab@cs.university.edu", allowed),
        true
      );
      assert.equal(
        isAllowedInstitutionalEmail("student@ict.dau.ac.in", allowed),
        true
      );
    });

    it("should reject domain suffix spoofing attempts", () => {
      // student@fakeuniversity.edu must NOT match university.edu
      assert.equal(
        isAllowedInstitutionalEmail("attacker@fakeuniversity.edu", allowed),
        false
      );
      assert.equal(
        isAllowedInstitutionalEmail("attacker@notdau.ac.in", allowed),
        false
      );
      assert.equal(
        isAllowedInstitutionalEmail("attacker@university.edu.evil.com", allowed),
        false
      );
    });

    it("should reject invalid email formats or empty domains", () => {
      assert.equal(isAllowedInstitutionalEmail("", allowed), false);
      assert.equal(isAllowedInstitutionalEmail("noatsign", allowed), false);
      assert.equal(isAllowedInstitutionalEmail("test@other.org", allowed), false);
    });
  });

  describe("Registration Payload Validation (Affiliation & Research Interests)", () => {
    const validRegistration = {
      full_name: "Dr. Alice Turing",
      email: "alice@university.edu",
      password: "StrongPassword123!",
      role: "RESEARCHER",
      affiliation: "Department of Computer Science",
      research_interests: [
        "Artificial Intelligence",
        "Natural Language Processing",
        "Cryptography",
      ],
    };

    it("should validate and sanitize correct registration payload", () => {
      const res = validateRegisterPayload(validRegistration);
      assert.equal(res.valid, true);
      assert.equal(res.sanitized.affiliation, "Department of Computer Science");
      assert.equal(res.sanitized.research_interests.length, 3);
      assert.equal(res.sanitized.role, "RESEARCHER");
    });

    it("should deduplicate research interests", () => {
      const payload = {
        ...validRegistration,
        research_interests: ["AI", "AI", "NLP", " NLP "],
      };
      const res = validateRegisterPayload(payload);
      assert.equal(res.valid, true);
      assert.deepEqual(res.sanitized.research_interests, ["AI", "NLP"]);
    });

    it("should reject when research interests list exceeds 20 items", () => {
      const tooMany = Array.from({ length: 21 }, (_, i) => `Field ${i + 1}`);
      const res = validateRegisterPayload({
        ...validRegistration,
        research_interests: tooMany,
      });
      assert.equal(res.valid, false);
      assert.match(res.error, /up to 20/);
    });

    it("should reject empty or whitespace research interests", () => {
      const res = validateRegisterPayload({
        ...validRegistration,
        research_interests: ["Valid", "  ", ""],
      });
      assert.equal(res.valid, false);
      assert.match(res.error, /non-empty string/);
    });

    it("should reject non-array research interests", () => {
      const res = validateRegisterPayload({
        ...validRegistration,
        research_interests: "NotAnArray",
      });
      assert.equal(res.valid, false);
      assert.match(res.error, /must be a list/);
    });

    it("should reject empty affiliation when provided as empty string", () => {
      const res = validateRegisterPayload({
        ...validRegistration,
        affiliation: "   ",
      });
      assert.equal(res.valid, false);
      assert.match(res.error, /Affiliation is required/);
    });
  });

  describe("POST /api/auth/register (HTTP Policy & Enforcement)", () => {
    it("should reject researcher registration with non-institutional email (403)", async () => {
      const res = await fetch(`${baseUrl}/api/auth/register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          full_name: "External Researcher",
          email: "researcher@gmail.com",
          password: "SecurePassword123!",
          role: "RESEARCHER",
          affiliation: "Independent Lab",
          research_interests: ["Machine Learning"],
        }),
      });

      const data = await res.json();
      assert.equal(res.status, 403);
      assert.match(
        data.error,
        /Researchers must use an approved institutional email/
      );
    });

    it("should reject researcher with domain-suffix spoof email (403)", async () => {
      const res = await fetch(`${baseUrl}/api/auth/register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          full_name: "Spoof Researcher",
          email: "spoof@fakeuniversity.edu",
          password: "SecurePassword123!",
          role: "RESEARCHER",
          affiliation: "Fake Uni",
          research_interests: ["AI"],
        }),
      });

      const data = await res.json();
      assert.equal(res.status, 403);
      assert.match(
        data.error,
        /Researchers must use an approved institutional email/
      );
    });

    it("should reject registration missing affiliation (400)", async () => {
      const res = await fetch(`${baseUrl}/api/auth/register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          full_name: "Student Without Affiliation",
          email: "student_noaff@example.com",
          password: "SecurePassword123!",
          role: "STUDENT",
        }),
      });

      const data = await res.json();
      assert.equal(res.status, 400);
      assert.match(data.error, /Affiliation is required/);
    });

    it("should successfully register a new user and persist all fields", async () => {
      let createdUserData = null;
      _setFindUserByEmailForTesting(async () => null);
      _setCreateUserForTesting(async (u) => {
        createdUserData = u;
        return {
          id: "new-user-123",
          email: u.email,
          full_name: u.fullName,
          role: u.role,
          affiliation: u.affiliation,
          research_interests: u.researchInterests,
          email_verified: false,
        };
      });
      _setCreateEmailVerificationTokenForTesting(async () => ({ id: "tok-1" }));

      const res = await fetch(`${baseUrl}/api/auth/register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          full_name: "Dr. Alice Turing",
          email: "alice@university.edu",
          password: "SecurePassword123!",
          role: "RESEARCHER",
          affiliation: "Dept of CS",
          research_interests: ["Quantum Computing", "AI"],
        }),
      });

      assert.equal(res.status, 201);
      const data = await res.json();
      assert.ok(data.user);
      assert.equal(data.user.email, "alice@university.edu");
      assert.equal(data.user.full_name, "Dr. Alice Turing");
      assert.equal(data.user.role, "RESEARCHER");
      assert.equal(data.user.affiliation, "Dept of CS");
      assert.deepEqual(data.user.research_interests, ["Quantum Computing", "AI"]);

      // Verify password hashing before DB persistence
      assert.ok(createdUserData);
      assert.notEqual(createdUserData.passwordHash, "SecurePassword123!");
      assert.match(createdUserData.passwordHash, /^\$2[aby]\$\d+\$/);
      const isMatch = await bcrypt.compare(
        "SecurePassword123!",
        createdUserData.passwordHash
      );
      assert.equal(isMatch, true);
    });

    it("should reject duplicate email registration with 409 Conflict", async () => {
      _setFindUserByEmailForTesting(async (email) => ({
        id: "existing-user-uuid",
        email: email.toLowerCase(),
        full_name: "Existing Person",
        role: "STUDENT",
      }));

      const res = await fetch(`${baseUrl}/api/auth/register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          full_name: "Duplicate User",
          email: "duplicate@university.edu",
          password: "SecurePassword123!",
          role: "STUDENT",
          affiliation: "University College",
          research_interests: ["Databases"],
        }),
      });

      assert.equal(res.status, 409);
      const data = await res.json();
      assert.match(data.error, /Email already in use/);
    });

    it("should reject registration attempts with privileged roles like SYSTEM_ADMIN (400)", async () => {
      const res = await fetch(`${baseUrl}/api/auth/register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          full_name: "Hacker Admin",
          email: "hacker@university.edu",
          password: "SecurePassword123!",
          role: "SYSTEM_ADMIN",
          affiliation: "Evil Corp",
        }),
      });

      assert.equal(res.status, 400);
      const data = await res.json();
      assert.match(data.error, /Only STUDENT or RESEARCHER/);
    });

    it("should reject registration attempts with obsolete role LAB_ANNOTATOR (400)", async () => {
      const res = await fetch(`${baseUrl}/api/auth/register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          full_name: "Lab Person",
          email: "labperson@university.edu",
          password: "SecurePassword123!",
          role: "LAB_ANNOTATOR",
          affiliation: "Biology Lab",
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
          full_name: "Viewer Person",
          email: "viewer@university.edu",
          password: "SecurePassword123!",
          role: "READ_ONLY_VIEWER",
          affiliation: "University",
        }),
      });

      assert.equal(res.status, 400);
      const data = await res.json();
      assert.match(data.error, /Only STUDENT or RESEARCHER/);
    });

    it("should handle email delivery failure safely without crashing registration", async () => {
      // Mock repository methods so registration proceeds to email delivery
      _setFindUserByEmailForTesting(async () => null);
      _setCreateUserForTesting(async (u) => ({
        id: "mock-user-uuid",
        email: u.email,
        full_name: u.fullName,
        role: u.role,
        affiliation: u.affiliation,
        research_interests: u.researchInterests,
        email_verified: false,
      }));
      _setCreateEmailVerificationTokenForTesting(async (t) => ({
        id: "mock-token-uuid",
        user_id: t.userId,
        expires_at: t.expiresAt,
      }));

      // Mock transporter that throws delivery error
      setTransporterForTesting({
        sendMail: async () => {
          throw new Error("SMTP connection refused");
        },
      });

      const uniqueEmail = `failure_test_${Date.now()}@example.com`;

      const res = await fetch(`${baseUrl}/api/auth/register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          full_name: "Safe Delivery User",
          email: uniqueEmail,
          password: "SecurePassword123!",
          role: "STUDENT",
          affiliation: "City College",
          research_interests: ["Databases"],
        }),
      });

      // Should succeed or safely handle
      assert.ok([201, 409].includes(res.status));
    });
  });

  describe("Email Verification Endpoint & Resend Security", () => {
    it("POST /api/auth/verify-email should reject invalid or missing token (400)", async () => {
      const res = await fetch(`${baseUrl}/api/auth/verify-email`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ token: "invalid_short_token" }),
      });

      const data = await res.json();
      assert.equal(res.status, 400);
      assert.match(data.error, /valid 64-character verification token/);
    });

    it("POST /api/auth/verify-email should reject non-existent 64-char token (400)", async () => {
      _setConsumeEmailVerificationTokenForTesting(async () => ({
        success: false,
        reason: "not_found",
      }));

      const random64Token = crypto.randomBytes(32).toString("hex");
      const res = await fetch(`${baseUrl}/api/auth/verify-email`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ token: random64Token }),
      });

      const data = await res.json();
      assert.equal(res.status, 400);
      assert.match(data.error, /Invalid or non-existent verification token/);
    });

    it("POST /api/auth/resend-verification should return generic message for non-existent email (no enumeration)", async () => {
      _setFindUserByEmailForTesting(async () => null);

      const res = await fetch(`${baseUrl}/api/auth/resend-verification`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          email: `nonexistent_user_${Date.now()}@university.edu`,
        }),
      });

      const data = await res.json();
      assert.equal(res.status, 200);
      assert.match(data.message, /If an unverified account with that email exists/);
    });

    it("POST /api/auth/resend-verification should enforce rate limiting (429)", async () => {
      resendVerificationRateLimiter.reset();

      // Trigger 5 rapid requests
      for (let i = 0; i < 5; i++) {
        await fetch(`${baseUrl}/api/auth/resend-verification`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ email: `rate_${i}@university.edu` }),
        });
      }

      // 6th request should hit 429
      const res = await fetch(`${baseUrl}/api/auth/resend-verification`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: "rate_blocked@university.edu" }),
      });

      const data = await res.json();
      assert.equal(res.status, 429);
      assert.match(data.error, /Too many verification requests/);
      assert.ok(res.headers.get("retry-after"));
    });
  });

  describe("Nodemailer Email Verification Service", () => {
    it("sendEmailVerificationEmail should format console email correctly in dev mode", async () => {
      process.env.EMAIL_SERVICE_MODE = "console";
      process.env.FRONTEND_URL = "http://localhost:5173";

      const result = await sendEmailVerificationEmail({
        to: "researcher@dau.ac.in",
        name: "Dr. Smith",
        verificationToken: "token_abc123",
      });

      assert.equal(result.success, true);
      assert.equal(result.mode, "console");
      assert.equal(
        result.targetUrl,
        "http://localhost:5173/verify-email?token=token_abc123"
      );
    });

    it("sendEmailVerificationEmail should dispatch email through mocked transporter with escaped HTML", async () => {
      process.env.EMAIL_SERVICE_MODE = "smtp";
      process.env.SMTP_USER = "test@gmail.com";
      process.env.SMTP_PASS = "mockpassword";

      let capturedOptions = null;
      setTransporterForTesting({
        sendMail: async (opts) => {
          capturedOptions = opts;
          return { messageId: "<verify-123@gmail.com>" };
        },
      });

      const result = await sendEmailVerificationEmail({
        to: "newuser@dau.ac.in",
        name: "<script>alert('xss')</script> John",
        verificationToken: "abcdef1234567890",
      });

      assert.equal(result.success, true);
      assert.equal(result.mode, "smtp");
      assert.equal(result.messageId, "<verify-123@gmail.com>");
      assert.ok(capturedOptions);
      assert.equal(capturedOptions.to, "newuser@dau.ac.in");
      assert.match(capturedOptions.subject, /Verify Your Email/);
      assert.match(capturedOptions.text, /abcdef1234567890/);
      // HTML escaping check: raw script tag should not be present
      assert.doesNotMatch(capturedOptions.html, /<script>alert/);
      assert.match(capturedOptions.html, /&lt;script&gt;/);
    });

    it("sendEmailVerificationEmail should safely handle SMTP delivery failure", async () => {
      process.env.EMAIL_SERVICE_MODE = "smtp";
      process.env.SMTP_USER = "test@gmail.com";
      process.env.SMTP_PASS = "mockpassword";

      setTransporterForTesting({
        sendMail: async () => {
          throw new Error("Connection timed out to SMTP host");
        },
      });

      const result = await sendEmailVerificationEmail({
        to: "user@dau.ac.in",
        name: "Test User",
        verificationToken: "mocktoken",
      });

      assert.equal(result.success, false);
      assert.equal(result.mode, "smtp");
      assert.match(result.error, /could not be delivered/);
    });
  });
});
