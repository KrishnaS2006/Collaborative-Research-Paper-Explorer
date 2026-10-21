


import test from "node:test";
import assert from "node:assert/strict";
import { createAuthorizeRoles } from "../middleware/authorize.js";

function mockResponse() {
  return {
    statusCode: 200,
    body: null,
    status(code) {
      this.statusCode = code;
      return this;
    },
    json(data) {
      this.body = data;
      return this;
    },
  };
}

async function runAuthorization({
  requestUser = { id: "test-user-1" },
  databaseUser = null,
  allowedRoles = [],
  databaseError = null,
} = {}) {
  const findUser = async () => {
    if (databaseError) throw databaseError;
    return databaseUser;
  };

  const authorizeRoles = createAuthorizeRoles(findUser);
  const req = requestUser ? { user: { ...requestUser } } : {};
  const res = mockResponse();
  let nextCalled = false;

  await authorizeRoles(...allowedRoles)(req, res, () => {
    nextCalled = true;
  });

  return { req, res, nextCalled };
}

test("FR-05 RBAC: SYSTEM_ADMIN can access admin routes", async () => {
  const { res, nextCalled } = await runAuthorization({
    databaseUser: { id: "test-user-1", role: "STUDENT", access_role: "SYSTEM_ADMIN" },
    allowedRoles: ["SYSTEM_ADMIN"],
  });
  assert.equal(nextCalled, true);
  assert.equal(res.statusCode, 200);
});

test("FR-05 RBAC: LAB_ANNOTATOR can access annotation routes", async () => {
  const { res, nextCalled } = await runAuthorization({
    databaseUser: { id: "test-user-1", role: "RESEARCHER", access_role: "LAB_ANNOTATOR" },
    allowedRoles: ["SYSTEM_ADMIN", "LAB_ANNOTATOR"],
  });
  assert.equal(nextCalled, true);
  assert.equal(res.statusCode, 200);
});

test("FR-05 RBAC: LAB_ANNOTATOR cannot access admin-only routes", async () => {
  const { res, nextCalled } = await runAuthorization({
    databaseUser: { id: "test-user-1", role: "RESEARCHER", access_role: "LAB_ANNOTATOR" },
    allowedRoles: ["SYSTEM_ADMIN"],
  });
  assert.equal(nextCalled, false);
  assert.equal(res.statusCode, 403);
});

test("FR-05 RBAC: READ_ONLY_VIEWER cannot access annotation routes", async () => {
  const { res, nextCalled } = await runAuthorization({
    databaseUser: { id: "test-user-1", role: "STUDENT", access_role: "READ_ONLY_VIEWER" },
    allowedRoles: ["SYSTEM_ADMIN", "LAB_ANNOTATOR"],
  });
  assert.equal(nextCalled, false);
  assert.equal(res.statusCode, 403);
});

test("FR-05 RBAC: missing user returns 401", async () => {
  const { res, nextCalled } = await runAuthorization({
    requestUser: null,
    allowedRoles: ["SYSTEM_ADMIN"],
  });
  assert.equal(nextCalled, false);
  assert.equal(res.statusCode, 401);
});

test("FR-05 RBAC: missing database access role returns 403", async () => {
  const { res, nextCalled } = await runAuthorization({
    databaseUser: { id: "test-user-1", role: "STUDENT" },
    allowedRoles: ["SYSTEM_ADMIN"],
  });
  assert.equal(nextCalled, false);
  assert.equal(res.statusCode, 403);
});

test("FR-05 RBAC: invalid database access role returns 403", async () => {
  const { res, nextCalled } = await runAuthorization({
    databaseUser: { id: "test-user-1", role: "STUDENT", access_role: "SUPERUSER" },
    allowedRoles: ["SYSTEM_ADMIN"],
  });
  assert.equal(nextCalled, false);
  assert.equal(res.statusCode, 403);
});

test("FR-05 RBAC: deleted database user returns 401", async () => {
  const { res, nextCalled } = await runAuthorization({
    databaseUser: null,
    allowedRoles: ["SYSTEM_ADMIN"],
  });
  assert.equal(nextCalled, false);
  assert.equal(res.statusCode, 401);
});

test("FR-05 RBAC: database lookup failure returns 500", async () => {
  const { res, nextCalled } = await runAuthorization({
    databaseError: new Error("Database unavailable"),
    allowedRoles: ["SYSTEM_ADMIN"],
  });
  assert.equal(nextCalled, false);
  assert.equal(res.statusCode, 500);
});

test("FR-05 RBAC: current database role overrides stale JWT role", async () => {
  const { req, res, nextCalled } = await runAuthorization({
    requestUser: { id: "test-user-1", access_role: "SYSTEM_ADMIN" },
    databaseUser: {
      id: "test-user-1",
      role: "STUDENT",
      access_role: "READ_ONLY_VIEWER",
    },
    allowedRoles: ["SYSTEM_ADMIN"],
  });
  assert.equal(nextCalled, false);
  assert.equal(res.statusCode, 403);
  assert.equal(req.user.access_role, "READ_ONLY_VIEWER");
});
