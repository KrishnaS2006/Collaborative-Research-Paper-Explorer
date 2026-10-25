import test from "node:test";
import assert from "node:assert/strict";
import { createAuthorizeRoles } from "../middleware/authorize.js";
import { ROLES } from "../utils/roles.js";

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
  requestUser = { id: "test-user-1", role: "STUDENT" },
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
    databaseUser: { id: "test-user-1", role: ROLES.SYSTEM_ADMIN },
    allowedRoles: [ROLES.SYSTEM_ADMIN],
  });
  assert.equal(nextCalled, true);
  assert.equal(res.statusCode, 200);
});

test("FR-05 RBAC: RESEARCHER can access researcher routes", async () => {
  const { res, nextCalled } = await runAuthorization({
    databaseUser: { id: "test-user-1", role: ROLES.RESEARCHER },
    allowedRoles: [ROLES.SYSTEM_ADMIN, ROLES.RESEARCHER],
  });
  assert.equal(nextCalled, true);
  assert.equal(res.statusCode, 200);
});

test("FR-05 RBAC: RESEARCHER cannot access admin-only routes", async () => {
  const { res, nextCalled } = await runAuthorization({
    databaseUser: { id: "test-user-1", role: ROLES.RESEARCHER },
    allowedRoles: [ROLES.SYSTEM_ADMIN],
  });
  assert.equal(nextCalled, false);
  assert.equal(res.statusCode, 403);
});

test("FR-05 RBAC: STUDENT cannot access researcher-only routes", async () => {
  const { res, nextCalled } = await runAuthorization({
    databaseUser: { id: "test-user-1", role: ROLES.STUDENT },
    allowedRoles: [ROLES.SYSTEM_ADMIN, ROLES.RESEARCHER],
  });
  assert.equal(nextCalled, false);
  assert.equal(res.statusCode, 403);
});

test("FR-05 RBAC: STUDENT can access student routes", async () => {
  const { res, nextCalled } = await runAuthorization({
    databaseUser: { id: "test-user-1", role: ROLES.STUDENT },
    allowedRoles: [ROLES.STUDENT, ROLES.RESEARCHER, ROLES.SYSTEM_ADMIN],
  });
  assert.equal(nextCalled, true);
  assert.equal(res.statusCode, 200);
});

test("FR-05 RBAC: missing user returns 401", async () => {
  const { res, nextCalled } = await runAuthorization({
    requestUser: null,
    allowedRoles: [ROLES.SYSTEM_ADMIN],
  });
  assert.equal(nextCalled, false);
  assert.equal(res.statusCode, 401);
});

test("FR-05 RBAC: missing database role returns 403", async () => {
  const { res, nextCalled } = await runAuthorization({
    databaseUser: { id: "test-user-1", role: null },
    allowedRoles: [ROLES.SYSTEM_ADMIN],
  });
  assert.equal(nextCalled, false);
  assert.equal(res.statusCode, 403);
});

test("FR-05 RBAC: invalid database role returns 403", async () => {
  const { res, nextCalled } = await runAuthorization({
    databaseUser: { id: "test-user-1", role: "SUPERUSER" },
    allowedRoles: [ROLES.SYSTEM_ADMIN],
  });
  assert.equal(nextCalled, false);
  assert.equal(res.statusCode, 403);
});

test("FR-05 RBAC: obsolete role LAB_ANNOTATOR returns 403", async () => {
  const { res, nextCalled } = await runAuthorization({
    databaseUser: { id: "test-user-1", role: "LAB_ANNOTATOR" },
    allowedRoles: [ROLES.SYSTEM_ADMIN, ROLES.RESEARCHER],
  });
  assert.equal(nextCalled, false);
  assert.equal(res.statusCode, 403);
});

test("FR-05 RBAC: obsolete role READ_ONLY_VIEWER returns 403", async () => {
  const { res, nextCalled } = await runAuthorization({
    databaseUser: { id: "test-user-1", role: "READ_ONLY_VIEWER" },
    allowedRoles: [ROLES.STUDENT, ROLES.RESEARCHER],
  });
  assert.equal(nextCalled, false);
  assert.equal(res.statusCode, 403);
});

test("FR-05 RBAC: deleted database user returns 401", async () => {
  const { res, nextCalled } = await runAuthorization({
    databaseUser: null,
    allowedRoles: [ROLES.SYSTEM_ADMIN],
  });
  assert.equal(nextCalled, false);
  assert.equal(res.statusCode, 401);
});

test("FR-05 RBAC: database lookup failure returns 500", async () => {
  const { res, nextCalled } = await runAuthorization({
    databaseError: new Error("Database unavailable"),
    allowedRoles: [ROLES.SYSTEM_ADMIN],
  });
  assert.equal(nextCalled, false);
  assert.equal(res.statusCode, 500);
});

test("FR-05 RBAC: current database role overrides stale JWT role", async () => {
  const { req, res, nextCalled } = await runAuthorization({
    requestUser: { id: "test-user-1", role: ROLES.SYSTEM_ADMIN },
    databaseUser: {
      id: "test-user-1",
      role: ROLES.STUDENT,
    },
    allowedRoles: [ROLES.SYSTEM_ADMIN],
  });
  assert.equal(nextCalled, false);
  assert.equal(res.statusCode, 403);
  assert.equal(req.user.role, ROLES.STUDENT);
});
