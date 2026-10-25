import pool from "../config/database.js";

// ---------------------------------------------------------------------------
// NOTE: The email_verified column and email_verification_tokens table are
// confirmed present in the live database. The migration-guard caches have
// been removed because they silently suppressed token inserts when the server
// started before the migration had run, producing a broken verification flow.
// ---------------------------------------------------------------------------

let testFindUserByEmailHandler = null;

export const _setFindUserByEmailForTesting = (fn) => {
  testFindUserByEmailHandler = fn;
};

export const _resetFindUserByEmailForTesting = () => {
  testFindUserByEmailHandler = null;
};

export const findUserByEmail = async (email) => {
  if (testFindUserByEmailHandler) {
    return testFindUserByEmailHandler(email);
  }

  const result = await pool.query(
    `SELECT id, email, password_hash, full_name, role,
       affiliation, research_interests, email_verified
     FROM users
     WHERE LOWER(email) = LOWER($1)`,
    [email]
  );
  return result.rows[0] ?? null;
};

let testCreateUserHandler = null;

export const _setCreateUserForTesting = (fn) => {
  testCreateUserHandler = fn;
};

export const _resetCreateUserForTesting = () => {
  testCreateUserHandler = null;
};

export const createUser = async ({
  email,
  passwordHash,
  fullName,
  role,
  affiliation,
  researchInterests = [],
  emailVerified = false,
}) => {
  if (testCreateUserHandler) {
    return testCreateUserHandler({
      email,
      passwordHash,
      fullName,
      role,
      affiliation,
      researchInterests,
      emailVerified,
    });
  }

  const result = await pool.query(
    `INSERT INTO users (
       email, password_hash, full_name, role,
       affiliation, research_interests, email_verified
     )
     VALUES ($1, $2, $3, $4, $5, $6, $7)
     RETURNING id, email, full_name, role,
          affiliation, research_interests, email_verified`,
    [
      email,
      passwordHash,
      fullName,
      role,
      affiliation,
      researchInterests,
      emailVerified,
    ]
  );
  return result.rows[0];
};

export const findUserById = async (id) => {
  const result = await pool.query(
    `SELECT id, email, full_name, role,
       affiliation, research_interests, email_verified
     FROM users
     WHERE id = $1`,
    [id]
  );
  return result.rows[0] ?? null;
};

let testInvalidateResetTokensHandler = null;
export const _setInvalidateResetTokensForTesting = (fn) => {
  testInvalidateResetTokensHandler = fn;
};
export const _resetInvalidateResetTokensForTesting = () => {
  testInvalidateResetTokensHandler = null;
};

// Invalidate previous, unused password-reset tokens for this user.
export const invalidateUnusedPasswordResetTokens = async (userId) => {
  if (testInvalidateResetTokensHandler) {
    return testInvalidateResetTokensHandler(userId);
  }

  await pool.query(
    `UPDATE password_reset_tokens
     SET used_at = CURRENT_TIMESTAMP
     WHERE user_id = $1
       AND used_at IS NULL`,
    [userId]
  );
};

let testCreateResetTokenHandler = null;
export const _setCreatePasswordResetTokenForTesting = (fn) => {
  testCreateResetTokenHandler = fn;
};
export const _resetCreatePasswordResetTokenForTesting = () => {
  testCreateResetTokenHandler = null;
};

// Save the hash of the reset token, never the raw token.
export const createPasswordResetToken = async ({
  userId,
  tokenHash,
  expiresAt,
}) => {
  if (testCreateResetTokenHandler) {
    return testCreateResetTokenHandler({ userId, tokenHash, expiresAt });
  }

  const result = await pool.query(
    `INSERT INTO password_reset_tokens
       (user_id, token_hash, expires_at)
     VALUES ($1, $2, $3)
     RETURNING id, user_id, expires_at`,
    [userId, tokenHash, expiresAt]
  );

  return result.rows[0];
};

let testConsumeHandler = null;

export const _setConsumePasswordResetTokenForTesting = (fn) => {
  testConsumeHandler = fn;
};

export const _resetConsumePasswordResetTokenForTesting = () => {
  testConsumeHandler = null;
};

// Validate and consume the password-reset token, then update password in one transaction.
export const consumePasswordResetTokenAndUpdatePassword = async ({
  tokenHash,
  passwordHash,
}) => {
  if (testConsumeHandler) {
    return testConsumeHandler({ tokenHash, passwordHash });
  }

  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    const tokenResult = await client.query(
      `SELECT id, user_id, expires_at, used_at
       FROM password_reset_tokens
       WHERE token_hash = $1
       FOR UPDATE`,
      [tokenHash]
    );

    if (tokenResult.rows.length === 0) {
      await client.query("ROLLBACK");
      return { success: false, reason: "invalid" };
    }

    const resetToken = tokenResult.rows[0];

    if (resetToken.used_at) {
      await client.query("ROLLBACK");
      return { success: false, reason: "already_used" };
    }

    if (new Date(resetToken.expires_at) <= new Date()) {
      await client.query("ROLLBACK");
      return { success: false, reason: "expired" };
    }

    const consumeResult = await client.query(
      `UPDATE password_reset_tokens
       SET used_at = CURRENT_TIMESTAMP
       WHERE id = $1
         AND used_at IS NULL
       RETURNING id`,
      [resetToken.id]
    );

    if (consumeResult.rows.length === 0) {
      await client.query("ROLLBACK");
      return { success: false, reason: "already_used" };
    }

    const passwordResult = await client.query(
      `UPDATE users
       SET password_hash = $1,
           updated_at = CURRENT_TIMESTAMP
       WHERE id = $2
       RETURNING id`,
      [passwordHash, resetToken.user_id]
    );

    if (passwordResult.rows.length === 0) {
      await client.query("ROLLBACK");
      return { success: false, reason: "invalid" };
    }

    // Revoke all active sessions for this user in the same database transaction
    await client.query(
      `UPDATE user_sessions
       SET revoked_at = CURRENT_TIMESTAMP
       WHERE user_id = $1 AND revoked_at IS NULL`,
      [resetToken.user_id]
    );

    await client.query("COMMIT");
    return { success: true, userId: resetToken.user_id };
  } catch (error) {
    try {
      await client.query("ROLLBACK");
    } catch (rollbackError) {
      console.error("Password reset rollback failed:", rollbackError.message);
    }

    throw error;
  } finally {
    client.release();
  }
};

/* ==============================================================================
 * EMAIL VERIFICATION REPOSITORY METHODS
 * ============================================================================== */

let testCreateEmailVerificationTokenHandler = null;

export const _setCreateEmailVerificationTokenForTesting = (fn) => {
  testCreateEmailVerificationTokenHandler = fn;
};

export const _resetCreateEmailVerificationTokenForTesting = () => {
  testCreateEmailVerificationTokenHandler = null;
};

export const createEmailVerificationToken = async ({
  userId,
  tokenHash,
  expiresAt,
}) => {
  if (testCreateEmailVerificationTokenHandler) {
    return testCreateEmailVerificationTokenHandler({
      userId,
      tokenHash,
      expiresAt,
    });
  }

  const result = await pool.query(
    `INSERT INTO email_verification_tokens
       (user_id, token_hash, expires_at)
     VALUES ($1, $2, $3)
     RETURNING id, user_id, expires_at`,
    [userId, tokenHash, expiresAt]
  );

  return result.rows[0];
};

export const invalidateUnusedEmailVerificationTokens = async (userId) => {
  await pool.query(
    `UPDATE email_verification_tokens
     SET used_at = CURRENT_TIMESTAMP
     WHERE user_id = $1
       AND used_at IS NULL`,
    [userId]
  );
};

let testConsumeEmailVerificationTokenHandler = null;

export const _setConsumeEmailVerificationTokenForTesting = (fn) => {
  testConsumeEmailVerificationTokenHandler = fn;
};

export const _resetConsumeEmailVerificationTokenForTesting = () => {
  testConsumeEmailVerificationTokenHandler = null;
};

export const consumeEmailVerificationToken = async (tokenHash) => {
  if (testConsumeEmailVerificationTokenHandler) {
    return testConsumeEmailVerificationTokenHandler(tokenHash);
  }

  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    const tokenResult = await client.query(
      `SELECT id, user_id, expires_at, used_at
       FROM email_verification_tokens
       WHERE token_hash = $1
       FOR UPDATE`,
      [tokenHash]
    );

    if (tokenResult.rows.length === 0) {
      await client.query("ROLLBACK");
      return { success: false, reason: "not_found" };
    }

    const tokenRecord = tokenResult.rows[0];

    if (tokenRecord.used_at) {
      await client.query("ROLLBACK");
      return { success: false, reason: "already_used" };
    }

    if (new Date(tokenRecord.expires_at) <= new Date()) {
      await client.query("ROLLBACK");
      return { success: false, reason: "expired" };
    }

    const updateTokenResult = await client.query(
      `UPDATE email_verification_tokens
       SET used_at = CURRENT_TIMESTAMP
       WHERE id = $1
         AND used_at IS NULL
       RETURNING id`,
      [tokenRecord.id]
    );

    if (updateTokenResult.rows.length === 0) {
      await client.query("ROLLBACK");
      return { success: false, reason: "already_used" };
    }

    const userResult = await client.query(
      `UPDATE users
       SET email_verified = TRUE,
           updated_at = CURRENT_TIMESTAMP
       WHERE id = $1
       RETURNING id, email, full_name, role, affiliation, research_interests, email_verified`,
      [tokenRecord.user_id]
    );

    if (userResult.rows.length === 0) {
      await client.query("ROLLBACK");
      return { success: false, reason: "user_not_found" };
    }

    await client.query("COMMIT");
    return { success: true, user: userResult.rows[0] };
  } catch (error) {
    try {
      await client.query("ROLLBACK");
    } catch (rollbackError) {
      console.error(
        "Email verification rollback failed:",
        rollbackError.message
      );
    }
    throw error;
  } finally {
    client.release();
  }
};

/* ==============================================================================
 * SSO IDENTITIES REPOSITORY METHODS
 * ============================================================================== */

export const findSsoIdentity = async (provider, providerSubjectId) => {
  const result = await pool.query(
    `SELECT id, user_id, provider, provider_subject_id, email, created_at
     FROM sso_identities
     WHERE provider = $1 AND provider_subject_id = $2`,
    [provider, providerSubjectId]
  );

  return result.rows[0] ?? null;
};

export const findSsoIdentitiesByUserId = async (userId) => {
  const result = await pool.query(
    `SELECT id, user_id, provider, provider_subject_id, email, created_at
     FROM sso_identities
     WHERE user_id = $1`,
    [userId]
  );

  return result.rows;
};

export const linkSsoIdentityToUser = async ({
  userId,
  provider,
  providerSubjectId,
  email,
}) => {
  const result = await pool.query(
    `INSERT INTO sso_identities
       (user_id, provider, provider_subject_id, email)
     VALUES ($1, $2, $3, $4)
     ON CONFLICT (provider, provider_subject_id) DO UPDATE
       SET updated_at = CURRENT_TIMESTAMP
     RETURNING id, user_id, provider, provider_subject_id, email`,
    [userId, provider, providerSubjectId, email]
  );

  return result.rows[0];
};

export const createSsoUserWithIdentity = async ({
  email,
  fullName,
  role = "STUDENT",
  affiliation = null,
  researchInterests = [],
  provider,
  providerSubjectId,
  passwordHash,
}) => {
  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    const userRes = await client.query(
      `INSERT INTO users (
         email, password_hash, full_name, role,
         affiliation, research_interests, email_verified
       )
       VALUES ($1, $2, $3, $4, $5, $6, TRUE)
       RETURNING id, email, full_name, role,
          affiliation, research_interests, email_verified`,
      [
        email,
        passwordHash,
        fullName,
        role,
        affiliation,
        researchInterests,
      ]
    );
    const user = userRes.rows[0];

    await client.query(
      `INSERT INTO sso_identities
         (user_id, provider, provider_subject_id, email)
       VALUES ($1, $2, $3, $4)`,
      [user.id, provider, providerSubjectId, email]
    );

    await client.query("COMMIT");
    return user;
  } catch (error) {
    try {
      await client.query("ROLLBACK");
    } catch (rollbackError) {
      console.error("SSO user creation rollback failed:", rollbackError.message);
    }
    throw error;
  } finally {
    client.release();
  }
};

// ---------------------------------------------------------------------------
// Kept for backward compatibility with existing tests that mock these.
// These are now no-ops — the caches they controlled have been removed.
// ---------------------------------------------------------------------------
export const checkEmailVerifiedColumn = async () => true;
export const checkVerificationTokensTable = async () => true;
export const checkSsoIdentitiesTable = async () => true;
export const _setHasEmailVerifiedColumnCache = () => {};
export const _setHasVerificationTokensTableCache = () => {};
export const _setHasSsoIdentitiesTableCache = () => {};

/* ==============================================================================
 * FR-04: USER SESSIONS & TOKEN REVOCATION REPOSITORY METHODS
 * ============================================================================== */

export const createUserSession = async ({
  userId,
  tokenHash,
  expiresAt,
  lastActiveAt = new Date(),
  userAgent = null,
  ipAddress = null,
}) => {
  const result = await pool.query(
    `INSERT INTO user_sessions
       (user_id, token_hash, expires_at, last_active_at, user_agent, ip_address)
     VALUES ($1, $2, $3, $4, $5, $6)
     RETURNING id, user_id, token_hash, created_at, last_active_at, expires_at, revoked_at`,
    [userId, tokenHash, expiresAt, lastActiveAt, userAgent, ipAddress]
  );
  return result.rows[0];
};

export const findUserSessionByTokenHash = async (tokenHash) => {
  const result = await pool.query(
    `SELECT id, user_id, token_hash, created_at, last_active_at, expires_at, revoked_at
     FROM user_sessions
     WHERE token_hash = $1`,
    [tokenHash]
  );
  return result.rows[0] ?? null;
};

export const updateUserSessionActivity = async (
  tokenHash,
  lastActiveAt = new Date()
) => {
  const result = await pool.query(
    `UPDATE user_sessions
     SET last_active_at = $2
     WHERE token_hash = $1 AND revoked_at IS NULL
     RETURNING id, user_id, token_hash, last_active_at`,
    [tokenHash, lastActiveAt]
  );
  return result.rows[0] ?? null;
};

export const revokeUserSession = async (tokenHash) => {
  const result = await pool.query(
    `UPDATE user_sessions
     SET revoked_at = CURRENT_TIMESTAMP
     WHERE token_hash = $1 AND revoked_at IS NULL
     RETURNING id, user_id, token_hash, revoked_at`,
    [tokenHash]
  );
  return result.rows[0] ?? null;
};

export const revokeAllUserSessions = async (userId) => {
  const result = await pool.query(
    `UPDATE user_sessions
     SET revoked_at = CURRENT_TIMESTAMP
     WHERE user_id = $1 AND revoked_at IS NULL
     RETURNING id`,
    [userId]
  );
  return result.rowCount;
};

/* ==============================================================================
 * ROLE & USER ADMINISTRATION REPOSITORY METHODS
 * ============================================================================== */

export const updateUserRole = async (userId, role) => {
  const result = await pool.query(
    `UPDATE users
     SET role = $1,
         updated_at = CURRENT_TIMESTAMP
     WHERE id = $2
     RETURNING id, email, full_name, role, affiliation, research_interests, email_verified, updated_at`,
    [role, userId]
  );
  return result.rows[0] ?? null;
};

let testUpdateUserProfileHandler = null;

export const _setUpdateUserProfileForTesting = (fn) => {
  testUpdateUserProfileHandler = fn;
};

export const _resetUpdateUserProfileForTesting = () => {
  testUpdateUserProfileHandler = null;
};

export const updateUserProfile = async ({
  userId,
  fullName,
  affiliation,
  researchInterests,
}) => {
  if (testUpdateUserProfileHandler) {
    return testUpdateUserProfileHandler({
      userId,
      fullName,
      affiliation,
      researchInterests,
    });
  }

  const fields = [];
  const params = [];

  if (fullName !== undefined) {
    params.push(fullName);
    fields.push(`full_name = ${params.length}`);
  }
  if (affiliation !== undefined) {
    params.push(affiliation);
    fields.push(`affiliation = ${params.length}`);
  }
  if (researchInterests !== undefined) {
    params.push(researchInterests);
    fields.push(`research_interests = ${params.length}`);
  }

  if (fields.length === 0) {
    return findUserById(userId);
  }

  fields.push('updated_at = CURRENT_TIMESTAMP');
  params.push(userId);

  const query = `
    UPDATE users
    SET ${fields.join(', ')}
    WHERE id = ${params.length}
    RETURNING id, email, full_name, role, affiliation, research_interests, email_verified, updated_at
  `;

  const result = await pool.query(query, params);
  return result.rows[0] ?? null;
};

export const findAllUsers = async ({ limit = 50, offset = 0, role = null } = {}) => {
  let query = `
    SELECT id, email, full_name, role, affiliation, research_interests, email_verified, created_at
    FROM users
  `;
  const params = [];

  if (role) {
    params.push(role);
    query += ` WHERE role = $${params.length}`;
  }

  params.push(limit);
  query += ` ORDER BY created_at DESC LIMIT $${params.length}`;

  params.push(offset);
  query += ` OFFSET $${params.length}`;

  const result = await pool.query(query, params);
  return result.rows;
};


