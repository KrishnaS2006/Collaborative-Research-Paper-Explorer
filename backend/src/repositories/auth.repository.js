import pool from "../config/database.js";

// ---------------------------------------------------------------------------
// NOTE: The email_verified column and email_verification_tokens table are
// confirmed present in the live database. The migration-guard caches have
// been removed because they silently suppressed token inserts when the server
// started before the migration had run, producing a broken verification flow.
// ---------------------------------------------------------------------------

export const findUserByEmail = async (email) => {
  const result = await pool.query(
    `SELECT id, email, password_hash, full_name, role,
            affiliation, research_interests, email_verified
     FROM users
     WHERE LOWER(email) = LOWER($1)`,
    [email]
  );
  return result.rows[0] ?? null;
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

// Invalidate previous, unused password-reset tokens for this user.
export const invalidateUnusedPasswordResetTokens = async (userId) => {
  await pool.query(
    `UPDATE password_reset_tokens
     SET used_at = CURRENT_TIMESTAMP
     WHERE user_id = $1
       AND used_at IS NULL`,
    [userId]
  );
};

// Save the hash of the reset token, never the raw token.
export const createPasswordResetToken = async ({
  userId,
  tokenHash,
  expiresAt,
}) => {
  const result = await pool.query(
    `INSERT INTO password_reset_tokens
       (user_id, token_hash, expires_at)
     VALUES ($1, $2, $3)
     RETURNING id, user_id, expires_at`,
    [userId, tokenHash, expiresAt]
  );

  return result.rows[0];
};

// Validate and consume the password-reset token, then update password in one transaction.
export const consumePasswordResetTokenAndUpdatePassword = async ({
  tokenHash,
  passwordHash,
}) => {
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

    await client.query("COMMIT");
    return { success: true };
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

export const createEmailVerificationToken = async ({
  userId,
  tokenHash,
  expiresAt,
}) => {
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

export const consumeEmailVerificationToken = async (tokenHash) => {
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
