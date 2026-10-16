import pool from "../config/database.js";

export const findUserByEmail = async (email) => {
  const result = await pool.query(
    `SELECT id, email, password_hash, full_name, role
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
}) => {
  const result = await pool.query(
    `INSERT INTO users (email, password_hash, full_name, role)
     VALUES ($1, $2, $3, $4)
     RETURNING id, email, full_name, role`,
    [email, passwordHash, fullName, role]
  );

  return result.rows[0];
};

export const findUserById = async (id) => {
  const result = await pool.query(
    `SELECT id, email, full_name, role
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

// Validate and consume the token, then update the password atomically.
export const consumePasswordResetTokenAndUpdatePassword = async ({
  tokenHash,
  passwordHash,
}) => {
  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    const tokenResult = await client.query(
      `SELECT id, user_id
       FROM password_reset_tokens
       WHERE token_hash = $1
         AND used_at IS NULL
         AND expires_at > CURRENT_TIMESTAMP
       FOR UPDATE`,
      [tokenHash]
    );

    if (tokenResult.rows.length === 0) {
      await client.query("ROLLBACK");
      return false;
    }

    const resetToken = tokenResult.rows[0];

    // Mark the token as used.
    const consumeResult = await client.query(
      `UPDATE password_reset_tokens
       SET used_at = CURRENT_TIMESTAMP
       WHERE id = $1
         AND used_at IS NULL
         AND expires_at > CURRENT_TIMESTAMP
       RETURNING id`,
      [resetToken.id]
    );

    if (consumeResult.rows.length === 0) {
      await client.query("ROLLBACK");
      return false;
    }

    // Update the user's password.
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
      return false;
    }

    await client.query("COMMIT");
    return true;
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
