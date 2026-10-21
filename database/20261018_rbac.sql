-- FR-05: Role-Based Access Control (RBAC)

-- Keep system-level access roles separate from account types
-- such as STUDENT and RESEARCHER.
DO $$
BEGIN
    CREATE TYPE access_role AS ENUM (
        'SYSTEM_ADMIN',
        'LAB_ANNOTATOR',
        'READ_ONLY_VIEWER'
    );
EXCEPTION
    WHEN duplicate_object THEN NULL;
END
$$;

-- Apply least privilege by default.
-- Existing users will also receive READ_ONLY_VIEWER initially.
ALTER TABLE users
ADD COLUMN IF NOT EXISTS access_role access_role
NOT NULL DEFAULT 'READ_ONLY_VIEWER';

-- Index to support role-based user lookups.
CREATE INDEX IF NOT EXISTS idx_users_access_role
ON users (access_role);
