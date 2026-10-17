-- This is a non-destructive migration script used when we are updating an existing database with existing tables


ALTER TABLE users ADD COLUMN IF NOT EXISTS research_interests TEXT[] NOT NULL DEFAULT '{}';
CREATE INDEX IF NOT EXISTS idx_users_research_interests ON users USING GIN (research_interests);

DO $$
BEGIN
    ALTER TYPE user_role ADD VALUE IF NOT EXISTS 'SYSTEM_ADMIN';
    ALTER TYPE user_role ADD VALUE IF NOT EXISTS 'RESEARCHER';
    ALTER TYPE user_role ADD VALUE IF NOT EXISTS 'STUDENT';
EXCEPTION
    WHEN duplicate_object THEN NULL;
END $$;

ALTER TABLE users ALTER COLUMN role SET DEFAULT 'STUDENT';