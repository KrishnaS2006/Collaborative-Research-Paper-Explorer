-- FR-05: Role-Based Access Control (RBAC)
-- Decommission obsolete parallel 'access_role' schema (LAB_ANNOTATOR, READ_ONLY_VIEWER)
-- and align completely with canonical roles: SYSTEM_ADMIN, RESEARCHER, STUDENT.

DO $$
BEGIN
    -- Drop obsolete index if present
    DROP INDEX IF EXISTS idx_users_access_role;

    -- Drop obsolete access_role column if present
    IF EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_name = 'users' AND column_name = 'access_role'
    ) THEN
        ALTER TABLE users DROP COLUMN access_role;
    END IF;

    -- Drop obsolete enum type if present
    IF EXISTS (SELECT 1 FROM pg_type WHERE typname = 'access_role') THEN
        DROP TYPE access_role;
    END IF;
END $$;
