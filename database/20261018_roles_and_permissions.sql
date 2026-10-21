-- ==============================================================================
-- Align user_role ENUM to accept both 'SYSTEM_ADMIN' and 'SYSTEM ADMIN'
-- Target: PostgreSQL 15+
-- ==============================================================================

DO $$
BEGIN
    ALTER TYPE user_role ADD VALUE IF NOT EXISTS 'SYSTEM ADMIN';
EXCEPTION
    WHEN duplicate_object THEN NULL;
END $$;
