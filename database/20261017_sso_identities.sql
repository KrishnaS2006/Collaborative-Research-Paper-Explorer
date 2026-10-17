-- ==============================================================================
-- FR-02: Institutional Single Sign-On (SSO) Identities Mapping Table
-- Target: PostgreSQL 15+
-- ==============================================================================

CREATE TABLE IF NOT EXISTS sso_identities (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id             UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider            VARCHAR(50) NOT NULL,
    provider_subject_id VARCHAR(255) NOT NULL,
    email               VARCHAR(255),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT uq_sso_provider_subject UNIQUE (provider, provider_subject_id)
);

CREATE INDEX IF NOT EXISTS idx_sso_identities_user_id ON sso_identities (user_id);
CREATE INDEX IF NOT EXISTS idx_sso_identities_provider_email ON sso_identities (provider, LOWER(email));
