CREATE TABLE IF NOT EXISTS site_verifications (
    id UUID PRIMARY KEY,
    target_url TEXT NOT NULL,
    target_host TEXT NOT NULL,
    token_hash CHAR(64) NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    verified_at TIMESTAMPTZ,
    used_at TIMESTAMPTZ,
    last_error_code TEXT,
    CHECK (expires_at > created_at)
);

CREATE INDEX IF NOT EXISTS site_verifications_target_host_idx
    ON site_verifications (target_host);

CREATE INDEX IF NOT EXISTS site_verifications_expires_at_idx
    ON site_verifications (expires_at);

