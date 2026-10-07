-- Additive only. Do not replace the existing DB or change product handoffs.
BEGIN;

CREATE TABLE IF NOT EXISTS security_accounts (
    id UUID PRIMARY KEY,
    issuer TEXT NOT NULL,
    subject UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    last_login_at TIMESTAMPTZ NOT NULL,
    disabled_at TIMESTAMPTZ,
    UNIQUE (issuer, subject),
    CHECK (substring(subject::text FROM 15 FOR 1) = '4')
);

CREATE TABLE IF NOT EXISTS security_login_attempts (
    id UUID PRIMARY KEY,
    state_hash CHAR(64) NOT NULL UNIQUE,
    browser_token_hash CHAR(64) NOT NULL,
    pkce_challenge CHAR(43) NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    last_error_code TEXT,
    CHECK (status IN ('pending', 'exchanging', 'completed', 'failed', 'cancelled')),
    CHECK (expires_at > created_at)
);
CREATE INDEX IF NOT EXISTS security_login_attempts_browser_idx
    ON security_login_attempts (browser_token_hash);
CREATE INDEX IF NOT EXISTS security_login_attempts_expiry_idx
    ON security_login_attempts (expires_at);

CREATE TABLE IF NOT EXISTS security_account_sessions (
    id UUID PRIMARY KEY,
    account_id UUID NOT NULL REFERENCES security_accounts(id),
    login_id UUID NOT NULL UNIQUE,
    token_hash CHAR(64) NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    CHECK (expires_at = created_at + INTERVAL '8 hours'),
    CHECK (last_seen_at >= created_at)
);
CREATE INDEX IF NOT EXISTS security_account_sessions_account_idx
    ON security_account_sessions (account_id);
CREATE INDEX IF NOT EXISTS security_account_sessions_expiry_idx
    ON security_account_sessions (expires_at);

CREATE TABLE IF NOT EXISTS security_login_rate_limits (
    bucket_key CHAR(64) NOT NULL,
    bucket_start TIMESTAMPTZ NOT NULL,
    request_count INTEGER NOT NULL,
    PRIMARY KEY (bucket_key, bucket_start),
    CHECK (request_count > 0)
);

COMMIT;
