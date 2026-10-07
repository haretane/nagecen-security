CREATE TABLE IF NOT EXISTS verification_challenges (
    id UUID PRIMARY KEY,
    target_url TEXT NOT NULL,
    target_host TEXT NOT NULL,
    token_hash CHAR(64) NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    verified_at TIMESTAMPTZ,
    used_at TIMESTAMPTZ,
    last_error_code TEXT,
    confirmation_attempt_count INTEGER NOT NULL DEFAULT 0,
    last_confirmation_attempt_at TIMESTAMPTZ,
    CHECK (confirmation_attempt_count >= 0),
    CHECK (expires_at > created_at)
);

CREATE INDEX IF NOT EXISTS verification_challenges_target_host_idx
    ON verification_challenges (target_host);

CREATE INDEX IF NOT EXISTS verification_challenges_expires_at_idx
    ON verification_challenges (expires_at);

CREATE TABLE IF NOT EXISTS verified_targets (
    id UUID PRIMARY KEY,
    verification_challenge_id UUID UNIQUE REFERENCES verification_challenges(id),
    nagecen_product_id TEXT,
    verified_url TEXT NOT NULL,
    verified_origin TEXT NOT NULL,
    verified_base_path TEXT NOT NULL,
    source TEXT NOT NULL,
    method TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    verified_at TIMESTAMPTZ NOT NULL,
    valid_until TIMESTAMPTZ,
    last_revalidated_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    CHECK (source IN ('security', 'nagecen')),
    CHECK (method IN ('meta_tag', 'nagecen_assertion', 'meta_tag_recheck')),
    CHECK (status IN ('active', 'expired', 'revoked', 'superseded')),
    CHECK (verified_base_path LIKE '/%')
);

CREATE INDEX IF NOT EXISTS verified_targets_scope_idx
    ON verified_targets (verified_origin, verified_base_path, status);

CREATE INDEX IF NOT EXISTS verified_targets_product_idx
    ON verified_targets (nagecen_product_id);

CREATE TABLE IF NOT EXISTS scan_jobs (
    id UUID PRIMARY KEY,
    verification_challenge_id UUID REFERENCES verification_challenges(id),
    verified_target_id UUID NOT NULL REFERENCES verified_targets(id),
    level_id TEXT NOT NULL,
    status TEXT NOT NULL,
    target_url TEXT NOT NULL,
    target_host TEXT NOT NULL,
    target_origin TEXT NOT NULL,
    target_base_path TEXT NOT NULL,
    consent_confirmed_at TIMESTAMPTZ NOT NULL,
    active_scan_consent_at TIMESTAMPTZ,
    data_change_risk_acknowledged_at TIMESTAMPTZ,
    authentication_type TEXT NOT NULL DEFAULT 'none',
    authentication_status TEXT NOT NULL DEFAULT 'not_required',
    service_features JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at TIMESTAMPTZ NOT NULL,
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    heartbeat_at TIMESTAMPTZ,
    spider_type TEXT,
    crawled_url_count INTEGER NOT NULL DEFAULT 0,
    enabled_rule_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
    completed_check_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
    timed_out_steps JSONB NOT NULL DEFAULT '[]'::jsonb,
    failed_steps JSONB NOT NULL DEFAULT '[]'::jsonb,
    zap_exit_code INTEGER,
    alert_count INTEGER NOT NULL DEFAULT 0,
    report JSONB,
    error_code TEXT,
    error_message TEXT,
    CHECK (status IN ('queued', 'running', 'completed', 'failed', 'cancelled')),
    CHECK (authentication_type IN ('none', 'form', 'external', 'special')),
    CHECK (authentication_status IN ('not_required', 'not_attempted', 'succeeded', 'failed', 'unsupported')),
    CHECK (crawled_url_count >= 0),
    CHECK (alert_count >= 0)
);

CREATE INDEX IF NOT EXISTS scan_jobs_status_created_at_idx
    ON scan_jobs (status, created_at);

CREATE INDEX IF NOT EXISTS scan_jobs_verification_idx
    ON scan_jobs (verified_target_id);

CREATE TABLE IF NOT EXISTS nagecen_handoffs (
    id UUID PRIMARY KEY,
    jti UUID NOT NULL UNIQUE,
    version TEXT NOT NULL,
    intent TEXT NOT NULL,
    product_id TEXT NOT NULL,
    product_status TEXT NOT NULL,
    owner_subject TEXT NOT NULL,
    product_url TEXT NOT NULL,
    normalized_url TEXT NOT NULL,
    target_origin TEXT NOT NULL,
    target_base_path TEXT NOT NULL,
    return_context_type TEXT NOT NULL,
    return_context_id TEXT NOT NULL,
    request_key_id TEXT NOT NULL,
    request_timestamp BIGINT NOT NULL,
    request_body_sha256 CHAR(64) NOT NULL,
    handoff_token_hash CHAR(64) NOT NULL UNIQUE,
    handoff_token_expires_at TIMESTAMPTZ NOT NULL,
    handoff_token_used_at TIMESTAMPTZ,
    status TEXT NOT NULL DEFAULT 'created',
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CHECK (version = '1'),
    CHECK (intent IN ('verify_only', 'verify_and_scan')),
    CHECK (product_status IN ('draft', 'published')),
    CHECK (return_context_type IN ('product_draft', 'product_edit', 'mypage')),
    CHECK (status IN ('created', 'active', 'verification_completed', 'assessment_completed', 'failed', 'cancelled'))
);

CREATE INDEX IF NOT EXISTS nagecen_handoffs_product_idx
    ON nagecen_handoffs (product_id, created_at);

CREATE TABLE IF NOT EXISTS nagecen_handoff_sessions (
    id UUID PRIMARY KEY,
    handoff_id UUID NOT NULL REFERENCES nagecen_handoffs(id) ON DELETE CASCADE,
    session_token_hash CHAR(64) NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    CHECK (expires_at > created_at)
);

CREATE INDEX IF NOT EXISTS nagecen_handoff_sessions_handoff_idx
    ON nagecen_handoff_sessions (handoff_id, expires_at);

ALTER TABLE verified_targets
    ADD COLUMN IF NOT EXISTS nagecen_handoff_id UUID REFERENCES nagecen_handoffs(id);

ALTER TABLE verification_challenges
    ADD COLUMN IF NOT EXISTS nagecen_handoff_id UUID REFERENCES nagecen_handoffs(id);

ALTER TABLE scan_jobs
    ADD COLUMN IF NOT EXISTS nagecen_handoff_id UUID REFERENCES nagecen_handoffs(id);

CREATE TABLE IF NOT EXISTS nagecen_webhook_outbox (
    id UUID PRIMARY KEY,
    handoff_id UUID NOT NULL REFERENCES nagecen_handoffs(id),
    event_id UUID NOT NULL UNIQUE,
    event_type TEXT NOT NULL,
    payload JSONB NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    attempt_count INTEGER NOT NULL DEFAULT 0,
    next_attempt_at TIMESTAMPTZ NOT NULL,
    last_attempt_at TIMESTAMPTZ,
    delivered_at TIMESTAMPTZ,
    last_http_status INTEGER,
    last_error_code TEXT,
    created_at TIMESTAMPTZ NOT NULL,
    CHECK (status IN ('pending', 'delivered', 'delivery_failed')),
    CHECK (attempt_count >= 0)
);

CREATE INDEX IF NOT EXISTS nagecen_webhook_outbox_delivery_idx
    ON nagecen_webhook_outbox (status, next_attempt_at);

-- Independent account login. Existing product handoffs are not account sessions.
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

-- Apply after 20261004_add_security_account_login.sql. No ownership backfill.
ALTER TABLE verification_challenges
    ADD COLUMN IF NOT EXISTS account_id UUID REFERENCES security_accounts(id);
ALTER TABLE verified_targets
    ADD COLUMN IF NOT EXISTS account_id UUID REFERENCES security_accounts(id);
ALTER TABLE scan_jobs
    ADD COLUMN IF NOT EXISTS account_id UUID REFERENCES security_accounts(id);

CREATE INDEX IF NOT EXISTS verification_challenges_account_created_idx
    ON verification_challenges (account_id, created_at DESC);
CREATE INDEX IF NOT EXISTS verified_targets_account_created_idx
    ON verified_targets (account_id, created_at DESC);
CREATE INDEX IF NOT EXISTS scan_jobs_account_created_idx
    ON scan_jobs (account_id, created_at DESC);

-- Immutable ownership and consistent parent/child ownership, including NULL
-- legacy owners. Product handoff identities are never adopted as account IDs.
CREATE OR REPLACE FUNCTION security_assert_diagnostic_owner() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE parent_owner UUID;
BEGIN
    IF TG_OP = 'UPDATE' THEN
        IF NEW.account_id IS DISTINCT FROM OLD.account_id THEN
            RAISE EXCEPTION 'Diagnostic ownership cannot be reassigned'
                USING ERRCODE = '23514';
        END IF;
    END IF;
    IF NEW.account_id IS NOT NULL AND NEW.nagecen_handoff_id IS NOT NULL THEN
        RAISE EXCEPTION 'Account diagnostics are independent of product handoffs'
            USING ERRCODE = '23514';
    END IF;
    IF TG_TABLE_NAME = 'verified_targets' THEN
        IF NEW.account_id IS NOT NULL AND NEW.verification_challenge_id IS NULL THEN
            RAISE EXCEPTION 'Account targets require a verification challenge'
                USING ERRCODE = '23514';
        END IF;
        IF NEW.verification_challenge_id IS NOT NULL THEN
            SELECT account_id INTO parent_owner FROM verification_challenges
                WHERE id = NEW.verification_challenge_id;
            IF NEW.account_id IS DISTINCT FROM parent_owner THEN
                RAISE EXCEPTION 'Verification ownership must match'
                    USING ERRCODE = '23514';
            END IF;
        END IF;
    ELSIF TG_TABLE_NAME = 'scan_jobs' THEN
        SELECT account_id INTO parent_owner FROM verified_targets
            WHERE id = NEW.verified_target_id;
        IF NEW.account_id IS DISTINCT FROM parent_owner THEN
            RAISE EXCEPTION 'Scan ownership must match'
                USING ERRCODE = '23514';
        END IF;
        IF NEW.verification_challenge_id IS NOT NULL THEN
            SELECT account_id INTO parent_owner FROM verification_challenges
                WHERE id = NEW.verification_challenge_id;
            IF NEW.account_id IS DISTINCT FROM parent_owner THEN
                RAISE EXCEPTION 'Scan challenge ownership must match'
                    USING ERRCODE = '23514';
            END IF;
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS security_challenge_owner_guard ON verification_challenges;
CREATE TRIGGER security_challenge_owner_guard
    BEFORE INSERT OR UPDATE ON verification_challenges
    FOR EACH ROW EXECUTE FUNCTION security_assert_diagnostic_owner();
DROP TRIGGER IF EXISTS security_target_owner_guard ON verified_targets;
CREATE TRIGGER security_target_owner_guard
    BEFORE INSERT OR UPDATE ON verified_targets
    FOR EACH ROW EXECUTE FUNCTION security_assert_diagnostic_owner();
DROP TRIGGER IF EXISTS security_scan_owner_guard ON scan_jobs;
CREATE TRIGGER security_scan_owner_guard
    BEFORE INSERT OR UPDATE ON scan_jobs
    FOR EACH ROW EXECUTE FUNCTION security_assert_diagnostic_owner();
