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
