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

CREATE TABLE IF NOT EXISTS scan_jobs (
    id UUID PRIMARY KEY,
    site_verification_id UUID NOT NULL REFERENCES site_verifications(id),
    level_id TEXT NOT NULL,
    status TEXT NOT NULL,
    target_url TEXT NOT NULL,
    target_host TEXT NOT NULL,
    consent_confirmed_at TIMESTAMPTZ NOT NULL,
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
    CHECK (crawled_url_count >= 0),
    CHECK (alert_count >= 0)
);

CREATE INDEX IF NOT EXISTS scan_jobs_status_created_at_idx
    ON scan_jobs (status, created_at);

CREATE INDEX IF NOT EXISTS scan_jobs_verification_idx
    ON scan_jobs (site_verification_id);
