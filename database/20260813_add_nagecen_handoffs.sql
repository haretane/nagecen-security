BEGIN;

CREATE TABLE nagecen_handoffs (
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
CREATE INDEX nagecen_handoffs_product_idx ON nagecen_handoffs (product_id, created_at);

CREATE TABLE nagecen_handoff_sessions (
    id UUID PRIMARY KEY,
    handoff_id UUID NOT NULL REFERENCES nagecen_handoffs(id) ON DELETE CASCADE,
    session_token_hash CHAR(64) NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    CHECK (expires_at > created_at)
);
CREATE INDEX nagecen_handoff_sessions_handoff_idx ON nagecen_handoff_sessions (handoff_id, expires_at);

ALTER TABLE verified_targets ADD COLUMN nagecen_handoff_id UUID REFERENCES nagecen_handoffs(id);
ALTER TABLE verification_challenges ADD COLUMN nagecen_handoff_id UUID REFERENCES nagecen_handoffs(id);
ALTER TABLE scan_jobs ADD COLUMN nagecen_handoff_id UUID REFERENCES nagecen_handoffs(id);

CREATE TABLE nagecen_webhook_outbox (
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
CREATE INDEX nagecen_webhook_outbox_delivery_idx ON nagecen_webhook_outbox (status, next_attempt_at);

COMMIT;
