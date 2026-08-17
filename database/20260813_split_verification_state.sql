BEGIN;

ALTER TABLE site_verifications RENAME TO verification_challenges;
ALTER INDEX site_verifications_target_host_idx RENAME TO verification_challenges_target_host_idx;
ALTER INDEX site_verifications_expires_at_idx RENAME TO verification_challenges_expires_at_idx;

CREATE TABLE verified_targets (
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

CREATE INDEX verified_targets_scope_idx
    ON verified_targets (verified_origin, verified_base_path, status);
CREATE INDEX verified_targets_product_idx
    ON verified_targets (nagecen_product_id);

ALTER TABLE scan_jobs RENAME COLUMN site_verification_id TO verification_challenge_id;
ALTER TABLE scan_jobs ALTER COLUMN verification_challenge_id DROP NOT NULL;
ALTER TABLE scan_jobs ADD COLUMN verified_target_id UUID REFERENCES verified_targets(id);

COMMIT;
