BEGIN;

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

COMMIT;
