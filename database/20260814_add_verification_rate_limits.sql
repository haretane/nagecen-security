BEGIN;

ALTER TABLE verification_challenges
    ADD COLUMN IF NOT EXISTS confirmation_attempt_count INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS last_confirmation_attempt_at TIMESTAMPTZ;

COMMIT;
