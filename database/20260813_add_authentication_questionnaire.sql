BEGIN;

ALTER TABLE scan_jobs
    ADD COLUMN authentication_type TEXT NOT NULL DEFAULT 'none',
    ADD COLUMN authentication_status TEXT NOT NULL DEFAULT 'not_required';

ALTER TABLE scan_jobs
    ADD CONSTRAINT scan_jobs_authentication_type_check
        CHECK (authentication_type IN ('none', 'form', 'external', 'special')),
    ADD CONSTRAINT scan_jobs_authentication_status_check
        CHECK (authentication_status IN ('not_required', 'not_attempted', 'succeeded', 'failed', 'unsupported'));

COMMIT;
