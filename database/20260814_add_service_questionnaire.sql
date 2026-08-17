BEGIN;

ALTER TABLE scan_jobs
    ADD COLUMN IF NOT EXISTS service_features JSONB NOT NULL DEFAULT '[]'::jsonb;

COMMIT;
