BEGIN;

ALTER TABLE scan_jobs ADD COLUMN target_origin TEXT;
ALTER TABLE scan_jobs ADD COLUMN target_base_path TEXT;

UPDATE scan_jobs j
SET target_origin = v.verified_origin,
    target_base_path = v.verified_base_path
FROM verified_targets v
WHERE v.id = j.verified_target_id;

ALTER TABLE scan_jobs ALTER COLUMN target_origin SET NOT NULL;
ALTER TABLE scan_jobs ALTER COLUMN target_base_path SET NOT NULL;
ALTER TABLE scan_jobs ALTER COLUMN verified_target_id SET NOT NULL;

COMMIT;
