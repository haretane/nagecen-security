BEGIN;

ALTER TABLE scan_jobs ADD COLUMN active_scan_consent_at TIMESTAMPTZ;
ALTER TABLE scan_jobs ADD COLUMN data_change_risk_acknowledged_at TIMESTAMPTZ;

COMMIT;
