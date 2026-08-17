BEGIN;

UPDATE scan_jobs
SET level_id = 'xss'
WHERE level_id = 'basic'
  AND enabled_rule_ids @> '["40012"]'::jsonb;

COMMIT;
