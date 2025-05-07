DROP INDEX IF EXISTS idx_audit_logs_hash;

DROP INDEX IF EXISTS idx_audit_logs_created_at;

DROP INDEX IF EXISTS idx_audit_logs_target_id;

DROP INDEX IF EXISTS idx_audit_logs_resource;

DROP INDEX IF EXISTS idx_audit_logs_action;

DROP INDEX IF EXISTS idx_audit_logs_actor_id;

DROP TABLE IF EXISTS audit_logs;