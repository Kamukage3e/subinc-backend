DROP INDEX IF EXISTS idx_audit_logs_timestamp;

DROP INDEX IF EXISTS idx_audit_logs_action;

DROP INDEX IF EXISTS idx_audit_logs_target_id;

DROP TABLE IF EXISTS audit_logs;

DROP INDEX IF EXISTS idx_payments_status;

DROP INDEX IF EXISTS idx_payments_invoice_id;

DROP TABLE IF EXISTS payments;

DROP INDEX IF EXISTS idx_invoices_status;

DROP INDEX IF EXISTS idx_invoices_account_id;

DROP TABLE IF EXISTS invoices;

DROP INDEX IF EXISTS idx_usage_events_timestamp;

DROP INDEX IF EXISTS idx_usage_events_account_id;

DROP TABLE IF EXISTS usage_events;

DROP INDEX IF EXISTS idx_billing_plans_is_active;

DROP TABLE IF EXISTS billing_plans;

DROP INDEX IF EXISTS idx_billing_accounts_tenant_id;

DROP TABLE IF EXISTS billing_accounts;