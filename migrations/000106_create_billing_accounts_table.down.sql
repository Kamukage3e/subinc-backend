-- Drop billing_accounts table and indexes
DROP INDEX IF EXISTS idx_billing_accounts_email;

DROP INDEX IF EXISTS idx_billing_accounts_tenant_id;

DROP TABLE IF EXISTS billing_accounts;