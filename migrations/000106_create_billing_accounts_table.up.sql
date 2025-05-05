CREATE TABLE
    IF NOT EXISTS billing_accounts (
        id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL,
        email TEXT NOT NULL UNIQUE,
        created_at TIMESTAMPTZ NOT NULL,
        updated_at TIMESTAMPTZ NOT NULL,
        is_active BOOLEAN NOT NULL DEFAULT TRUE
    );

CREATE INDEX IF NOT EXISTS idx_billing_accounts_tenant_id ON billing_accounts (tenant_id);

CREATE INDEX IF NOT EXISTS idx_billing_accounts_email ON billing_accounts (email);

CREATE INDEX IF NOT EXISTS idx_billing_accounts_is_active ON billing_accounts (is_active);