-- Billing accounts table for SaaS billing
CREATE TABLE
    IF NOT EXISTS billing_accounts (
        id UUID PRIMARY KEY,
        tenant_id UUID REFERENCES tenants (id) ON DELETE CASCADE,
        email TEXT NOT NULL,
        is_active BOOLEAN NOT NULL DEFAULT TRUE,
        name TEXT NOT NULL,
        status TEXT NOT NULL CHECK (
            status IN ('active', 'inactive', 'suspended', 'closed')
        ),
        created_at TIMESTAMPTZ NOT NULL DEFAULT now (),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now (),
        metadata JSONB NOT NULL DEFAULT '{}',
        UNIQUE (tenant_id, email)
    );

CREATE INDEX IF NOT EXISTS idx_billing_accounts_tenant_id ON billing_accounts (tenant_id);

CREATE INDEX IF NOT EXISTS idx_billing_accounts_email ON billing_accounts (email);

-- Make tenant_id nullable if not already
ALTER TABLE billing_accounts
ALTER COLUMN tenant_id
DROP NOT NULL;