-- Billing accounts table for SaaS billing
CREATE TABLE
    billing_accounts (
        id UUID PRIMARY KEY,
        tenant_id UUID NOT NULL,
        email TEXT NOT NULL,
        is_active BOOLEAN NOT NULL DEFAULT TRUE,
        name TEXT NOT NULL,
        status TEXT NOT NULL CHECK (
            status IN ('active', 'inactive', 'suspended', 'closed')
        ),
        created_at TIMESTAMPTZ NOT NULL,
        updated_at TIMESTAMPTZ NOT NULL,
        metadata JSONB NOT NULL DEFAULT '{}'
    );

CREATE INDEX idx_billing_accounts_tenant_id ON billing_accounts (tenant_id);

CREATE INDEX idx_billing_accounts_email ON billing_accounts (email);

CREATE INDEX idx_billing_accounts_status ON billing_accounts (status);