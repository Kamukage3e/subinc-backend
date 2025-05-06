-- Billing items table for SaaS billing
CREATE TABLE
    billing_items (
        id UUID PRIMARY KEY,
        invoice_id UUID NOT NULL REFERENCES invoices (id) ON DELETE CASCADE,
        account_id UUID NOT NULL REFERENCES billing_accounts (id) ON DELETE CASCADE,
        provider TEXT NOT NULL,
        service TEXT NOT NULL,
        description TEXT NOT NULL,
        resource_id TEXT,
        usage_type TEXT,
        usage_quantity DOUBLE PRECISION,
        usage_unit TEXT,
        cost_amount DOUBLE PRECISION,
        cost_currency TEXT,
        effective_price DOUBLE PRECISION,
        billing_period TEXT,
        tags JSONB NOT NULL DEFAULT '{}',
        tax_amount DOUBLE PRECISION,
        tax_rate DOUBLE PRECISION,
        fees JSONB NOT NULL DEFAULT '[]',
        quantity INTEGER NOT NULL CHECK (quantity > 0),
        unit_price DOUBLE PRECISION NOT NULL CHECK (unit_price >= 0),
        amount DOUBLE PRECISION NOT NULL CHECK (amount >= 0),
        currency TEXT NOT NULL,
        start_date TIMESTAMPTZ,
        end_date TIMESTAMPTZ,
        created_at TIMESTAMPTZ NOT NULL,
        updated_at TIMESTAMPTZ NOT NULL,
        metadata JSONB NOT NULL DEFAULT '{}'
    );

CREATE INDEX idx_billing_items_invoice_id ON billing_items (invoice_id);

CREATE INDEX idx_billing_items_account_id ON billing_items (account_id);

CREATE INDEX idx_billing_items_provider ON billing_items (provider);

CREATE INDEX idx_billing_items_service ON billing_items (service);

CREATE INDEX idx_billing_items_resource_id ON billing_items (resource_id);