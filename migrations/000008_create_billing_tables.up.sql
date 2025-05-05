-- Billing Accounts
CREATE TABLE
    billing_accounts (
        id UUID PRIMARY KEY,
        tenant_id UUID NOT NULL,
        email TEXT NOT NULL,
        created_at TIMESTAMPTZ NOT NULL,
        updated_at TIMESTAMPTZ NOT NULL,
        is_active BOOLEAN NOT NULL DEFAULT TRUE
    );

CREATE INDEX idx_billing_accounts_tenant_id ON billing_accounts (tenant_id);

-- Billing Plans
CREATE TABLE
    billing_plans (
        id UUID PRIMARY KEY,
        name TEXT NOT NULL,
        description TEXT NOT NULL,
        is_active BOOLEAN NOT NULL DEFAULT TRUE,
        created_at TIMESTAMPTZ NOT NULL,
        updated_at TIMESTAMPTZ NOT NULL,
        pricing JSONB NOT NULL
    );

CREATE INDEX idx_billing_plans_is_active ON billing_plans (is_active);

-- Usage Events
CREATE TABLE
    usage_events (
        id UUID PRIMARY KEY,
        account_id UUID NOT NULL REFERENCES billing_accounts (id) ON DELETE CASCADE,
        resource TEXT NOT NULL,
        quantity DOUBLE PRECISION NOT NULL,
        unit TEXT NOT NULL,
        timestamp TIMESTAMPTZ NOT NULL,
        metadata JSONB NOT NULL
    );

CREATE INDEX idx_usage_events_account_id ON usage_events (account_id);

CREATE INDEX idx_usage_events_timestamp ON usage_events (timestamp);

-- Invoices
CREATE TABLE
    invoices (
        id UUID PRIMARY KEY,
        account_id UUID NOT NULL REFERENCES billing_accounts (id) ON DELETE CASCADE,
        period_start TIMESTAMPTZ NOT NULL,
        period_end TIMESTAMPTZ NOT NULL,
        amount DOUBLE PRECISION NOT NULL,
        currency TEXT NOT NULL,
        status TEXT NOT NULL,
        created_at TIMESTAMPTZ NOT NULL,
        updated_at TIMESTAMPTZ NOT NULL,
        paid_at TIMESTAMPTZ,
        line_items JSONB NOT NULL
    );

CREATE INDEX idx_invoices_account_id ON invoices (account_id);

CREATE INDEX idx_invoices_status ON invoices (status);

-- Payments
CREATE TABLE
    payments (
        id UUID PRIMARY KEY,
        invoice_id UUID NOT NULL REFERENCES invoices (id) ON DELETE CASCADE,
        amount DOUBLE PRECISION NOT NULL,
        currency TEXT NOT NULL,
        provider TEXT NOT NULL,
        status TEXT NOT NULL,
        created_at TIMESTAMPTZ NOT NULL,
        updated_at TIMESTAMPTZ NOT NULL,
        reference TEXT NOT NULL
    );

CREATE INDEX idx_payments_invoice_id ON payments (invoice_id);

CREATE INDEX idx_payments_status ON payments (status);

-- Audit Logs
CREATE TABLE
    audit_logs (
        id UUID PRIMARY KEY,
        actor_id UUID NOT NULL,
        action TEXT NOT NULL,
        target_id UUID NOT NULL,
        timestamp TIMESTAMPTZ NOT NULL,
        details JSONB NOT NULL
    );

CREATE INDEX idx_audit_logs_target_id ON audit_logs (target_id);

CREATE INDEX idx_audit_logs_action ON audit_logs (action);

CREATE INDEX idx_audit_logs_timestamp ON audit_logs (timestamp);