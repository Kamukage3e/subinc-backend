CREATE TABLE
    budgets (
        id UUID PRIMARY KEY,
        tenant_id UUID NOT NULL,
        name TEXT NOT NULL,
        description TEXT,
        provider TEXT,
        account_id TEXT,
        service TEXT,
        amount DOUBLE PRECISION NOT NULL,
        currency TEXT NOT NULL,
        period TEXT NOT NULL,
        start_time TIMESTAMPTZ NOT NULL,
        end_time TIMESTAMPTZ,
        created_at TIMESTAMPTZ NOT NULL,
        updated_at TIMESTAMPTZ NOT NULL
    );

CREATE INDEX idx_budgets_tenant_id ON budgets (tenant_id);

CREATE INDEX idx_budgets_provider ON budgets (provider);

CREATE INDEX idx_budgets_account_id ON budgets (account_id);