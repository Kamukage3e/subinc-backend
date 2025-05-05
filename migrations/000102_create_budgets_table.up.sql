CREATE TABLE
    IF NOT EXISTS budgets (
        id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL,
        name TEXT NOT NULL,
        description TEXT NOT NULL,
        provider TEXT NOT NULL,
        account_id TEXT NOT NULL,
        service TEXT NOT NULL,
        amount NUMERIC(20, 6) NOT NULL,
        currency TEXT NOT NULL,
        period TEXT NOT NULL,
        start_time TIMESTAMPTZ NOT NULL,
        end_time TIMESTAMPTZ NOT NULL,
        created_at TIMESTAMPTZ NOT NULL,
        updated_at TIMESTAMPTZ NOT NULL
    );

CREATE INDEX IF NOT EXISTS idx_budgets_tenant_id ON budgets (tenant_id);

CREATE INDEX IF NOT EXISTS idx_budgets_provider ON budgets (provider);

CREATE INDEX IF NOT EXISTS idx_budgets_account_id ON budgets (account_id);