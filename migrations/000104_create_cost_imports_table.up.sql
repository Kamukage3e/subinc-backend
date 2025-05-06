CREATE TABLE
    cost_imports (
        id UUID PRIMARY KEY,
        tenant_id UUID NOT NULL,
        provider TEXT NOT NULL,
        account_id TEXT NOT NULL,
        start_time TIMESTAMPTZ NOT NULL,
        end_time TIMESTAMPTZ NOT NULL,
        status TEXT NOT NULL,
        records_count INTEGER NOT NULL,
        error_message TEXT,
        created_at TIMESTAMPTZ NOT NULL,
        updated_at TIMESTAMPTZ NOT NULL,
        completed_at TIMESTAMPTZ
    );

CREATE INDEX idx_cost_imports_tenant_id ON cost_imports (tenant_id);

CREATE INDEX idx_cost_imports_provider ON cost_imports (provider);

CREATE INDEX idx_cost_imports_account_id ON cost_imports (account_id);

CREATE INDEX idx_cost_imports_status ON cost_imports (status);