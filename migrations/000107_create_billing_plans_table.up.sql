CREATE TABLE
    IF NOT EXISTS billing_plans (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL UNIQUE,
        description TEXT NOT NULL,
        is_active BOOLEAN NOT NULL DEFAULT TRUE,
        created_at TIMESTAMPTZ NOT NULL,
        updated_at TIMESTAMPTZ NOT NULL,
        pricing JSONB NOT NULL
    );

CREATE INDEX IF NOT EXISTS idx_billing_plans_name ON billing_plans (name);

CREATE INDEX IF NOT EXISTS idx_billing_plans_is_active ON billing_plans (is_active);