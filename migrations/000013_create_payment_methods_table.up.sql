-- Payment Methods table for SaaS billing
CREATE TABLE
    payment_methods (
        id UUID PRIMARY KEY,
        account_id UUID NOT NULL REFERENCES billing_accounts (id) ON DELETE CASCADE,
        type TEXT NOT NULL CHECK (type IN ('card', 'bank', 'other')),
        provider TEXT NOT NULL,
        last4 TEXT NOT NULL CHECK (char_length(last4) = 4),
        exp_month INT CHECK (
            exp_month >= 1
            AND exp_month <= 12
        ),
        exp_year INT CHECK (exp_year >= 2000),
        is_default BOOLEAN NOT NULL DEFAULT FALSE,
        status TEXT NOT NULL CHECK (
            status IN ('active', 'inactive', 'expired', 'failed')
        ),
        created_at TIMESTAMPTZ NOT NULL,
        updated_at TIMESTAMPTZ NOT NULL,
        metadata JSONB NOT NULL DEFAULT '{}'
    );

CREATE INDEX idx_payment_methods_account_id ON payment_methods (account_id);

CREATE INDEX idx_payment_methods_status ON payment_methods (status);