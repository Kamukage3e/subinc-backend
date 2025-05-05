CREATE TABLE
    IF NOT EXISTS credits (
        id TEXT PRIMARY KEY,
        account_id TEXT NOT NULL,
        invoice_id TEXT,
        amount NUMERIC(20, 6) NOT NULL,
        currency TEXT NOT NULL,
        type TEXT NOT NULL,
        status TEXT NOT NULL,
        created_at TIMESTAMPTZ NOT NULL,
        updated_at TIMESTAMPTZ NOT NULL,
        metadata JSONB NOT NULL DEFAULT '{}'
    );

CREATE INDEX IF NOT EXISTS idx_credits_account_id ON credits (account_id);

CREATE INDEX IF NOT EXISTS idx_credits_invoice_id ON credits (invoice_id);

CREATE INDEX IF NOT EXISTS idx_credits_type ON credits (type);

CREATE INDEX IF NOT EXISTS idx_credits_status ON credits (status);