-- Credits table for SaaS billing
CREATE TABLE
    credits (
        id UUID PRIMARY KEY,
        account_id UUID NOT NULL REFERENCES billing_accounts (id) ON DELETE CASCADE,
        invoice_id UUID REFERENCES invoices (id) ON DELETE SET NULL,
        amount DOUBLE PRECISION NOT NULL CHECK (amount > 0),
        currency TEXT NOT NULL,
        type TEXT NOT NULL CHECK (type IN ('account', 'invoice')),
        status TEXT NOT NULL CHECK (status IN ('active', 'consumed', 'expired')),
        created_at TIMESTAMPTZ NOT NULL,
        updated_at TIMESTAMPTZ NOT NULL,
        metadata JSONB NOT NULL DEFAULT '{}'
    );

CREATE INDEX idx_credits_account_id ON credits (account_id);

CREATE INDEX idx_credits_invoice_id ON credits (invoice_id);

CREATE INDEX idx_credits_status ON credits (status);