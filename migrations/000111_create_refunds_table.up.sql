CREATE TABLE
    IF NOT EXISTS refunds (
        id TEXT PRIMARY KEY,
        payment_id TEXT NOT NULL,
        invoice_id TEXT,
        amount NUMERIC(20, 6) NOT NULL,
        currency TEXT NOT NULL,
        status TEXT NOT NULL,
        reason TEXT NOT NULL,
        created_at TIMESTAMPTZ NOT NULL,
        updated_at TIMESTAMPTZ NOT NULL,
        metadata JSONB NOT NULL DEFAULT '{}'
    );

CREATE INDEX IF NOT EXISTS idx_refunds_payment_id ON refunds (payment_id);

CREATE INDEX IF NOT EXISTS idx_refunds_invoice_id ON refunds (invoice_id);

CREATE INDEX IF NOT EXISTS idx_refunds_status ON refunds (status);