-- Refunds table for SaaS billing
CREATE TABLE
    refunds (
        id UUID PRIMARY KEY,
        payment_id UUID NOT NULL REFERENCES payments (id) ON DELETE CASCADE,
        invoice_id UUID REFERENCES invoices (id) ON DELETE SET NULL,
        amount DOUBLE PRECISION NOT NULL CHECK (amount > 0),
        currency TEXT NOT NULL,
        status TEXT NOT NULL CHECK (
            status IN ('pending', 'processed', 'failed', 'reversed')
        ),
        reason TEXT NOT NULL,
        created_at TIMESTAMPTZ NOT NULL,
        updated_at TIMESTAMPTZ NOT NULL,
        metadata JSONB NOT NULL DEFAULT '{}'
    );

CREATE INDEX idx_refunds_payment_id ON refunds (payment_id);

CREATE INDEX idx_refunds_invoice_id ON refunds (invoice_id);

CREATE INDEX idx_refunds_status ON refunds (status);