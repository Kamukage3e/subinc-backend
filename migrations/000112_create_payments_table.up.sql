-- Payments table for SaaS billing
CREATE TABLE
    payments (
        id UUID PRIMARY KEY,
        invoice_id UUID NOT NULL REFERENCES invoices (id) ON DELETE SET NULL,
        amount DOUBLE PRECISION NOT NULL CHECK (amount > 0),
        currency TEXT NOT NULL,
        provider TEXT NOT NULL,
        status TEXT NOT NULL CHECK (status IN ('pending', 'completed', 'failed')),
        created_at TIMESTAMPTZ NOT NULL,
        updated_at TIMESTAMPTZ NOT NULL,
        reference TEXT
    );

CREATE INDEX idx_payments_invoice_id ON payments (invoice_id);

CREATE INDEX idx_payments_status ON payments (status);