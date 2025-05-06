-- Invoice Adjustments table for SaaS billing
CREATE TABLE
    invoice_adjustments (
        id UUID PRIMARY KEY,
        invoice_id UUID NOT NULL REFERENCES invoices (id) ON DELETE CASCADE,
        type TEXT NOT NULL CHECK (type IN ('discount', 'credit', 'manual')),
        amount DOUBLE PRECISION NOT NULL CHECK (amount <> 0),
        currency TEXT NOT NULL,
        reason TEXT NOT NULL,
        created_at TIMESTAMPTZ NOT NULL,
        updated_at TIMESTAMPTZ NOT NULL,
        metadata TEXT
    );

CREATE INDEX idx_invoice_adjustments_invoice_id ON invoice_adjustments (invoice_id);

CREATE INDEX idx_invoice_adjustments_type ON invoice_adjustments (type);