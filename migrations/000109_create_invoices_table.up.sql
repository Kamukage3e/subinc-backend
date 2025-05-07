-- Invoices table for SaaS billing
CREATE TABLE
    invoices (
        id UUID PRIMARY KEY,
        account_id UUID NOT NULL REFERENCES billing_accounts (id) ON DELETE CASCADE,
        period_start TIMESTAMPTZ NOT NULL,
        period_end TIMESTAMPTZ NOT NULL,
        amount DOUBLE PRECISION NOT NULL CHECK (amount >= 0),
        currency TEXT NOT NULL,
        status TEXT NOT NULL CHECK (
            status IN (
                'draft',
                'issued',
                'paid',
                'void',
                'overdue',
                'refunded'
            )
        ),
        created_at TIMESTAMPTZ NOT NULL DEFAULT now (),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now (),
        metadata JSONB NOT NULL DEFAULT '{}'
    );

CREATE INDEX idx_invoices_account_id ON invoices (account_id);