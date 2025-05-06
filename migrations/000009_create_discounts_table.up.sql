-- Discounts table for SaaS billing
CREATE TABLE
    discounts (
        id UUID PRIMARY KEY,
        code TEXT NOT NULL UNIQUE,
        type TEXT NOT NULL CHECK (type IN ('percentage', 'fixed')),
        value DOUBLE PRECISION NOT NULL CHECK (value > 0),
        max_redemptions INT NOT NULL DEFAULT 0,
        redeemed INT NOT NULL DEFAULT 0,
        start_at TIMESTAMPTZ NOT NULL,
        end_at TIMESTAMPTZ NOT NULL,
        is_active BOOLEAN NOT NULL DEFAULT TRUE,
        created_at TIMESTAMPTZ NOT NULL,
        updated_at TIMESTAMPTZ NOT NULL,
        metadata TEXT
    );

CREATE INDEX idx_discounts_code ON discounts (code);

CREATE INDEX idx_discounts_is_active ON discounts (is_active);

CREATE INDEX idx_discounts_start_end ON discounts (start_at, end_at);