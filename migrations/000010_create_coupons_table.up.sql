-- Coupons table for SaaS billing
CREATE TABLE
    coupons (
        id UUID PRIMARY KEY,
        code TEXT NOT NULL UNIQUE,
        discount_id UUID NOT NULL REFERENCES discounts (id) ON DELETE CASCADE,
        max_redemptions INT NOT NULL DEFAULT 0,
        redeemed INT NOT NULL DEFAULT 0,
        start_at TIMESTAMPTZ NOT NULL,
        end_at TIMESTAMPTZ NOT NULL,
        is_active BOOLEAN NOT NULL DEFAULT TRUE,
        created_at TIMESTAMPTZ NOT NULL,
        updated_at TIMESTAMPTZ NOT NULL,
        metadata TEXT
    );

CREATE INDEX idx_coupons_code ON coupons (code);

CREATE INDEX idx_coupons_is_active ON coupons (is_active);

CREATE INDEX idx_coupons_start_end ON coupons (start_at, end_at);

CREATE INDEX idx_coupons_discount_id ON coupons (discount_id);