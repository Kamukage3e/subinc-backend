-- Add tax and fee support to billing_items table for SaaS billing
ALTER TABLE billing_items
ADD COLUMN tax_amount DOUBLE PRECISION NOT NULL DEFAULT 0,
ADD COLUMN tax_rate DOUBLE PRECISION NOT NULL DEFAULT 0,
ADD COLUMN fees TEXT NOT NULL DEFAULT '[]';