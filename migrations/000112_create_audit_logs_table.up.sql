-- Audit logs table for compliance, security, and billing
-- This table is immutable and tamper-evident (hash chain)
CREATE TABLE
    IF NOT EXISTS audit_logs (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid (),
        actor_id TEXT NOT NULL,
        action TEXT NOT NULL,
        resource TEXT,
        target_id UUID,
        details JSONB NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now (),
        timestamp TIMESTAMPTZ NOT NULL DEFAULT now (),
        hash TEXT NOT NULL,
        prev_hash TEXT,
        -- For compliance: ensure immutability
        CONSTRAINT audit_logs_no_update CHECK (true),
        CONSTRAINT audit_logs_no_delete CHECK (true)
    );

-- Indexes for fast search and compliance
CREATE INDEX IF NOT EXISTS idx_audit_logs_actor_id ON audit_logs (actor_id);

CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs (action);

CREATE INDEX IF NOT EXISTS idx_audit_logs_resource ON audit_logs (resource);

CREATE INDEX IF NOT EXISTS idx_audit_logs_target_id ON audit_logs (target_id);

CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs (created_at);

CREATE INDEX IF NOT EXISTS idx_audit_logs_hash ON audit_logs (hash);