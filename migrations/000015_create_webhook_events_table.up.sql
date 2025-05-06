-- Webhook Events table for SaaS billing
CREATE TABLE
    webhook_events (
        id UUID PRIMARY KEY,
        provider TEXT NOT NULL,
        event_type TEXT NOT NULL,
        payload TEXT NOT NULL,
        status TEXT NOT NULL CHECK (status IN ('received', 'processed', 'failed')),
        received_at TIMESTAMPTZ NOT NULL,
        processed_at TIMESTAMPTZ,
        error TEXT,
        metadata TEXT
    );

CREATE INDEX idx_webhook_events_provider ON webhook_events (provider);

CREATE INDEX idx_webhook_events_status ON webhook_events (status);

CREATE INDEX idx_webhook_events_event_type ON webhook_events (event_type);