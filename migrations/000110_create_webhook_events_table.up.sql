CREATE TABLE
    IF NOT EXISTS webhook_events (
        id TEXT PRIMARY KEY,
        provider TEXT NOT NULL,
        event_type TEXT NOT NULL,
        payload JSONB NOT NULL,
        status TEXT NOT NULL,
        received_at TIMESTAMPTZ NOT NULL,
        processed_at TIMESTAMPTZ,
        error TEXT,
        metadata JSONB NOT NULL DEFAULT '{}'
    );

CREATE INDEX IF NOT EXISTS idx_webhook_events_provider ON webhook_events (provider);

CREATE INDEX IF NOT EXISTS idx_webhook_events_event_type ON webhook_events (event_type);

CREATE INDEX IF NOT EXISTS idx_webhook_events_status ON webhook_events (status);