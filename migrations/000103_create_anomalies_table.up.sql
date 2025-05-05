CREATE TABLE
    IF NOT EXISTS anomalies (
        id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL,
        provider TEXT NOT NULL,
        account_id TEXT NOT NULL,
        resource_id TEXT NOT NULL,
        service TEXT NOT NULL,
        detected_at TIMESTAMPTZ NOT NULL,
        start_time TIMESTAMPTZ NOT NULL,
        end_time TIMESTAMPTZ NOT NULL,
        expected_cost NUMERIC(20, 6) NOT NULL,
        actual_cost NUMERIC(20, 6) NOT NULL,
        deviation NUMERIC(20, 6) NOT NULL,
        severity TEXT NOT NULL,
        status TEXT NOT NULL,
        root_cause TEXT NOT NULL,
        recommendation TEXT NOT NULL,
        created_at TIMESTAMPTZ NOT NULL,
        updated_at TIMESTAMPTZ NOT NULL
    );

CREATE INDEX IF NOT EXISTS idx_anomalies_tenant_id ON anomalies (tenant_id);

CREATE INDEX IF NOT EXISTS idx_anomalies_provider ON anomalies (provider);

CREATE INDEX IF NOT EXISTS idx_anomalies_account_id ON anomalies (account_id);

CREATE INDEX IF NOT EXISTS idx_anomalies_resource_id ON anomalies (resource_id);

CREATE INDEX IF NOT EXISTS idx_anomalies_severity ON anomalies (severity);

CREATE INDEX IF NOT EXISTS idx_anomalies_status ON anomalies (status);