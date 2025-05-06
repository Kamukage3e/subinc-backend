CREATE TABLE
    anomalies (
        id UUID PRIMARY KEY,
        tenant_id UUID NOT NULL,
        provider TEXT NOT NULL,
        account_id TEXT,
        resource_id TEXT,
        service TEXT,
        detected_at TIMESTAMPTZ NOT NULL,
        start_time TIMESTAMPTZ NOT NULL,
        end_time TIMESTAMPTZ NOT NULL,
        expected_cost DOUBLE PRECISION NOT NULL,
        actual_cost DOUBLE PRECISION NOT NULL,
        deviation DOUBLE PRECISION NOT NULL,
        severity TEXT NOT NULL,
        status TEXT NOT NULL,
        root_cause TEXT,
        recommendation TEXT,
        created_at TIMESTAMPTZ NOT NULL,
        updated_at TIMESTAMPTZ NOT NULL
    );

CREATE INDEX idx_anomalies_tenant_id ON anomalies (tenant_id);

CREATE INDEX idx_anomalies_provider ON anomalies (provider);

CREATE INDEX idx_anomalies_account_id ON anomalies (account_id);

CREATE INDEX idx_anomalies_resource_id ON anomalies (resource_id);

CREATE INDEX idx_anomalies_severity ON anomalies (severity);

CREATE INDEX idx_anomalies_status ON anomalies (status);