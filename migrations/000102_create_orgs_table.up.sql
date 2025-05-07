-- Orgs table for SaaS multi-tenancy
CREATE TABLE
    orgs (
        id UUID PRIMARY KEY,
        tenant_id UUID NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
        name TEXT NOT NULL,
        is_active BOOLEAN NOT NULL DEFAULT TRUE,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now (),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now (),
        metadata JSONB NOT NULL DEFAULT '{}',
        UNIQUE (tenant_id, name)
    );

CREATE INDEX idx_orgs_tenant_id ON orgs (tenant_id);