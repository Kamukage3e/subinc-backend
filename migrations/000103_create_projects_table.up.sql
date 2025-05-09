-- Projects table for SaaS multi-tenancy
CREATE TABLE
    projects (
        id UUID PRIMARY KEY,
        tenant_id UUID NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
        org_id UUID NOT NULL REFERENCES orgs (id) ON DELETE CASCADE,
        name TEXT NOT NULL,
        is_active BOOLEAN NOT NULL DEFAULT TRUE,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now (),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now (),
        metadata JSONB NOT NULL DEFAULT '{}',
        UNIQUE (org_id, name)
    );

CREATE INDEX idx_projects_tenant_id ON projects (tenant_id);

CREATE INDEX idx_projects_org_id ON projects (org_id);