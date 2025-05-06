CREATE TABLE
    projects (
        id UUID PRIMARY KEY,
        tenant_id UUID NOT NULL,
        org_id UUID,
        name TEXT NOT NULL,
        description TEXT NOT NULL,
        status TEXT NOT NULL,
        tags JSONB NOT NULL DEFAULT '{}',
        created_at TIMESTAMPTZ NOT NULL,
        updated_at TIMESTAMPTZ NOT NULL
    );

CREATE INDEX idx_projects_tenant_id ON projects (tenant_id);

CREATE INDEX idx_projects_org_id ON projects (org_id);