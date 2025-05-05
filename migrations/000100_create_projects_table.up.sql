CREATE TABLE
    IF NOT EXISTS projects (
        id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL,
        org_id TEXT,
        name TEXT NOT NULL,
        description TEXT NOT NULL,
        status TEXT NOT NULL,
        tags JSONB NOT NULL DEFAULT '{}',
        created_at TIMESTAMPTZ NOT NULL,
        updated_at TIMESTAMPTZ NOT NULL
    );

CREATE INDEX IF NOT EXISTS idx_projects_tenant_id ON projects (tenant_id);

CREATE INDEX IF NOT EXISTS idx_projects_org_id ON projects (org_id);