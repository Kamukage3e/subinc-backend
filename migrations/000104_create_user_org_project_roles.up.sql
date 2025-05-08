-- User-Org-Project Roles table for RBAC
CREATE TABLE
    IF NOT EXISTS user_org_project_roles (
        id UUID PRIMARY KEY,
        tenant_id UUID REFERENCES tenants (id) ON DELETE CASCADE,
        user_id UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
        org_id UUID REFERENCES orgs (id) ON DELETE CASCADE,
        project_id UUID REFERENCES projects (id) ON DELETE CASCADE,
        role TEXT NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now (),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now (),
        UNIQUE (user_id, org_id, project_id, role)
    );

CREATE INDEX IF NOT EXISTS idx_user_org_project_roles_user_id ON user_org_project_roles (user_id);

CREATE INDEX IF NOT EXISTS idx_user_org_project_roles_org_id ON user_org_project_roles (org_id);

CREATE INDEX IF NOT EXISTS idx_user_org_project_roles_project_id ON user_org_project_roles (project_id);

-- Make tenant_id nullable if not already
ALTER TABLE user_org_project_roles
ALTER COLUMN tenant_id
DROP NOT NULL;