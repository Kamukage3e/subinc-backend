-- User-Org-Project Roles table for RBAC
CREATE TABLE
    user_org_project_roles (
        id UUID PRIMARY KEY,
        tenant_id UUID NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
        user_id UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
        org_id UUID REFERENCES orgs (id) ON DELETE CASCADE,
        project_id UUID REFERENCES projects (id) ON DELETE CASCADE,
        role TEXT NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now (),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now (),
        UNIQUE (user_id, org_id, project_id, role)
    );

CREATE INDEX idx_user_org_project_roles_user_id ON user_org_project_roles (user_id);

CREATE INDEX idx_user_org_project_roles_org_id ON user_org_project_roles (org_id);

CREATE INDEX idx_user_org_project_roles_project_id ON user_org_project_roles (project_id);