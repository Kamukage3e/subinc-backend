-- Project invitations table for SaaS
CREATE TABLE
    IF NOT EXISTS project_invitations (
        id UUID PRIMARY KEY,
        project_id UUID NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
        email TEXT NOT NULL,
        role TEXT NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now (),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now ()
    );

CREATE INDEX IF NOT EXISTS idx_project_invitations_project_id ON project_invitations (project_id);

CREATE INDEX IF NOT EXISTS idx_project_invitations_email ON project_invitations (email);