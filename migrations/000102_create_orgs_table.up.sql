-- Orgs table for SaaS multi-tenancy
CREATE TABLE IF NOT EXISTS orgs (
    id UUID PRIMARY KEY,
    tenant_id UUID REFERENCES tenants (id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    metadata JSONB NOT NULL DEFAULT '{}',
    settings JSONB NOT NULL DEFAULT '{}',
    UNIQUE (tenant_id, name)
);

CREATE INDEX IF NOT EXISTS idx_orgs_tenant_id ON orgs (tenant_id);

-- Make tenant_id nullable for global orgs (SaaS multi-tenancy)
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name='orgs' AND column_name='tenant_id' AND is_nullable='NO'
    ) THEN
        ALTER TABLE orgs ALTER COLUMN tenant_id DROP NOT NULL;
    END IF;
END$$;

-- Add settings column to orgs if missing
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns WHERE table_name='orgs' AND column_name='settings'
    ) THEN
        ALTER TABLE orgs ADD COLUMN settings JSONB NOT NULL DEFAULT '{}';
    END IF;
END $$;

-- Create org_invitations table if not exists
CREATE TABLE IF NOT EXISTS org_invitations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    email TEXT NOT NULL,
    role TEXT NOT NULL,
    invited_by UUID,
    status TEXT NOT NULL DEFAULT 'pending',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(org_id, email)
);

-- Add status column to org_invitations if missing
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns WHERE table_name='org_invitations' AND column_name='status'
    ) THEN
        ALTER TABLE org_invitations ADD COLUMN status TEXT NOT NULL DEFAULT 'pending';
    END IF;
END $$;

-- Create api_keys table if not exists
CREATE TABLE IF NOT EXISTS api_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    key TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at TIMESTAMPTZ,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    UNIQUE(org_id, name)
);

-- Add status column to api_keys if missing
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns WHERE table_name='api_keys' AND column_name='status'
    ) THEN
        ALTER TABLE api_keys ADD COLUMN status TEXT NOT NULL DEFAULT 'active';
    END IF;
END $$;

-- Add user_id column to api_keys if missing
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns WHERE table_name='api_keys' AND column_name='user_id'
    ) THEN
        ALTER TABLE api_keys ADD COLUMN user_id UUID;
    END IF;
END $$;

-- Create org_teams table if not exists
CREATE TABLE IF NOT EXISTS org_teams (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    description TEXT,
    name TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(org_id, name)
);

-- Add user_id column to org_teams if missing
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns WHERE table_name='org_teams' AND column_name='user_id'
    ) THEN
        ALTER TABLE org_teams ADD COLUMN user_id UUID;
    END IF;
END $$;

-- Add description column to org_teams if missing
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns WHERE table_name='org_teams' AND column_name='description'
    ) THEN
        ALTER TABLE org_teams ADD COLUMN description TEXT;
    END IF;
END $$;

-- Add user_ids column to org_teams if missing
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns WHERE table_name='org_teams' AND column_name='user_ids'
    ) THEN
        ALTER TABLE org_teams ADD COLUMN user_ids TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[];
    END IF;
END $$;

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_org_invitations_org_id ON org_invitations(org_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_org_id ON api_keys(org_id);
CREATE INDEX IF NOT EXISTS idx_org_teams_org_id ON org_teams(org_id);