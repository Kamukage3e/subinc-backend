-- Add missing columns and fix types for SaaS admin tables

-- Add ip_address to admin_sessions if missing
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.tables WHERE table_name='admin_sessions'
    ) AND NOT EXISTS (
        SELECT 1 FROM information_schema.columns WHERE table_name='admin_sessions' AND column_name='ip_address'
    ) THEN
        ALTER TABLE admin_sessions ADD COLUMN ip_address TEXT;
    END IF;
END $$;

-- Add endpoint to rate_limits if missing
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.tables WHERE table_name='rate_limits'
    ) AND NOT EXISTS (
        SELECT 1 FROM information_schema.columns WHERE table_name='rate_limits' AND column_name='endpoint'
    ) THEN
        ALTER TABLE rate_limits ADD COLUMN endpoint TEXT NOT NULL DEFAULT '';
    END IF;
END $$;

-- Add severity to alerts if missing
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.tables WHERE table_name='alerts'
    ) AND NOT EXISTS (
        SELECT 1 FROM information_schema.columns WHERE table_name='alerts' AND column_name='severity'
    ) THEN
        ALTER TABLE alerts ADD COLUMN severity TEXT NOT NULL DEFAULT 'info';
    END IF;
END $$;

-- Add status to secrets if table exists
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.tables WHERE table_name='secrets'
    ) AND NOT EXISTS (
        SELECT 1 FROM information_schema.columns WHERE table_name='secrets' AND column_name='status'
    ) THEN
        ALTER TABLE secrets ADD COLUMN status TEXT NOT NULL DEFAULT 'active';
    END IF;
END $$;

-- Add permissions to admin_roles as JSONB if table exists
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.tables WHERE table_name='admin_roles'
    ) AND NOT EXISTS (
        SELECT 1 FROM information_schema.columns WHERE table_name='admin_roles' AND column_name='permissions'
    ) THEN
        ALTER TABLE admin_roles ADD COLUMN permissions JSONB NOT NULL DEFAULT '[]';
    END IF;
END $$;

-- Add permissions to admin_permissions if missing
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.tables WHERE table_name='admin_permissions'
    ) AND NOT EXISTS (
        SELECT 1 FROM information_schema.columns WHERE table_name='admin_permissions' AND column_name='permissions'
    ) THEN
        ALTER TABLE admin_permissions ADD COLUMN permissions JSONB NOT NULL DEFAULT '[]';
    END IF;
END $$;

-- Add type to policies if missing
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.tables WHERE table_name='policies'
    ) AND NOT EXISTS (
        SELECT 1 FROM information_schema.columns WHERE table_name='policies' AND column_name='type'
    ) THEN
        ALTER TABLE policies ADD COLUMN type TEXT NOT NULL DEFAULT 'custom';
    END IF;
END $$;

-- Add permissions to user_org_project_roles if missing
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.tables WHERE table_name='user_org_project_roles'
    ) AND NOT EXISTS (
        SELECT 1 FROM information_schema.columns WHERE table_name='user_org_project_roles' AND column_name='permissions'
    ) THEN
        ALTER TABLE user_org_project_roles ADD COLUMN permissions JSONB NOT NULL DEFAULT '[]';
    END IF;
END $$;

-- Add status to projects if missing
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.tables WHERE table_name='projects'
    ) AND NOT EXISTS (
        SELECT 1 FROM information_schema.columns WHERE table_name='projects' AND column_name='status'
    ) THEN
        ALTER TABLE projects ADD COLUMN status TEXT NOT NULL DEFAULT 'active';
    END IF;
END $$;

-- Add settings to projects if table exists
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.tables WHERE table_name='projects'
    ) AND NOT EXISTS (
        SELECT 1 FROM information_schema.columns WHERE table_name='projects' AND column_name='settings'
    ) THEN
        ALTER TABLE projects ADD COLUMN settings JSONB NOT NULL DEFAULT '{}';
    END IF;
END $$;

-- Add created_at and updated_at to feature_flags if table exists
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.tables WHERE table_name='feature_flags'
    ) THEN
        IF NOT EXISTS (
            SELECT 1 FROM information_schema.columns WHERE table_name='feature_flags' AND column_name='created_at'
        ) THEN
            ALTER TABLE feature_flags ADD COLUMN created_at TIMESTAMPTZ NOT NULL DEFAULT now();
        END IF;
        IF NOT EXISTS (
            SELECT 1 FROM information_schema.columns WHERE table_name='feature_flags' AND column_name='updated_at'
        ) THEN
            ALTER TABLE feature_flags ADD COLUMN updated_at TIMESTAMPTZ NOT NULL DEFAULT now();
        END IF;
    END IF;
END $$;

-- admin_users: enforce unique username/email, password_hash not null, roles not null default
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name='admin_users') THEN
        BEGIN
            ALTER TABLE admin_users ADD CONSTRAINT admin_users_username_key UNIQUE (username);
        EXCEPTION WHEN duplicate_object THEN END;
        BEGIN
            ALTER TABLE admin_users ADD CONSTRAINT admin_users_email_key UNIQUE (email);
        EXCEPTION WHEN duplicate_object THEN END;
        ALTER TABLE admin_users ALTER COLUMN password_hash SET NOT NULL;
        ALTER TABLE admin_users ALTER COLUMN roles SET NOT NULL;
        ALTER TABLE admin_users ALTER COLUMN roles SET DEFAULT '{admin}';
    END IF;
END $$;

-- admin_sessions: admin_user_id NOT NULL, ip_address TEXT
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name='admin_sessions') THEN
        ALTER TABLE admin_sessions ALTER COLUMN admin_user_id SET NOT NULL;
        IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='admin_sessions' AND column_name='ip_address') THEN
            ALTER TABLE admin_sessions ADD COLUMN ip_address TEXT;
        END IF;
    END IF;
END $$;

-- tenants: settings JSONB NOT NULL DEFAULT '{}'
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name='tenants') AND NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='tenants' AND column_name='settings') THEN
        ALTER TABLE tenants ADD COLUMN settings JSONB NOT NULL DEFAULT '{}';
    END IF;
END $$;

-- feature_flags: name TEXT NOT NULL, created_at, updated_at
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name='feature_flags') THEN
        IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='feature_flags' AND column_name='name') THEN
            ALTER TABLE feature_flags ADD COLUMN name TEXT NOT NULL;
        END IF;
        IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='feature_flags' AND column_name='created_at') THEN
            ALTER TABLE feature_flags ADD COLUMN created_at TIMESTAMPTZ NOT NULL DEFAULT now();
        END IF;
        IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='feature_flags' AND column_name='updated_at') THEN
            ALTER TABLE feature_flags ADD COLUMN updated_at TIMESTAMPTZ NOT NULL DEFAULT now();
        END IF;
    END IF;
END $$;

-- alerts: active BOOLEAN NOT NULL DEFAULT true
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name='alerts') AND NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='alerts' AND column_name='active') THEN
        ALTER TABLE alerts ADD COLUMN active BOOLEAN NOT NULL DEFAULT true;
    END IF;
END $$;

-- rate_limits: limit_per_minute INTEGER NOT NULL DEFAULT 60
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name='rate_limits') AND NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='rate_limits' AND column_name='limit_per_minute') THEN
        ALTER TABLE rate_limits ADD COLUMN limit_per_minute INTEGER NOT NULL DEFAULT 60;
    END IF;
END $$;

-- secrets: status TEXT NOT NULL DEFAULT 'active'
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name='secrets') AND NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='secrets' AND column_name='status') THEN
        ALTER TABLE secrets ADD COLUMN status TEXT NOT NULL DEFAULT 'active';
    END IF;
END $$;

-- projects: status TEXT NOT NULL DEFAULT 'active'
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name='projects') AND NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='projects' AND column_name='status') THEN
        ALTER TABLE projects ADD COLUMN status TEXT NOT NULL DEFAULT 'active';
    END IF;
END $$;

-- user_org_project_roles: permissions JSONB NOT NULL DEFAULT '[]'
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name='user_org_project_roles') AND NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='user_org_project_roles' AND column_name='permissions') THEN
        ALTER TABLE user_org_project_roles ADD COLUMN permissions JSONB NOT NULL DEFAULT '[]';
    END IF;
END $$;

-- admin_permissions: permissions JSONB NOT NULL DEFAULT '[]'
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name='admin_permissions') AND NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='admin_permissions' AND column_name='permissions') THEN
        ALTER TABLE admin_permissions ADD COLUMN permissions JSONB NOT NULL DEFAULT '[]';
    END IF;
END $$;

-- policies: type TEXT NOT NULL DEFAULT 'custom'
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name='policies') AND NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='policies' AND column_name='type') THEN
        ALTER TABLE policies ADD COLUMN type TEXT NOT NULL DEFAULT 'custom';
    END IF;
END $$;

-- Add missing columns, constraints, and tables for orgs, projects, teams, users, invitations, and all referenced entities

-- Add tenant_id to orgs if missing
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.tables WHERE table_name='orgs'
    ) AND NOT EXISTS (
        SELECT 1 FROM information_schema.columns WHERE table_name='orgs' AND column_name='tenant_id'
    ) THEN
        ALTER TABLE orgs ADD COLUMN tenant_id UUID NOT NULL;
    END IF;
END $$;

-- Add org_id and tenant_id to projects if missing
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.tables WHERE table_name='projects'
    ) AND NOT EXISTS (
        SELECT 1 FROM information_schema.columns WHERE table_name='projects' AND column_name='org_id'
    ) THEN
        ALTER TABLE projects ADD COLUMN org_id UUID NOT NULL;
    END IF;
    IF EXISTS (
        SELECT 1 FROM information_schema.tables WHERE table_name='projects'
    ) AND NOT EXISTS (
        SELECT 1 FROM information_schema.columns WHERE table_name='projects' AND column_name='tenant_id'
    ) THEN
        ALTER TABLE projects ADD COLUMN tenant_id UUID NOT NULL;
    END IF;
END $$;

-- Add org_id, tenant_id, and project_id to teams if missing
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.tables WHERE table_name='teams'
    ) AND NOT EXISTS (
        SELECT 1 FROM information_schema.columns WHERE table_name='teams' AND column_name='org_id'
    ) THEN
        ALTER TABLE teams ADD COLUMN org_id UUID NOT NULL;
    END IF;
    IF EXISTS (
        SELECT 1 FROM information_schema.tables WHERE table_name='teams'
    ) AND NOT EXISTS (
        SELECT 1 FROM information_schema.columns WHERE table_name='teams' AND column_name='tenant_id'
    ) THEN
        ALTER TABLE teams ADD COLUMN tenant_id UUID NOT NULL;
    END IF;
    IF EXISTS (
        SELECT 1 FROM information_schema.tables WHERE table_name='teams'
    ) AND NOT EXISTS (
        SELECT 1 FROM information_schema.columns WHERE table_name='teams' AND column_name='project_id'
    ) THEN
        ALTER TABLE teams ADD COLUMN project_id UUID;
    END IF;
END $$;

-- Add org_id, tenant_id to invitations if missing
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.tables WHERE table_name='project_invitations'
    ) AND NOT EXISTS (
        SELECT 1 FROM information_schema.columns WHERE table_name='project_invitations' AND column_name='org_id'
    ) THEN
        ALTER TABLE project_invitations ADD COLUMN org_id UUID;
    END IF;
    IF EXISTS (
        SELECT 1 FROM information_schema.tables WHERE table_name='project_invitations'
    ) AND NOT EXISTS (
        SELECT 1 FROM information_schema.columns WHERE table_name='project_invitations' AND column_name='tenant_id'
    ) THEN
        ALTER TABLE project_invitations ADD COLUMN tenant_id UUID;
    END IF;
END $$;

-- Add org_id, tenant_id to users if missing
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.tables WHERE table_name='users'
    ) AND NOT EXISTS (
        SELECT 1 FROM information_schema.columns WHERE table_name='users' AND column_name='org_id'
    ) THEN
        ALTER TABLE users ADD COLUMN org_id UUID;
    END IF;
    IF EXISTS (
        SELECT 1 FROM information_schema.tables WHERE table_name='users'
    ) AND NOT EXISTS (
        SELECT 1 FROM information_schema.columns WHERE table_name='users' AND column_name='tenant_id'
    ) THEN
        ALTER TABLE users ADD COLUMN tenant_id UUID;
    END IF;
END $$;

-- Add org_id, tenant_id, team_id to user_org_project_roles if missing
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.tables WHERE table_name='user_org_project_roles'
    ) AND NOT EXISTS (
        SELECT 1 FROM information_schema.columns WHERE table_name='user_org_project_roles' AND column_name='org_id'
    ) THEN
        ALTER TABLE user_org_project_roles ADD COLUMN org_id UUID;
    END IF;
    IF EXISTS (
        SELECT 1 FROM information_schema.tables WHERE table_name='user_org_project_roles'
    ) AND NOT EXISTS (
        SELECT 1 FROM information_schema.columns WHERE table_name='user_org_project_roles' AND column_name='tenant_id'
    ) THEN
        ALTER TABLE user_org_project_roles ADD COLUMN tenant_id UUID;
    END IF;
    IF EXISTS (
        SELECT 1 FROM information_schema.tables WHERE table_name='user_org_project_roles'
    ) AND NOT EXISTS (
        SELECT 1 FROM information_schema.columns WHERE table_name='user_org_project_roles' AND column_name='team_id'
    ) THEN
        ALTER TABLE user_org_project_roles ADD COLUMN team_id UUID;
    END IF;
END $$;

-- Add NOT NULL and DEFAULT constraints as needed
-- Add UNIQUE constraints as needed
-- Add missing foreign key constraints for org_id, tenant_id, user_id, team_id, project_id
-- All changes must be idempotent and production-grade 