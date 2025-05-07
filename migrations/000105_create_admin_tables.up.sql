-- Admin users table
CREATE TABLE
    admin_users (
        id UUID PRIMARY KEY,
        username TEXT NOT NULL UNIQUE,
        email TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        roles TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
        is_active BOOLEAN NOT NULL DEFAULT TRUE,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now (),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now ()
    );

-- Admin roles table
CREATE TABLE
    admin_roles (
        id UUID PRIMARY KEY,
        name TEXT NOT NULL UNIQUE,
        permissions TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
        description TEXT,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now (),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now ()
    );

-- Admin permissions table
CREATE TABLE
    admin_permissions (
        id UUID PRIMARY KEY,
        name TEXT NOT NULL UNIQUE,
        description TEXT,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now (),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now ()
    );

-- Admin role-permissions join table
CREATE TABLE
    admin_role_permissions (
        role_id UUID NOT NULL REFERENCES admin_roles (id) ON DELETE CASCADE,
        permission_id UUID NOT NULL REFERENCES admin_permissions (id) ON DELETE CASCADE,
        PRIMARY KEY (role_id, permission_id)
    );

-- Admin user-roles join table
CREATE TABLE
    admin_user_roles (
        user_id UUID NOT NULL REFERENCES admin_users (id) ON DELETE CASCADE,
        role_id UUID NOT NULL REFERENCES admin_roles (id) ON DELETE CASCADE,
        PRIMARY KEY (user_id, role_id)
    );