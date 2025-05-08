-- Add permissions JSONB column to admin_roles for flexible RBAC
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name='admin_roles' AND column_name='permissions'
    ) THEN
        ALTER TABLE admin_roles ADD COLUMN permissions JSONB NOT NULL DEFAULT '[]';
    END IF;
END $$;