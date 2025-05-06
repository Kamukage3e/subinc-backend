-- Email Providers Table
CREATE TABLE
    IF NOT EXISTS email_providers (
        name VARCHAR(64) PRIMARY KEY,
        type VARCHAR(32) NOT NULL,
        host VARCHAR(255) NOT NULL,
        port INTEGER NOT NULL,
        username VARCHAR(255) NOT NULL,
        password VARCHAR(255) NOT NULL,
        email_from VARCHAR(255) NOT NULL,
        created_at TIMESTAMP
        WITH
            TIME ZONE DEFAULT now (),
            updated_at TIMESTAMP
        WITH
            TIME ZONE DEFAULT now ()
    );

-- Email Templates Table
CREATE TABLE
    IF NOT EXISTS email_templates (
        name VARCHAR(64) PRIMARY KEY,
        subject TEXT NOT NULL,
        body TEXT NOT NULL,
        created_at TIMESTAMP
        WITH
            TIME ZONE DEFAULT now (),
            updated_at TIMESTAMP
        WITH
            TIME ZONE DEFAULT now ()
    );