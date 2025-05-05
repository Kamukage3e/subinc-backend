-- Architecture Docs Table
CREATE TABLE
    IF NOT EXISTS architecture_docs (
        id UUID PRIMARY KEY,
        tenant_id UUID NOT NULL,
        project_id UUID NOT NULL,
        version INT NOT NULL,
        created_at TIMESTAMPTZ NOT NULL,
        created_by UUID NOT NULL,
        format TEXT NOT NULL,
        export_url TEXT,
        diagram_id UUID,
        resource_hash TEXT NOT NULL,
        graph_data BYTEA,
        UNIQUE (tenant_id, project_id, version)
    );

-- Architecture Diagrams Table
CREATE TABLE
    IF NOT EXISTS architecture_diagrams (
        id UUID PRIMARY KEY,
        doc_id UUID NOT NULL REFERENCES architecture_docs (id) ON DELETE CASCADE,
        tenant_id UUID NOT NULL,
        project_id UUID NOT NULL,
        format TEXT NOT NULL,
        created_at TIMESTAMPTZ NOT NULL,
        export_url TEXT,
        graph_data BYTEA NOT NULL
    );