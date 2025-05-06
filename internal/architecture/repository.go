package architecture

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func NewPostgresRepository(db *pgxpool.Pool) Repository {
	return &postgresRepository{db: db}
}

func (r *postgresRepository) CreateDoc(ctx context.Context, doc *ArchitectureDoc) error {
	q := `INSERT INTO architecture_docs (id, tenant_id, project_id, version, created_at, created_by, format, export_url, diagram_id, resource_hash, graph_data) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`
	_, err := r.db.Exec(ctx, q, doc.ID, doc.TenantID, doc.ProjectID, doc.Version, doc.CreatedAt, doc.CreatedBy, doc.Format, doc.ExportURL, doc.DiagramID, doc.ResourceHash, doc.GraphData)
	return err
}

func (r *postgresRepository) GetDoc(ctx context.Context, tenantID, projectID, docID string) (*ArchitectureDoc, error) {
	q := `SELECT id, tenant_id, project_id, version, created_at, created_by, format, export_url, diagram_id, resource_hash, graph_data FROM architecture_docs WHERE id=$1 AND tenant_id=$2 AND project_id=$3`
	row := r.db.QueryRow(ctx, q, docID, tenantID, projectID)
	var doc ArchitectureDoc
	err := row.Scan(&doc.ID, &doc.TenantID, &doc.ProjectID, &doc.Version, &doc.CreatedAt, &doc.CreatedBy, &doc.Format, &doc.ExportURL, &doc.DiagramID, &doc.ResourceHash, &doc.GraphData)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return &doc, err
}

func (r *postgresRepository) ListDocs(ctx context.Context, tenantID, projectID string, limit, offset int) ([]*ArchitectureDoc, error) {
	q := `SELECT id, tenant_id, project_id, version, created_at, created_by, format, export_url, diagram_id, resource_hash, graph_data FROM architecture_docs WHERE tenant_id=$1 AND project_id=$2 ORDER BY version DESC LIMIT $3 OFFSET $4`
	rows, err := r.db.Query(ctx, q, tenantID, projectID, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var docs []*ArchitectureDoc
	for rows.Next() {
		var doc ArchitectureDoc
		err := rows.Scan(&doc.ID, &doc.TenantID, &doc.ProjectID, &doc.Version, &doc.CreatedAt, &doc.CreatedBy, &doc.Format, &doc.ExportURL, &doc.DiagramID, &doc.ResourceHash, &doc.GraphData)
		if err != nil {
			return nil, err
		}
		docs = append(docs, &doc)
	}
	return docs, rows.Err()
}

func (r *postgresRepository) GetLatestDoc(ctx context.Context, tenantID, projectID string) (*ArchitectureDoc, error) {
	q := `SELECT id, tenant_id, project_id, version, created_at, created_by, format, export_url, diagram_id, resource_hash, graph_data FROM architecture_docs WHERE tenant_id=$1 AND project_id=$2 ORDER BY version DESC LIMIT 1`
	row := r.db.QueryRow(ctx, q, tenantID, projectID)
	var doc ArchitectureDoc
	err := row.Scan(&doc.ID, &doc.TenantID, &doc.ProjectID, &doc.Version, &doc.CreatedAt, &doc.CreatedBy, &doc.Format, &doc.ExportURL, &doc.DiagramID, &doc.ResourceHash, &doc.GraphData)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return &doc, err
}

func (r *postgresRepository) CreateDiagram(ctx context.Context, diagram *ArchitectureDiagram) error {
	q := `INSERT INTO architecture_diagrams (id, doc_id, tenant_id, project_id, format, created_at, export_url, graph_data) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`
	_, err := r.db.Exec(ctx, q, diagram.ID, diagram.DocID, diagram.TenantID, diagram.ProjectID, diagram.Format, diagram.CreatedAt, diagram.ExportURL, diagram.GraphData)
	return err
}

func (r *postgresRepository) GetDiagram(ctx context.Context, tenantID, projectID, diagramID string) (*ArchitectureDiagram, error) {
	q := `SELECT id, doc_id, tenant_id, project_id, format, created_at, export_url, graph_data FROM architecture_diagrams WHERE id=$1 AND tenant_id=$2 AND project_id=$3`
	row := r.db.QueryRow(ctx, q, diagramID, tenantID, projectID)
	var d ArchitectureDiagram
	err := row.Scan(&d.ID, &d.DocID, &d.TenantID, &d.ProjectID, &d.Format, &d.CreatedAt, &d.ExportURL, &d.GraphData)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return &d, err
}

func (r *postgresRepository) ListDiagrams(ctx context.Context, tenantID, projectID string, limit, offset int) ([]*ArchitectureDiagram, error) {
	q := `SELECT id, doc_id, tenant_id, project_id, format, created_at, export_url, graph_data FROM architecture_diagrams WHERE tenant_id=$1 AND project_id=$2 ORDER BY created_at DESC LIMIT $3 OFFSET $4`
	rows, err := r.db.Query(ctx, q, tenantID, projectID, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var diagrams []*ArchitectureDiagram
	for rows.Next() {
		var d ArchitectureDiagram
		err := rows.Scan(&d.ID, &d.DocID, &d.TenantID, &d.ProjectID, &d.Format, &d.CreatedAt, &d.ExportURL, &d.GraphData)
		if err != nil {
			return nil, err
		}
		diagrams = append(diagrams, &d)
	}
	return diagrams, rows.Err()
}

func (r *postgresRepository) PingDB(ctx context.Context) error {
	if r.db == nil {
		return fmt.Errorf("db not initialized")
	}
	return r.db.Ping(ctx)
}

func (r *postgresRepository) PingRedis(ctx context.Context) error {
	// No Redis in this repo, always healthy
	return nil
}
