package architecture

import (
	"time"
)

// ArchitectureDoc represents a versioned architecture document for a tenant/project
// All fields are required for SaaS-grade multi-tenant support
// No sensitive info, no placeholders

type ArchitectureDoc struct {
	ID           string            `json:"id" gorm:"primaryKey"`
	TenantID     string            `json:"tenant_id" gorm:"index"`
	ProjectID    string            `json:"project_id" gorm:"index"`
	Version      int               `json:"version"`
	CreatedAt    time.Time         `json:"created_at"`
	CreatedBy    string            `json:"created_by"`
	Format       string            `json:"format"` // pdf, json, md, etc.
	ExportURL    string            `json:"export_url"`
	DiagramID    string            `json:"diagram_id" gorm:"index"`
	ResourceHash string            `json:"resource_hash" gorm:"index"` // for dedup/versioning
	Meta         map[string]string `json:"meta" gorm:"-"`
	GraphData    []byte            `json:"-" gorm:"type:bytea"` // stores full ArchitectureGraph JSON for round-tripping
}

// ArchitectureDiagram represents a rendered diagram (SVG/PNG/JSON) for a doc/version
// No sensitive info, no placeholders

type ArchitectureDiagram struct {
	ID        string            `json:"id" gorm:"primaryKey"`
	DocID     string            `json:"doc_id" gorm:"index"`
	TenantID  string            `json:"tenant_id" gorm:"index"`
	ProjectID string            `json:"project_id" gorm:"index"`
	Format    string            `json:"format"` // svg, png, json
	CreatedAt time.Time         `json:"created_at"`
	ExportURL string            `json:"export_url"`
	GraphData []byte            `json:"-" gorm:"type:bytea"` // raw graph data (for SVG/PNG/JSON)
	Meta      map[string]string `json:"meta" gorm:"-"`
}
