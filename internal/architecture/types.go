package architecture

import (
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/subinc/subinc-backend/internal/pkg/logger"
)

// ResourceNode represents a cloud resource in the architecture graph
// Used for graph construction and export

type ResourceNode struct {
	ID         string            `json:"id"`
	Type       string            `json:"type"`
	Provider   string            `json:"provider"`
	Name       string            `json:"name"`
	Properties map[string]string `json:"properties"`
}

// ResourceEdge represents a relationship between resources

type ResourceEdge struct {
	SourceID string `json:"source_id"`
	TargetID string `json:"target_id"`
	Type     string `json:"type"`
}

// ArchitectureGraph is the in-memory graph for doc/diagram generation

type ArchitectureGraph struct {
	Nodes []ResourceNode `json:"nodes"`
	Edges []ResourceEdge `json:"edges"`
}

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

type Handler struct {
	service Service
	logger  logger.Logger
}

var (
	BuildVersion = "dev"
	BuildCommit  = "none"
	BuildTime    = "unknown"
)

type postgresRepository struct {
	db *pgxpool.Pool
}

type service struct {
	repo Repository
}

type AWSInventory struct {
	Logger *logger.Logger
}
