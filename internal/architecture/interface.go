package architecture

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
)

// AWSResourceInventory abstracts AWS resource inventory for testability and no import cycle
// Real prod interface, no placeholders

type AWSResourceInventory interface {
	GetCredentials(ctx context.Context, tenantID string) (map[string]string, error)
	GetAccountID(ctx context.Context, tenantID string) (string, error)
	ListResources(ctx context.Context, accountID string, credentials map[string]string) ([]ResourceNode, error)
}

type Repository interface {
	CreateDoc(ctx context.Context, doc *ArchitectureDoc) error
	GetDoc(ctx context.Context, tenantID, projectID, docID string) (*ArchitectureDoc, error)
	ListDocs(ctx context.Context, tenantID, projectID string, limit, offset int) ([]*ArchitectureDoc, error)
	GetLatestDoc(ctx context.Context, tenantID, projectID string) (*ArchitectureDoc, error)
	CreateDiagram(ctx context.Context, diagram *ArchitectureDiagram) error
	GetDiagram(ctx context.Context, tenantID, projectID, diagramID string) (*ArchitectureDiagram, error)
	ListDiagrams(ctx context.Context, tenantID, projectID string, limit, offset int) ([]*ArchitectureDiagram, error)
	PingDB(ctx context.Context) error
	PingRedis(ctx context.Context) error
}

type Service interface {
	GenerateDoc(ctx context.Context, tenantID, projectID, createdBy, format string, graph *ArchitectureGraph) (*ArchitectureDoc, error)
	GetDoc(ctx context.Context, tenantID, projectID, docID string) (*ArchitectureDoc, error)
	ListDocs(ctx context.Context, tenantID, projectID string, limit, offset int) ([]*ArchitectureDoc, error)
	GenerateDiagram(ctx context.Context, tenantID, projectID, docID, format string, graph *ArchitectureGraph) (*ArchitectureDiagram, error)
	GetDiagram(ctx context.Context, tenantID, projectID, diagramID string) (*ArchitectureDiagram, error)
	ListDiagrams(ctx context.Context, tenantID, projectID string, limit, offset int) ([]*ArchitectureDiagram, error)
	GenerateDocAuto(ctx context.Context, tenantID, projectID, createdBy, format string, inv AWSResourceInventory) (*ArchitectureDoc, error)
	GetArchitectureGraph(ctx context.Context, doc *ArchitectureDoc) (*ArchitectureGraph, error)
	PingDB(ctx context.Context) error
	PingRedis(ctx context.Context) error
}

type DynamicServiceAPI interface {
	ListResources(ctx context.Context, cfg aws.Config) ([]ResourceNode, error)
}
