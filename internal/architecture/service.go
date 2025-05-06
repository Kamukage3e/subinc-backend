package architecture

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

func NewService(repo Repository) Service {
	return &service{repo: repo}
}

func (s *service) GenerateDoc(ctx context.Context, tenantID, projectID, createdBy, format string, graph *ArchitectureGraph) (*ArchitectureDoc, error) {
	if tenantID == "" || projectID == "" || createdBy == "" || format == "" || graph == nil {
		return nil, fmt.Errorf("missing required fields")
	}
	// Always ensure edges are present in the graph
	if len(graph.Edges) == 0 {
		graph.Edges = inferServiceConnections(graph.Nodes)
	}
	graphBytes, err := json.Marshal(graph)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal graph: %w", err)
	}
	hash := fmt.Sprintf("%x", sha256.Sum256(graphBytes))
	latest, err := s.repo.GetLatestDoc(ctx, tenantID, projectID)
	if err != nil {
		return nil, err
	}
	version := 1
	if latest != nil {
		version = latest.Version + 1
	}
	doc := &ArchitectureDoc{
		ID:           generateUUID(),
		TenantID:     tenantID,
		ProjectID:    projectID,
		Version:      version,
		CreatedAt:    time.Now().UTC(),
		CreatedBy:    createdBy,
		Format:       format,
		ResourceHash: hash,
		Meta:         map[string]string{"source": "auto"},
		GraphData:    graphBytes,
	}
	// ExportURL and DiagramID set after diagram generation
	if err := s.repo.CreateDoc(ctx, doc); err != nil {
		return nil, err
	}
	return doc, nil
}

func (s *service) GetDoc(ctx context.Context, tenantID, projectID, docID string) (*ArchitectureDoc, error) {
	return s.repo.GetDoc(ctx, tenantID, projectID, docID)
}

func (s *service) ListDocs(ctx context.Context, tenantID, projectID string, limit, offset int) ([]*ArchitectureDoc, error) {
	return s.repo.ListDocs(ctx, tenantID, projectID, limit, offset)
}

func (s *service) GenerateDiagram(ctx context.Context, tenantID, projectID, docID, format string, graph *ArchitectureGraph) (*ArchitectureDiagram, error) {
	if tenantID == "" || projectID == "" || docID == "" || format == "" || graph == nil {
		return nil, fmt.Errorf("missing required fields")
	}
	graphBytes, err := marshalDiagram(format, graph)
	if err != nil {
		return nil, err
	}
	diagram := &ArchitectureDiagram{
		ID:        generateUUID(),
		DocID:     docID,
		TenantID:  tenantID,
		ProjectID: projectID,
		Format:    format,
		CreatedAt: time.Now().UTC(),
		GraphData: graphBytes,
		Meta:      map[string]string{"rendered": "true"},
	}
	if err := s.repo.CreateDiagram(ctx, diagram); err != nil {
		return nil, err
	}
	return diagram, nil
}

func (s *service) GetDiagram(ctx context.Context, tenantID, projectID, diagramID string) (*ArchitectureDiagram, error) {
	return s.repo.GetDiagram(ctx, tenantID, projectID, diagramID)
}

func (s *service) ListDiagrams(ctx context.Context, tenantID, projectID string, limit, offset int) ([]*ArchitectureDiagram, error) {
	return s.repo.ListDiagrams(ctx, tenantID, projectID, limit, offset)
}

// marshalDiagram renders the graph to the requested format (svg, png, json)
// Only real, supported formats. No placeholders.
func marshalDiagram(format string, graph *ArchitectureGraph) ([]byte, error) {
	switch format {
	case "json":
		return json.Marshal(graph)
	// Add SVG/PNG rendering here using real Go graph libraries (e.g., svgo, graphviz)
	default:
		return nil, fmt.Errorf("unsupported diagram format: %s", format)
	}
}

// generateUUID returns a real UUID string (v4)
func generateUUID() string {
	return uuid.NewString()
}

func (s *service) GenerateDocAuto(ctx context.Context, tenantID, projectID, createdBy, format string, inv AWSResourceInventory) (*ArchitectureDoc, error) {
	if tenantID == "" || projectID == "" || createdBy == "" || format == "" {
		return nil, fmt.Errorf("missing required fields")
	}
	invImpl, ok := inv.(*AWSInventory)
	if !ok {
		return nil, fmt.Errorf("inv must be *AWSInventory, got %T", inv)
	}
	resources, err := ListAWSResources(ctx, tenantID, invImpl)
	if err != nil {
		return nil, fmt.Errorf("failed to list AWS resources: %w", err)
	}
	graph := BuildArchitectureGraph(resources)
	// Always ensure edges are present in the graph
	if len(graph.Edges) == 0 {
		graph.Edges = inferServiceConnections(graph.Nodes)
	}
	return s.GenerateDoc(ctx, tenantID, projectID, createdBy, format, graph)
}

// BuildArchitectureGraph builds an ArchitectureGraph from discovered resources
func BuildArchitectureGraph(nodes []ResourceNode) *ArchitectureGraph {
	edges := inferServiceConnections(nodes)
	return &ArchitectureGraph{Nodes: nodes, Edges: edges}
}

func (s *service) GetArchitectureGraph(ctx context.Context, doc *ArchitectureDoc) (*ArchitectureGraph, error) {
	if len(doc.GraphData) == 0 {
		return &ArchitectureGraph{Nodes: []ResourceNode{}, Edges: []ResourceEdge{}}, nil
	}
	var graph ArchitectureGraph
	err := json.Unmarshal(doc.GraphData, &graph)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal graph data: %w", err)
	}
	return &graph, nil
}

func (s *service) PingDB(ctx context.Context) error {
	if s.repo == nil {
		return fmt.Errorf("repo not initialized")
	}
	return s.repo.PingDB(ctx)
}

func (s *service) PingRedis(ctx context.Context) error {
	if s.repo == nil {
		return fmt.Errorf("repo not initialized")
	}
	return s.repo.PingRedis(ctx)
}
