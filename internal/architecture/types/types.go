package types

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
