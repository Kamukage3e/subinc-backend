package architecture

import (
	"context"
	"net/http"
	"strconv"

	"github.com/gofiber/fiber/v2"
	"github.com/subinc/subinc-backend/internal/architecture/types"
)

type Handler struct {
	service Service
}

func NewHandler(service Service) *Handler {
	return &Handler{service: service}
}

func (h *Handler) RegisterRoutes(router fiber.Router) {
	arch := router.Group("/architecture")
	arch.Get("/docs", h.ListDocs)
	arch.Post("/docs/generate", h.GenerateDoc)
	arch.Get("/docs/:id", h.GetDoc)
	arch.Get("/diagrams", h.ListDiagrams)
	arch.Post("/diagrams/generate", h.GenerateDiagram)
	arch.Get("/diagrams/:id", h.GetDiagram)
}

func (h *Handler) ListDocs(c *fiber.Ctx) error {
	tenantID := c.Locals("tenant_id").(string)
	projectID := c.Locals("project_id").(string)
	limit, _ := strconv.Atoi(c.Query("limit", "20"))
	offset, _ := strconv.Atoi(c.Query("offset", "0"))
	docs, err := h.service.ListDocs(context.Background(), tenantID, projectID, limit, offset)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "failed to list docs"})
	}
	var results []fiber.Map
	for _, doc := range docs {
		graph, gerr := h.service.GetArchitectureGraph(context.Background(), doc)
		if gerr != nil {
			if gerr.Error() == "graph retrieval not implemented: graph data not stored with doc" {
				graph = &types.ArchitectureGraph{Nodes: []types.ResourceNode{}, Edges: []types.ResourceEdge{}}
			} else {
				return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "failed to load graph for doc", "doc_id": doc.ID})
			}
		}
		results = append(results, fiber.Map{"doc": doc, "graph": graph})
	}
	return c.JSON(results)
}

func (h *Handler) GetDoc(c *fiber.Ctx) error {
	tenantID := c.Locals("tenant_id").(string)
	projectID := c.Locals("project_id").(string)
	docID := c.Params("id")
	doc, err := h.service.GetDoc(context.Background(), tenantID, projectID, docID)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "failed to get doc"})
	}
	if doc == nil {
		return c.Status(http.StatusNotFound).JSON(fiber.Map{"error": "doc not found"})
	}
	graph, gerr := h.service.GetArchitectureGraph(context.Background(), doc)
	if gerr != nil {
		if gerr.Error() == "graph retrieval not implemented: graph data not stored with doc" {
			graph = &types.ArchitectureGraph{Nodes: []types.ResourceNode{}, Edges: []types.ResourceEdge{}}
		} else {
			return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "failed to load graph for doc", "doc_id": doc.ID})
		}
	}
	return c.JSON(fiber.Map{"doc": doc, "graph": graph})
}

func (h *Handler) GenerateDoc(c *fiber.Ctx) error {
	tenantID := c.Locals("tenant_id").(string)
	projectID := c.Locals("project_id").(string)
	userID := c.Locals("user_id").(string)
	var req struct {
		Format string                   `json:"format"`
		Graph  *types.ArchitectureGraph `json:"graph"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "invalid request body"})
	}
	doc, err := h.service.GenerateDoc(context.Background(), tenantID, projectID, userID, req.Format, req.Graph)
	if err != nil {
		return c.Status(http.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.Status(http.StatusCreated).JSON(fiber.Map{
		"doc":   doc,
		"graph": req.Graph,
	})
}

func (h *Handler) ListDiagrams(c *fiber.Ctx) error {
	tenantID := c.Locals("tenant_id").(string)
	projectID := c.Locals("project_id").(string)
	limit, _ := strconv.Atoi(c.Query("limit", "20"))
	offset, _ := strconv.Atoi(c.Query("offset", "0"))
	diagrams, err := h.service.ListDiagrams(context.Background(), tenantID, projectID, limit, offset)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "failed to list diagrams"})
	}
	return c.JSON(diagrams)
}

func (h *Handler) GetDiagram(c *fiber.Ctx) error {
	tenantID := c.Locals("tenant_id").(string)
	projectID := c.Locals("project_id").(string)
	diagramID := c.Params("id")
	diagram, err := h.service.GetDiagram(context.Background(), tenantID, projectID, diagramID)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "failed to get diagram"})
	}
	if diagram == nil {
		return c.Status(http.StatusNotFound).JSON(fiber.Map{"error": "diagram not found"})
	}
	return c.JSON(diagram)
}

func (h *Handler) GenerateDiagram(c *fiber.Ctx) error {
	tenantID := c.Locals("tenant_id").(string)
	projectID := c.Locals("project_id").(string)
	var req struct {
		DocID  string                   `json:"doc_id"`
		Format string                   `json:"format"`
		Graph  *types.ArchitectureGraph `json:"graph"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "invalid request body"})
	}
	diagram, err := h.service.GenerateDiagram(context.Background(), tenantID, projectID, req.DocID, req.Format, req.Graph)
	if err != nil {
		return c.Status(http.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.Status(http.StatusCreated).JSON(fiber.Map{
		"diagram": diagram,
		"graph":   req.Graph,
	})
}
