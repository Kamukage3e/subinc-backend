package architecture

import (
	"net/http"
	"strconv"

	"github.com/gofiber/fiber/v2"

	"github.com/subinc/subinc-backend/internal/pkg/logger"
)

func NewHandler(service Service, logger logger.Logger) *Handler {
	return &Handler{service: service, logger: logger}
}

func (h *Handler) ListDocs(c *fiber.Ctx) error {
	tenantID := c.Locals("tenant_id").(string)
	projectID := c.Locals("project_id").(string)
	limit, _ := strconv.Atoi(c.Query("limit", "20"))
	offset, _ := strconv.Atoi(c.Query("offset", "0"))
	docs, err := h.service.ListDocs(c.Context(), tenantID, projectID, limit, offset)
	if err != nil {
		h.logger.Error("failed to list docs", logger.ErrorField(err))
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "internal server error"})
	}
	var results []fiber.Map
	for _, doc := range docs {
		graph, gerr := h.service.GetArchitectureGraph(c.Context(), doc)
		if gerr != nil {
			if gerr.Error() == "graph retrieval not implemented: graph data not stored with doc" {
				graph = &ArchitectureGraph{Nodes: []ResourceNode{}, Edges: []ResourceEdge{}}
			} else {
				h.logger.Error("failed to load graph for doc", logger.ErrorField(gerr), logger.String("doc_id", doc.ID))
				return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "internal server error"})
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
	doc, err := h.service.GetDoc(c.Context(), tenantID, projectID, docID)
	if err != nil {
		h.logger.Error("failed to get doc", logger.ErrorField(err))
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "internal server error"})
	}
	if doc == nil {
		return c.Status(http.StatusNotFound).JSON(fiber.Map{"error": "doc not found"})
	}
	graph, gerr := h.service.GetArchitectureGraph(c.Context(), doc)
	if gerr != nil {
		if gerr.Error() == "graph retrieval not implemented: graph data not stored with doc" {
			graph = &ArchitectureGraph{Nodes: []ResourceNode{}, Edges: []ResourceEdge{}}
		} else {
			h.logger.Error("failed to load graph for doc", logger.ErrorField(gerr), logger.String("doc_id", doc.ID))
			return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "internal server error"})
		}
	}
	return c.JSON(fiber.Map{"doc": doc, "graph": graph})
}

func (h *Handler) GenerateDoc(c *fiber.Ctx) error {
	tenantID := c.Locals("tenant_id").(string)
	projectID := c.Locals("project_id").(string)
	userID := c.Locals("user_id").(string)
	var req struct {
		Format string             `json:"format"`
		Graph  *ArchitectureGraph `json:"graph"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "invalid request body"})
	}
	doc, err := h.service.GenerateDoc(c.Context(), tenantID, projectID, userID, req.Format, req.Graph)
	if err != nil {
		h.logger.Error("failed to generate doc", logger.ErrorField(err))
		return c.Status(http.StatusUnprocessableEntity).JSON(fiber.Map{"error": "unprocessable entity"})
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
	diagrams, err := h.service.ListDiagrams(c.Context(), tenantID, projectID, limit, offset)
	if err != nil {
		h.logger.Error("failed to list diagrams", logger.ErrorField(err))
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "internal server error"})
	}
	return c.JSON(diagrams)
}

func (h *Handler) GetDiagram(c *fiber.Ctx) error {
	tenantID := c.Locals("tenant_id").(string)
	projectID := c.Locals("project_id").(string)
	diagramID := c.Params("id")
	diagram, err := h.service.GetDiagram(c.Context(), tenantID, projectID, diagramID)
	if err != nil {
		h.logger.Error("failed to get diagram", logger.ErrorField(err))
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "internal server error"})
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
		DocID  string             `json:"doc_id"`
		Format string             `json:"format"`
		Graph  *ArchitectureGraph `json:"graph"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "invalid request body"})
	}
	diagram, err := h.service.GenerateDiagram(c.Context(), tenantID, projectID, req.DocID, req.Format, req.Graph)
	if err != nil {
		h.logger.Error("failed to generate diagram", logger.ErrorField(err))
		return c.Status(http.StatusUnprocessableEntity).JSON(fiber.Map{"error": "unprocessable entity"})
	}
	return c.Status(http.StatusCreated).JSON(fiber.Map{
		"diagram": diagram,
		"graph":   req.Graph,
	})
}

func (h *Handler) Healthz(c *fiber.Ctx) error {
	// Example: check DB and Redis health if available
	ctx := c.Context()
	var dbOK, redisOK bool
	if h.service != nil {
		dbOK = h.service.PingDB(ctx) == nil
		redisOK = h.service.PingRedis(ctx) == nil
	}
	if !dbOK || !redisOK {
		return c.Status(http.StatusServiceUnavailable).JSON(fiber.Map{"db": dbOK, "redis": redisOK, "status": "unhealthy"})
	}
	return c.JSON(fiber.Map{"db": dbOK, "redis": redisOK, "status": "ok"})
}

func (h *Handler) Readyz(c *fiber.Ctx) error {
	// Ready if DB and Redis are up
	ctx := c.Context()
	if h.service == nil || h.service.PingDB(ctx) != nil || h.service.PingRedis(ctx) != nil {
		return c.Status(http.StatusServiceUnavailable).JSON(fiber.Map{"ready": false})
	}
	return c.JSON(fiber.Map{"ready": true})
}

func (h *Handler) Version(c *fiber.Ctx) error {
	return c.JSON(fiber.Map{
		"version":    BuildVersion,
		"commit":     BuildCommit,
		"build_time": BuildTime,
	})
}
