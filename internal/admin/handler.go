package admin

import (
	"github.com/gofiber/fiber/v2"
)

// AdminStore defines the interface for admin data access
// Must be implemented by any admin storage backend
// All methods must be production-ready and secure

type AdminStore interface {
	ListUsers() ([]interface{}, error)
	ListTenants() ([]interface{}, error)
	ListAuditLogs() ([]interface{}, error)
}

// Only production-grade AdminStore implementations are supported. No in-memory or dev/test stores.

// AdminHandler handles admin-related endpoints
// Modular, SaaS-grade, handler-based routing
// All endpoints must be production-ready and secure

type AdminHandler struct {
	store AdminStore
}

func NewHandler(store AdminStore) *AdminHandler {
	return &AdminHandler{store: store}
}

func (h *AdminHandler) RegisterRoutes(router fiber.Router) {
	admin := router.Group("/admin")

	admin.Get("/users", h.ListUsers)
	admin.Get("/tenants", h.ListTenants)
	admin.Get("/audit", h.ListAuditLogs)
	// Add more admin endpoints as needed
}

func (h *AdminHandler) ListUsers(c *fiber.Ctx) error {
	users, err := h.store.ListUsers()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to fetch users"})
	}
	return c.Status(fiber.StatusOK).JSON(users)
}

func (h *AdminHandler) ListTenants(c *fiber.Ctx) error {
	tenants, err := h.store.ListTenants()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to fetch tenants"})
	}
	return c.Status(fiber.StatusOK).JSON(tenants)
}

func (h *AdminHandler) ListAuditLogs(c *fiber.Ctx) error {
	logs, err := h.store.ListAuditLogs()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to fetch audit logs"})
	}
	return c.Status(fiber.StatusOK).JSON(logs)
}
