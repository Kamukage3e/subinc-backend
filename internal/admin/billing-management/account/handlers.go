package account

import (
	"context"
	"time"

	"github.com/gofiber/fiber/v2"

	security_management "github.com/subinc/subinc-backend/internal/admin/security-management"
	"github.com/subinc/subinc-backend/internal/pkg/commonutil"
	"github.com/subinc/subinc-backend/internal/pkg/logger"
)

func (h *AccountHandler) CreateAccount(c *fiber.Ctx) error {
	accountType := c.Query("type", "project")
	ctx := c.Context()
	var input interface{}
	switch accountType {
	case "user":
		input = &UserBillingAccount{}
	case "organization":
		input = &OrganizationBillingAccount{}
	default:
		input = &ProjectBillingAccount{}
	}
	if err := c.BodyParser(input); err != nil {
		logger.LogError("CreateAccount: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}

	now := time.Now().UTC()
	switch v := input.(type) {
	case *UserBillingAccount:
		v.ID = commonutil.GenerateUUID()
		v.CreatedAt = now
		v.UpdatedAt = now
	case *OrganizationBillingAccount:
		v.ID = commonutil.GenerateUUID()
		v.CreatedAt = now
		v.UpdatedAt = now
	case *ProjectBillingAccount:
		v.ID = commonutil.GenerateUUID()
		v.CreatedAt = now
		v.UpdatedAt = now
	}

	if v, ok := input.(interface{ Validate() *Error }); ok {
		if err := v.Validate(); err != nil {
			logger.LogError("CreateAccount: validation failed", logger.ErrorField(err))
			return c.JSON(fiber.ErrBadRequest)
		}
	}
	account, err := h.BillingAccountService.Create(ctx, BillingAccountType(accountType), input)
	if err != nil {
		logger.LogError("CreateAccount: failed", logger.ErrorField(err))
		return c.JSON(fiber.ErrExpectationFailed)
	}
	if h.NotificationService != nil && account != nil {
		go func(acct interface{}) {
			var email, id, status string
			var createdAt any
			switch a := acct.(type) {
			case *ProjectBillingAccount:
				email, id, status, createdAt = a.Email, a.ID, a.Status, a.CreatedAt
			case *UserBillingAccount:
				email, id, status, createdAt = a.Email, a.ID, a.Status, a.CreatedAt
			case *OrganizationBillingAccount:
				email, id, status, createdAt = a.Email, a.ID, a.Status, a.CreatedAt
			}
			if email != "" {
				details := map[string]any{
					"account_id":    id,
					"account_email": email,
					"status":        status,
					"created_at":    createdAt,
				}
				err := h.NotificationService.SendNotification(
					context.Background(),
					"",
					security_management.NotificationEmail,
					[]string{email},
					"account.created",
					details,
					3,
				)
				if err != nil {
					logger.LogError("CreateAccount: onboarding notification failed", logger.ErrorField(err), logger.String("account_id", id))
				}
			}
		}(account)
	}
	return c.Status(fiber.StatusCreated).JSON(account)
}

func (h *AccountHandler) UpdateAccount(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		logger.LogError("UpdateAccount: id required", logger.String("id", id))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "error occured"})
	}
	accountType := c.Query("type", "project")
	ctx := c.Context()
	var input interface{}
	switch accountType {
	case "user":
		input = &UserBillingAccount{}
	case "organization":
		input = &OrganizationBillingAccount{}
	default:
		input = &ProjectBillingAccount{}
	}
	if err := c.BodyParser(input); err != nil {
		logger.LogError("UpdateAccount: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	switch v := input.(type) {
	case *UserBillingAccount:
		v.ID = id
	case *OrganizationBillingAccount:
		v.ID = id
	case *ProjectBillingAccount:
		v.ID = id
	}
	if v, ok := input.(interface{ Validate() *Error }); ok {
		if err := v.Validate(); err != nil {
			logger.LogError("UpdateAccount: validation failed", logger.ErrorField(err))
			return c.JSON(fiber.ErrBadRequest)
		}
	}
	account, err := h.BillingAccountService.Update(ctx, BillingAccountType(accountType), input)
	if err != nil {
		logger.LogError("UpdateAccount: failed", logger.ErrorField(err))
		return c.JSON(fiber.ErrExpectationFailed)
	}
	return c.JSON(account)
}

func (h *AccountHandler) GetAccount(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		logger.LogError("GetAccount: id required", logger.String("id", id))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "error occured"})
	}
	accountType := c.Query("type", "project")
	ctx := c.Context()
	account, err := h.BillingAccountService.Get(ctx, BillingAccountType(accountType), id)
	if err != nil {
		logger.LogError("GetAccount: not found", logger.ErrorField(err))
		return c.JSON(fiber.ErrNotFound)
	}
	return c.JSON(account)
}

func (h *AccountHandler) ListAccounts(c *fiber.Ctx) error {
	accountType := c.Query("type", "project")
	var ownerID string
	switch accountType {
	case "project":
		ownerID = c.Query("project_id")
	case "user":
		ownerID = c.Query("user_id")
	case "organization":
		ownerID = c.Query("org_id")
	default:
		ownerID = ""
	}
	page := c.QueryInt("page", 1)
	pageSize := c.QueryInt("page_size", 100)
	ctx := c.Context()
	accounts, err := h.BillingAccountService.List(ctx, BillingAccountType(accountType), ownerID, page, pageSize)
	if err != nil {
		logger.LogError("ListAccounts: failed", logger.ErrorField(err), logger.String("owner_id", ownerID))
		return c.JSON(fiber.ErrExpectationFailed)
	}
	if accounts == nil {
		accounts = make([]interface{}, 0)
	}
	return c.JSON(fiber.Map{"accounts": accounts, "page": page, "page_size": pageSize})
}

func (h *AccountHandler) PerformAccountAction(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		logger.LogError("PerformAccountAction: id required", logger.String("id", id))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "error occured"})
	}
	accountType := c.Query("type", "project")
	var input struct {
		Action string         `json:"action"`
		Params map[string]any `json:"params"`
	}
	if err := c.BodyParser(&input); err != nil || input.Action == "" {
		logger.LogError("PerformAccountAction: action required", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "action required"})
	}
	ctx := c.Context()
	result, err := h.BillingAccountService.PerformAction(ctx, BillingAccountType(accountType), id, input.Action, input.Params)
	if err != nil {
		logger.LogError("PerformAccountAction: failed", logger.ErrorField(err), logger.String("account_id", id), logger.String("action", input.Action))
		return c.JSON(fiber.ErrExpectationFailed)
	}
	if result == nil {
		result = fiber.Map{"action": input.Action, "status": "no result"}
	}
	return c.Status(fiber.StatusOK).JSON(result)
}

func (h *AccountHandler) DeleteAccount(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		logger.LogError("DeleteAccount: id required", logger.String("id", id))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "error occured"})
	}
	accountType := c.Query("type", "project")
	ctx := c.Context()
	if err := h.BillingAccountService.Delete(ctx, BillingAccountType(accountType), id); err != nil {
		logger.LogError("DeleteAccount: failed", logger.ErrorField(err), logger.String("account_id", id))
		return c.JSON(fiber.ErrExpectationFailed)
	}
	return c.SendStatus(fiber.StatusNoContent)
}
