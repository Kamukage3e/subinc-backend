package account

import (
	"context"

	"github.com/gofiber/fiber/v2"

	security_management "github.com/subinc/subinc-backend/internal/admin/security-management"
	commonutil "github.com/subinc/subinc-backend/internal/pkg/commonutil"
	"github.com/subinc/subinc-backend/internal/pkg/logger"
)

func (h *AccountHandler) CreateAccount(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := commonutil.GetActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "billing_account", "create")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input Account
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("CreateAccount: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if err := input.Validate(); err != nil {
		logger.LogError("CreateAccount: validation failed", logger.ErrorField(err))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Message, "code": err.Code, "field": err.Field})
	}
	account, err := h.AccountService.CreateAccount(input)
	if err != nil {
		logger.LogError("CreateAccount: failed", logger.ErrorField(err), logger.Any("input", input))
		errResp := fiber.Map{"error": err.Error()}
		if apiErr, ok := err.(interface {
			Message() string
			Code() string
			Field() string
		}); ok {
			errResp["error"] = apiErr.Message()
			errResp["code"] = apiErr.Code()
			errResp["field"] = apiErr.Field()
		}
		return c.Status(fiber.StatusUnprocessableEntity).JSON(errResp)
	}

	// --- Send onboarding notification (non-blocking) ---
	if h.NotificationService != nil && account.Email != "" {
		go func(acct Account) {
			details := map[string]interface{}{
				"account_id":    acct.ID,
				"account_email": acct.Email,
				"tenant_id":     acct.TenantID,
				"status":        acct.Status,
				"created_at":    acct.CreatedAt,
			}
			err := h.NotificationService.SendNotification(
				context.Background(),
				acct.TenantID,
				security_management.NotificationEmail,
				[]string{acct.Email},
				"account.created",
				details,
				3,
			)
			if err != nil {
				logger.LogError("CreateAccount: onboarding notification failed", logger.ErrorField(err), logger.String("account_id", acct.ID))
			}
		}(account)
	}

	return c.Status(fiber.StatusCreated).JSON(account)
}

func (h *AccountHandler) UpdateAccount(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := commonutil.GetActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "billing_account", "update")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	id := c.Params("id")
	if id == "" {
		logger.LogError("UpdateAccount: id required", logger.String("id", id))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	var input Account
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("UpdateAccount: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	input.ID = id
	if err := input.Validate(); err != nil {
		logger.LogError("UpdateAccount: validation failed", logger.ErrorField(err))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Message, "code": err.Code, "field": err.Field})
	}
	account, err := h.AccountService.UpdateAccount(input)
	if err != nil {
		logger.LogError("UpdateAccount: failed", logger.ErrorField(err), logger.Any("input", input))
		errResp := fiber.Map{"error": err.Error()}
		if apiErr, ok := err.(interface {
			Message() string
			Code() string
			Field() string
		}); ok {
			errResp["error"] = apiErr.Message()
			errResp["code"] = apiErr.Code()
			errResp["field"] = apiErr.Field()
		}
		return c.Status(fiber.StatusUnprocessableEntity).JSON(errResp)
	}
	return c.JSON(account)
}

func (h *AccountHandler) GetAccount(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := commonutil.GetActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "billing_account", "read")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	id := c.Params("id")
	if id == "" {
		logger.LogError("GetAccount: id required", logger.String("id", id))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	account, err := h.AccountService.GetAccount(id)
	if err != nil {
		logger.LogError("GetAccount: not found", logger.ErrorField(err))
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(account)
}

func (h *AccountHandler) ListAccounts(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := commonutil.GetActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "billing_account", "list")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	tenantID := c.Query("tenant_id")
	page := c.QueryInt("page", 1)
	pageSize := c.QueryInt("page_size", 100)
	accounts, err := h.AccountService.ListAccounts(tenantID, page, pageSize)
	if err != nil {
		logger.LogError("ListAccounts: failed", logger.ErrorField(err), logger.String("tenant_id", tenantID))
		errResp := fiber.Map{"error": err.Error()}
		if apiErr, ok := err.(interface {
			Message() string
			Code() string
			Field() string
		}); ok {
			errResp["error"] = apiErr.Message()
			errResp["code"] = apiErr.Code()
			errResp["field"] = apiErr.Field()
		}
		return c.Status(fiber.StatusUnprocessableEntity).JSON(errResp)
	}
	return c.JSON(fiber.Map{"accounts": accounts, "page": page, "page_size": pageSize})
}

func (h *AccountHandler) PerformAccountAction(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := commonutil.GetActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "account_action", "perform")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	id := c.Params("id")
	if id == "" {
		logger.LogError("PerformAccountAction: id required", logger.String("id", id))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	var input struct {
		Action string                 `json:"action"`
		Params map[string]interface{} `json:"params"`
	}
	if err := c.BodyParser(&input); err != nil || input.Action == "" {
		logger.LogError("PerformAccountAction: action required", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "action required"})
	}
	result, err := h.AccountService.PerformAccountAction(c.Context(), id, input.Action, input.Params)
	if err != nil {
		logger.LogError("PerformAccountAction: failed", logger.ErrorField(err), logger.String("account_id", id), logger.String("action", input.Action))
		errResp := fiber.Map{"error": err.Error()}
		if apiErr, ok := err.(*Error); ok {
			errResp["error"] = apiErr.Message
			errResp["code"] = apiErr.Code
			errResp["field"] = apiErr.Field
		}
		return c.Status(fiber.StatusUnprocessableEntity).JSON(errResp)
	}
	return c.Status(fiber.StatusOK).JSON(result)
}
