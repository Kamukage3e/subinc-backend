package billing_management

import (
	"bytes"
	"context"
	"fmt"
	"time"

	"encoding/json"

	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/jung-kurt/gofpdf"
	viper "github.com/spf13/viper"
	"github.com/subinc/subinc-backend/internal/admin/billing-management/payment"
	paymentpkg "github.com/subinc/subinc-backend/internal/admin/billing-management/payment"
	security_management "github.com/subinc/subinc-backend/internal/admin/security-management"
	"github.com/subinc/subinc-backend/internal/pkg/logger"
)

// All connection strings are stored in the viper config here
func getStripeWebhookSecret() string {
	return viper.GetString("stripe.webhook_secret")
}

// Helper to serialize details to string for audit logs
func auditDetails(v interface{}) string {
	if s, ok := v.(string); ok {
		return s
	}
	b, err := json.Marshal(v)
	if err != nil {
		return "{}"
	}
	return string(b)
}

// getActorID extracts the user_id from fiber context or returns "system" if not present
func getActorID(c *fiber.Ctx) string {
	id := c.Get("X-Actor-ID")
	if id != "" {
		return id
	}
	id = c.Get("X-User-ID")
	if id != "" {
		return id
	}
	return ""
}

func (h *BillingAdminHandler) CreateAccount(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := getActorID(c)
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
		if apiErr, ok := err.(*Error); ok {
			errResp["error"] = apiErr.Message
			errResp["code"] = apiErr.Code
			errResp["field"] = apiErr.Field
		}
		return c.Status(fiber.StatusUnprocessableEntity).JSON(errResp)
	}
	if h.AuditLogger != nil {
		_, err := h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        account.ID,
			ActorID:   getActorID(c),
			Action:    "create_account",
			TargetID:  account.ID,
			Details:   auditDetails(map[string]interface{}{"input": input}),
			CreatedAt: time.Now(),
		})
		if err != nil {
			logger.LogError("CreateAccount: audit log failed", logger.ErrorField(err))
		}
	}
	return c.Status(fiber.StatusCreated).JSON(account)
}

func (h *BillingAdminHandler) UpdateAccount(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := getActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "billing_account", "update")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input Account
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("UpdateAccount: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if err := input.Validate(); err != nil {
		logger.LogError("UpdateAccount: validation failed", logger.ErrorField(err))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Message, "code": err.Code, "field": err.Field})
	}
	account, err := h.AccountService.UpdateAccount(input)
	if err != nil {
		logger.LogError("UpdateAccount: failed", logger.ErrorField(err), logger.Any("input", input))
		errResp := fiber.Map{"error": err.Error()}
		if apiErr, ok := err.(*Error); ok {
			errResp["error"] = apiErr.Message
			errResp["code"] = apiErr.Code
			errResp["field"] = apiErr.Field
		}
		return c.Status(fiber.StatusUnprocessableEntity).JSON(errResp)
	}
	if h.AuditLogger != nil {
		_, err := h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        account.ID,
			ActorID:   getActorID(c),
			Action:    "update_account",
			TargetID:  account.ID,
			Details:   auditDetails(map[string]interface{}{"input": input}),
			CreatedAt: time.Now(),
		})
		if err != nil {
			logger.LogError("UpdateAccount: audit log failed", logger.ErrorField(err))
		}
	}
	return c.JSON(account)
}

func (h *BillingAdminHandler) GetAccount(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := getActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "billing_account", "read")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input struct {
		ActorID string `json:"actor_id"`
	}
	if err := c.BodyParser(&input); err != nil || input.ActorID == "" {
		logger.LogError("GetAccount: actor_id required", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "actor_id required"})
	}
	account, err := h.AccountService.GetAccount(input.ActorID)
	if err != nil {
		logger.LogError("GetAccount: not found", logger.ErrorField(err))
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": err.Error()})
	}
	if h.AuditLogger != nil {
		_, err := h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        account.ID,
			ActorID:   input.ActorID,
			Action:    "get_account",
			TargetID:  account.ID,
			Details:   auditDetails(map[string]interface{}{"id": account.ID}),
			CreatedAt: time.Now(),
		})
		if err != nil {
			logger.LogError("GetAccount: audit log failed", logger.ErrorField(err))
		}
	}
	return c.JSON(account)
}

func (h *BillingAdminHandler) ListAccounts(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := getActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "billing_account", "list")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input struct {
		TenantID string `json:"tenant_id"`
		Page     int    `json:"page"`
		PageSize int    `json:"page_size"`
	}
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("ListAccounts: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if input.Page == 0 {
		input.Page = 1
	}
	if input.PageSize == 0 {
		input.PageSize = 100
	}
	accounts, err := h.AccountService.ListAccounts(input.TenantID, input.Page, input.PageSize)
	if err != nil {
		logger.LogError("ListAccounts: failed", logger.ErrorField(err), logger.String("tenant_id", input.TenantID))
		errResp := fiber.Map{"error": err.Error()}
		if apiErr, ok := err.(*Error); ok {
			errResp["error"] = apiErr.Message
			errResp["code"] = apiErr.Code
			errResp["field"] = apiErr.Field
		}
		return c.Status(fiber.StatusUnprocessableEntity).JSON(errResp)
	}
	if h.AuditLogger != nil {
		_, err := h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        "",
			ActorID:   getActorID(c),
			Action:    "list_accounts",
			TargetID:  input.TenantID,
			Details:   auditDetails(map[string]interface{}{"tenant_id": input.TenantID, "page": input.Page, "page_size": input.PageSize}),
			CreatedAt: time.Now(),
		})
		if err != nil {
			logger.LogError("ListAccounts: audit log failed", logger.ErrorField(err))
		}
	}
	return c.JSON(fiber.Map{"accounts": accounts, "page": input.Page, "page_size": input.PageSize})
}

func (h *BillingAdminHandler) CreatePlan(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := getActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "billing_plan", "create")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input Plan
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("CreatePlan: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if err := input.Validate(); err != nil {
		logger.LogError("CreatePlan: validation failed", logger.ErrorField(err))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Message, "code": err.Code, "field": err.Field})
	}
	plan, err := h.PlanService.CreatePlan(input)
	if err != nil {
		logger.LogError("CreatePlan: failed", logger.ErrorField(err), logger.Any("input", input))
		errResp := fiber.Map{"error": err.Error()}
		if apiErr, ok := err.(*Error); ok {
			errResp["error"] = apiErr.Message
			errResp["code"] = apiErr.Code
			errResp["field"] = apiErr.Field
		}
		return c.Status(fiber.StatusUnprocessableEntity).JSON(errResp)
	}
	if h.AuditLogger != nil {
		_, err := h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        plan.ID,
			ActorID:   getActorID(c),
			Action:    "create_plan",
			TargetID:  plan.ID,
			Details:   auditDetails(map[string]interface{}{"input": input}),
			CreatedAt: time.Now(),
		})
		if err != nil {
			logger.LogError("CreatePlan: audit log failed", logger.ErrorField(err))
		}
	}
	return c.Status(fiber.StatusCreated).JSON(plan)
}

func (h *BillingAdminHandler) UpdatePlan(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := getActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "billing_plan", "update")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input Plan
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("UpdatePlan: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if err := input.Validate(); err != nil {
		logger.LogError("UpdatePlan: validation failed", logger.ErrorField(err))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Message, "code": err.Code, "field": err.Field})
	}
	plan, err := h.PlanService.UpdatePlan(input)
	if err != nil {
		logger.LogError("UpdatePlan: failed", logger.ErrorField(err), logger.Any("input", input))
		errResp := fiber.Map{"error": err.Error()}
		if apiErr, ok := err.(*Error); ok {
			errResp["error"] = apiErr.Message
			errResp["code"] = apiErr.Code
			errResp["field"] = apiErr.Field
		}
		return c.Status(fiber.StatusUnprocessableEntity).JSON(errResp)
	}
	if h.AuditLogger != nil {
		_, err := h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        plan.ID,
			ActorID:   getActorID(c),
			Action:    "update_plan",
			TargetID:  plan.ID,
			Details:   auditDetails(map[string]interface{}{"input": input}),
			CreatedAt: time.Now(),
		})
		if err != nil {
			logger.LogError("UpdatePlan: audit log failed", logger.ErrorField(err))
		}
	}
	return c.JSON(plan)
}

func (h *BillingAdminHandler) GetPlan(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := getActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "billing_plan", "read")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input struct {
		PlanID string `json:"plan_id"`
	}
	if err := c.BodyParser(&input); err != nil || input.PlanID == "" {
		logger.LogError("GetPlan: plan_id required", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "plan_id required"})
	}
	plan, err := h.PlanService.GetPlan(input.PlanID)
	if err != nil {
		logger.LogError("GetPlan: not found", logger.ErrorField(err))
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": err.Error()})
	}
	if h.AuditLogger != nil {
		_, err := h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        plan.ID,
			ActorID:   getActorID(c),
			Action:    "get_plan",
			TargetID:  plan.ID,
			Details:   auditDetails(map[string]interface{}{"id": plan.ID}),
			CreatedAt: time.Now(),
		})
		if err != nil {
			logger.LogError("GetPlan: audit log failed", logger.ErrorField(err))
		}
	}
	return c.JSON(plan)
}

func (h *BillingAdminHandler) ListPlans(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := getActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "billing_plan", "list")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input struct {
		ActiveOnly bool `json:"active_only"`
		Page       int  `json:"page"`
		PageSize   int  `json:"page_size"`
	}
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("ListPlans: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if input.Page == 0 {
		input.Page = 1
	}
	if input.PageSize == 0 {
		input.PageSize = 100
	}
	plans, err := h.PlanService.ListPlans(input.ActiveOnly, input.Page, input.PageSize)
	if err != nil {
		logger.LogError("ListPlans: failed", logger.ErrorField(err), logger.Bool("active_only", input.ActiveOnly))
		errResp := fiber.Map{"error": err.Error()}
		if apiErr, ok := err.(*Error); ok {
			errResp["error"] = apiErr.Message
			errResp["code"] = apiErr.Code
			errResp["field"] = apiErr.Field
		}
		return c.Status(fiber.StatusUnprocessableEntity).JSON(errResp)
	}
	if h.AuditLogger != nil {
		_, err := h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        "",
			ActorID:   getActorID(c),
			Action:    "list_plans",
			TargetID:  "",
			Details:   auditDetails(map[string]interface{}{"active_only": input.ActiveOnly, "page": input.Page, "page_size": input.PageSize}),
			CreatedAt: time.Now(),
		})
		if err != nil {
			logger.LogError("ListPlans: audit log failed", logger.ErrorField(err))
		}
	}
	return c.JSON(fiber.Map{"plans": plans, "page": input.Page, "page_size": input.PageSize})
}

func (h *BillingAdminHandler) DeletePlan(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := getActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "billing_plan", "delete")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input struct {
		PlanID string `json:"plan_id"`
	}
	if err := c.BodyParser(&input); err != nil || input.PlanID == "" {
		logger.LogError("DeletePlan: plan_id required", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "plan_id required"})
	}
	if err := h.PlanService.DeletePlan(input.PlanID); err != nil {
		logger.LogError("DeletePlan: failed", logger.ErrorField(err))
		errResp := fiber.Map{"error": err.Error()}
		if apiErr, ok := err.(*Error); ok {
			errResp["error"] = apiErr.Message
			errResp["code"] = apiErr.Code
			errResp["field"] = apiErr.Field
		}
		return c.Status(fiber.StatusUnprocessableEntity).JSON(errResp)
	}
	if h.AuditLogger != nil {
		_, err := h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        input.PlanID,
			ActorID:   getActorID(c),
			Action:    "delete_plan",
			TargetID:  input.PlanID,
			Details:   auditDetails(map[string]interface{}{"id": input.PlanID}),
			CreatedAt: time.Now(),
		})
		if err != nil {
			logger.LogError("DeletePlan: audit log failed", logger.ErrorField(err))
		}
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *BillingAdminHandler) CreateUsage(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := getActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "billing_usage", "create")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input Usage
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("CreateUsage: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if err := input.Validate(); err != nil {
		logger.LogError("CreateUsage: validation failed", logger.ErrorField(err))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Message, "code": err.Code, "field": err.Field})
	}
	usage, err := h.UsageService.CreateUsage(input)
	if err != nil {
		logger.LogError("CreateUsage: failed", logger.ErrorField(err), logger.Any("input", input))
		errResp := fiber.Map{"error": err.Error()}
		if apiErr, ok := err.(*Error); ok {
			errResp["error"] = apiErr.Message
			errResp["code"] = apiErr.Code
			errResp["field"] = apiErr.Field
		}
		return c.Status(fiber.StatusUnprocessableEntity).JSON(errResp)
	}
	if h.AuditLogger != nil {
		_, err := h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        usage.ID,
			ActorID:   getActorID(c),
			Action:    "create_usage",
			TargetID:  usage.AccountID,
			Details:   auditDetails(map[string]interface{}{"input": input}),
			CreatedAt: time.Now(),
		})
		if err != nil {
			logger.LogError("CreateUsage: audit log failed", logger.ErrorField(err))
		}
	}
	return c.Status(fiber.StatusCreated).JSON(usage)
}

func (h *BillingAdminHandler) GetDiscount(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := getActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "billing_discount", "read")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input struct {
		ID string `json:"id"`
	}
	if err := c.BodyParser(&input); err != nil || input.ID == "" {
		logger.LogError("GetDiscount: id required", logger.String("id", input.ID))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	discount, err := h.DiscountService.GetDiscount(input.ID)
	if err != nil {
		logger.LogError("GetDiscount: not found", logger.ErrorField(err), logger.String("id", input.ID))
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": err.Error()})
	}
	if h.AuditLogger != nil {
		_, err := h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        discount.ID,
			ActorID:   getActorID(c),
			Action:    "get_discount",
			TargetID:  discount.ID,
			Details:   auditDetails(map[string]interface{}{"id": input.ID}),
			CreatedAt: time.Now(),
		})
		if err != nil {
			logger.LogError("GetDiscount: audit log failed", logger.ErrorField(err))
		}
	}
	return c.JSON(discount)
}

func (h *BillingAdminHandler) GetDiscountByCode(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := getActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "billing_discount", "read")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input struct {
		Code string `json:"code"`
	}
	if err := c.BodyParser(&input); err != nil || input.Code == "" {
		logger.LogError("GetDiscountByCode: code required", logger.String("code", input.Code))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "code required"})
	}
	discount, err := h.DiscountService.GetDiscountByCode(input.Code)
	if err != nil {
		logger.LogError("GetDiscountByCode: not found", logger.ErrorField(err), logger.String("code", input.Code))
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": err.Error()})
	}
	if h.AuditLogger != nil {
		_, err := h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        discount.ID,
			ActorID:   getActorID(c),
			Action:    "get_discount_by_code",
			TargetID:  discount.ID,
			Details:   auditDetails(map[string]interface{}{"code": input.Code}),
			CreatedAt: time.Now(),
		})
		if err != nil {
			logger.LogError("GetDiscountByCode: audit log failed", logger.ErrorField(err))
		}
	}
	return c.JSON(discount)
}

func (h *BillingAdminHandler) ListDiscounts(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := getActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "billing_discount", "list")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input struct {
		ActiveOnly bool `json:"active_only"`
		Page       int  `json:"page"`
		PageSize   int  `json:"page_size"`
	}
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("ListDiscounts: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if input.Page == 0 {
		input.Page = 1
	}
	if input.PageSize == 0 {
		input.PageSize = 100
	}
	discounts, err := h.DiscountService.ListDiscounts(input.ActiveOnly, input.Page, input.PageSize)
	if err != nil {
		logger.LogError("ListDiscounts: failed", logger.ErrorField(err), logger.Bool("active_only", input.ActiveOnly))
		errResp := fiber.Map{"error": err.Error()}
		if apiErr, ok := err.(*Error); ok {
			errResp["error"] = apiErr.Message
			errResp["code"] = apiErr.Code
			errResp["field"] = apiErr.Field
		}
		return c.Status(fiber.StatusUnprocessableEntity).JSON(errResp)
	}
	if h.AuditLogger != nil {
		_, err := h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        "",
			ActorID:   getActorID(c),
			Action:    "list_discounts",
			TargetID:  "",
			Details:   auditDetails(map[string]interface{}{"active_only": input.ActiveOnly, "page": input.Page, "page_size": input.PageSize}),
			CreatedAt: time.Now(),
		})
		if err != nil {
			logger.LogError("ListDiscounts: audit log failed", logger.ErrorField(err))
		}
	}
	return c.JSON(fiber.Map{"discounts": discounts, "page": input.Page, "page_size": input.PageSize})
}

func (h *BillingAdminHandler) CreateCoupon(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := getActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "billing_coupon", "create")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input Coupon
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("CreateCoupon: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if err := input.Validate(); err != nil {
		logger.LogError("CreateCoupon: validation failed", logger.ErrorField(err))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Message, "code": err.Code, "field": err.Field})
	}
	coupon, err := h.CouponService.CreateCoupon(input)
	if err != nil {
		logger.LogError("CreateCoupon: failed", logger.ErrorField(err), logger.Any("input", input))
		errResp := fiber.Map{"error": err.Error()}
		if apiErr, ok := err.(*Error); ok {
			errResp["error"] = apiErr.Message
			errResp["code"] = apiErr.Code
			errResp["field"] = apiErr.Field
		}
		return c.Status(fiber.StatusUnprocessableEntity).JSON(errResp)
	}
	if h.AuditLogger != nil {
		_, err := h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        coupon.ID,
			ActorID:   getActorID(c),
			Action:    "create_coupon",
			TargetID:  coupon.ID,
			Details:   auditDetails(map[string]interface{}{"input": input}),
			CreatedAt: time.Now(),
		})
		if err != nil {
			logger.LogError("CreateCoupon: audit log failed", logger.ErrorField(err))
		}
	}
	return c.Status(fiber.StatusCreated).JSON(coupon)
}

func (h *BillingAdminHandler) UpdateCoupon(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := getActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "billing_coupon", "update")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input Coupon
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("UpdateCoupon: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if input.ID == "" {
		logger.LogError("UpdateCoupon: id required")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	if err := input.Validate(); err != nil {
		logger.LogError("UpdateCoupon: validation failed", logger.ErrorField(err))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Message, "code": err.Code, "field": err.Field})
	}
	coupon, err := h.CouponService.UpdateCoupon(input)
	if err != nil {
		logger.LogError("UpdateCoupon: failed", logger.ErrorField(err), logger.Any("input", input))
		errResp := fiber.Map{"error": err.Error()}
		if apiErr, ok := err.(*Error); ok {
			errResp["error"] = apiErr.Message
			errResp["code"] = apiErr.Code
			errResp["field"] = apiErr.Field
		}
		return c.Status(fiber.StatusUnprocessableEntity).JSON(errResp)
	}
	if h.AuditLogger != nil {
		_, err := h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        coupon.ID,
			ActorID:   getActorID(c),
			Action:    "update_coupon",
			TargetID:  coupon.ID,
			Details:   auditDetails(map[string]interface{}{"input": input}),
			CreatedAt: time.Now(),
		})
		if err != nil {
			logger.LogError("UpdateCoupon: audit log failed", logger.ErrorField(err))
		}
	}
	return c.JSON(coupon)
}

func (h *BillingAdminHandler) DeleteCoupon(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := getActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "billing_coupon", "delete")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input struct {
		ID string `json:"id"`
	}
	if err := c.BodyParser(&input); err != nil || input.ID == "" {
		logger.LogError("DeleteCoupon: id required", logger.String("id", input.ID))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	if err := h.CouponService.DeleteCoupon(input.ID); err != nil {
		logger.LogError("DeleteCoupon: failed", logger.ErrorField(err), logger.String("id", input.ID))
		errResp := fiber.Map{"error": err.Error()}
		if apiErr, ok := err.(*Error); ok {
			errResp["error"] = apiErr.Message
			errResp["code"] = apiErr.Code
			errResp["field"] = apiErr.Field
		}
		return c.Status(fiber.StatusUnprocessableEntity).JSON(errResp)
	}
	if h.AuditLogger != nil {
		_, err := h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        input.ID,
			ActorID:   getActorID(c),
			Action:    "delete_coupon",
			TargetID:  input.ID,
			Details:   auditDetails(map[string]interface{}{"id": input.ID}),
			CreatedAt: time.Now(),
		})
		if err != nil {
			logger.LogError("DeleteCoupon: audit log failed", logger.ErrorField(err))
		}
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *BillingAdminHandler) GetCoupon(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := getActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "billing_coupon", "read")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input struct {
		ID string `json:"id"`
	}
	if err := c.BodyParser(&input); err != nil || input.ID == "" {
		logger.LogError("GetCoupon: id required", logger.String("id", input.ID))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	coupon, err := h.CouponService.GetCoupon(input.ID)
	if err != nil {
		logger.LogError("GetCoupon: not found", logger.ErrorField(err), logger.String("id", input.ID))
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": err.Error()})
	}
	if h.AuditLogger != nil {
		_, err := h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        coupon.ID,
			ActorID:   getActorID(c),
			Action:    "get_coupon",
			TargetID:  coupon.ID,
			Details:   auditDetails(map[string]interface{}{"id": input.ID}),
			CreatedAt: time.Now(),
		})
		if err != nil {
			logger.LogError("GetCoupon: audit log failed", logger.ErrorField(err))
		}
	}
	return c.JSON(coupon)
}

func (h *BillingAdminHandler) GetCouponByCode(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := getActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "billing_coupon", "read")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input struct {
		Code string `json:"code"`
	}
	if err := c.BodyParser(&input); err != nil || input.Code == "" {
		logger.LogError("GetCouponByCode: code required", logger.String("code", input.Code))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "code required"})
	}
	coupon, err := h.CouponService.GetCouponByCode(input.Code)
	if err != nil {
		logger.LogError("GetCouponByCode: not found", logger.ErrorField(err), logger.String("code", input.Code))
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": err.Error()})
	}
	if h.AuditLogger != nil {
		_, err := h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        coupon.ID,
			ActorID:   getActorID(c),
			Action:    "get_coupon_by_code",
			TargetID:  coupon.ID,
			Details:   auditDetails(map[string]interface{}{"code": input.Code}),
			CreatedAt: time.Now(),
		})
		if err != nil {
			logger.LogError("GetCouponByCode: audit log failed", logger.ErrorField(err))
		}
	}
	return c.JSON(coupon)
}

func (h *BillingAdminHandler) ListCoupons(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := getActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "billing_coupon", "list")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input struct {
		DiscountID string `json:"discount_id"`
		IsActive   *bool  `json:"is_active"`
		Page       int    `json:"page"`
		PageSize   int    `json:"page_size"`
	}
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("ListCoupons: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if input.Page == 0 {
		input.Page = 1
	}
	if input.PageSize == 0 {
		input.PageSize = 100
	}
	coupons, err := h.CouponService.ListCoupons(input.DiscountID, input.IsActive, input.Page, input.PageSize)
	if err != nil {
		logger.LogError("ListCoupons: failed", logger.ErrorField(err), logger.String("discount_id", input.DiscountID))
		errResp := fiber.Map{"error": err.Error()}
		if apiErr, ok := err.(*Error); ok {
			errResp["error"] = apiErr.Message
			errResp["code"] = apiErr.Code
			errResp["field"] = apiErr.Field
		}
		return c.Status(fiber.StatusUnprocessableEntity).JSON(errResp)
	}
	if h.AuditLogger != nil {
		_, err := h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        "",
			ActorID:   getActorID(c),
			Action:    "list_coupons",
			TargetID:  input.DiscountID,
			Details:   auditDetails(map[string]interface{}{"discount_id": input.DiscountID, "is_active": input.IsActive, "page": input.Page, "page_size": input.PageSize}),
			CreatedAt: time.Now(),
		})
		if err != nil {
			logger.LogError("ListCoupons: audit log failed", logger.ErrorField(err))
		}
	}
	return c.JSON(fiber.Map{"coupons": coupons, "page": input.Page, "page_size": input.PageSize})
}

func (h *BillingAdminHandler) CreateCredit(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := getActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "credit", "create")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input Credit
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("CreateCredit: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if err := input.Validate(); err != nil {
		logger.LogError("CreateCredit: validation failed", logger.ErrorField(err))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Message, "code": err.Code, "field": err.Field})
	}
	account, err := h.AccountService.GetAccount(input.AccountID)
	if err != nil {
		logger.LogError("CreateCredit: account not found", logger.ErrorField(err), logger.String("account_id", input.AccountID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": "account not found"})
	}
	currency := strings.ToUpper(strings.TrimSpace(input.Currency))
	if currency == "" {
		currency = strings.ToUpper(strings.TrimSpace(account.Currency))
		if currency == "" {
			return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": "no currency set for credit or account"})
		}
		input.Currency = currency
	}
	if input.Currency != account.Currency && account.Currency != "" {
		rate, rerr := h.Store.GetExchangeRate(c.Context(), input.Currency, account.Currency)
		if rerr != nil || rate.Rate <= 0 {
			return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": "no valid exchange rate from " + input.Currency + " to " + account.Currency})
		}
		input.OriginalAmount = input.Amount
		input.OriginalCurrency = input.Currency
		input.Amount = input.Amount * rate.Rate
		input.Currency = account.Currency
	}
	credit, err := h.CreditService.CreateCredit(input)
	if err != nil {
		logger.LogError("CreateCredit: failed", logger.ErrorField(err), logger.Any("input", input))
		errResp := fiber.Map{"error": err.Error()}
		if apiErr, ok := err.(*Error); ok {
			errResp["error"] = apiErr.Message
			errResp["code"] = apiErr.Code
			errResp["field"] = apiErr.Field
		}
		return c.Status(fiber.StatusUnprocessableEntity).JSON(errResp)
	}
	if h.AuditLogger != nil {
		_, err := h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        credit.ID,
			ActorID:   getActorID(c),
			Action:    "create_credit",
			TargetID:  credit.AccountID,
			Details:   auditDetails(map[string]interface{}{"input": input, "account_currency": account.Currency}),
			CreatedAt: time.Now(),
		})
		if err != nil {
			logger.LogError("CreateCredit: audit log failed", logger.ErrorField(err))
		}
	}
	return c.Status(fiber.StatusCreated).JSON(credit)
}

func (h *BillingAdminHandler) UpdateCredit(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := getActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "credit", "update")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input struct {
		ID string `json:"id"`
		Credit
	}
	if err := c.BodyParser(&input); err != nil || input.ID == "" {
		logger.LogError("UpdateCredit: id required", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	if err := input.Credit.Validate(); err != nil {
		logger.LogError("UpdateCredit: validation failed", logger.ErrorField(err))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Message, "code": err.Code, "field": err.Field})
	}
	credit, err := h.CreditService.UpdateCredit(input.Credit)
	if err != nil {
		logger.LogError("UpdateCredit: failed", logger.ErrorField(err), logger.Any("input", input))
		errResp := fiber.Map{"error": err.Error()}
		if apiErr, ok := err.(*Error); ok {
			errResp["error"] = apiErr.Message
			errResp["code"] = apiErr.Code
			errResp["field"] = apiErr.Field
		}
		return c.Status(fiber.StatusUnprocessableEntity).JSON(errResp)
	}
	if h.AuditLogger != nil {
		_, err := h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        credit.ID,
			ActorID:   getActorID(c),
			Action:    "update_credit",
			TargetID:  credit.AccountID,
			Details:   auditDetails(map[string]interface{}{"input": input}),
			CreatedAt: time.Now(),
		})
		if err != nil {
			logger.LogError("UpdateCredit: audit log failed", logger.ErrorField(err))
		}
	}
	return c.JSON(credit)
}

func (h *BillingAdminHandler) PatchCredit(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := getActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "credit", "patch")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input struct {
		ID     string  `json:"id"`
		Action string  `json:"action"`
		Amount float64 `json:"amount"`
	}
	if err := c.BodyParser(&input); err != nil || input.ID == "" || input.Action == "" {
		logger.LogError("PatchCredit: id and action required", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id and action required"})
	}
	if err := h.CreditService.PatchCredit(input.ID, input.Action, input.Amount); err != nil {
		logger.LogError("PatchCredit: failed", logger.ErrorField(err), logger.String("id", input.ID))
		errResp := fiber.Map{"error": err.Error()}
		if apiErr, ok := err.(*Error); ok {
			errResp["error"] = apiErr.Message
			errResp["code"] = apiErr.Code
			errResp["field"] = apiErr.Field
		}
		return c.Status(fiber.StatusUnprocessableEntity).JSON(errResp)
	}
	if h.AuditLogger != nil {
		_, err := h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        input.ID,
			ActorID:   getActorID(c),
			Action:    "patch_credit",
			TargetID:  input.ID,
			Details:   auditDetails(map[string]interface{}{"action": input.Action, "amount": input.Amount}),
			CreatedAt: time.Now(),
		})
		if err != nil {
			logger.LogError("PatchCredit: audit log failed", logger.ErrorField(err))
		}
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *BillingAdminHandler) DeleteCredit(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := getActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "credit", "delete")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input struct {
		ID string `json:"id"`
	}
	if err := c.BodyParser(&input); err != nil || input.ID == "" {
		logger.LogError("DeleteCredit: id required", logger.String("id", input.ID))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	if err := h.CreditService.DeleteCredit(input.ID); err != nil {
		logger.LogError("DeleteCredit: failed", logger.ErrorField(err), logger.String("id", input.ID))
		errResp := fiber.Map{"error": err.Error()}
		if apiErr, ok := err.(*Error); ok {
			errResp["error"] = apiErr.Message
			errResp["code"] = apiErr.Code
			errResp["field"] = apiErr.Field
		}
		return c.Status(fiber.StatusUnprocessableEntity).JSON(errResp)
	}
	if h.AuditLogger != nil {
		_, err := h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        input.ID,
			ActorID:   getActorID(c),
			Action:    "delete_credit",
			TargetID:  input.ID,
			Details:   auditDetails(map[string]interface{}{"id": input.ID}),
			CreatedAt: time.Now(),
		})
		if err != nil {
			logger.LogError("DeleteCredit: audit log failed", logger.ErrorField(err))
		}
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *BillingAdminHandler) GetCredit(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := getActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "credit", "read")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input struct {
		ID string `json:"id"`
	}
	if err := c.BodyParser(&input); err != nil || input.ID == "" {
		logger.LogError("GetCredit: id required", logger.String("id", input.ID))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	credit, err := h.CreditService.GetCredit(input.ID)
	if err != nil {
		logger.LogError("GetCredit: not found", logger.ErrorField(err), logger.String("id", input.ID))
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": err.Error()})
	}
	if h.AuditLogger != nil {
		_, err := h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        credit.ID,
			ActorID:   getActorID(c),
			Action:    "get_credit",
			TargetID:  credit.AccountID,
			Details:   auditDetails(map[string]interface{}{"id": input.ID}),
			CreatedAt: time.Now(),
		})
		if err != nil {
			logger.LogError("GetCredit: audit log failed", logger.ErrorField(err))
		}
	}
	return c.JSON(credit)
}

func (h *BillingAdminHandler) ListCredits(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := getActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "credit", "list")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input struct {
		AccountID string `json:"account_id"`
		InvoiceID string `json:"invoice_id"`
		Status    string `json:"status"`
		Page      int    `json:"page"`
		PageSize  int    `json:"page_size"`
	}
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("ListCredits: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if input.Page == 0 {
		input.Page = 1
	}
	if input.PageSize == 0 {
		input.PageSize = 100
	}
	credits, err := h.CreditService.ListCredits(input.AccountID, input.InvoiceID, input.Status, input.Page, input.PageSize)
	if err != nil {
		logger.LogError("ListCredits: failed", logger.ErrorField(err), logger.String("account_id", input.AccountID), logger.String("invoice_id", input.InvoiceID), logger.String("status", input.Status))
		errResp := fiber.Map{"error": err.Error()}
		if apiErr, ok := err.(*Error); ok {
			errResp["error"] = apiErr.Message
			errResp["code"] = apiErr.Code
			errResp["field"] = apiErr.Field
		}
		return c.Status(fiber.StatusUnprocessableEntity).JSON(errResp)
	}
	if h.AuditLogger != nil {
		_, err := h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        "",
			ActorID:   getActorID(c),
			Action:    "list_credits",
			TargetID:  input.AccountID,
			Details:   auditDetails(map[string]interface{}{"account_id": input.AccountID, "invoice_id": input.InvoiceID, "status": input.Status, "page": input.Page, "page_size": input.PageSize}),
			CreatedAt: time.Now(),
		})
		if err != nil {
			logger.LogError("ListCredits: audit log failed", logger.ErrorField(err))
		}
	}
	return c.JSON(fiber.Map{"credits": credits, "page": input.Page, "page_size": input.PageSize})
}

func (h *BillingAdminHandler) CreateRefund(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := getActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "refund", "create")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input Refund
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("CreateRefund: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if err := input.Validate(); err != nil {
		logger.LogError("CreateRefund: validation failed", logger.ErrorField(err))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Message, "code": err.Code, "field": err.Field})
	}
	refund, err := h.RefundService.CreateRefund(input)
	if err != nil {
		logger.LogError("CreateRefund: failed", logger.ErrorField(err), logger.Any("input", input))
		errResp := fiber.Map{"error": err.Error()}
		if apiErr, ok := err.(*Error); ok {
			errResp["error"] = apiErr.Message
			errResp["code"] = apiErr.Code
			errResp["field"] = apiErr.Field
		}
		return c.Status(fiber.StatusUnprocessableEntity).JSON(errResp)
	}
	if h.AuditLogger != nil {
		_, err := h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        refund.ID,
			ActorID:   getActorID(c),
			Action:    "create_refund",
			TargetID:  refund.ID,
			Details:   auditDetails(map[string]interface{}{"input": input}),
			CreatedAt: time.Now(),
		})
		if err != nil {
			logger.LogError("CreateRefund: audit log failed", logger.ErrorField(err))
		}
	}
	return c.Status(fiber.StatusCreated).JSON(refund)
}

func (h *BillingAdminHandler) UpdateRefund(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := getActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "refund", "update")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input struct {
		ID string `json:"id"`
	}
	if err := c.BodyParser(&input); err != nil || input.ID == "" {
		logger.LogError("UpdateRefund: id required", logger.String("id", input.ID))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	if err := h.RefundService.UpdateRefund(input.ID); err != nil {
		logger.LogError("UpdateRefund: failed", logger.ErrorField(err), logger.String("id", input.ID))
		errResp := fiber.Map{"error": err.Error()}
		if apiErr, ok := err.(*Error); ok {
			errResp["error"] = apiErr.Message
			errResp["code"] = apiErr.Code
			errResp["field"] = apiErr.Field
		}
		return c.Status(fiber.StatusUnprocessableEntity).JSON(errResp)
	}
	if h.AuditLogger != nil {
		_, err := h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        input.ID,
			ActorID:   getActorID(c),
			Action:    "update_refund",
			TargetID:  input.ID,
			Details:   auditDetails(map[string]interface{}{"id": input.ID}),
			CreatedAt: time.Now(),
		})
		if err != nil {
			logger.LogError("UpdateRefund: audit log failed", logger.ErrorField(err))
		}
	}
	return c.SendStatus(fiber.StatusOK)
}

func (h *BillingAdminHandler) DeleteRefund(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := getActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "refund", "delete")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input struct {
		ID string `json:"id"`
	}
	if err := c.BodyParser(&input); err != nil || input.ID == "" {
		logger.LogError("DeleteRefund: id required", logger.String("id", input.ID))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	if err := h.RefundService.DeleteRefund(input.ID); err != nil {
		logger.LogError("DeleteRefund: failed", logger.ErrorField(err), logger.String("id", input.ID))
		errResp := fiber.Map{"error": err.Error()}
		if apiErr, ok := err.(*Error); ok {
			errResp["error"] = apiErr.Message
			errResp["code"] = apiErr.Code
			errResp["field"] = apiErr.Field
		}
		return c.Status(fiber.StatusUnprocessableEntity).JSON(errResp)
	}
	if h.AuditLogger != nil {
		_, err := h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        input.ID,
			ActorID:   getActorID(c),
			Action:    "delete_refund",
			TargetID:  input.ID,
			Details:   auditDetails(map[string]interface{}{"id": input.ID}),
			CreatedAt: time.Now(),
		})
		if err != nil {
			logger.LogError("DeleteRefund: audit log failed", logger.ErrorField(err))
		}
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *BillingAdminHandler) GetRefund(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := getActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "refund", "read")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input struct {
		ID string `json:"id"`
	}
	if err := c.BodyParser(&input); err != nil || input.ID == "" {
		logger.LogError("GetRefund: id required", logger.String("id", input.ID))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	refund, err := h.RefundService.GetRefund(input.ID)
	if err != nil {
		logger.LogError("GetRefund: not found", logger.ErrorField(err), logger.String("id", input.ID))
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": err.Error()})
	}
	if h.AuditLogger != nil {
		_, err := h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        refund.ID,
			ActorID:   getActorID(c),
			Action:    "get_refund",
			TargetID:  refund.ID,
			Details:   auditDetails(map[string]interface{}{"id": input.ID}),
			CreatedAt: time.Now(),
		})
		if err != nil {
			logger.LogError("GetRefund: audit log failed", logger.ErrorField(err))
		}
	}
	return c.JSON(refund)
}

func (h *BillingAdminHandler) ListRefunds(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := getActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "refund", "list")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input struct {
		PaymentID string `json:"payment_id"`
		InvoiceID string `json:"invoice_id"`
		Status    string `json:"status"`
		Page      int    `json:"page"`
		PageSize  int    `json:"page_size"`
	}
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("ListRefunds: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if input.Page == 0 {
		input.Page = 1
	}
	if input.PageSize == 0 {
		input.PageSize = 100
	}
	refunds, err := h.RefundService.ListRefunds(input.PaymentID, input.InvoiceID, input.Status, input.Page, input.PageSize)
	if err != nil {
		logger.LogError("ListRefunds: failed", logger.ErrorField(err), logger.String("payment_id", input.PaymentID), logger.String("invoice_id", input.InvoiceID), logger.String("status", input.Status))
		errResp := fiber.Map{"error": err.Error()}
		if apiErr, ok := err.(*Error); ok {
			errResp["error"] = apiErr.Message
			errResp["code"] = apiErr.Code
			errResp["field"] = apiErr.Field
		}
		return c.Status(fiber.StatusUnprocessableEntity).JSON(errResp)
	}
	if h.AuditLogger != nil {
		_, err := h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        "",
			ActorID:   getActorID(c),
			Action:    "list_refunds",
			TargetID:  input.PaymentID,
			Details:   auditDetails(map[string]interface{}{"payment_id": input.PaymentID, "invoice_id": input.InvoiceID, "status": input.Status, "page": input.Page, "page_size": input.PageSize}),
			CreatedAt: time.Now(),
		})
		if err != nil {
			logger.LogError("ListRefunds: audit log failed", logger.ErrorField(err))
		}
	}
	return c.JSON(fiber.Map{"refunds": refunds, "page": input.Page, "page_size": input.PageSize})
}

func (h *BillingAdminHandler) CreatePaymentMethod(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := getActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "payment_method", "create")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input struct {
		PaymentMethod PaymentMethod     `json:"payment_method"`
		PaymentData   map[string]string `json:"payment_data"`
	}
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("CreatePaymentMethod: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if err := input.PaymentMethod.Validate(); err != nil {
		logger.LogError("CreatePaymentMethod: validation failed", logger.ErrorField(err))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Message, "code": err.Code, "field": err.Field})
	}
	pm, err := h.PaymentMethodService.CreatePaymentMethod(input.PaymentMethod, input.PaymentData)
	if err != nil {
		logger.LogError("CreatePaymentMethod: failed", logger.ErrorField(err))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": "failed to create payment method"})
	}
	if h.AuditLogger != nil {
		_, err := h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        pm.ID,
			ActorID:   getActorID(c),
			Action:    "create_payment_method",
			TargetID:  pm.ID,
			Details:   auditDetails(map[string]interface{}{"input": input}),
			CreatedAt: time.Now(),
		})
		if err != nil {
			logger.LogError("CreatePaymentMethod: audit log failed", logger.ErrorField(err))
		}
	}
	return c.Status(fiber.StatusCreated).JSON(pm)
}

func (h *BillingAdminHandler) UpdatePaymentMethod(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := getActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "payment_method", "update")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input PaymentMethod
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("UpdatePaymentMethod: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if input.ID == "" {
		logger.LogError("UpdatePaymentMethod: id required")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	if err := input.Validate(); err != nil {
		logger.LogError("UpdatePaymentMethod: validation failed", logger.ErrorField(err))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Message, "code": err.Code, "field": err.Field})
	}
	pm, err := h.PaymentMethodService.UpdatePaymentMethod(input)
	if err != nil {
		logger.LogError("UpdatePaymentMethod: failed", logger.ErrorField(err))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": "failed to update payment method"})
	}
	if h.AuditLogger != nil {
		_, err := h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        pm.ID,
			ActorID:   getActorID(c),
			Action:    "update_payment_method",
			TargetID:  pm.ID,
			Details:   auditDetails(map[string]interface{}{"input": input}),
			CreatedAt: time.Now(),
		})
		if err != nil {
			logger.LogError("UpdatePaymentMethod: audit log failed", logger.ErrorField(err))
		}
	}
	return c.JSON(pm)
}

func (h *BillingAdminHandler) PatchPaymentMethod(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := getActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "payment_method", "patch")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input struct {
		ID         string `json:"id"`
		SetDefault *bool  `json:"set_default"`
		Status     string `json:"status"`
	}
	if err := c.BodyParser(&input); err != nil || input.ID == "" {
		logger.LogError("PatchPaymentMethod: id required", logger.String("id", input.ID))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	if err := h.PaymentMethodService.PatchPaymentMethod(input.ID, input.SetDefault, input.Status); err != nil {
		logger.LogError("PatchPaymentMethod: failed", logger.ErrorField(err), logger.String("id", input.ID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": "failed to update payment method"})
	}
	if h.AuditLogger != nil {
		_, err := h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        input.ID,
			ActorID:   getActorID(c),
			Action:    "patch_payment_method",
			TargetID:  input.ID,
			Details:   auditDetails(map[string]interface{}{"action": input.Status, "set_default": input.SetDefault}),
			CreatedAt: time.Now(),
		})
		if err != nil {
			logger.LogError("PatchPaymentMethod: audit log failed", logger.ErrorField(err))
		}
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *BillingAdminHandler) GetPaymentMethod(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := getActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "payment_method", "read")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input struct {
		ID string `json:"id"`
	}
	if err := c.BodyParser(&input); err != nil || input.ID == "" {
		logger.LogError("GetPaymentMethod: id required")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	pm, err := h.PaymentMethodService.GetPaymentMethod(input.ID)
	if err != nil {
		logger.LogError("GetPaymentMethod: not found", logger.ErrorField(err), logger.String("id", input.ID))
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "payment method not found"})
	}
	if h.AuditLogger != nil {
		_, err := h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        pm.ID,
			ActorID:   getActorID(c),
			Action:    "get_payment_method",
			TargetID:  pm.ID,
			Details:   auditDetails(map[string]interface{}{"id": input.ID}),
			CreatedAt: time.Now(),
		})
		if err != nil {
			logger.LogError("GetPaymentMethod: audit log failed", logger.ErrorField(err))
		}
	}
	return c.JSON(pm)
}

func (h *BillingAdminHandler) ListPaymentMethods(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := getActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "payment_method", "list")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input struct {
		AccountID string `json:"account_id"`
		Status    string `json:"status"`
		Page      int    `json:"page"`
		PageSize  int    `json:"page_size"`
	}
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("ListPaymentMethods: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if input.Page == 0 {
		input.Page = 1
	}
	if input.PageSize == 0 {
		input.PageSize = 100
	}
	methods, err := h.PaymentMethodService.ListPaymentMethods(input.AccountID, input.Status, input.Page, input.PageSize)
	if err != nil {
		logger.LogError("ListPaymentMethods: failed", logger.ErrorField(err), logger.String("account_id", input.AccountID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": "failed to list payment methods"})
	}
	if h.AuditLogger != nil {
		_, err := h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        "",
			ActorID:   getActorID(c),
			Action:    "list_payment_methods",
			TargetID:  input.AccountID,
			Details:   auditDetails(map[string]interface{}{"account_id": input.AccountID, "status": input.Status, "page": input.Page, "page_size": input.PageSize}),
			CreatedAt: time.Now(),
		})
		if err != nil {
			logger.LogError("ListPaymentMethods: audit log failed", logger.ErrorField(err))
		}
	}
	return c.JSON(fiber.Map{"payment_methods": methods, "page": input.Page, "page_size": input.PageSize})
}

func (h *BillingAdminHandler) CreateSubscription(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := getActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "subscription", "create")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input Subscription
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("CreateSubscription: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if err := input.Validate(); err != nil {
		logger.LogError("CreateSubscription: validation failed", logger.ErrorField(err))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Message, "code": err.Code, "field": err.Field})
	}
	sub, err := h.SubscriptionService.CreateSubscription(input)
	if err != nil {
		logger.LogError("CreateSubscription: failed", logger.ErrorField(err))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": "failed to create subscription"})
	}
	if h.AuditLogger != nil {
		_, err := h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        sub.ID,
			ActorID:   getActorID(c),
			Action:    "create_subscription",
			TargetID:  sub.ID,
			Details:   auditDetails(map[string]interface{}{"input": input}),
			CreatedAt: time.Now(),
		})
		if err != nil {
			logger.LogError("CreateSubscription: audit log failed", logger.ErrorField(err))
		}
	}
	return c.Status(fiber.StatusCreated).JSON(sub)
}

func (h *BillingAdminHandler) UpdateSubscription(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := getActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "subscription", "update")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input Subscription
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("UpdateSubscription: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if input.ID == "" {
		logger.LogError("UpdateSubscription: id required")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	if err := input.Validate(); err != nil {
		logger.LogError("UpdateSubscription: validation failed", logger.ErrorField(err))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Message, "code": err.Code, "field": err.Field})
	}
	sub, err := h.SubscriptionService.UpdateSubscription(input)
	if err != nil {
		logger.LogError("UpdateSubscription: failed", logger.ErrorField(err))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": "failed to update subscription"})
	}
	if h.AuditLogger != nil {
		_, err := h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        sub.ID,
			ActorID:   getActorID(c),
			Action:    "update_subscription",
			TargetID:  sub.ID,
			Details:   auditDetails(map[string]interface{}{"input": input}),
			CreatedAt: time.Now(),
		})
		if err != nil {
			logger.LogError("UpdateSubscription: audit log failed", logger.ErrorField(err))
		}
	}
	return c.JSON(sub)
}

func (h *BillingAdminHandler) PatchSubscription(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := getActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "subscription", "patch")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input struct {
		ID     string `json:"id"`
		Action string `json:"action"`
	}
	if err := c.BodyParser(&input); err != nil || input.ID == "" || input.Action == "" {
		logger.LogError("PatchSubscription: id and action required", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id and action required"})
	}
	if err := h.SubscriptionService.PatchSubscription(input.ID, input.Action); err != nil {
		logger.LogError("PatchSubscription: failed", logger.ErrorField(err), logger.String("id", input.ID))
		errResp := fiber.Map{"error": err.Error()}
		if apiErr, ok := err.(*Error); ok {
			errResp["error"] = apiErr.Message
			errResp["code"] = apiErr.Code
			errResp["field"] = apiErr.Field
		}
		return c.Status(fiber.StatusUnprocessableEntity).JSON(errResp)
	}
	if h.AuditLogger != nil {
		_, err := h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        input.ID,
			ActorID:   getActorID(c),
			Action:    "patch_subscription",
			TargetID:  input.ID,
			Details:   auditDetails(map[string]interface{}{"action": input.Action}),
			CreatedAt: time.Now(),
		})
		if err != nil {
			logger.LogError("PatchSubscription: audit log failed", logger.ErrorField(err))
		}
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *BillingAdminHandler) DeleteSubscription(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := getActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "subscription", "delete")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input struct {
		ID string `json:"id"`
	}
	if err := c.BodyParser(&input); err != nil || input.ID == "" {
		logger.LogError("DeleteSubscription: id required")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	if err := h.SubscriptionService.DeleteSubscription(input.ID); err != nil {
		logger.LogError("DeleteSubscription: failed", logger.ErrorField(err), logger.String("id", input.ID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": "failed to delete subscription"})
	}
	if h.AuditLogger != nil {
		_, err := h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        input.ID,
			ActorID:   getActorID(c),
			Action:    "delete_subscription",
			TargetID:  input.ID,
			Details:   auditDetails(map[string]interface{}{"id": input.ID}),
			CreatedAt: time.Now(),
		})
		if err != nil {
			logger.LogError("DeleteSubscription: audit log failed", logger.ErrorField(err))
		}
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *BillingAdminHandler) GetSubscription(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := getActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "subscription", "read")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input struct {
		ID string `json:"id"`
	}
	if err := c.BodyParser(&input); err != nil || input.ID == "" {
		logger.LogError("GetSubscription: id required")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	sub, err := h.SubscriptionService.GetSubscription(input.ID)
	if err != nil {
		logger.LogError("GetSubscription: not found", logger.ErrorField(err), logger.String("id", input.ID))
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "subscription not found"})
	}
	if h.AuditLogger != nil {
		_, err := h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        sub.ID,
			ActorID:   getActorID(c),
			Action:    "get_subscription",
			TargetID:  sub.ID,
			Details:   auditDetails(map[string]interface{}{"id": input.ID}),
			CreatedAt: time.Now(),
		})
		if err != nil {
			logger.LogError("GetSubscription: audit log failed", logger.ErrorField(err))
		}
	}
	return c.JSON(sub)
}

func (h *BillingAdminHandler) ListSubscriptions(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := getActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "subscription", "list")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input struct {
		AccountID string `json:"account_id"`
		Status    string `json:"status"`
		Page      int    `json:"page"`
		PageSize  int    `json:"page_size"`
	}
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("ListSubscriptions: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if input.Page == 0 {
		input.Page = 1
	}
	if input.PageSize == 0 {
		input.PageSize = 100
	}
	subs, err := h.SubscriptionService.ListSubscriptions(input.AccountID, input.Status, input.Page, input.PageSize)
	if err != nil {
		logger.LogError("ListSubscriptions: failed", logger.ErrorField(err), logger.String("account_id", input.AccountID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": "failed to list subscriptions"})
	}
	if h.AuditLogger != nil {
		_, err := h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        "",
			ActorID:   getActorID(c),
			Action:    "list_subscriptions",
			TargetID:  input.AccountID,
			Details:   auditDetails(map[string]interface{}{"account_id": input.AccountID, "status": input.Status, "page": input.Page, "page_size": input.PageSize}),
			CreatedAt: time.Now(),
		})
		if err != nil {
			logger.LogError("ListSubscriptions: audit log failed", logger.ErrorField(err))
		}
	}
	return c.JSON(fiber.Map{"subscriptions": subs, "page": input.Page, "page_size": input.PageSize})
}

func (h *BillingAdminHandler) ChangePlanSubscription(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := getActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "subscription", "change_plan")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input struct {
		ID       string  `json:"id"`
		PlanID   string  `json:"plan_id"`
		ChangeAt *string `json:"change_at,omitempty"`
	}
	if err := c.BodyParser(&input); err != nil || input.ID == "" || input.PlanID == "" {
		logger.LogError("ChangePlanSubscription: id and plan_id required", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id and plan_id required"})
	}
	if err := h.SubscriptionService.ChangePlanSubscription(input.ID, input.PlanID); err != nil {
		logger.LogError("ChangePlanSubscription: failed", logger.ErrorField(err))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": "failed to change plan"})
	}
	if h.AuditLogger != nil {
		_, err := h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        input.ID,
			ActorID:   getActorID(c),
			Action:    "change_plan_subscription",
			TargetID:  input.ID,
			Details:   auditDetails(map[string]interface{}{"plan_id": input.PlanID, "change_at": input.ChangeAt}),
			CreatedAt: time.Now(),
		})
		if err != nil {
			logger.LogError("ChangePlanSubscription: audit log failed", logger.ErrorField(err))
		}
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *BillingAdminHandler) CancelSubscriptionNow(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := getActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "subscription", "cancel_now")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input struct {
		ID string `json:"id"`
	}
	if err := c.BodyParser(&input); err != nil || input.ID == "" {
		logger.LogError("CancelSubscriptionNow: id required")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	if err := h.SubscriptionService.CancelSubscriptionNow(input.ID); err != nil {
		logger.LogError("CancelSubscriptionNow: failed", logger.ErrorField(err))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": "failed to cancel subscription"})
	}
	if h.AuditLogger != nil {
		_, err := h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        input.ID,
			ActorID:   getActorID(c),
			Action:    "cancel_subscription_now",
			TargetID:  input.ID,
			Details:   auditDetails(map[string]interface{}{"id": input.ID}),
			CreatedAt: time.Now(),
		})
		if err != nil {
			logger.LogError("CancelSubscriptionNow: audit log failed", logger.ErrorField(err))
		}
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *BillingAdminHandler) ResumeSubscription(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := getActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "subscription", "resume")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input struct {
		ID string `json:"id"`
	}
	if err := c.BodyParser(&input); err != nil || input.ID == "" {
		logger.LogError("ResumeSubscription: id required")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	if err := h.SubscriptionService.ResumeSubscription(input.ID); err != nil {
		logger.LogError("ResumeSubscription: failed", logger.ErrorField(err))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": "failed to resume subscription"})
	}
	if h.AuditLogger != nil {
		_, err := h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        input.ID,
			ActorID:   getActorID(c),
			Action:    "resume_subscription",
			TargetID:  input.ID,
			Details:   auditDetails(map[string]interface{}{"id": input.ID}),
			CreatedAt: time.Now(),
		})
		if err != nil {
			logger.LogError("ResumeSubscription: audit log failed", logger.ErrorField(err))
		}
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *BillingAdminHandler) UpgradeNowSubscription(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := getActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "subscription", "upgrade_now")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input struct {
		ID     string `json:"id"`
		PlanID string `json:"plan_id"`
	}
	if err := c.BodyParser(&input); err != nil || input.ID == "" || input.PlanID == "" {
		logger.LogError("UpgradeNowSubscription: id and plan_id required", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id and plan_id required"})
	}
	if err := h.SubscriptionService.UpgradeNowSubscription(input.ID); err != nil {
		logger.LogError("UpgradeNowSubscription: failed", logger.ErrorField(err))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": "failed to upgrade subscription"})
	}
	if h.AuditLogger != nil {
		_, err := h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        input.ID,
			ActorID:   getActorID(c),
			Action:    "upgrade_now_subscription",
			TargetID:  input.ID,
			Details:   auditDetails(map[string]interface{}{"plan_id": input.PlanID}),
			CreatedAt: time.Now(),
		})
		if err != nil {
			logger.LogError("UpgradeNowSubscription: audit log failed", logger.ErrorField(err))
		}
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *BillingAdminHandler) CreateWebhookEvent(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := getActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "webhook_event", "create")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input WebhookEvent
	if err := c.BodyParser(&input); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	event, err := h.WebhookEventService.CreateWebhookEvent(input)
	if err != nil {
		errResp := fiber.Map{"error": err.Error()}
		if apiErr, ok := err.(*Error); ok {
			errResp["error"] = apiErr.Message
			errResp["code"] = apiErr.Code
			errResp["field"] = apiErr.Field
		}
		return c.Status(fiber.StatusUnprocessableEntity).JSON(errResp)
	}
	if h.AuditLogger != nil {
		_, err := h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        event.ID,
			ActorID:   getActorID(c),
			Action:    "create_webhook_event",
			TargetID:  event.ID,
			Details:   auditDetails(map[string]interface{}{"input": input}),
			CreatedAt: time.Now(),
		})
		if err != nil {
			logger.LogError("CreateWebhookEvent: audit log failed", logger.ErrorField(err))
		}
	}
	return c.Status(fiber.StatusCreated).JSON(event)
}

func (h *BillingAdminHandler) UpdateWebhookEvent(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := getActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "webhook_event", "update")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input struct {
		ID string `json:"id"`
	}
	if err := c.BodyParser(&input); err != nil || input.ID == "" {
		logger.LogError("UpdateWebhookEvent: id required", logger.String("id", input.ID))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	if err := h.WebhookEventService.UpdateWebhookEvent(input.ID); err != nil {
		logger.LogError("UpdateWebhookEvent: failed", logger.ErrorField(err), logger.String("id", input.ID))
		errResp := fiber.Map{"error": err.Error()}
		if apiErr, ok := err.(*Error); ok {
			errResp["error"] = apiErr.Message
			errResp["code"] = apiErr.Code
			errResp["field"] = apiErr.Field
		}
		return c.Status(fiber.StatusUnprocessableEntity).JSON(errResp)
	}
	if h.AuditLogger != nil {
		_, err := h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        input.ID,
			ActorID:   getActorID(c),
			Action:    "update_webhook_event",
			TargetID:  input.ID,
			Details:   auditDetails(map[string]interface{}{"id": input.ID}),
			CreatedAt: time.Now(),
		})
		if err != nil {
			logger.LogError("UpdateWebhookEvent: audit log failed", logger.ErrorField(err))
		}
	}
	return c.SendStatus(fiber.StatusOK)
}

func (h *BillingAdminHandler) DeleteWebhookEvent(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := getActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "webhook_event", "delete")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input struct {
		ID string `json:"id"`
	}
	if err := c.BodyParser(&input); err != nil || input.ID == "" {
		logger.LogError("DeleteWebhookEvent: id required", logger.String("id", input.ID))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	if err := h.WebhookEventService.DeleteWebhookEvent(input.ID); err != nil {
		logger.LogError("DeleteWebhookEvent: failed", logger.ErrorField(err), logger.String("id", input.ID))
		errResp := fiber.Map{"error": err.Error()}
		if apiErr, ok := err.(*Error); ok {
			errResp["error"] = apiErr.Message
			errResp["code"] = apiErr.Code
			errResp["field"] = apiErr.Field
		}
		return c.Status(fiber.StatusUnprocessableEntity).JSON(errResp)
	}
	if h.AuditLogger != nil {
		_, err := h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        input.ID,
			ActorID:   getActorID(c),
			Action:    "delete_webhook_event",
			TargetID:  input.ID,
			Details:   auditDetails(map[string]interface{}{"id": input.ID}),
			CreatedAt: time.Now(),
		})
		if err != nil {
			logger.LogError("DeleteWebhookEvent: audit log failed", logger.ErrorField(err))
		}
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *BillingAdminHandler) GetWebhookEvent(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := getActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "webhook_event", "read")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input struct {
		ID string `json:"id"`
	}
	if err := c.BodyParser(&input); err != nil || input.ID == "" {
		logger.LogError("GetWebhookEvent: id required", logger.String("id", input.ID))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	event, err := h.WebhookEventService.GetWebhookEvent(input.ID)
	if err != nil {
		logger.LogError("GetWebhookEvent: not found", logger.ErrorField(err), logger.String("id", input.ID))
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": err.Error()})
	}
	if h.AuditLogger != nil {
		_, err := h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        event.ID,
			ActorID:   getActorID(c),
			Action:    "get_webhook_event",
			TargetID:  event.ID,
			Details:   auditDetails(map[string]interface{}{"id": input.ID}),
			CreatedAt: time.Now(),
		})
		if err != nil {
			logger.LogError("GetWebhookEvent: audit log failed", logger.ErrorField(err))
		}
	}
	return c.JSON(event)
}

func (h *BillingAdminHandler) ListWebhookEvents(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := getActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "webhook_event", "list")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input struct {
		Provider string `json:"provider"`
		Status   string `json:"status"`
		Type     string `json:"type"`
		Page     int    `json:"page"`
		PageSize int    `json:"page_size"`
	}
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("ListWebhookEvents: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if input.Page == 0 {
		input.Page = 1
	}
	if input.PageSize == 0 {
		input.PageSize = 100
	}
	events, err := h.WebhookEventService.ListWebhookEvents(input.Provider, input.Status, input.Type, input.Page, input.PageSize)
	if err != nil {
		logger.LogError("ListWebhookEvents: failed", logger.ErrorField(err), logger.String("provider", input.Provider))
		errResp := fiber.Map{"error": err.Error()}
		if apiErr, ok := err.(*Error); ok {
			errResp["error"] = apiErr.Message
			errResp["code"] = apiErr.Code
			errResp["field"] = apiErr.Field
		}
		return c.Status(fiber.StatusUnprocessableEntity).JSON(errResp)
	}
	if h.AuditLogger != nil {
		_, err := h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        "",
			ActorID:   getActorID(c),
			Action:    "list_webhook_events",
			TargetID:  input.Provider,
			Details:   auditDetails(map[string]interface{}{"provider": input.Provider, "status": input.Status, "type": input.Type, "page": input.Page, "page_size": input.PageSize}),
			CreatedAt: time.Now(),
		})
		if err != nil {
			logger.LogError("ListWebhookEvents: audit log failed", logger.ErrorField(err))
		}
	}
	return c.JSON(fiber.Map{"webhook_events": events, "page": input.Page, "page_size": input.PageSize})
}

func (h *BillingAdminHandler) CreateInvoiceAdjustment(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := getActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "invoice_adjustment", "create")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input InvoiceAdjustment
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("CreateInvoiceAdjustment: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if err := input.Validate(); err != nil {
		logger.LogError("CreateInvoiceAdjustment: validation failed", logger.ErrorField(err))
		errResp := fiber.Map{"error": err.Error()}
		if apiErr, ok := any(err).(*Error); ok {
			errResp["error"] = apiErr.Message
			errResp["code"] = apiErr.Code
			errResp["field"] = apiErr.Field
		}
		return c.Status(fiber.StatusUnprocessableEntity).JSON(errResp)
	}
	adj, err := h.InvoiceAdjustmentService.CreateInvoiceAdjustment(input)
	if err != nil {
		logger.LogError("CreateInvoiceAdjustment: failed", logger.ErrorField(err))
		errResp := fiber.Map{"error": err.Error()}
		if apiErr, ok := err.(*Error); ok {
			errResp["error"] = apiErr.Message
			errResp["code"] = apiErr.Code
			errResp["field"] = apiErr.Field
		}
		return c.Status(fiber.StatusUnprocessableEntity).JSON(errResp)
	}
	if h.AuditLogger != nil {
		_, err := h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        adj.ID,
			ActorID:   getActorID(c),
			Action:    "create_invoice_adjustment",
			TargetID:  adj.ID,
			Details:   auditDetails(map[string]interface{}{"input": input}),
			CreatedAt: time.Now(),
		})
		if err != nil {
			logger.LogError("CreateInvoiceAdjustment: audit log failed", logger.ErrorField(err))
		}
	}
	return c.Status(fiber.StatusCreated).JSON(adj)
}

func (h *BillingAdminHandler) UpdateInvoiceAdjustment(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := getActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "invoice_adjustment", "update")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input struct {
		ID string `json:"id"`
	}
	if err := c.BodyParser(&input); err != nil || input.ID == "" {
		logger.LogError("UpdateInvoiceAdjustment: id required", logger.String("id", input.ID))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	if err := h.InvoiceAdjustmentService.UpdateInvoiceAdjustment(input.ID); err != nil {
		logger.LogError("UpdateInvoiceAdjustment: failed", logger.ErrorField(err), logger.String("id", input.ID))
		errResp := fiber.Map{"error": err.Error()}
		if apiErr, ok := err.(*Error); ok {
			errResp["error"] = apiErr.Message
			errResp["code"] = apiErr.Code
			errResp["field"] = apiErr.Field
		}
		return c.Status(fiber.StatusUnprocessableEntity).JSON(errResp)
	}
	if h.AuditLogger != nil {
		_, err := h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        input.ID,
			ActorID:   getActorID(c),
			Action:    "update_invoice_adjustment",
			TargetID:  input.ID,
			Details:   auditDetails(map[string]interface{}{"id": input.ID}),
			CreatedAt: time.Now(),
		})
		if err != nil {
			logger.LogError("UpdateInvoiceAdjustment: audit log failed", logger.ErrorField(err))
		}
	}
	return c.SendStatus(fiber.StatusOK)
}

func (h *BillingAdminHandler) DeleteInvoiceAdjustment(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := getActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "invoice_adjustment", "delete")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input struct {
		ID string `json:"id"`
	}
	if err := c.BodyParser(&input); err != nil || input.ID == "" {
		logger.LogError("DeleteInvoiceAdjustment: id required", logger.String("id", input.ID))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	if err := h.InvoiceAdjustmentService.DeleteInvoiceAdjustment(input.ID); err != nil {
		logger.LogError("DeleteInvoiceAdjustment: failed", logger.ErrorField(err), logger.String("id", input.ID))
		errResp := fiber.Map{"error": err.Error()}
		if apiErr, ok := err.(*Error); ok {
			errResp["error"] = apiErr.Message
			errResp["code"] = apiErr.Code
			errResp["field"] = apiErr.Field
		}
		return c.Status(fiber.StatusUnprocessableEntity).JSON(errResp)
	}
	if h.AuditLogger != nil {
		_, err := h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        input.ID,
			ActorID:   getActorID(c),
			Action:    "delete_invoice_adjustment",
			TargetID:  input.ID,
			Details:   auditDetails(map[string]interface{}{"id": input.ID}),
			CreatedAt: time.Now(),
		})
		if err != nil {
			logger.LogError("DeleteInvoiceAdjustment: audit log failed", logger.ErrorField(err))
		}
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *BillingAdminHandler) GetInvoiceAdjustment(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := getActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "invoice_adjustment", "read")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input struct {
		ID string `json:"id"`
	}
	if err := c.BodyParser(&input); err != nil || input.ID == "" {
		logger.LogError("GetInvoiceAdjustment: id required", logger.String("id", input.ID))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	adj, err := h.InvoiceAdjustmentService.GetInvoiceAdjustment(input.ID)
	if err != nil {
		logger.LogError("GetInvoiceAdjustment: not found", logger.ErrorField(err), logger.String("id", input.ID))
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": err.Error()})
	}
	if h.AuditLogger != nil {
		_, err := h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        adj.ID,
			ActorID:   getActorID(c),
			Action:    "get_invoice_adjustment",
			TargetID:  adj.ID,
			Details:   auditDetails(map[string]interface{}{"id": input.ID}),
			CreatedAt: time.Now(),
		})
		if err != nil {
			logger.LogError("GetInvoiceAdjustment: audit log failed", logger.ErrorField(err))
		}
	}
	return c.JSON(adj)
}

func (h *BillingAdminHandler) ListInvoiceAdjustments(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := getActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "invoice_adjustment", "list")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input struct {
		InvoiceID string `json:"invoice_id"`
		Type      string `json:"type"`
		Page      int    `json:"page"`
		PageSize  int    `json:"page_size"`
	}
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("ListInvoiceAdjustments: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if input.Page == 0 {
		input.Page = 1
	}
	if input.PageSize == 0 {
		input.PageSize = 100
	}
	adjs, err := h.InvoiceAdjustmentService.ListInvoiceAdjustments(input.InvoiceID, input.Type, input.Page, input.PageSize)
	if err != nil {
		logger.LogError("ListInvoiceAdjustments: failed", logger.ErrorField(err), logger.String("invoice_id", input.InvoiceID))
		errResp := fiber.Map{"error": err.Error()}
		if apiErr, ok := err.(*Error); ok {
			errResp["error"] = apiErr.Message
			errResp["code"] = apiErr.Code
			errResp["field"] = apiErr.Field
		}
		return c.Status(fiber.StatusUnprocessableEntity).JSON(errResp)
	}
	if h.AuditLogger != nil {
		_, err := h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        "",
			ActorID:   getActorID(c),
			Action:    "list_invoice_adjustments",
			TargetID:  input.InvoiceID,
			Details:   auditDetails(map[string]interface{}{"invoice_id": input.InvoiceID, "type": input.Type, "page": input.Page, "page_size": input.PageSize}),
			CreatedAt: time.Now(),
		})
		if err != nil {
			logger.LogError("ListInvoiceAdjustments: audit log failed", logger.ErrorField(err))
		}
	}
	return c.JSON(fiber.Map{"invoice_adjustments": adjs, "page": input.Page, "page_size": input.PageSize})
}

func (h *BillingAdminHandler) CreateManualAdjustment(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := getActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "manual_adjustment", "create")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input InvoiceAdjustment
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("CreateManualAdjustment: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if err := input.Validate(); err != nil {
		logger.LogError("CreateManualAdjustment: validation failed", logger.ErrorField(err))
		errResp := fiber.Map{"error": err.Error()}
		if apiErr, ok := any(err).(*Error); ok {
			errResp["error"] = apiErr.Message
			errResp["code"] = apiErr.Code
			errResp["field"] = apiErr.Field
		}
		return c.Status(fiber.StatusUnprocessableEntity).JSON(errResp)
	}
	adj, err := h.ManualAdjustmentService.CreateManualAdjustment(input)
	if err != nil {
		logger.LogError("CreateManualAdjustment: failed", logger.ErrorField(err))
		errResp := fiber.Map{"error": err.Error()}
		if apiErr, ok := err.(*Error); ok {
			errResp["error"] = apiErr.Message
			errResp["code"] = apiErr.Code
			errResp["field"] = apiErr.Field
		}
		return c.Status(fiber.StatusUnprocessableEntity).JSON(errResp)
	}
	if h.AuditLogger != nil {
		_, err := h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        adj.ID,
			ActorID:   getActorID(c),
			Action:    "create_manual_adjustment",
			TargetID:  adj.ID,
			Details:   auditDetails(map[string]interface{}{"input": input}),
			CreatedAt: time.Now(),
		})
		if err != nil {
			logger.LogError("CreateManualAdjustment: audit log failed", logger.ErrorField(err))
		}
	}
	return c.Status(fiber.StatusCreated).JSON(adj)
}

func (h *BillingAdminHandler) CreateManualRefund(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := getActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "manual_refund", "create")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input Refund
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("CreateManualRefund: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if err := input.Validate(); err != nil {
		logger.LogError("CreateManualRefund: validation failed", logger.ErrorField(err))
		errResp := fiber.Map{"error": err.Error()}
		if apiErr, ok := any(err).(*Error); ok {
			errResp["error"] = apiErr.Message
			errResp["code"] = apiErr.Code
			errResp["field"] = apiErr.Field
		}
		return c.Status(fiber.StatusUnprocessableEntity).JSON(errResp)
	}
	refund, err := h.ManualRefundService.CreateManualRefund(input)
	if err != nil {
		logger.LogError("CreateManualRefund: failed", logger.ErrorField(err))
		errResp := fiber.Map{"error": err.Error()}
		if apiErr, ok := err.(*Error); ok {
			errResp["error"] = apiErr.Message
			errResp["code"] = apiErr.Code
			errResp["field"] = apiErr.Field
		}
		return c.Status(fiber.StatusUnprocessableEntity).JSON(errResp)
	}
	if h.AuditLogger != nil {
		_, err := h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        refund.ID,
			ActorID:   getActorID(c),
			Action:    "create_manual_refund",
			TargetID:  refund.ID,
			Details:   auditDetails(map[string]interface{}{"input": input}),
			CreatedAt: time.Now(),
		})
		if err != nil {
			logger.LogError("CreateManualRefund: audit log failed", logger.ErrorField(err))
		}
	}
	return c.Status(fiber.StatusCreated).JSON(refund)
}

func (h *BillingAdminHandler) PerformAccountAction(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := getActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "account_action", "perform")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input struct {
		ID     string                 `json:"id"`
		Action string                 `json:"action"`
		Params map[string]interface{} `json:"params"`
	}
	if err := c.BodyParser(&input); err != nil || input.ID == "" || input.Action == "" {
		logger.LogError("PerformAccountAction: id and action required", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id and action required"})
	}
	result, err := h.AccountActionService.PerformAccountAction(c.Context(), input.ID, input.Action, input.Params)
	if err != nil {
		logger.LogError("PerformAccountAction: failed", logger.ErrorField(err), logger.String("account_id", input.ID), logger.String("action", input.Action))
		errResp := fiber.Map{"error": err.Error()}
		if apiErr, ok := err.(*Error); ok {
			errResp["error"] = apiErr.Message
			errResp["code"] = apiErr.Code
			errResp["field"] = apiErr.Field
		}
		return c.Status(fiber.StatusUnprocessableEntity).JSON(errResp)
	}
	if h.AuditLogger != nil {
		_, err := h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        input.ID,
			ActorID:   getActorID(c),
			Action:    "perform_account_action",
			TargetID:  input.ID,
			Details:   auditDetails(map[string]interface{}{"action": input.Action, "params": input.Params}),
			CreatedAt: time.Now(),
		})
		if err != nil {
			logger.LogError("PerformAccountAction: audit log failed", logger.ErrorField(err))
		}
	}
	return c.Status(fiber.StatusOK).JSON(result)
}

func (h *BillingAdminHandler) GetInvoicePreview(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := getActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "invoice_preview", "get")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input struct {
		ID string `json:"id"`
	}
	if err := c.BodyParser(&input); err != nil || input.ID == "" {
		logger.LogError("GetInvoicePreview: id required", logger.String("id", input.ID))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	if err := h.PaymentMethodService.DeletePaymentMethod(input.ID); err != nil {
		logger.LogError("DeletePaymentMethod: failed", logger.ErrorField(err), logger.String("id", input.ID))
		errResp := fiber.Map{"error": "failed to delete payment method"}
		if apiErr, ok := err.(*Error); ok {
			errResp["error"] = apiErr.Message
			errResp["code"] = apiErr.Code
			errResp["field"] = apiErr.Field
		}
		return c.Status(fiber.StatusUnprocessableEntity).JSON(errResp)
	}
	if h.AuditLogger != nil {
		_, err := h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        input.ID,
			ActorID:   getActorID(c),
			Action:    "delete_payment_method",
			TargetID:  input.ID,
			Details:   auditDetails(map[string]interface{}{"id": input.ID}),
			CreatedAt: time.Now(),
		})
		if err != nil {
			logger.LogError("GetInvoicePreview: audit log failed", logger.ErrorField(err))
		}
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *BillingAdminHandler) RedeemCoupon(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := getActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "coupon", "redeem")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input struct {
		Code      string `json:"code"`
		AccountID string `json:"account_id"`
	}
	if err := c.BodyParser(&input); err != nil || input.Code == "" || input.AccountID == "" {
		logger.LogError("RedeemCoupon: code and account_id required", logger.String("code", input.Code), logger.String("account_id", input.AccountID))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "code and account_id required"})
	}
	coupon, err := h.CouponService.RedeemCoupon(input.Code, input.AccountID)
	if err != nil {
		logger.LogError("RedeemCoupon: failed", logger.ErrorField(err), logger.String("code", input.Code))
		errResp := fiber.Map{"error": err.Error()}
		if apiErr, ok := err.(*Error); ok {
			errResp["error"] = apiErr.Message
			errResp["code"] = apiErr.Code
			errResp["field"] = apiErr.Field
		}
		return c.Status(fiber.StatusUnprocessableEntity).JSON(errResp)
	}
	if h.AuditLogger != nil {
		_, err := h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        coupon.ID,
			ActorID:   getActorID(c),
			Action:    "redeem_coupon",
			TargetID:  input.AccountID,
			Details:   auditDetails(map[string]interface{}{"code": input.Code, "account_id": input.AccountID}),
			CreatedAt: time.Now(),
		})
		if err != nil {
			logger.LogError("RedeemCoupon: audit log failed", logger.ErrorField(err))
		}
	}
	return c.JSON(coupon)
}

func (h *BillingAdminHandler) ApplyCreditsToInvoice(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := getActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "credit", "apply")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input struct {
		InvoiceID string `json:"invoice_id"`
	}
	if err := c.BodyParser(&input); err != nil || input.InvoiceID == "" {
		logger.LogError("ApplyCreditsToInvoice: invoice_id required", logger.String("invoice_id", input.InvoiceID))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invoice_id required"})
	}
	if err := h.CreditService.ApplyCreditsToInvoice(input.InvoiceID); err != nil {
		logger.LogError("ApplyCreditsToInvoice: failed", logger.ErrorField(err), logger.String("invoice_id", input.InvoiceID))
		errResp := fiber.Map{"error": err.Error()}
		if apiErr, ok := err.(*Error); ok {
			errResp["error"] = apiErr.Message
			errResp["code"] = apiErr.Code
			errResp["field"] = apiErr.Field
		}
		return c.Status(fiber.StatusUnprocessableEntity).JSON(errResp)
	}
	if h.AuditLogger != nil {
		_, err := h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        input.InvoiceID,
			ActorID:   getActorID(c),
			Action:    "apply_credits_to_invoice",
			TargetID:  input.InvoiceID,
			Details:   auditDetails(map[string]interface{}{"invoice_id": input.InvoiceID}),
			CreatedAt: time.Now(),
		})
		if err != nil {
			logger.LogError("ApplyCreditsToInvoice: audit log failed", logger.ErrorField(err))
		}
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *BillingAdminHandler) GetBillingConfig(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := getActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "billing_config", "get")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input struct{}
	_ = c.BodyParser(&input) // Accepts empty body for consistency
	cfg, err := h.InvoiceService.GetBillingConfig()
	if err != nil {
		logger.LogError("GetBillingConfig: failed", logger.ErrorField(err))
		errResp := fiber.Map{"error": err.Error()}
		if apiErr, ok := err.(*Error); ok {
			errResp["error"] = apiErr.Message
			errResp["code"] = apiErr.Code
			errResp["field"] = apiErr.Field
		}
		return c.Status(fiber.StatusUnprocessableEntity).JSON(errResp)
	}
	if h.AuditLogger != nil {
		_, err := h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        "billing_config",
			ActorID:   getActorID(c),
			Action:    "get_billing_config",
			TargetID:  "billing_config",
			Details:   auditDetails(cfg),
			CreatedAt: time.Now(),
		})
		if err != nil {
			logger.LogError("GetBillingConfig: audit log failed", logger.ErrorField(err))
		}
	}
	return c.JSON(cfg)
}

func (h *BillingAdminHandler) SetBillingConfig(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := getActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "billing_config", "set")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input map[string]interface{}
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("SetBillingConfig: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if err := h.InvoiceService.SetBillingConfig(input); err != nil {
		logger.LogError("SetBillingConfig: failed", logger.ErrorField(err))
		errResp := fiber.Map{"error": err.Error()}
		if apiErr, ok := err.(*Error); ok {
			errResp["error"] = apiErr.Message
			errResp["code"] = apiErr.Code
			errResp["field"] = apiErr.Field
		}
		return c.Status(fiber.StatusUnprocessableEntity).JSON(errResp)
	}
	if h.AuditLogger != nil {
		_, err := h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        "billing_config",
			ActorID:   getActorID(c),
			Action:    "set_billing_config",
			TargetID:  "billing_config",
			Details:   auditDetails(input),
			CreatedAt: time.Now(),
		})
		if err != nil {
			logger.LogError("SetBillingConfig: audit log failed", logger.ErrorField(err))
		}
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *BillingAdminHandler) CreateWebhookSubscription(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := getActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "webhook_subscription", "create")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input WebhookSubscription
	if err := c.BodyParser(&input); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	out, err := h.WebhookSubscriptionService.CreateWebhookSubscription(c.Context(), input)
	if err != nil {
		errResp := fiber.Map{"error": err.Error()}
		if apiErr, ok := err.(*Error); ok {
			errResp["error"] = apiErr.Message
			errResp["code"] = apiErr.Code
			errResp["field"] = apiErr.Field
		}
		return c.Status(fiber.StatusUnprocessableEntity).JSON(errResp)
	}
	if h.AuditLogger != nil {
		_, err := h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        out.ID,
			ActorID:   getActorID(c),
			Action:    "create_webhook_subscription",
			TargetID:  out.ID,
			Details:   auditDetails(map[string]interface{}{"input": input}),
			CreatedAt: time.Now(),
		})
		if err != nil {
			logger.LogError("CreateWebhookSubscription: audit log failed", logger.ErrorField(err))
		}
	}
	return c.Status(fiber.StatusCreated).JSON(out)
}

func (h *BillingAdminHandler) ListWebhookSubscriptions(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := getActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "webhook_subscription", "list")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input struct {
		TenantID string `json:"tenant_id"`
		Page     int    `json:"page"`
		PageSize int    `json:"page_size"`
	}
	if err := c.BodyParser(&input); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if input.Page == 0 {
		input.Page = 1
	}
	if input.PageSize == 0 {
		input.PageSize = 100
	}
	out, err := h.WebhookSubscriptionService.ListWebhookSubscriptions(c.Context(), input.TenantID, input.Page, input.PageSize)
	if err != nil {
		errResp := fiber.Map{"error": err.Error()}
		if apiErr, ok := err.(*Error); ok {
			errResp["error"] = apiErr.Message
			errResp["code"] = apiErr.Code
			errResp["field"] = apiErr.Field
		}
		return c.Status(fiber.StatusUnprocessableEntity).JSON(errResp)
	}
	if h.AuditLogger != nil {
		_, err := h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        "",
			ActorID:   getActorID(c),
			Action:    "list_webhook_subscriptions",
			TargetID:  input.TenantID,
			Details:   auditDetails(map[string]interface{}{"tenant_id": input.TenantID, "page": input.Page, "page_size": input.PageSize}),
			CreatedAt: time.Now(),
		})
		if err != nil {
			logger.LogError("ListWebhookSubscriptions: audit log failed", logger.ErrorField(err))
		}
	}
	return c.JSON(out)
}

func (h *BillingAdminHandler) DeleteWebhookSubscription(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := getActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "webhook_subscription", "delete")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input struct {
		ID string `json:"id"`
	}
	if err := c.BodyParser(&input); err != nil || input.ID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	if err := h.WebhookSubscriptionService.DeleteWebhookSubscription(c.Context(), input.ID); err != nil {
		errResp := fiber.Map{"error": err.Error()}
		if apiErr, ok := err.(*Error); ok {
			errResp["error"] = apiErr.Message
			errResp["code"] = apiErr.Code
			errResp["field"] = apiErr.Field
		}
		return c.Status(fiber.StatusUnprocessableEntity).JSON(errResp)
	}
	if h.AuditLogger != nil {
		_, err := h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        input.ID,
			ActorID:   getActorID(c),
			Action:    "delete_webhook_subscription",
			TargetID:  input.ID,
			Details:   auditDetails(map[string]interface{}{"subscription_id": input.ID}),
			CreatedAt: time.Now(),
		})
		if err != nil {
			logger.LogError("DeleteWebhookSubscription: audit log failed", logger.ErrorField(err))
		}
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *BillingAdminHandler) SetTaxInfo(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := getActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "tax_info", "set")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input TaxInfo
	if err := c.BodyParser(&input); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	out, err := h.TaxInfoService.SetTaxInfo(c.Context(), input)
	if err != nil {
		errResp := fiber.Map{"error": err.Error()}
		if apiErr, ok := err.(*Error); ok {
			errResp["error"] = apiErr.Message
			errResp["code"] = apiErr.Code
			errResp["field"] = apiErr.Field
		}
		return c.Status(fiber.StatusUnprocessableEntity).JSON(errResp)
	}
	if h.AuditLogger != nil {
		_, err := h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        out.ID,
			ActorID:   getActorID(c),
			Action:    "set_tax_info",
			TargetID:  out.ID,
			Details:   auditDetails(map[string]interface{}{"input": input}),
			CreatedAt: time.Now(),
		})
		if err != nil {
			logger.LogError("SetTaxInfo: audit log failed", logger.ErrorField(err))
		}
	}
	return c.Status(fiber.StatusCreated).JSON(out)
}

func (h *BillingAdminHandler) GetTaxInfo(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := getActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "tax_info", "get")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input struct {
		TenantID string `json:"tenant_id"`
	}
	if err := c.BodyParser(&input); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	out, err := h.TaxInfoService.GetTaxInfo(c.Context(), input.TenantID)
	if err != nil {
		errResp := fiber.Map{"error": err.Error()}
		if apiErr, ok := err.(*Error); ok {
			errResp["error"] = apiErr.Message
			errResp["code"] = apiErr.Code
			errResp["field"] = apiErr.Field
		}
		return c.Status(fiber.StatusUnprocessableEntity).JSON(errResp)
	}
	if h.AuditLogger != nil {
		_, err := h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        input.TenantID,
			ActorID:   getActorID(c),
			Action:    "get_tax_info",
			TargetID:  input.TenantID,
			Details:   auditDetails(map[string]interface{}{"tenant_id": input.TenantID}),
			CreatedAt: time.Now(),
		})
		if err != nil {
			logger.LogError("GetTaxInfo: audit log failed", logger.ErrorField(err))
		}
	}
	return c.JSON(out)
}

func (h *BillingAdminHandler) GetRevenueReport(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := getActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "revenue_report", "get")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input struct{}
	_ = c.BodyParser(&input)
	out, err := h.Store.GetRevenueReport(c.Context())
	if err != nil {
		errResp := fiber.Map{"error": err.Error()}
		if apiErr, ok := err.(*Error); ok {
			errResp["error"] = apiErr.Message
			errResp["code"] = apiErr.Code
			errResp["field"] = apiErr.Field
		}
		return c.Status(fiber.StatusUnprocessableEntity).JSON(errResp)
	}
	if h.AuditLogger != nil {
		_, err := h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        "revenue_report",
			ActorID:   getActorID(c),
			Action:    "get_revenue_report",
			TargetID:  "revenue_report",
			Details:   auditDetails(out),
			CreatedAt: time.Now(),
		})
		if err != nil {
			logger.LogError("GetRevenueReport: audit log failed", logger.ErrorField(err))
		}
	}
	return c.JSON(out)
}

func (h *BillingAdminHandler) GetARReport(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := getActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "ar_report", "get")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input struct{}
	_ = c.BodyParser(&input)
	out, err := h.Store.GetARReport(c.Context())
	if err != nil {
		errResp := fiber.Map{"error": err.Error()}
		if apiErr, ok := err.(*Error); ok {
			errResp["error"] = apiErr.Message
			errResp["code"] = apiErr.Code
			errResp["field"] = apiErr.Field
		}
		return c.Status(fiber.StatusUnprocessableEntity).JSON(errResp)
	}
	if h.AuditLogger != nil {
		_, err := h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        "ar_report",
			ActorID:   getActorID(c),
			Action:    "get_ar_report",
			TargetID:  "ar_report",
			Details:   auditDetails(out),
			CreatedAt: time.Now(),
		})
		if err != nil {
			logger.LogError("GetARReport: audit log failed", logger.ErrorField(err))
		}
	}
	return c.JSON(out)
}

func (h *BillingAdminHandler) GetChurnReport(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := getActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "churn_report", "get")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input struct{}
	_ = c.BodyParser(&input)
	out, err := h.Store.GetChurnReport(c.Context())
	if err != nil {
		errResp := fiber.Map{"error": err.Error()}
		if apiErr, ok := err.(*Error); ok {
			errResp["error"] = apiErr.Message
			errResp["code"] = apiErr.Code
			errResp["field"] = apiErr.Field
		}
		return c.Status(fiber.StatusUnprocessableEntity).JSON(errResp)
	}
	if h.AuditLogger != nil {
		_, err := h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        "churn_report",
			ActorID:   getActorID(c),
			Action:    "get_churn_report",
			TargetID:  "churn_report",
			Details:   auditDetails(out),
			CreatedAt: time.Now(),
		})
		if err != nil {
			logger.LogError("GetChurnReport: audit log failed", logger.ErrorField(err))
		}
	}
	return c.JSON(out)
}

func (h *BillingAdminHandler) AggregateUsageForBillingCycle(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := getActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "aggregate_usage", "get")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input struct {
		AccountID   string `json:"account_id"`
		PeriodStart string `json:"period_start"`
		PeriodEnd   string `json:"period_end"`
	}
	if err := c.BodyParser(&input); err != nil || input.AccountID == "" || input.PeriodStart == "" || input.PeriodEnd == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "account_id, period_start, and period_end required"})
	}
	periodStart, err := time.Parse(time.RFC3339, input.PeriodStart)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid period_start format"})
	}
	periodEnd, err := time.Parse(time.RFC3339, input.PeriodEnd)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid period_end format"})
	}
	out, err := h.Store.AggregateUsageForBillingCycle(c.Context(), input.AccountID, periodStart, periodEnd)
	if err != nil {
		errResp := fiber.Map{"error": err.Error()}
		if apiErr, ok := err.(*Error); ok {
			errResp["error"] = apiErr.Message
			errResp["code"] = apiErr.Code
			errResp["field"] = apiErr.Field
		}
		return c.Status(fiber.StatusUnprocessableEntity).JSON(errResp)
	}
	if h.AuditLogger != nil {
		_, err := h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        "aggregate_usage",
			ActorID:   getActorID(c),
			Action:    "aggregate_usage_for_billing_cycle",
			TargetID:  input.AccountID,
			Details:   auditDetails(map[string]interface{}{"account_id": input.AccountID, "period_start": input.PeriodStart, "period_end": input.PeriodEnd}),
			CreatedAt: time.Now(),
		})
		if err != nil {
			logger.LogError("AggregateUsageForBillingCycle: audit log failed", logger.ErrorField(err))
		}
	}
	return c.JSON(out)
}

func (h *BillingAdminHandler) CalculateOverageCharges(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := getActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "overage_charges", "calculate")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input struct {
		AccountID   string `json:"account_id"`
		PlanID      string `json:"plan_id"`
		PeriodStart string `json:"period_start"`
		PeriodEnd   string `json:"period_end"`
	}
	if err := c.BodyParser(&input); err != nil || input.AccountID == "" || input.PlanID == "" || input.PeriodStart == "" || input.PeriodEnd == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "account_id, plan_id, period_start, and period_end required"})
	}
	periodStart, err := time.Parse(time.RFC3339, input.PeriodStart)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid period_start format"})
	}
	periodEnd, err := time.Parse(time.RFC3339, input.PeriodEnd)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid period_end format"})
	}
	out, err := h.Store.CalculateOverageCharges(c.Context(), input.AccountID, input.PlanID, periodStart, periodEnd)
	if err != nil {
		errResp := fiber.Map{"error": err.Error()}
		if apiErr, ok := err.(*Error); ok {
			errResp["error"] = apiErr.Message
			errResp["code"] = apiErr.Code
			errResp["field"] = apiErr.Field
		}
		return c.Status(fiber.StatusUnprocessableEntity).JSON(errResp)
	}
	if h.AuditLogger != nil {
		_, err := h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        "overage_charges",
			ActorID:   getActorID(c),
			Action:    "calculate_overage_charges",
			TargetID:  input.AccountID,
			Details:   auditDetails(map[string]interface{}{"account_id": input.AccountID, "plan_id": input.PlanID, "period_start": input.PeriodStart, "period_end": input.PeriodEnd}),
			CreatedAt: time.Now(),
		})
		if err != nil {
			logger.LogError("CalculateOverageCharges: audit log failed", logger.ErrorField(err))
		}
	}
	return c.JSON(out)
}

func (h *BillingAdminHandler) CreateInvoiceWithFeesAndTax(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := getActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "invoice", "create")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input struct {
		Invoice    Invoice `json:"invoice"`
		FixedFee   float64 `json:"fixed_fee"`
		PercentFee float64 `json:"percent_fee"`
		TaxRate    float64 `json:"tax_rate"`
	}
	if err := c.BodyParser(&input); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	out, err := h.Store.CreateInvoiceWithFeesAndTax(c.Context(), input.Invoice, input.FixedFee, input.PercentFee, input.TaxRate)
	if err != nil {
		errResp := fiber.Map{"error": err.Error()}
		if apiErr, ok := err.(*Error); ok {
			errResp["error"] = apiErr.Message
			errResp["code"] = apiErr.Code
			errResp["field"] = apiErr.Field
		}
		return c.Status(fiber.StatusUnprocessableEntity).JSON(errResp)
	}
	if h.AuditLogger != nil {
		_, err := h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        out.ID,
			ActorID:   getActorID(c),
			Action:    "create_invoice_with_fees_and_tax",
			TargetID:  out.ID,
			Details:   auditDetails(map[string]interface{}{"input": input}),
			CreatedAt: time.Now(),
		})
		if err != nil {
			logger.LogError("CreateInvoiceWithFeesAndTax: audit log failed", logger.ErrorField(err))
		}
	}
	return c.Status(fiber.StatusCreated).JSON(out)
}

func (h *BillingAdminHandler) DeletePaymentMethod(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := getActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "payment_method", "delete")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input struct {
		ID string `json:"id"`
	}
	if err := c.BodyParser(&input); err != nil || input.ID == "" {
		logger.LogError("DeletePaymentMethod: id required", logger.String("id", input.ID))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	if err := h.PaymentMethodService.DeletePaymentMethod(input.ID); err != nil {
		logger.LogError("DeletePaymentMethod: failed", logger.ErrorField(err), logger.String("id", input.ID))
		errResp := fiber.Map{"error": err.Error()}
		if apiErr, ok := err.(*Error); ok {
			errResp["error"] = apiErr.Message
			errResp["code"] = apiErr.Code
			errResp["field"] = apiErr.Field
		}
		return c.Status(fiber.StatusUnprocessableEntity).JSON(errResp)
	}
	if h.AuditLogger != nil {
		_, err := h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        input.ID,
			ActorID:   getActorID(c),
			Action:    "delete_payment_method",
			TargetID:  input.ID,
			Details:   auditDetails(map[string]interface{}{"id": input.ID}),
			CreatedAt: time.Now(),
		})
		if err != nil {
			logger.LogError("DeletePaymentMethod: audit log failed", logger.ErrorField(err))
		}
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *BillingAdminHandler) ListUsage(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := getActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "usage", "list")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input struct {
		AccountID string `json:"account_id"`
		Metric    string `json:"metric"`
		Period    string `json:"period"`
		Page      int    `json:"page"`
		PageSize  int    `json:"page_size"`
	}
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("ListUsage: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if input.Page == 0 {
		input.Page = 1
	}
	if input.PageSize == 0 {
		input.PageSize = 100
	}
	usages, err := h.UsageService.ListUsage(input.AccountID, input.Metric, input.Period, input.Page, input.PageSize)
	if err != nil {
		logger.LogError("ListUsage: failed", logger.ErrorField(err), logger.String("account_id", input.AccountID), logger.String("metric", input.Metric), logger.String("period", input.Period))
		errResp := fiber.Map{"error": err.Error()}
		if apiErr, ok := err.(*Error); ok {
			errResp["error"] = apiErr.Message
			errResp["code"] = apiErr.Code
			errResp["field"] = apiErr.Field
		}
		return c.Status(fiber.StatusUnprocessableEntity).JSON(errResp)
	}
	if h.AuditLogger != nil {
		_, err := h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        "",
			ActorID:   getActorID(c),
			Action:    "list_usage",
			TargetID:  input.AccountID,
			Details:   auditDetails(map[string]interface{}{"account_id": input.AccountID, "metric": input.Metric, "period": input.Period, "page": input.Page, "page_size": input.PageSize}),
			CreatedAt: time.Now(),
		})
		if err != nil {
			logger.LogError("ListUsage: audit log failed", logger.ErrorField(err))
		}
	}
	return c.JSON(fiber.Map{"usages": usages, "page": input.Page, "page_size": input.PageSize})
}

func (h *BillingAdminHandler) CreateInvoice(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := getActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "invoice", "create")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input Invoice
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("CreateInvoice: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if err := input.Validate(); err != nil {
		logger.LogError("CreateInvoice: validation failed", logger.ErrorField(err))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Message, "code": err.Code, "field": err.Field})
	}
	account, err := h.AccountService.GetAccount(input.AccountID)
	if err != nil {
		logger.LogError("CreateInvoice: account not found", logger.ErrorField(err), logger.String("account_id", input.AccountID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": "account not found"})
	}
	currency := strings.ToUpper(strings.TrimSpace(input.Currency))
	if currency == "" {
		currency = strings.ToUpper(strings.TrimSpace(account.Currency))
		if currency == "" {
			return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": "no currency set for invoice or account"})
		}
		input.Currency = currency
	}
	if input.Currency != account.Currency && account.Currency != "" {
		rate, rerr := h.Store.GetExchangeRate(c.Context(), input.Currency, account.Currency)
		if rerr != nil || rate.Rate <= 0 {
			return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": "no valid exchange rate from " + input.Currency + " to " + account.Currency})
		}
		input.OriginalAmount = input.Amount
		input.OriginalCurrency = input.Currency
		input.Amount = input.Amount * rate.Rate
		input.Currency = account.Currency
	}
	// --- Tax plugin selection and calculation ---
	pluginName := "default"
	if cfg, err := h.Store.GetTaxPluginConfig(c.Context(), account.TenantID); err == nil && cfg.PluginName != "" {
		pluginName = cfg.PluginName
	}
	plugin, ok := TaxPlugins.Lookup(pluginName)
	if !ok {
		plugin = DefaultTaxPlugin{}
	}
	taxAmount, taxRate, terr := plugin.CalculateTax(c.Context(), input, account, account.TenantID)
	if terr != nil {
		logger.LogError("CreateInvoice: tax plugin failed", logger.ErrorField(terr), logger.String("plugin", pluginName))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": "tax calculation failed: " + terr.Error()})
	}
	input.TaxAmount = taxAmount
	input.TaxRate = taxRate
	invoice, err := h.InvoiceService.CreateInvoice(input)
	if err != nil {
		logger.LogError("CreateInvoice: failed", logger.ErrorField(err), logger.Any("input", input))
		errResp := fiber.Map{"error": err.Error()}
		if apiErr, ok := err.(*Error); ok {
			errResp["error"] = apiErr.Message
			errResp["code"] = apiErr.Code
			errResp["field"] = apiErr.Field
		}
		return c.Status(fiber.StatusUnprocessableEntity).JSON(errResp)
	}
	if h.AuditLogger != nil {
		_, err := h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        invoice.ID,
			ActorID:   getActorID(c),
			Action:    "create_invoice",
			TargetID:  invoice.AccountID,
			Details:   auditDetails(map[string]interface{}{"input": input, "account_currency": account.Currency, "tax_plugin": pluginName}),
			CreatedAt: time.Now(),
		})
		if err != nil {
			logger.LogError("CreateInvoice: audit log failed", logger.ErrorField(err))
		}
	}
	return c.Status(fiber.StatusCreated).JSON(invoice)
}

func (h *BillingAdminHandler) UpdateInvoice(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := getActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "invoice", "update")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input Invoice
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("UpdateInvoice: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if err := input.Validate(); err != nil {
		logger.LogError("UpdateInvoice: validation failed", logger.ErrorField(err))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Message, "code": err.Code, "field": err.Field})
	}
	invoice, err := h.InvoiceService.UpdateInvoice(input)
	if err != nil {
		logger.LogError("UpdateInvoice: failed", logger.ErrorField(err), logger.Any("input", input))
		errResp := fiber.Map{"error": err.Error()}
		if apiErr, ok := err.(*Error); ok {
			errResp["error"] = apiErr.Message
			errResp["code"] = apiErr.Code
			errResp["field"] = apiErr.Field
		}
		return c.Status(fiber.StatusUnprocessableEntity).JSON(errResp)
	}
	if h.AuditLogger != nil {
		_, err := h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        invoice.ID,
			ActorID:   getActorID(c),
			Action:    "update_invoice",
			TargetID:  invoice.AccountID,
			Details:   auditDetails(map[string]interface{}{"input": input}),
			CreatedAt: time.Now(),
		})
		if err != nil {
			logger.LogError("UpdateInvoice: audit log failed", logger.ErrorField(err))
		}
	}
	return c.JSON(invoice)
}

func (h *BillingAdminHandler) GetInvoice(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := getActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "invoice", "get")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input struct {
		InvoiceID string `json:"invoice_id"`
	}
	if err := c.BodyParser(&input); err != nil || input.InvoiceID == "" {
		logger.LogError("GetInvoice: invoice_id required", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invoice_id required"})
	}
	invoice, err := h.InvoiceService.GetInvoice(input.InvoiceID)
	if err != nil {
		logger.LogError("CreateInvoiceAdjustment: invoice not found", logger.ErrorField(err), logger.String("invoice_id", input.InvoiceID))
		logger.LogError("GetInvoice: not found", logger.ErrorField(err))
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": err.Error()})
	}
	if h.AuditLogger != nil {
		_, err := h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        invoice.ID,
			ActorID:   getActorID(c),
			Action:    "get_invoice",
			TargetID:  invoice.AccountID,
			Details:   auditDetails(map[string]interface{}{"id": invoice.ID}),
			CreatedAt: time.Now(),
		})
		if err != nil {
			logger.LogError("GetInvoice: audit log failed", logger.ErrorField(err))
		}
	}
	return c.JSON(invoice)
}

func (h *BillingAdminHandler) ListInvoices(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := getActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "invoice", "list")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input struct {
		AccountID string `json:"account_id"`
		Status    string `json:"status"`
		Page      int    `json:"page"`
		PageSize  int    `json:"page_size"`
	}
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("ListInvoices: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if input.Page == 0 {
		input.Page = 1
	}
	if input.PageSize == 0 {
		input.PageSize = 100
	}
	invoices, err := h.InvoiceService.ListInvoices(input.AccountID, input.Status, input.Page, input.PageSize)
	if err != nil {
		logger.LogError("ListInvoices: failed", logger.ErrorField(err), logger.String("account_id", input.AccountID), logger.String("status", input.Status))
		errResp := fiber.Map{"error": err.Error()}
		if apiErr, ok := err.(*Error); ok {
			errResp["error"] = apiErr.Message
			errResp["code"] = apiErr.Code
			errResp["field"] = apiErr.Field
		}
		return c.Status(fiber.StatusUnprocessableEntity).JSON(errResp)
	}
	if h.AuditLogger != nil {
		_, err := h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        "",
			ActorID:   getActorID(c),
			Action:    "list_invoices",
			TargetID:  input.AccountID,
			Details:   auditDetails(map[string]interface{}{"account_id": input.AccountID, "status": input.Status, "page": input.Page, "page_size": input.PageSize}),
			CreatedAt: time.Now(),
		})
		if err != nil {
			logger.LogError("ListInvoices: audit log failed", logger.ErrorField(err))
		}
	}
	return c.JSON(fiber.Map{"invoices": invoices, "page": input.Page, "page_size": input.PageSize})
}

func (h *BillingAdminHandler) CreatePayment(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := getActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "payment", "create")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	idempotencyKey := c.Get("Idempotency-Key")
	var input Payment
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("CreatePayment: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if input.Metadata == "" && idempotencyKey != "" {
		input.Metadata = `{"idempotency_key":"` + idempotencyKey + `"}`
	}
	if idempotencyKey != "" {
		existing, err := h.PaymentService.GetPaymentByIdempotencyKey(idempotencyKey)
		if err == nil && existing.ID != "" {
			return c.Status(fiber.StatusConflict).JSON(fiber.Map{"error": "duplicate payment", "payment": existing})
		}
	}
	if err := input.Validate(); err != nil {
		logger.LogError("CreatePayment: validation failed", logger.ErrorField(err))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Message, "code": err.Code, "field": err.Field})
	}
	invoice, err := h.InvoiceService.GetInvoice(input.InvoiceID)
	if err != nil {
		logger.LogError("CreatePayment: invoice not found", logger.ErrorField(err), logger.String("invoice_id", input.InvoiceID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": "invoice not found"})
	}
	account, err := h.AccountService.GetAccount(invoice.AccountID)
	if err != nil {
		logger.LogError("CreatePayment: account not found", logger.ErrorField(err), logger.String("account_id", invoice.AccountID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": "account not found"})
	}
	currency := strings.ToUpper(strings.TrimSpace(input.Currency))
	if currency == "" {
		currency = strings.ToUpper(strings.TrimSpace(invoice.Currency))
		if currency == "" {
			currency = strings.ToUpper(strings.TrimSpace(account.Currency))
			if currency == "" {
				tc, terr := h.Store.GetTenantCurrency(c.Context(), account.TenantID)
				if terr != nil || tc.Currency == "" {
					return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": "no currency set for payment, invoice, account, or tenant"})
				}
				currency = tc.Currency
			}
		}
		input.Currency = currency
	}
	if input.Currency != invoice.Currency && invoice.Currency != "" {
		// Multi-currency: convert
		rate, rerr := h.Store.GetExchangeRate(c.Context(), input.Currency, invoice.Currency)
		if rerr != nil || rate.Rate <= 0 {
			return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": "no valid exchange rate from " + input.Currency + " to " + invoice.Currency})
		}
		input.OriginalAmount = input.Amount
		input.OriginalCurrency = input.Currency
		input.Amount = input.Amount * rate.Rate
		input.Currency = invoice.Currency
	}
	payment, err := h.PaymentService.CreatePayment(input)
	if err != nil {
		logger.LogError("CreatePayment: failed", logger.ErrorField(err), logger.Any("input", input))
		errResp := fiber.Map{"error": err.Error()}
		if apiErr, ok := err.(*Error); ok {
			errResp["error"] = apiErr.Message
			errResp["code"] = apiErr.Code
			errResp["field"] = apiErr.Field
		}
		return c.Status(fiber.StatusUnprocessableEntity).JSON(errResp)
	}
	if h.AuditLogger != nil {
		_, err := h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        payment.ID,
			ActorID:   getActorID(c),
			Action:    "create_payment",
			TargetID:  payment.InvoiceID,
			Details:   auditDetails(map[string]interface{}{"input": input, "invoice_currency": invoice.Currency}),
			CreatedAt: time.Now(),
		})
		if err != nil {
			logger.LogError("CreatePayment: audit log failed", logger.ErrorField(err))
		}
	}
	return c.Status(fiber.StatusCreated).JSON(payment)
}

func (h *BillingAdminHandler) UpdatePayment(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := getActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "payment", "update")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input Payment
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("UpdatePayment: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if err := input.Validate(); err != nil {
		logger.LogError("UpdatePayment: validation failed", logger.ErrorField(err))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Message, "code": err.Code, "field": err.Field})
	}
	payment, err := h.PaymentService.UpdatePayment(input)
	if err != nil {
		logger.LogError("UpdatePayment: failed", logger.ErrorField(err), logger.Any("input", input))
		errResp := fiber.Map{"error": err.Error()}
		if apiErr, ok := err.(*Error); ok {
			errResp["error"] = apiErr.Message
			errResp["code"] = apiErr.Code
			errResp["field"] = apiErr.Field
		}
		return c.Status(fiber.StatusUnprocessableEntity).JSON(errResp)
	}
	if h.AuditLogger != nil {
		_, err := h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        payment.ID,
			ActorID:   getActorID(c),
			Action:    "update_payment",
			TargetID:  payment.InvoiceID,
			Details:   auditDetails(map[string]interface{}{"input": input}),
			CreatedAt: time.Now(),
		})
		if err != nil {
			logger.LogError("UpdatePayment: audit log failed", logger.ErrorField(err))
		}
	}
	return c.JSON(payment)
}

func (h *BillingAdminHandler) GetPayment(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := getActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "payment", "get")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input struct {
		PaymentID string `json:"payment_id"`
	}
	if err := c.BodyParser(&input); err != nil || input.PaymentID == "" {
		logger.LogError("GetPayment: payment_id required", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "payment_id required"})
	}
	payment, err := h.PaymentService.GetPayment(input.PaymentID)
	if err != nil {
		logger.LogError("GetPayment: not found", logger.ErrorField(err))
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "payment method not found"})
	}
	if h.AuditLogger != nil {
		_, err := h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        payment.ID,
			ActorID:   getActorID(c),
			Action:    "get_payment",
			TargetID:  payment.InvoiceID,
			Details:   auditDetails(map[string]interface{}{"id": payment.ID}),
			CreatedAt: time.Now(),
		})
		if err != nil {
			logger.LogError("GetPayment: audit log failed", logger.ErrorField(err))
		}
	}
	return c.JSON(payment)
}

func (h *BillingAdminHandler) ListPayments(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := getActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "payment", "list")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input struct {
		InvoiceID string `json:"invoice_id"`
		Page      int    `json:"page"`
		PageSize  int    `json:"page_size"`
	}
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("ListPayments: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if input.Page == 0 {
		input.Page = 1
	}
	if input.PageSize == 0 {
		input.PageSize = 100
	}
	payments, err := h.PaymentService.ListPayments(input.InvoiceID, input.Page, input.PageSize)
	if err != nil {
		logger.LogError("ListPayments: failed", logger.ErrorField(err), logger.String("invoice_id", input.InvoiceID))
		errResp := fiber.Map{"error": err.Error()}
		if apiErr, ok := err.(*Error); ok {
			errResp["error"] = apiErr.Message
			errResp["code"] = apiErr.Code
			errResp["field"] = apiErr.Field
		}
		return c.Status(fiber.StatusUnprocessableEntity).JSON(errResp)
	}
	if h.AuditLogger != nil {
		_, err := h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        "",
			ActorID:   getActorID(c),
			Action:    "list_payments",
			TargetID:  input.InvoiceID,
			Details:   auditDetails(map[string]interface{}{"invoice_id": input.InvoiceID, "page": input.Page, "page_size": input.PageSize}),
			CreatedAt: time.Now(),
		})
		if err != nil {
			logger.LogError("ListPayments: audit log failed", logger.ErrorField(err))
		}
	}
	return c.JSON(fiber.Map{"payments": payments, "page": input.Page, "page_size": input.PageSize})
}

func (h *BillingAdminHandler) CreateDiscount(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := getActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "discount", "create")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input Discount
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("CreateDiscount: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if err := input.Validate(); err != nil {
		logger.LogError("CreateDiscount: validation failed", logger.ErrorField(err))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Message, "code": err.Code, "field": err.Field})
	}
	discount, err := h.DiscountService.CreateDiscount(input)
	if err != nil {
		logger.LogError("CreateDiscount: failed", logger.ErrorField(err), logger.Any("input", input))
		errResp := fiber.Map{"error": err.Error()}
		if apiErr, ok := err.(*Error); ok {
			errResp["error"] = apiErr.Message
			errResp["code"] = apiErr.Code
			errResp["field"] = apiErr.Field
		}
		return c.Status(fiber.StatusUnprocessableEntity).JSON(errResp)
	}
	if h.AuditLogger != nil {
		_, err := h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        discount.ID,
			ActorID:   getActorID(c),
			Action:    "create_discount",
			TargetID:  discount.ID,
			Details:   auditDetails(map[string]interface{}{"input": input}),
			CreatedAt: time.Now(),
		})
		if err != nil {
			logger.LogError("CreateDiscount: audit log failed", logger.ErrorField(err))
		}
	}
	return c.Status(fiber.StatusCreated).JSON(discount)
}

func (h *BillingAdminHandler) UpdateDiscount(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := getActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "discount", "update")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input Discount
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("UpdateDiscount: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if input.ID == "" {
		logger.LogError("UpdateDiscount: id required")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	if err := input.Validate(); err != nil {
		logger.LogError("UpdateDiscount: validation failed", logger.ErrorField(err))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Message, "code": err.Code, "field": err.Field})
	}
	discount, err := h.DiscountService.UpdateDiscount(input)
	if err != nil {
		logger.LogError("UpdateDiscount: failed", logger.ErrorField(err), logger.Any("input", input))
		errResp := fiber.Map{"error": err.Error()}
		if apiErr, ok := err.(*Error); ok {
			errResp["error"] = apiErr.Message
			errResp["code"] = apiErr.Code
			errResp["field"] = apiErr.Field
		}
		return c.Status(fiber.StatusUnprocessableEntity).JSON(errResp)
	}
	if h.AuditLogger != nil {
		_, err := h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        discount.ID,
			ActorID:   getActorID(c),
			Action:    "update_discount",
			TargetID:  discount.ID,
			Details:   auditDetails(map[string]interface{}{"input": input}),
			CreatedAt: time.Now(),
		})
		if err != nil {
			logger.LogError("UpdateDiscount: audit log failed", logger.ErrorField(err))
		}
	}
	return c.JSON(discount)
}

func (h *BillingAdminHandler) DeleteDiscount(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := getActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "discount", "delete")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input struct {
		ID string `json:"id"`
	}
	if err := c.BodyParser(&input); err != nil || input.ID == "" {
		logger.LogError("DeleteDiscount: id required", logger.String("id", input.ID))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	if err := h.DiscountService.DeleteDiscount(input.ID); err != nil {
		logger.LogError("DeleteDiscount: failed", logger.ErrorField(err), logger.String("id", input.ID))
		errResp := fiber.Map{"error": err.Error()}
		if apiErr, ok := err.(*Error); ok {
			errResp["error"] = apiErr.Message
			errResp["code"] = apiErr.Code
			errResp["field"] = apiErr.Field
		}
		return c.Status(fiber.StatusUnprocessableEntity).JSON(errResp)
	}
	if h.AuditLogger != nil {
		_, err := h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        input.ID,
			ActorID:   getActorID(c),
			Action:    "delete_discount",
			TargetID:  input.ID,
			Details:   auditDetails(map[string]interface{}{"id": input.ID}),
			CreatedAt: time.Now(),
		})
		if err != nil {
			logger.LogError("DeleteDiscount: audit log failed", logger.ErrorField(err))
		}
	}
	return c.SendStatus(fiber.StatusNoContent)
}

// --- ExchangeRate Handlers ---

func (h *BillingAdminHandler) CreateExchangeRate(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := getActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "exchange_rate", "create")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input ExchangeRate
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("CreateExchangeRate: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if input.BaseCurrency == "" || input.QuoteCurrency == "" || input.Rate <= 0 {
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": "base_currency, quote_currency, and positive rate required"})
	}
	if len(input.BaseCurrency) != 3 || len(input.QuoteCurrency) != 3 {
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": "currencies must be ISO 4217 codes"})
	}
	input.BaseCurrency = strings.ToUpper(input.BaseCurrency)
	input.QuoteCurrency = strings.ToUpper(input.QuoteCurrency)
	input.UpdatedAt = time.Now().UTC()
	if input.ID == "" {
		input.ID = generateUUID()
	}
	rate, err := h.Store.CreateExchangeRate(c.Context(), input)
	if err != nil {
		logger.LogError("CreateExchangeRate: failed", logger.ErrorField(err), logger.Any("input", input))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if h.AuditLogger != nil {
		_, err := h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        rate.ID,
			ActorID:   getActorID(c),
			Action:    "create_exchange_rate",
			TargetID:  rate.ID,
			Details:   auditDetails(input),
			CreatedAt: time.Now(),
		})
		if err != nil {
			logger.LogError("CreateExchangeRate: audit log failed", logger.ErrorField(err))
		}
	}
	return c.Status(fiber.StatusCreated).JSON(rate)
}

func (h *BillingAdminHandler) UpdateExchangeRate(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := getActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "exchange_rate", "update")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input ExchangeRate
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("UpdateExchangeRate: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if input.BaseCurrency == "" || input.QuoteCurrency == "" || input.Rate <= 0 {
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": "base_currency, quote_currency, and positive rate required"})
	}
	if len(input.BaseCurrency) != 3 || len(input.QuoteCurrency) != 3 {
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": "currencies must be ISO 4217 codes"})
	}
	input.BaseCurrency = strings.ToUpper(input.BaseCurrency)
	input.QuoteCurrency = strings.ToUpper(input.QuoteCurrency)
	input.UpdatedAt = time.Now().UTC()
	rate, err := h.Store.UpdateExchangeRate(c.Context(), input)
	if err != nil {
		logger.LogError("UpdateExchangeRate: failed", logger.ErrorField(err), logger.Any("input", input))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if h.AuditLogger != nil {
		_, err := h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        rate.ID,
			ActorID:   getActorID(c),
			Action:    "update_exchange_rate",
			TargetID:  rate.ID,
			Details:   auditDetails(input),
			CreatedAt: time.Now(),
		})
		if err != nil {
			logger.LogError("UpdateExchangeRate: audit log failed", logger.ErrorField(err))
		}
	}
	return c.JSON(rate)
}

func (h *BillingAdminHandler) DeleteExchangeRate(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := getActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "exchange_rate", "delete")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input struct {
		BaseCurrency  string `json:"base_currency"`
		QuoteCurrency string `json:"quote_currency"`
	}
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("DeleteExchangeRate: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if input.BaseCurrency == "" || input.QuoteCurrency == "" {
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": "base_currency and quote_currency required"})
	}
	if len(input.BaseCurrency) != 3 || len(input.QuoteCurrency) != 3 {
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": "currencies must be ISO 4217 codes"})
	}
	input.BaseCurrency = strings.ToUpper(input.BaseCurrency)
	input.QuoteCurrency = strings.ToUpper(input.QuoteCurrency)
	err := h.Store.DeleteExchangeRate(c.Context(), input.BaseCurrency, input.QuoteCurrency)
	if err != nil {
		logger.LogError("DeleteExchangeRate: failed", logger.ErrorField(err), logger.Any("input", input))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if h.AuditLogger != nil {
		_, err := h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        "",
			ActorID:   getActorID(c),
			Action:    "delete_exchange_rate",
			TargetID:  input.BaseCurrency + ":" + input.QuoteCurrency,
			Details:   auditDetails(input),
			CreatedAt: time.Now(),
		})
		if err != nil {
			logger.LogError("DeleteExchangeRate: audit log failed", logger.ErrorField(err))
		}
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *BillingAdminHandler) GetExchangeRate(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := getActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "exchange_rate", "read")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input struct {
		BaseCurrency  string `json:"base_currency"`
		QuoteCurrency string `json:"quote_currency"`
	}
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("GetExchangeRate: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if input.BaseCurrency == "" || input.QuoteCurrency == "" {
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": "base_currency and quote_currency required"})
	}
	if len(input.BaseCurrency) != 3 || len(input.QuoteCurrency) != 3 {
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": "currencies must be ISO 4217 codes"})
	}
	input.BaseCurrency = strings.ToUpper(input.BaseCurrency)
	input.QuoteCurrency = strings.ToUpper(input.QuoteCurrency)
	rate, err := h.Store.GetExchangeRate(c.Context(), input.BaseCurrency, input.QuoteCurrency)
	if err != nil {
		logger.LogError("GetExchangeRate: failed", logger.ErrorField(err), logger.Any("input", input))
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(rate)
}

func (h *BillingAdminHandler) ListExchangeRates(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := getActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "exchange_rate", "list")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	rates, err := h.Store.ListExchangeRates(c.Context())
	if err != nil {
		logger.LogError("ListExchangeRates: failed", logger.ErrorField(err))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(fiber.Map{"exchange_rates": rates})
}

// generateUUID returns a new RFC4122 UUID string
func generateUUID() string {
	return uuid.NewString()
}

// --- TenantCurrency Handlers ---

func (h *BillingAdminHandler) SetTenantCurrency(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := getActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "tenant_currency", "set")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input struct {
		TenantID string `json:"tenant_id"`
		Currency string `json:"currency"`
	}
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("SetTenantCurrency: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if input.TenantID == "" || input.Currency == "" {
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": "tenant_id and currency required"})
	}
	curr, err := h.Store.SetTenantCurrency(c.Context(), input.TenantID, input.Currency)
	if err != nil {
		logger.LogError("SetTenantCurrency: failed", logger.ErrorField(err), logger.Any("input", input))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if h.AuditLogger != nil {
		_, err := h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        input.TenantID,
			ActorID:   getActorID(c),
			Action:    "set_tenant_currency",
			TargetID:  input.TenantID,
			Details:   auditDetails(input),
			CreatedAt: time.Now(),
		})
		if err != nil {
			logger.LogError("SetTenantCurrency: audit log failed", logger.ErrorField(err))
		}
	}
	return c.Status(fiber.StatusCreated).JSON(curr)
}

func (h *BillingAdminHandler) GetTenantCurrency(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := getActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "tenant_currency", "get")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input struct {
		TenantID string `json:"tenant_id"`
	}
	if err := c.BodyParser(&input); err != nil || input.TenantID == "" {
		logger.LogError("GetTenantCurrency: tenant_id required", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "tenant_id required"})
	}
	curr, err := h.Store.GetTenantCurrency(c.Context(), input.TenantID)
	if err != nil {
		logger.LogError("GetTenantCurrency: failed", logger.ErrorField(err), logger.String("tenant_id", input.TenantID))
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(curr)
}

// --- TaxPlugin Handlers ---

func (h *BillingAdminHandler) ListTaxPlugins(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := getActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "tax_plugin", "list")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	plugins, err := h.Store.ListTaxPlugins(c.Context())
	if err != nil {
		logger.LogError("ListTaxPlugins: failed", logger.ErrorField(err))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(fiber.Map{"plugins": plugins})
}

func (h *BillingAdminHandler) SetTaxPluginConfig(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := getActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "tax_plugin", "set")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input struct {
		TenantID   string `json:"tenant_id"`
		PluginName string `json:"plugin_name"`
	}
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("SetTaxPluginConfig: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if input.TenantID == "" || input.PluginName == "" {
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": "tenant_id and plugin_name required"})
	}
	if _, ok := TaxPlugins.Lookup(input.PluginName); !ok {
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": "plugin not found"})
	}
	cfg, err := h.Store.SetTaxPluginConfig(c.Context(), input.TenantID, input.PluginName)
	if err != nil {
		logger.LogError("SetTaxPluginConfig: failed", logger.ErrorField(err), logger.Any("input", input))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if h.AuditLogger != nil {
		_, err := h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        input.TenantID,
			ActorID:   getActorID(c),
			Action:    "set_tax_plugin_config",
			TargetID:  input.TenantID,
			Details:   auditDetails(input),
			CreatedAt: time.Now(),
		})
		if err != nil {
			logger.LogError("SetTaxPluginConfig: audit log failed", logger.ErrorField(err))
		}
	}
	return c.Status(fiber.StatusCreated).JSON(cfg)
}

func generateInvoicePDF(pdfData map[string]interface{}) ([]byte, error) {
	pdf := gofpdf.New("P", "mm", "A4", "")
	if title, ok := pdfData["title"].(string); ok && title != "" {
		pdf.SetTitle(title, false)
	}
	pdf.AddPage()

	// Logo (optional)
	if logo, ok := pdfData["logo"].(string); ok && logo != "" {
		pdf.ImageOptions(logo, 10, 10, 30, 0, false, gofpdf.ImageOptions{}, 0, "")
		pdf.Ln(20)
	}

	// Header lines (optional)
	if header, ok := pdfData["header"].([]string); ok {
		pdf.SetFont("Arial", "B", 20)
		for _, line := range header {
			pdf.Cell(0, 12, line)
			pdf.Ln(8)
		}
		pdf.Ln(4)
	}

	// Fields (label/value pairs)
	if fields, ok := pdfData["fields"].([][2]string); ok {
		pdf.SetFont("Arial", "", 12)
		for _, pair := range fields {
			pdf.Cell(40, 8, pair[0])
			pdf.Cell(0, 8, pair[1])
			pdf.Ln(8)
		}
		pdf.Ln(4)
	}

	// Table (rows: description, amount, currency)
	if table, ok := pdfData["table"].([][3]string); ok && len(table) > 0 {
		pdf.SetFont("Arial", "B", 12)
		pdf.Cell(60, 8, "Description")
		pdf.Cell(40, 8, "Amount")
		pdf.Cell(40, 8, "Currency")
		pdf.Ln(8)
		pdf.SetFont("Arial", "", 12)
		for _, row := range table {
			pdf.Cell(60, 8, row[0])
			pdf.Cell(40, 8, row[1])
			pdf.Cell(40, 8, row[2])
			pdf.Ln(8)
		}
		pdf.Ln(4)
	}

	// Footer/notes (optional)
	if footer, ok := pdfData["footer"].(string); ok && footer != "" {
		pdf.SetFont("Arial", "I", 10)
		pdf.MultiCell(0, 7, footer, "", "L", false)
	}

	var buf bytes.Buffer
	if err := pdf.Output(&buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// DownloadInvoicePDF returns the invoice PDF as an attachment. Only JSON body allowed.
func (h *BillingAdminHandler) DownloadInvoicePDF(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := getActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "invoice", "read")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input struct {
		InvoiceID string `json:"invoice_id"`
	}
	if err := c.BodyParser(&input); err != nil || input.InvoiceID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invoice_id required"})
	}
	invoice, err := h.InvoiceService.GetInvoice(input.InvoiceID)
	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "invoice not found"})
	}
	account, err := h.AccountService.GetAccount(invoice.AccountID)
	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "account not found"})
	}
	pdfData := map[string]interface{}{
		"title":  "Invoice " + invoice.ID,
		"header": []string{"INVOICE"},
		"fields": [][2]string{
			{"Invoice ID:", invoice.ID},
			{"Status:", invoice.Status},
			{"Account Email:", account.Email},
			{"Account ID:", account.ID},
			{"Created:", invoice.CreatedAt.Format("2006-01-02 15:04")},
			{"Due Date:", invoice.DueDate.Format("2006-01-02")},
		},
		"table": [][3]string{
			{"Subtotal", fmt.Sprintf("%.2f", invoice.Amount-invoice.TaxAmount), invoice.Currency},
			{"Tax", fmt.Sprintf("%.2f (%.2f%%)", invoice.TaxAmount, invoice.TaxRate), invoice.Currency},
			{"Total", fmt.Sprintf("%.2f", invoice.Amount), invoice.Currency},
		},
		"footer": "Thank you for your business. If you have any questions, contact support@company.com.",
	}
	if invoice.OriginalAmount > 0 && invoice.OriginalCurrency != "" {
		table := pdfData["table"].([][3]string)
		table = append(table, [3]string{"Original Amount", fmt.Sprintf("%.2f", invoice.OriginalAmount), invoice.OriginalCurrency})
		pdfData["table"] = table
	}
	pdfBytes, pdfErr := generateInvoicePDF(pdfData)
	if pdfErr != nil {
		return c.Status(fiber.StatusNotImplemented).JSON(fiber.Map{"error": pdfErr.Error()})
	}
	c.Set("Content-Type", "application/pdf")
	c.Set("Content-Disposition", "attachment; filename=invoice-"+invoice.ID+".pdf")
	if h.AuditLogger != nil {
		_, err := h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        invoice.ID,
			ActorID:   getActorID(c),
			Action:    "download_invoice_pdf",
			TargetID:  invoice.AccountID,
			Details:   auditDetails(map[string]interface{}{"invoice_id": invoice.ID}),
			CreatedAt: time.Now(),
		})
		if err != nil {
			logger.LogError("DownloadInvoicePDF: audit log failed", logger.ErrorField(err))
		}
	}
	return c.Send(pdfBytes)
}

func (h *BillingAdminHandler) RefundPayment(c *fiber.Ctx) error {
	var req payment.RefundPaymentRequest
	if err := c.BodyParser(&req); err != nil {
		logger.LogError("billing.refund_payment.invalid_request", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid request"})
	}
	result, err := h.PaymentService.RefundPayment(c.Context(), &req)
	if err != nil {
		logger.LogError("billing.refund_payment.failed", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}
	return c.Status(fiber.StatusOK).JSON(result)
}

func (h *BillingAdminHandler) GetPaymentStatus(c *fiber.Ctx) error {
	paymentID := c.Query("payment_id")
	if paymentID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "payment_id is required"})
	}
	result, err := h.PaymentService.GetPaymentStatus(c.Context(), paymentID)
	if err != nil {
		logger.LogError("billing.get_payment_status.failed", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}
	return c.Status(fiber.StatusOK).JSON(result)
}

func DunningJob(ctx context.Context, store paymentpkg.StoreInterface, notificationService security_management.NotificationService, auditLogger security_management.AuditLogger, tenantID string) error {
	failedPayments, err := store.ListFailedPayments(ctx, tenantID)
	if err != nil {
		logger.LogError("dunning.list_failed_payments", logger.ErrorField(err))
		return err
	}
	dunningCfg, err := store.GetDunningConfig(ctx, tenantID)
	if err != nil {
		logger.LogError("dunning.get_config", logger.ErrorField(err))
		return err
	}
	now := time.Now().UTC()
	for _, p := range failedPayments {
		if p.DunningAttempts >= dunningCfg.MaxAttempts {
			if p.DunningState != "failed" {
				_ = store.UpdateDunningState(ctx, p.ID, "failed", p.DunningAttempts)
				_ = notificationService.SendNotification(ctx, tenantID, "dunning_failed", map[string]interface{}{"payment_id": p.ID, "invoice_id": p.InvoiceID})
				if auditLogger != nil {
					_, _ = auditLogger.CreateSecurityAuditLog(ctx, security_management.SecurityAuditLog{
						ActorID:   "system",
						Action:    "dunning_failed",
						TargetID:  p.ID,
						Details:   paymentpkg.MarshalAuditDetails(map[string]interface{}{"payment_id": p.ID, "invoice_id": p.InvoiceID}),
						CreatedAt: now,
					})
				}
			}
			continue
		}
		if now.Sub(p.LastDunningAttempt) < dunningCfg.RetryIntervals[p.DunningAttempts] {
			continue
		}
		// Attempt retry
		result, retryErr := paymentpkg.RetryPayment(ctx, store, p)
		_ = store.UpdateDunningAttempt(ctx, p.ID, now, p.DunningAttempts+1)
		if retryErr == nil && result.Status == "completed" {
			_ = store.UpdateDunningState(ctx, p.ID, "recovered", p.DunningAttempts+1)
			_ = notificationService.SendNotification(ctx, tenantID, "dunning_recovered", map[string]interface{}{"payment_id": p.ID, "invoice_id": p.InvoiceID})
			if auditLogger != nil {
				_, _ = auditLogger.CreateSecurityAuditLog(ctx, security_management.SecurityAuditLog{
					ActorID:   "system",
					Action:    "dunning_recovered",
					TargetID:  p.ID,
					Details:   paymentpkg.MarshalAuditDetails(map[string]interface{}{"payment_id": p.ID, "invoice_id": p.InvoiceID}),
					CreatedAt: now,
				})
			}
			continue
		}
		_ = notificationService.SendNotification(ctx, tenantID, "dunning_retry", map[string]interface{}{"payment_id": p.ID, "invoice_id": p.InvoiceID, "attempt": p.DunningAttempts + 1})
		if auditLogger != nil {
			_, _ = auditLogger.CreateSecurityAuditLog(ctx, security_management.SecurityAuditLog{
				ActorID:   "system",
				Action:    "dunning_retry",
				TargetID:  p.ID,
				Details:   paymentpkg.MarshalAuditDetails(map[string]interface{}{"payment_id": p.ID, "invoice_id": p.InvoiceID, "attempt": p.DunningAttempts + 1}),
				CreatedAt: now,
			})
		}
	}
	return nil
}

func (h *BillingAdminHandler) ListDisputes(c *fiber.Ctx) error {
	var input struct {
		TenantID  string                `json:"tenant_id"`
		PaymentID string                `json:"payment_id"`
		Status    payment.DisputeStatus `json:"status"`
		Page      int                   `json:"page"`
		PageSize  int                   `json:"page_size"`
	}
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("ListDisputes: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if input.Page == 0 {
		input.Page = 1
	}
	if input.PageSize == 0 {
		input.PageSize = 100
	}
	list, err := h.DisputeService.ListDisputes(c.Context(), input.TenantID, input.PaymentID, input.Status, input.Page, input.PageSize)
	if err != nil {
		logger.LogError("ListDisputes: failed", logger.ErrorField(err))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(list)
}

// GetDispute admin handler
func (h *BillingAdminHandler) GetDispute(c *fiber.Ctx) error {
	id := c.Query("id")
	if id == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	d, err := h.DisputeService.GetDispute(c.Context(), id)
	if err != nil {
		logger.LogError("GetDispute: failed", logger.ErrorField(err))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(d)
}

// UpdateDisputeStatus admin handler
func (h *BillingAdminHandler) UpdateDisputeStatus(c *fiber.Ctx) error {
	var input struct {
		DisputeID         string                `json:"dispute_id"`
		Status            payment.DisputeStatus `json:"status"`
		EvidenceSubmitted *time.Time            `json:"evidence_submitted,omitempty"`
	}
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("UpdateDisputeStatus: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if input.DisputeID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "dispute_id required"})
	}
	err := h.DisputeService.UpdateDisputeStatus(c.Context(), input.DisputeID, input.Status, input.EvidenceSubmitted)
	if err != nil {
		logger.LogError("UpdateDisputeStatus: failed", logger.ErrorField(err))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.SendStatus(fiber.StatusOK)
}

// ListDisputeEvidence admin handler
func (h *BillingAdminHandler) ListDisputeEvidence(c *fiber.Ctx) error {
	var input struct {
		DisputeID string `json:"dispute_id"`
		TenantID  string `json:"tenant_id"`
		Page      int    `json:"page"`
		PageSize  int    `json:"page_size"`
	}
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("ListDisputeEvidence: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if input.Page == 0 {
		input.Page = 1
	}
	if input.PageSize == 0 {
		input.PageSize = 100
	}
	list, err := h.DisputeEvidenceService.ListEvidence(c.Context(), input.DisputeID, input.TenantID, input.Page, input.PageSize)
	if err != nil {
		logger.LogError("ListDisputeEvidence: failed", logger.ErrorField(err))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(list)
}

// GetDisputeEvidence admin handler
func (h *BillingAdminHandler) GetDisputeEvidence(c *fiber.Ctx) error {
	id := c.Query("id")
	if id == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	e, err := h.DisputeEvidenceService.GetEvidence(c.Context(), id)
	if err != nil {
		logger.LogError("GetDisputeEvidence: failed", logger.ErrorField(err))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(e)
}

// UploadDisputeEvidence admin handler
func (h *BillingAdminHandler) UploadDisputeEvidence(c *fiber.Ctx) error {
	var input payment.DisputeEvidence
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("UploadDisputeEvidence: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if input.DisputeID == "" || input.TenantID == "" || input.FileURL == "" || input.FileName == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "missing required fields"})
	}
	err := h.DisputeEvidenceService.UploadEvidence(c.Context(), &input)
	if err != nil {
		logger.LogError("UploadDisputeEvidence: failed", logger.ErrorField(err))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.SendStatus(fiber.StatusOK)
}

// UpdateDisputeEvidenceStatus admin handler
func (h *BillingAdminHandler) UpdateDisputeEvidenceStatus(c *fiber.Ctx) error {
	var input struct {
		EvidenceID       string `json:"evidence_id"`
		ProviderStatus   string `json:"provider_status"`
		ProviderResponse string `json:"provider_response"`
	}
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("UpdateDisputeEvidenceStatus: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if input.EvidenceID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "evidence_id required"})
	}
	err := h.DisputeEvidenceService.UpdateEvidenceStatus(c.Context(), input.EvidenceID, input.ProviderStatus, input.ProviderResponse)
	if err != nil {
		logger.LogError("UpdateDisputeEvidenceStatus: failed", logger.ErrorField(err))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.SendStatus(fiber.StatusOK)
}
