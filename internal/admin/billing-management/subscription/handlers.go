package subscription

import (



	"github.com/gofiber/fiber/v2"
	"github.com/subinc/subinc-backend/internal/pkg/commonutil"
	"github.com/subinc/subinc-backend/internal/pkg/logger"
)

func (h *SubscriptionHandler) CreatePlan(c *fiber.Ctx) error { 
	if h.RBACService != nil {
		actorID := commonutil.GetActorID(c)
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

	return c.Status(fiber.StatusCreated).JSON(plan)
}

func (h *SubscriptionHandler) UpdatePlan(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := commonutil.GetActorID(c)
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

	return c.JSON(plan)
}

func (h *SubscriptionHandler) GetPlan(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := commonutil.GetActorID(c)
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

	return c.JSON(plan)
}

func (h *SubscriptionHandler) ListPlans(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := commonutil.GetActorID(c)
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
	return c.JSON(fiber.Map{"plans": plans, "page": input.Page, "page_size": input.PageSize})
}

func (h *SubscriptionHandler) DeletePlan(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := commonutil.GetActorID(c)
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

	return c.SendStatus(fiber.StatusNoContent)
}



func (h *SubscriptionHandler) CreateUsage(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := commonutil.GetActorID(c)
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

	return c.Status(fiber.StatusCreated).JSON(usage)
}

func (h *SubscriptionHandler) ListUsage(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := commonutil.GetActorID(c)
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

	return c.JSON(fiber.Map{"usages": usages, "page": input.Page, "page_size": input.PageSize})
}



func (h *SubscriptionHandler) CreateSubscription(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := commonutil.GetActorID(c)
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

	return c.Status(fiber.StatusCreated).JSON(sub)
}

func (h *SubscriptionHandler) UpdateSubscription(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := commonutil.GetActorID(c)
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

	return c.JSON(sub)
}

func (h *SubscriptionHandler) PatchSubscription(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := commonutil.GetActorID(c)
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

	return c.SendStatus(fiber.StatusNoContent)
}

func (h *SubscriptionHandler) DeleteSubscription(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := commonutil.GetActorID(c)
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

	return c.SendStatus(fiber.StatusNoContent)
}

func (h *SubscriptionHandler) GetSubscription(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := commonutil.GetActorID(c)
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

	return c.JSON(sub)
}

func (h *SubscriptionHandler) ListSubscriptions(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := commonutil.GetActorID(c)
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

	return c.JSON(fiber.Map{"subscriptions": subs, "page": input.Page, "page_size": input.PageSize})
}

func (h *SubscriptionHandler) ChangePlanSubscription(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := commonutil.GetActorID(c)
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

	return c.SendStatus(fiber.StatusNoContent)
}

func (h *SubscriptionHandler) CancelSubscriptionNow(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := commonutil.GetActorID(c)
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

	return c.SendStatus(fiber.StatusNoContent)
}

func (h *SubscriptionHandler) ResumeSubscription(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := commonutil.GetActorID(c)
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

	return c.SendStatus(fiber.StatusNoContent)
}

func (h *SubscriptionHandler) UpgradeNowSubscription(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := commonutil.GetActorID(c)
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

	return c.SendStatus(fiber.StatusNoContent)
}