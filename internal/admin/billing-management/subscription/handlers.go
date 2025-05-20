package subscription

import (
	"github.com/gofiber/fiber/v2"
	"github.com/subinc/subinc-backend/internal/pkg/logger"
)

func (h *SubscriptionHandler) CreatePlan(c *fiber.Ctx) error {
	var input Plan
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("CreatePlan: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request format"})
	}

	if err := input.Validate(); err != nil {
		logger.LogError("CreatePlan: validation failed", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request format"})
	}

	plan, err := h.PlanService.CreatePlan(input)
	if err != nil {
		logger.LogError("CreatePlan: failed", logger.ErrorField(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to process request"})
	}

	return c.Status(fiber.StatusCreated).JSON(plan)
}

func (h *SubscriptionHandler) UpdatePlan(c *fiber.Ctx) error {
	var input Plan
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("UpdatePlan: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if err := input.Validate(); err != nil {
		logger.LogError("UpdatePlan: validation failed", logger.ErrorField(err))
		return c.JSON(fiber.ErrBadRequest)
	}
	plan, err := h.PlanService.UpdatePlan(input)
	if err != nil {
		logger.LogError("UpdatePlan: failed", logger.ErrorField(err), logger.Any("input", input))

		return c.JSON(fiber.ErrBadRequest)
	}

	return c.JSON(plan)
}

func (h *SubscriptionHandler) GetPlan(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		logger.LogError("GetPlan: id required", logger.String("path", c.Path()))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Missing required parameter"})
	}

	plan, err := h.PlanService.GetPlan(id)
	if err != nil {
		logger.LogError("GetPlan: not found or error", logger.ErrorField(err), logger.String("id", id))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to process request"})
	}

	return c.JSON(plan)
}

func (h *SubscriptionHandler) ListPlans(c *fiber.Ctx) error {
	activeOnly := c.QueryBool("active_only", false)
	page := c.QueryInt("page", 1)
	pageSize := c.QueryInt("page_size", 100)
	plans, err := h.PlanService.ListPlans(activeOnly, page, pageSize)
	if err != nil {
		return c.JSON(fiber.ErrExpectationFailed)
	}
	return c.JSON(fiber.Map{"plans": plans, "page": page, "page_size": pageSize})
}

func (h *SubscriptionHandler) DeletePlan(c *fiber.Ctx) error {
	var input struct {
		PlanID string `json:"plan_id"`
	}
	if err := c.BodyParser(&input); err != nil || input.PlanID == "" {
		logger.LogError("DeletePlan: plan_id required", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "plan_id required"})
	}
	if err := h.PlanService.DeletePlan(input.PlanID); err != nil {
		logger.LogError("DeletePlan: failed", logger.ErrorField(err))

		return c.JSON(fiber.ErrBadRequest)
	}

	return c.SendStatus(fiber.StatusNoContent)
}

func (h *SubscriptionHandler) CreateUsage(c *fiber.Ctx) error {
	var input Usage
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("CreateUsage: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if err := input.Validate(); err != nil {
		logger.LogError("CreateUsage: validation failed", logger.ErrorField(err))
		return c.JSON(fiber.ErrBadRequest)
	}
	usage, err := h.UsageService.CreateUsage(input)
	if err != nil {
		logger.LogError("CreateUsage: failed", logger.ErrorField(err), logger.Any("input", input))

		return c.JSON(fiber.ErrBadRequest)
	}

	return c.Status(fiber.StatusCreated).JSON(usage)
}

func (h *SubscriptionHandler) ListUsage(c *fiber.Ctx) error {
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

		return c.JSON(fiber.ErrBadRequest)
	}

	return c.JSON(fiber.Map{"usages": usages, "page": input.Page, "page_size": input.PageSize})
}

func (h *SubscriptionHandler) CreateSubscription(c *fiber.Ctx) error {
	var input Subscription
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("CreateSubscription: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if err := input.Validate(); err != nil {
		logger.LogError("CreateSubscription: validation failed", logger.ErrorField(err))
		return c.JSON(fiber.ErrBadRequest)
	}
	sub, err := h.SubscriptionService.CreateSubscription(input)
	if err != nil {
		logger.LogError("CreateSubscription: failed", logger.ErrorField(err))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": "failed to create subscription"})
	}

	return c.Status(fiber.StatusCreated).JSON(sub)
}

func (h *SubscriptionHandler) UpdateSubscription(c *fiber.Ctx) error {
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
		return c.JSON(fiber.ErrBadRequest)
	}
	sub, err := h.SubscriptionService.UpdateSubscription(input)
	if err != nil {
		logger.LogError("UpdateSubscription: failed", logger.ErrorField(err))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": "failed to update subscription"})
	}

	return c.JSON(sub)
}

func (h *SubscriptionHandler) PatchSubscription(c *fiber.Ctx) error {
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

		return c.JSON(fiber.ErrBadRequest)
	}

	return c.SendStatus(fiber.StatusNoContent)
}

func (h *SubscriptionHandler) DeleteSubscription(c *fiber.Ctx) error {
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

// ListSubscriptionPlugins returns all registered subscription plugins
func (h *SubscriptionHandler) ListSubscriptionPlugins(c *fiber.Ctx) error {
	pluginNames := h.SubscriptionService.ListSubscriptionPlugins()
	if len(pluginNames) == 0 {
		logger.LogInfo("ListSubscriptionPlugins: no plugins found")
	}
	return c.JSON(fiber.Map{"plugins": pluginNames})
}

// GetSubscriptionPlugin returns details about a specific subscription plugin
func (h *SubscriptionHandler) GetSubscriptionPlugin(c *fiber.Ctx) error {
	pluginName := c.Params("name")
	if pluginName == "" {
		logger.LogError("GetSubscriptionPlugin: plugin name is required", logger.String("path", c.Path()))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Missing required parameter"})
	}

	_, exists := h.SubscriptionService.GetSubscriptionPlugin(pluginName)
	if !exists {
		logger.LogError("GetSubscriptionPlugin: plugin not found", logger.String("plugin_name", pluginName))
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "Resource not found"})
	}

	return c.JSON(fiber.Map{
		"name":         pluginName,
		"capabilities": "custom", // Extend as needed
	})
}

// ConfigureSubscriptionPlugin configures a subscription plugin
func (h *SubscriptionHandler) ConfigureSubscriptionPlugin(c *fiber.Ctx) error {
	pluginName := c.Params("name")
	if pluginName == "" {
		logger.LogError("ConfigureSubscriptionPlugin: plugin name is required", logger.String("path", c.Path()))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Missing required parameter"})
	}

	var config map[string]interface{}
	if err := c.BodyParser(&config); err != nil {
		logger.LogError("ConfigureSubscriptionPlugin: invalid configuration format", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request format"})
	}

	if err := h.SubscriptionService.ConfigureSubscriptionPlugin(pluginName, config); err != nil {
		if err == ErrPluginNotFound {
			logger.LogError("ConfigureSubscriptionPlugin: plugin not found", logger.String("plugin_name", pluginName))
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "Resource not found"})
		}
		logger.LogError("ConfigureSubscriptionPlugin: failed to configure plugin", logger.ErrorField(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to process request"})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"status":  "success",
		"message": "Subscription plugin configured successfully",
	})
}

// DisableSubscriptionPlugin disables a subscription plugin (removes from registry)
func (h *SubscriptionHandler) DisableSubscriptionPlugin(c *fiber.Ctx) error {
	pluginName := c.Params("name")
	if pluginName == "" {
		logger.LogError("DisableSubscriptionPlugin: plugin name is required", logger.String("path", c.Path()))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Missing required parameter"})
	}

	if err := h.SubscriptionService.DisableSubscriptionPlugin(pluginName); err != nil {
		if err == ErrPluginNotFound {
			logger.LogError("DisableSubscriptionPlugin: plugin not found", logger.String("plugin_name", pluginName))
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "Resource not found"})
		}
		logger.LogError("DisableSubscriptionPlugin: failed to disable plugin", logger.ErrorField(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to process request"})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"status":  "success",
		"message": "Subscription plugin disabled successfully",
	})
}

// ProcessAutoRenewals handles automatic renewal of subscriptions
func (h *SubscriptionHandler) ProcessAutoRenewals(c *fiber.Ctx) error {
	// Process renewals
	if err := h.SubscriptionService.ProcessAutoRenewals(); err != nil {
		logger.LogError("ProcessAutoRenewals: failed", logger.ErrorField(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to process request",
		})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"status":  "success",
		"message": "Subscription renewals processed successfully",
	})
}
