package service

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/subinc/subinc-backend/internal/cost/domain"
	"github.com/subinc/subinc-backend/internal/cost/repository"
	"github.com/subinc/subinc-backend/internal/pkg/logger"
)

type WebhookEventService interface {
	ReceiveEvent(ctx context.Context, event *domain.WebhookEvent) error
	ProcessEvent(ctx context.Context, id string) error
	RetryEvent(ctx context.Context, id string) error
	GetWebhookEventByID(ctx context.Context, id string) (*domain.WebhookEvent, error)
	ListWebhookEvents(ctx context.Context, provider, status, eventType string, page, pageSize int) ([]*domain.WebhookEvent, int, error)
}

type webhookEventService struct {
	repo   repository.BillingRepository
	logger *logger.Logger
}

func NewWebhookEventService(repo repository.BillingRepository, log *logger.Logger) WebhookEventService {
	if log == nil {
		log = logger.NewNoop()
	}
	return &webhookEventService{repo: repo, logger: log}
}

func (s *webhookEventService) ReceiveEvent(ctx context.Context, event *domain.WebhookEvent) error {
	if event == nil {
		s.logger.Error("nil webhook event provided")
		return domain.NewValidationError("webhook_event", "must not be nil")
	}
	event.ID = uuid.NewString()
	event.Status = "received"
	event.ReceivedAt = time.Now().UTC()
	return s.repo.CreateWebhookEvent(ctx, event)
}

func (s *webhookEventService) ProcessEvent(ctx context.Context, id string) error {
	if id == "" {
		s.logger.Error("empty webhook event id for process")
		return domain.NewValidationError("webhook_event_id", "must not be empty")
	}
	event, err := s.repo.GetWebhookEventByID(ctx, id)
	if err != nil {
		s.logger.Error("failed to get webhook event for process", logger.ErrorField(err))
		return err
	}
	if event.Status != "received" {
		return domain.NewValidationError("webhook_event", "not in received state")
	}
	event.Status = "processed"
	event.ProcessedAt = timePtr(time.Now().UTC())
	return s.repo.UpdateWebhookEvent(ctx, event)
}

func (s *webhookEventService) RetryEvent(ctx context.Context, id string) error {
	if id == "" {
		s.logger.Error("empty webhook event id for retry")
		return domain.NewValidationError("webhook_event_id", "must not be empty")
	}
	event, err := s.repo.GetWebhookEventByID(ctx, id)
	if err != nil {
		s.logger.Error("failed to get webhook event for retry", logger.ErrorField(err))
		return err
	}
	if event.Status != "failed" {
		return domain.NewValidationError("webhook_event", "not in failed state")
	}
	event.Status = "received"
	event.Error = ""
	return s.repo.UpdateWebhookEvent(ctx, event)
}

func (s *webhookEventService) GetWebhookEventByID(ctx context.Context, id string) (*domain.WebhookEvent, error) {
	return s.repo.GetWebhookEventByID(ctx, id)
}

func (s *webhookEventService) ListWebhookEvents(ctx context.Context, provider, status, eventType string, page, pageSize int) ([]*domain.WebhookEvent, int, error) {
	return s.repo.ListWebhookEvents(ctx, provider, status, eventType, page, pageSize)
}

func timePtr(t time.Time) *time.Time {
	return &t
}
