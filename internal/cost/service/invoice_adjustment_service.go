package service

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/subinc/subinc-backend/internal/cost/domain"
	"github.com/subinc/subinc-backend/internal/cost/repository"
	"github.com/subinc/subinc-backend/internal/pkg/logger"
)

type InvoiceAdjustmentService interface {
	ApplyAdjustment(ctx context.Context, adj *domain.InvoiceAdjustment) error
	GetInvoiceAdjustmentByID(ctx context.Context, id string) (*domain.InvoiceAdjustment, error)
	ListInvoiceAdjustments(ctx context.Context, invoiceID, adjType string, page, pageSize int) ([]*domain.InvoiceAdjustment, int, error)
}

type invoiceAdjustmentService struct {
	repo   repository.BillingRepository
	logger *logger.Logger
}

func NewInvoiceAdjustmentService(repo repository.BillingRepository, log *logger.Logger) InvoiceAdjustmentService {
	if log == nil {
		log = logger.NewNoop()
	}
	return &invoiceAdjustmentService{repo: repo, logger: log}
}

func (s *invoiceAdjustmentService) ApplyAdjustment(ctx context.Context, adj *domain.InvoiceAdjustment) error {
	if adj == nil {
		s.logger.Error("nil invoice adjustment provided")
		return domain.NewValidationError("invoice_adjustment", "must not be nil")
	}
	adj.ID = uuid.NewString()
	adj.CreatedAt = time.Now().UTC()
	adj.UpdatedAt = adj.CreatedAt
	return s.repo.CreateInvoiceAdjustment(ctx, adj)
}

func (s *invoiceAdjustmentService) GetInvoiceAdjustmentByID(ctx context.Context, id string) (*domain.InvoiceAdjustment, error) {
	return s.repo.GetInvoiceAdjustmentByID(ctx, id)
}

func (s *invoiceAdjustmentService) ListInvoiceAdjustments(ctx context.Context, invoiceID, adjType string, page, pageSize int) ([]*domain.InvoiceAdjustment, int, error) {
	return s.repo.ListInvoiceAdjustments(ctx, invoiceID, adjType, page, pageSize)
}
