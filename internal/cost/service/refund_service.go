package service

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/subinc/subinc-backend/internal/cost/domain"
	"github.com/subinc/subinc-backend/internal/cost/repository"
	"github.com/subinc/subinc-backend/internal/pkg/logger"
)

type RefundService interface {
	CreateRefund(ctx context.Context, refund *domain.Refund) error
	ProcessRefund(ctx context.Context, id string) error
	GetRefundByID(ctx context.Context, id string) (*domain.Refund, error)
	ListRefunds(ctx context.Context, paymentID, invoiceID, status string, page, pageSize int) ([]*domain.Refund, int, error)
}

type refundService struct {
	repo   repository.BillingRepository
	logger *logger.Logger
}

func NewRefundService(repo repository.BillingRepository, log *logger.Logger) RefundService {
	if log == nil {
		log = logger.NewNoop()
	}
	return &refundService{repo: repo, logger: log}
}

func (s *refundService) CreateRefund(ctx context.Context, refund *domain.Refund) error {
	if refund == nil {
		s.logger.Error("nil refund provided")
		return domain.NewValidationError("refund", "must not be nil")
	}
	refund.ID = uuid.NewString()
	refund.Status = "pending"
	refund.CreatedAt = time.Now().UTC()
	refund.UpdatedAt = refund.CreatedAt
	return s.repo.CreateRefund(ctx, refund)
}

func (s *refundService) ProcessRefund(ctx context.Context, id string) error {
	if id == "" {
		s.logger.Error("empty refund id for process")
		return domain.NewValidationError("refund_id", "must not be empty")
	}
	refund, err := s.repo.GetRefundByID(ctx, id)
	if err != nil {
		s.logger.Error("failed to get refund for process", logger.ErrorField(err))
		return err
	}
	if refund.Status != "pending" {
		return domain.NewValidationError("refund", "not pending")
	}
	// Fetch payment and validate
	payment, err := s.repo.GetPaymentByID(ctx, refund.PaymentID)
	if err != nil {
		s.logger.Error("failed to get payment for refund", logger.ErrorField(err))
		refund.Status = "failed"
		refund.UpdatedAt = time.Now().UTC()
		_ = s.repo.UpdateRefund(ctx, refund)
		return err
	}
	if payment.Status != "completed" {
		refund.Status = "failed"
		refund.UpdatedAt = time.Now().UTC()
		_ = s.repo.UpdateRefund(ctx, refund)
		return domain.NewValidationError("payment", "not completed")
	}
	if refund.Amount > payment.Amount {
		refund.Status = "failed"
		refund.UpdatedAt = time.Now().UTC()
		_ = s.repo.UpdateRefund(ctx, refund)
		return domain.NewValidationError("refund", "amount exceeds payment")
	}
	// Mark payment as reversed if full refund
	if refund.Amount == payment.Amount {
		payment.Status = "reversed"
		payment.UpdatedAt = time.Now().UTC()
		if err := s.repo.UpdatePayment(ctx, payment); err != nil {
			s.logger.Error("failed to mark payment as reversed", logger.ErrorField(err))
			refund.Status = "failed"
			refund.UpdatedAt = time.Now().UTC()
			_ = s.repo.UpdateRefund(ctx, refund)
			return err
		}
	}
	// Mark refund as processed
	refund.Status = "processed"
	refund.UpdatedAt = time.Now().UTC()
	return s.repo.UpdateRefund(ctx, refund)
}

func (s *refundService) GetRefundByID(ctx context.Context, id string) (*domain.Refund, error) {
	return s.repo.GetRefundByID(ctx, id)
}

func (s *refundService) ListRefunds(ctx context.Context, paymentID, invoiceID, status string, page, pageSize int) ([]*domain.Refund, int, error) {
	return s.repo.ListRefunds(ctx, paymentID, invoiceID, status, page, pageSize)
}
