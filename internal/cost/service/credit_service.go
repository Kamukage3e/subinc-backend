package service

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/subinc/subinc-backend/internal/cost/domain"
	"github.com/subinc/subinc-backend/internal/cost/repository"
	"github.com/subinc/subinc-backend/internal/pkg/logger"
)

type CreditService interface {
	ApplyCredit(ctx context.Context, credit *domain.Credit) error
	ConsumeCredit(ctx context.Context, id string, amount float64) error
	ExpireCredit(ctx context.Context, id string) error
	GetCreditByID(ctx context.Context, id string) (*domain.Credit, error)
	ListCredits(ctx context.Context, accountID, invoiceID, status string, page, pageSize int) ([]*domain.Credit, int, error)
	ApplyCreditsToInvoice(ctx context.Context, invoiceID string) error
}

type creditService struct {
	repo   repository.BillingRepository
	logger *logger.Logger
}

func NewCreditService(repo repository.BillingRepository, log *logger.Logger) CreditService {
	if log == nil {
		log = logger.NewNoop()
	}
	return &creditService{repo: repo, logger: log}
}

func (s *creditService) ApplyCredit(ctx context.Context, credit *domain.Credit) error {
	if credit == nil {
		s.logger.Error("nil credit provided")
		return domain.NewValidationError("credit", "must not be nil")
	}
	credit.ID = uuid.NewString()
	credit.Status = "active"
	credit.CreatedAt = time.Now().UTC()
	credit.UpdatedAt = credit.CreatedAt
	return s.repo.CreateCredit(ctx, credit)
}

func (s *creditService) ConsumeCredit(ctx context.Context, id string, amount float64) error {
	if id == "" || amount <= 0 {
		s.logger.Error("invalid consume credit params")
		return domain.NewValidationError("credit", "invalid id or amount")
	}
	credit, err := s.repo.GetCreditByID(ctx, id)
	if err != nil {
		s.logger.Error("failed to get credit for consume", logger.ErrorField(err))
		return err
	}
	if credit.Status != "active" || credit.Amount < amount {
		return domain.NewValidationError("credit", "insufficient or inactive credit")
	}
	credit.Amount -= amount
	if credit.Amount == 0 {
		credit.Status = "consumed"
	}
	credit.UpdatedAt = time.Now().UTC()
	return s.repo.UpdateCredit(ctx, credit)
}

func (s *creditService) ExpireCredit(ctx context.Context, id string) error {
	if id == "" {
		s.logger.Error("empty credit id for expire")
		return domain.NewValidationError("credit_id", "must not be empty")
	}
	credit, err := s.repo.GetCreditByID(ctx, id)
	if err != nil {
		s.logger.Error("failed to get credit for expire", logger.ErrorField(err))
		return err
	}
	credit.Status = "expired"
	credit.UpdatedAt = time.Now().UTC()
	return s.repo.UpdateCredit(ctx, credit)
}

func (s *creditService) GetCreditByID(ctx context.Context, id string) (*domain.Credit, error) {
	return s.repo.GetCreditByID(ctx, id)
}

func (s *creditService) ListCredits(ctx context.Context, accountID, invoiceID, status string, page, pageSize int) ([]*domain.Credit, int, error) {
	return s.repo.ListCredits(ctx, accountID, invoiceID, status, page, pageSize)
}

func (s *creditService) ApplyCreditsToInvoice(ctx context.Context, invoiceID string) error {
	if invoiceID == "" {
		s.logger.Error("empty invoice id for credit application")
		return domain.NewValidationError("invoice_id", "must not be empty")
	}
	invoice, err := s.repo.GetInvoiceByID(ctx, invoiceID)
	if err != nil {
		s.logger.Error("failed to get invoice for credit application", logger.ErrorField(err))
		return err
	}
	credits, _, err := s.repo.ListCredits(ctx, invoice.AccountID, "", "active", 1, 100)
	if err != nil {
		s.logger.Error("failed to list credits for invoice", logger.ErrorField(err))
		return err
	}
	remaining := invoice.Amount
	for _, credit := range credits {
		if credit.Amount <= 0 || credit.Status != "active" {
			continue
		}
		apply := credit.Amount
		if apply > remaining {
			apply = remaining
		}
		remaining -= apply
		credit.Amount -= apply
		if credit.Amount == 0 {
			credit.Status = "consumed"
		}
		credit.UpdatedAt = time.Now().UTC()
		if err := s.repo.UpdateCredit(ctx, credit); err != nil {
			s.logger.Error("failed to update credit after application", logger.ErrorField(err))
			return err
		}
		if remaining <= 0 {
			break
		}
	}
	invoice.Amount = remaining
	invoice.UpdatedAt = time.Now().UTC()
	return s.repo.UpdateInvoice(ctx, invoice)
}
