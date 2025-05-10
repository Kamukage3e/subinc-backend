package billing_management

import (
	"context"
)

type paymentService struct {
	store *PostgresStore
}

func (s *paymentService) GetPaymentByIdempotencyKey(idempotencyKey string) (Payment, error) {
	return s.store.GetPaymentByIdempotencyKey(context.Background(), idempotencyKey)
}
