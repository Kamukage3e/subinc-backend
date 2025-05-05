package architecture

import (
	"context"
	"errors"
	"os"

	"github.com/subinc/subinc-backend/internal/architecture/types"
	"github.com/subinc/subinc-backend/internal/cost/domain"
	"github.com/subinc/subinc-backend/internal/pkg/logger"
)

type AWSInventory struct {
	Logger *logger.Logger
}

func NewAWSInventory(log *logger.Logger) *AWSInventory {
	if log == nil {
		log = logger.NewNoop()
	}
	return &AWSInventory{Logger: log}
}

func (inv *AWSInventory) ListResources(ctx context.Context, accountID string, credentials map[string]string) ([]types.ResourceNode, error) {
	// Use the real scanner for EC2, S3, VPC
	return ScanAWSResources(ctx, credentials, "")
}

func (inv *AWSInventory) GetCredentials(ctx context.Context, tenantID string) (map[string]string, error) {
	accessKey := os.Getenv("AWS_ACCESS_KEY_ID")
	secretKey := os.Getenv("AWS_SECRET_ACCESS_KEY")
	sessionToken := os.Getenv("AWS_SESSION_TOKEN")
	if accessKey == "" || secretKey == "" {
		return nil, errors.New("AWS credentials not set in environment")
	}
	return map[string]string{
		domain.AWSAccessKeyID:     accessKey,
		domain.AWSSecretAccessKey: secretKey,
		domain.AWSSessionToken:    sessionToken,
	}, nil
}

func (inv *AWSInventory) GetAccountID(ctx context.Context, tenantID string) (string, error) {
	accountID := os.Getenv("AWS_ACCOUNT_ID")
	if accountID == "" {
		return "", errors.New("AWS_ACCOUNT_ID not set in environment")
	}
	return accountID, nil
}
