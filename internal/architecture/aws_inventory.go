package architecture

import (
	"context"
	"errors"

	"github.com/spf13/viper"
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
	accessKey := viper.GetString("AWS_ACCESS_KEY_ID")
	secretKey := viper.GetString("AWS_SECRET_ACCESS_KEY")
	sessionToken := viper.GetString("AWS_SESSION_TOKEN")
	if accessKey == "" || secretKey == "" {
		return nil, errors.New("AWS credentials not set in config")
	}
	return map[string]string{
		domain.AWSAccessKeyID:     accessKey,
		domain.AWSSecretAccessKey: secretKey,
		domain.AWSSessionToken:    sessionToken,
	}, nil
}

func (inv *AWSInventory) GetAccountID(ctx context.Context, tenantID string) (string, error) {
	accountID := viper.GetString("AWS_ACCOUNT_ID")
	if accountID == "" {
		return "", errors.New("AWS_ACCOUNT_ID not set in config")
	}
	return accountID, nil
}
