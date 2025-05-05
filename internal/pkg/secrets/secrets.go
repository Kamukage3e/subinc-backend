package secrets

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	"github.com/subinc/subinc-backend/internal/pkg/logger"
)

// SecretsManager abstracts secret retrieval for cloud-native SaaS. Supports AWS Secrets Manager (default) and can be extended for Vault.
type SecretsManager interface {
	GetSecret(ctx context.Context, name string) (string, error)
}

type awsSecretsManager struct {
	client *secretsmanager.Client
	cache  map[string]cachedSecret
	mu     sync.RWMutex
	log    *logger.Logger
}

type cachedSecret struct {
	value     string
	expiresAt time.Time
}

// NewAWSSecretsManager returns a production-grade AWS Secrets Manager client with in-memory caching.
func NewAWSSecretsManager(ctx context.Context, log *logger.Logger) (SecretsManager, error) {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}
	return &awsSecretsManager{
		client: secretsmanager.NewFromConfig(cfg),
		cache:  make(map[string]cachedSecret),
		log:    log,
	}, nil
}

// GetSecret fetches a secret by name, with short-lived in-memory caching for performance.
func (s *awsSecretsManager) GetSecret(ctx context.Context, name string) (string, error) {
	if name == "" {
		return "", fmt.Errorf("secret name must not be empty")
	}
	// Check cache first
	s.mu.RLock()
	c, ok := s.cache[name]
	if ok && time.Now().Before(c.expiresAt) {
		s.mu.RUnlock()
		return c.value, nil
	}
	s.mu.RUnlock()
	// Not cached or expired, fetch from AWS
	input := &secretsmanager.GetSecretValueInput{SecretId: &name}
	resp, err := s.client.GetSecretValue(ctx, input)
	if err != nil {
		var rnfe *types.ResourceNotFoundException
		if ok := errorAs(err, &rnfe); ok {
			s.log.Warn("secret not found", logger.String("name", name))
			return "", fmt.Errorf("secret not found: %s", name)
		}
		s.log.Error("failed to fetch secret", logger.String("name", name), logger.ErrorField(err))
		return "", fmt.Errorf("failed to fetch secret: %w", err)
	}
	if resp.SecretString == nil {
		return "", fmt.Errorf("secret value is empty for: %s", name)
	}
	val := *resp.SecretString
	// Cache for 60 seconds
	s.mu.Lock()
	s.cache[name] = cachedSecret{value: val, expiresAt: time.Now().Add(60 * time.Second)}
	s.mu.Unlock()
	return val, nil
}

// GetSecretJSON fetches a secret and unmarshals it into the provided struct pointer.
func (s *awsSecretsManager) GetSecretJSON(ctx context.Context, name string, v interface{}) error {
	val, err := s.GetSecret(ctx, name)
	if err != nil {
		return err
	}
	return json.Unmarshal([]byte(val), v)
}

// errorAs is a helper for error type assertion (Go 1.20+ idiom).
func errorAs(err error, target interface{}) bool {
	switch t := target.(type) {
	case **types.ResourceNotFoundException:
		e, ok := err.(*types.ResourceNotFoundException)
		if !ok {
			return false
		}
		*t = e
		return true
	default:
		return false
	}
}
