package repository

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/subinc/subinc-backend/internal/cost/cloud"
	"github.com/subinc/subinc-backend/internal/cost/domain"
	"github.com/subinc/subinc-backend/internal/pkg/logger"
)

// Errors
var (
	ErrInvalidEncryptionKey     = errors.New("invalid encryption key")
	ErrCredentialNotFound       = errors.New("credential not found")
	ErrCredentialExists         = errors.New("credential already exists")
	ErrNoDefaultAccountSet      = errors.New("no default account set")
	ErrInvalidCredentialPayload = errors.New("invalid credential payload")
	ErrPermissionDenied         = errors.New("permission denied")
)

// CloudCredential represents a stored credential
type CloudCredential struct {
	ID              string               `json:"id"`
	TenantID        string               `json:"tenant_id"`
	Provider        domain.CloudProvider `json:"provider"`
	Name            string               `json:"name"`
	Credentials     map[string]string    `json:"credentials"`
	DefaultAccount  string               `json:"default_account,omitempty"`
	AccountList     []string             `json:"account_list,omitempty"`
	CreatedAt       time.Time            `json:"created_at"`
	UpdatedAt       time.Time            `json:"updated_at"`
	LastValidatedAt *time.Time           `json:"last_validated_at,omitempty"`
	IsValid         bool                 `json:"is_valid"`
}

// CredentialRepository is responsible for storing and retrieving cloud provider credentials
type CredentialRepository struct {
	db              *pgxpool.Pool
	logger          *logger.Logger
	encryptionKey   []byte
	tokenExpiration time.Duration
}

// NewCredentialRepository creates a new credential repository
func NewCredentialRepository(db *pgxpool.Pool, encryptionKey []byte, log *logger.Logger) (*CredentialRepository, error) {
	if db == nil {
		return nil, errors.New("database connection is required")
	}

	if len(encryptionKey) != 32 {
		return nil, ErrInvalidEncryptionKey
	}

	if log == nil {
		log = logger.NewNoop()
	}

	return &CredentialRepository{
		db:              db,
		logger:          log,
		encryptionKey:   encryptionKey,
		tokenExpiration: 8 * time.Hour, // Default token expiration
	}, nil
}

// CreateCredential creates a new cloud provider credential
func (r *CredentialRepository) CreateCredential(ctx context.Context, credential *CloudCredential) error {
	// Encrypt the credentials
	encryptedCreds, err := r.encryptCredentials(credential.Credentials)
	if err != nil {
		r.logger.Error("Failed to encrypt credentials",
			logger.String("tenant_id", credential.TenantID),
			logger.String("provider", string(credential.Provider)),
			logger.ErrorField(err))
		return fmt.Errorf("failed to encrypt credentials: %w", err)
	}

	// Start a transaction
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() {
		if err := tx.Rollback(ctx); err != nil && err.Error() != "pgx: tx is closed" {
			r.logger.Error("failed to rollback tx", logger.ErrorField(err))
		}
	}()

	// Check if credential already exists
	var count int
	err = tx.QueryRow(ctx, `
		SELECT COUNT(*) FROM cloud_credentials 
		WHERE tenant_id = $1 AND provider = $2 AND name = $3`,
		credential.TenantID, string(credential.Provider), credential.Name).Scan(&count)
	if err != nil {
		return fmt.Errorf("failed to check existing credential: %w", err)
	}

	if count > 0 {
		return ErrCredentialExists
	}

	// Insert the credential
	_, err = tx.Exec(ctx, `
		INSERT INTO cloud_credentials (
			id, tenant_id, provider, name, encrypted_credentials, 
			default_account, account_list, created_at, updated_at, 
			last_validated_at, is_valid
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
		credential.ID,
		credential.TenantID,
		string(credential.Provider),
		credential.Name,
		encryptedCreds,
		credential.DefaultAccount,
		arrayOrNull(credential.AccountList),
		credential.CreatedAt,
		credential.UpdatedAt,
		credential.LastValidatedAt,
		credential.IsValid)
	if err != nil {
		return fmt.Errorf("failed to insert credential: %w", err)
	}

	// Commit the transaction
	if err = tx.Commit(ctx); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// GetCredential retrieves a credential by ID
func (r *CredentialRepository) GetCredential(ctx context.Context, id string) (*CloudCredential, error) {
	var (
		credential      CloudCredential
		encryptedCreds  string
		defaultAccount  *string
		accountList     []string
		lastValidatedAt *time.Time
	)

	err := r.db.QueryRow(ctx, `
		SELECT 
			id, tenant_id, provider, name, encrypted_credentials, 
			default_account, account_list, created_at, updated_at, 
			last_validated_at, is_valid
		FROM cloud_credentials
		WHERE id = $1`, id).Scan(
		&credential.ID,
		&credential.TenantID,
		&credential.Provider,
		&credential.Name,
		&encryptedCreds,
		&defaultAccount,
		&accountList,
		&credential.CreatedAt,
		&credential.UpdatedAt,
		&lastValidatedAt,
		&credential.IsValid)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrCredentialNotFound
		}
		return nil, fmt.Errorf("failed to query credential: %w", err)
	}

	// Decrypt the credentials
	creds, err := r.decryptCredentials(encryptedCreds)
	if err != nil {
		r.logger.Error("Failed to decrypt credentials",
			logger.String("credential_id", id),
			logger.ErrorField(err))
		return nil, fmt.Errorf("failed to decrypt credentials: %w", err)
	}

	credential.Credentials = creds
	credential.LastValidatedAt = lastValidatedAt

	if defaultAccount != nil {
		credential.DefaultAccount = *defaultAccount
	}

	credential.AccountList = accountList

	return &credential, nil
}

// GetCredentialsByTenant retrieves all credentials for a tenant
func (r *CredentialRepository) GetCredentialsByTenant(ctx context.Context, tenantID string) ([]*CloudCredential, error) {
	rows, err := r.db.Query(ctx, `
		SELECT 
			id, tenant_id, provider, name, encrypted_credentials, 
			default_account, account_list, created_at, updated_at, 
			last_validated_at, is_valid
		FROM cloud_credentials
		WHERE tenant_id = $1
		ORDER BY provider, name`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to query credentials: %w", err)
	}
	defer rows.Close()

	var credentials []*CloudCredential

	for rows.Next() {
		var (
			credential      CloudCredential
			encryptedCreds  string
			defaultAccount  *string
			accountList     []string
			lastValidatedAt *time.Time
		)

		err := rows.Scan(
			&credential.ID,
			&credential.TenantID,
			&credential.Provider,
			&credential.Name,
			&encryptedCreds,
			&defaultAccount,
			&accountList,
			&credential.CreatedAt,
			&credential.UpdatedAt,
			&lastValidatedAt,
			&credential.IsValid)
		if err != nil {
			return nil, fmt.Errorf("failed to scan credential row: %w", err)
		}

		// Decrypt the credentials
		creds, err := r.decryptCredentials(encryptedCreds)
		if err != nil {
			r.logger.Error("Failed to decrypt credentials",
				logger.String("credential_id", credential.ID),
				logger.ErrorField(err))
			// Skip this credential but continue processing others
			continue
		}

		credential.Credentials = creds
		credential.LastValidatedAt = lastValidatedAt

		if defaultAccount != nil {
			credential.DefaultAccount = *defaultAccount
		}

		credential.AccountList = accountList

		credentials = append(credentials, &credential)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating credential rows: %w", err)
	}

	return credentials, nil
}

// GetCredentialsByProvider retrieves credentials for a tenant and provider
func (r *CredentialRepository) GetCredentialsByProvider(ctx context.Context, tenantID string, provider domain.CloudProvider) ([]*CloudCredential, error) {
	rows, err := r.db.Query(ctx, `
		SELECT 
			id, tenant_id, provider, name, encrypted_credentials, 
			default_account, account_list, created_at, updated_at, 
			last_validated_at, is_valid
		FROM cloud_credentials
		WHERE tenant_id = $1 AND provider = $2
		ORDER BY name`, tenantID, string(provider))
	if err != nil {
		return nil, fmt.Errorf("failed to query credentials: %w", err)
	}
	defer rows.Close()

	var credentials []*CloudCredential

	for rows.Next() {
		var (
			credential      CloudCredential
			encryptedCreds  string
			defaultAccount  *string
			accountList     []string
			lastValidatedAt *time.Time
		)

		err := rows.Scan(
			&credential.ID,
			&credential.TenantID,
			&credential.Provider,
			&credential.Name,
			&encryptedCreds,
			&defaultAccount,
			&accountList,
			&credential.CreatedAt,
			&credential.UpdatedAt,
			&lastValidatedAt,
			&credential.IsValid)
		if err != nil {
			return nil, fmt.Errorf("failed to scan credential row: %w", err)
		}

		// Decrypt the credentials
		creds, err := r.decryptCredentials(encryptedCreds)
		if err != nil {
			r.logger.Error("Failed to decrypt credentials",
				logger.String("credential_id", credential.ID),
				logger.ErrorField(err))
			// Skip this credential but continue processing others
			continue
		}

		credential.Credentials = creds
		credential.LastValidatedAt = lastValidatedAt

		if defaultAccount != nil {
			credential.DefaultAccount = *defaultAccount
		}

		credential.AccountList = accountList

		credentials = append(credentials, &credential)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating credential rows: %w", err)
	}

	return credentials, nil
}

// UpdateCredential updates an existing credential
func (r *CredentialRepository) UpdateCredential(ctx context.Context, credential *CloudCredential) error {
	// Encrypt the credentials
	encryptedCreds, err := r.encryptCredentials(credential.Credentials)
	if err != nil {
		r.logger.Error("Failed to encrypt credentials for update",
			logger.String("credential_id", credential.ID),
			logger.ErrorField(err))
		return fmt.Errorf("failed to encrypt credentials: %w", err)
	}

	// Update the credential
	result, err := r.db.Exec(ctx, `
		UPDATE cloud_credentials SET
			name = $1,
			encrypted_credentials = $2,
			default_account = $3,
			account_list = $4,
			updated_at = $5,
			last_validated_at = $6,
			is_valid = $7
		WHERE id = $8 AND tenant_id = $9`,
		credential.Name,
		encryptedCreds,
		credential.DefaultAccount,
		arrayOrNull(credential.AccountList),
		credential.UpdatedAt,
		credential.LastValidatedAt,
		credential.IsValid,
		credential.ID,
		credential.TenantID)
	if err != nil {
		return fmt.Errorf("failed to update credential: %w", err)
	}

	if result.RowsAffected() == 0 {
		return ErrCredentialNotFound
	}

	return nil
}

// DeleteCredential deletes a credential
func (r *CredentialRepository) DeleteCredential(ctx context.Context, id string, tenantID string) error {
	result, err := r.db.Exec(ctx, `
		DELETE FROM cloud_credentials 
		WHERE id = $1 AND tenant_id = $2`,
		id, tenantID)
	if err != nil {
		return fmt.Errorf("failed to delete credential: %w", err)
	}

	if result.RowsAffected() == 0 {
		return ErrCredentialNotFound
	}

	return nil
}

// GetDefaultCredential gets the default credential for a tenant and provider
func (r *CredentialRepository) GetDefaultCredential(ctx context.Context, tenantID string, provider domain.CloudProvider) (*CloudCredential, error) {
	// Get all credentials for the tenant and provider
	credentials, err := r.GetCredentialsByProvider(ctx, tenantID, provider)
	if err != nil {
		return nil, err
	}

	// If there's only one credential, return it
	if len(credentials) == 1 {
		return credentials[0], nil
	}

	// If there are multiple credentials, find the first valid one
	for _, cred := range credentials {
		if cred.IsValid {
			return cred, nil
		}
	}

	// If no valid credentials, return the first one with a warning
	if len(credentials) > 0 {
		r.logger.Warn("No valid credentials found, returning first available",
			logger.String("tenant_id", tenantID),
			logger.String("provider", string(provider)))
		return credentials[0], nil
	}

	return nil, ErrCredentialNotFound
}

// ValidateCredential validates a credential and updates its status
func (r *CredentialRepository) ValidateCredential(ctx context.Context, id string, tenantID string, validator cloud.CostDataProvider) error {
	// Get the credential
	credential, err := r.GetCredential(ctx, id)
	if err != nil {
		return err
	}

	// Verify tenant ownership
	if credential.TenantID != tenantID {
		return ErrPermissionDenied
	}

	// Validate the credential
	err = validator.ValidateCredentials(ctx, "", credential.Credentials)
	validationTime := time.Now().UTC()

	// Update the credential status
	credential.LastValidatedAt = &validationTime
	credential.IsValid = err == nil
	credential.UpdatedAt = validationTime

	if err != nil {
		r.logger.Warn("Credential validation failed",
			logger.String("credential_id", id),
			logger.String("provider", string(credential.Provider)),
			logger.ErrorField(err))
	}

	// Update in database
	return r.UpdateCredential(ctx, credential)
}

// UpdateAccountList updates the account list for a credential
func (r *CredentialRepository) UpdateAccountList(ctx context.Context, id string, tenantID string, accounts []domain.CloudAccount) error {
	// Get the credential
	credential, err := r.GetCredential(ctx, id)
	if err != nil {
		return err
	}

	// Verify tenant ownership
	if credential.TenantID != tenantID {
		return ErrPermissionDenied
	}

	// Update the account list
	accountIDs := make([]string, len(accounts))
	for i, account := range accounts {
		accountIDs[i] = account.ID
	}

	credential.AccountList = accountIDs
	credential.UpdatedAt = time.Now().UTC()

	// If default account not in list or not set, set first account as default
	if credential.DefaultAccount == "" || !contains(accountIDs, credential.DefaultAccount) {
		if len(accountIDs) > 0 {
			credential.DefaultAccount = accountIDs[0]
		} else {
			credential.DefaultAccount = ""
		}
	}

	// Update in database
	return r.UpdateCredential(ctx, credential)
}

// SetDefaultAccount sets the default account for a credential
func (r *CredentialRepository) SetDefaultAccount(ctx context.Context, id string, tenantID string, accountID string) error {
	// Get the credential
	credential, err := r.GetCredential(ctx, id)
	if err != nil {
		return err
	}

	// Verify tenant ownership
	if credential.TenantID != tenantID {
		return ErrPermissionDenied
	}

	// Verify account is in list
	if len(credential.AccountList) > 0 && !contains(credential.AccountList, accountID) {
		return fmt.Errorf("account ID %s not found in credential account list", accountID)
	}

	// Update the default account
	credential.DefaultAccount = accountID
	credential.UpdatedAt = time.Now().UTC()

	// Update in database
	return r.UpdateCredential(ctx, credential)
}

// GetCredentials implements the CredentialStore interface
func (r *CredentialRepository) GetCredentials(ctx context.Context, tenantID string, provider domain.CloudProvider) (map[string]string, error) {
	// Get the default credential
	credential, err := r.GetDefaultCredential(ctx, tenantID, provider)
	if err != nil {
		return nil, err
	}

	return credential.Credentials, nil
}

// GetDefaultAccountID implements the CredentialStore interface
func (r *CredentialRepository) GetDefaultAccountID(ctx context.Context, tenantID string, provider domain.CloudProvider) (string, error) {
	// Get the default credential
	credential, err := r.GetDefaultCredential(ctx, tenantID, provider)
	if err != nil {
		return "", err
	}

	if credential.DefaultAccount == "" {
		return "", ErrNoDefaultAccountSet
	}

	return credential.DefaultAccount, nil
}

// Helper methods

// encryptCredentials encrypts credential data
func (r *CredentialRepository) encryptCredentials(credentials map[string]string) (string, error) {
	// Convert credentials map to JSON
	plaintext, err := json.Marshal(credentials)
	if err != nil {
		return "", fmt.Errorf("failed to serialize credentials: %w", err)
	}

	// Create a new AES cipher block
	block, err := aes.NewCipher(r.encryptionKey)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create a new GCM
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	// Create a nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)

	// Encode to base64
	encoded := base64.StdEncoding.EncodeToString(ciphertext)

	return encoded, nil
}

// decryptCredentials decrypts credential data
func (r *CredentialRepository) decryptCredentials(encryptedStr string) (map[string]string, error) {
	// Decode from base64
	ciphertext, err := base64.StdEncoding.DecodeString(encryptedStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64: %w", err)
	}

	// Create a new AES cipher block
	block, err := aes.NewCipher(r.encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create a new GCM
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Get the nonce size
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	// Extract nonce and ciphertext
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	// Decrypt
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	// Unmarshal JSON
	var credentials map[string]string
	if err := json.Unmarshal(plaintext, &credentials); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidCredentialPayload, err)
	}

	return credentials, nil
}

// arrayOrNull converts a slice to a database array or nil if empty
func arrayOrNull(arr []string) interface{} {
	if len(arr) == 0 {
		return nil
	}
	return arr
}

// contains checks if a string slice contains a value
func contains(slice []string, value string) bool {
	for _, item := range slice {
		if item == value {
			return true
		}
	}
	return false
}
