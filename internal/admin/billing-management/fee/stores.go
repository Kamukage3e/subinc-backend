package fee

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/subinc/subinc-backend/internal/pkg/logger"
)

// PostgresStore provides fee-related database operations
type PostgresStore struct {
	DB *pgxpool.Pool
}

// Add const for all SQL queries
const (
	qSetFeePluginConfig = `INSERT INTO fee_plugin_config (tenant_id, plugin_name, updated_at)
		VALUES ($1, $2, $3)
		ON CONFLICT (tenant_id) DO UPDATE SET plugin_name = $2, updated_at = $3
		RETURNING tenant_id, plugin_name, updated_at`
	qGetFeePluginConfig = `SELECT tenant_id, plugin_name, updated_at FROM fee_plugin_config WHERE tenant_id = $1`
	qDisableFeePlugin   = `DELETE FROM fee_plugin_config WHERE tenant_id = $1 AND plugin_name = $2`
	qCreateFee          = `INSERT INTO fees (id, invoice_id, account_id, amount, currency, type, status, created_at, updated_at, metadata, plugin_name)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
		RETURNING id, invoice_id, account_id, amount, currency, type, status, created_at, updated_at, metadata, plugin_name`
	qGetFee    = `SELECT id, invoice_id, account_id, amount, currency, type, status, created_at, updated_at, metadata, plugin_name FROM fees WHERE id = $1`
	qUpdateFee = `UPDATE fees SET invoice_id=$2, account_id=$3, amount=$4, currency=$5, type=$6, status=$7, updated_at=$8, metadata=$9, plugin_name=$10 WHERE id=$1
		RETURNING id, invoice_id, account_id, amount, currency, type, status, created_at, updated_at, metadata, plugin_name`
	qDeleteFee = `DELETE FROM fees WHERE id = $1`
	qListFees  = `SELECT id, invoice_id, account_id, amount, currency, type, status, created_at, updated_at, metadata, plugin_name FROM fees ORDER BY created_at DESC LIMIT $1 OFFSET $2`
)

// NewPostgresStore creates a new fee store with the provided database connection
func NewPostgresStore(db *pgxpool.Pool) *PostgresStore {
	return &PostgresStore{
		DB: db,
	}
}

// --- FeePluginConfig CRUD ---
func (s *PostgresStore) SetFeePluginConfig(ctx context.Context, tenantID, pluginName string) (FeePluginConfig, error) {
	if tenantID == "" {
		logger.LogError("SetFeePluginConfig: tenant_id is empty")
		return FeePluginConfig{}, NewValidationError("tenant_id", "must not be empty")
	}
	if pluginName == "" {
		logger.LogError("SetFeePluginConfig: plugin_name is empty")
		return FeePluginConfig{}, NewValidationError("plugin_name", "must not be empty")
	}
	updatedAt := time.Now().UTC()
	row := s.DB.QueryRow(ctx, qSetFeePluginConfig, tenantID, pluginName, updatedAt)
	var out FeePluginConfig
	if err := row.Scan(&out.TenantID, &out.PluginName, &out.UpdatedAt); err != nil {
		logger.LogError("SetFeePluginConfig: db error", logger.ErrorField(err), logger.String("tenant_id", tenantID), logger.String("plugin_name", pluginName))
		return FeePluginConfig{}, err
	}
	return out, nil
}

func (s *PostgresStore) GetFeePluginConfig(ctx context.Context, tenantID string) (FeePluginConfig, error) {
	if tenantID == "" {
		logger.LogError("GetFeePluginConfig: tenant_id is empty")
		return FeePluginConfig{}, NewValidationError("tenant_id", "must not be empty")
	}
	row := s.DB.QueryRow(ctx, qGetFeePluginConfig, tenantID)
	var out FeePluginConfig
	if err := row.Scan(&out.TenantID, &out.PluginName, &out.UpdatedAt); err != nil {
		logger.LogError("GetFeePluginConfig: db error", logger.ErrorField(err), logger.String("tenant_id", tenantID))
		return FeePluginConfig{}, err
	}
	return out, nil
}

// DisableFeePlugin removes the fee plugin configuration for a tenant
func (s *PostgresStore) DisableFeePlugin(ctx context.Context, tenantID, pluginName string) error {
	if tenantID == "" {
		logger.LogError("DisableFeePlugin: tenant_id is empty")
		return NewValidationError("tenant_id", "must not be empty")
	}
	if pluginName == "" {
		logger.LogError("DisableFeePlugin: plugin_name is empty")
		return NewValidationError("plugin_name", "must not be empty")
	}

	result, err := s.DB.Exec(ctx, qDisableFeePlugin, tenantID, pluginName)
	if err != nil {
		logger.LogError("DisableFeePlugin: db error", logger.ErrorField(err),
			logger.String("tenant_id", tenantID),
			logger.String("plugin_name", pluginName))
		return err
	}

	if result.RowsAffected() == 0 {
		logger.LogError("DisableFeePlugin: no config found",
			logger.String("tenant_id", tenantID),
			logger.String("plugin_name", pluginName))
		return NewValidationError("plugin_config", "configuration not found for tenant and plugin")
	}

	return nil
}

// --- Fee CRUD ---
func (s *PostgresStore) CreateFee(ctx context.Context, f Fee) (Fee, error) {
	if vErr := f.Validate(); vErr != nil {
		logger.LogError("CreateFee: validation failed", logger.ErrorField(vErr))
		return Fee{}, vErr
	}
	row := s.DB.QueryRow(ctx, qCreateFee, f.ID, f.InvoiceID, f.AccountID, f.Amount, f.Currency, f.Type, f.Status, f.CreatedAt, f.UpdatedAt, f.Metadata, f.PluginName)
	var out Fee
	if err := row.Scan(&out.ID, &out.InvoiceID, &out.AccountID, &out.Amount, &out.Currency, &out.Type, &out.Status, &out.CreatedAt, &out.UpdatedAt, &out.Metadata, &out.PluginName); err != nil {
		logger.LogError("CreateFee: db error", logger.ErrorField(err), logger.Any("fee", f))
		return Fee{}, err
	}
	return out, nil
}

func (s *PostgresStore) GetFee(ctx context.Context, id string) (Fee, error) {
	row := s.DB.QueryRow(ctx, qGetFee, id)
	var out Fee
	if err := row.Scan(&out.ID, &out.InvoiceID, &out.AccountID, &out.Amount, &out.Currency, &out.Type, &out.Status, &out.CreatedAt, &out.UpdatedAt, &out.Metadata, &out.PluginName); err != nil {
		logger.LogError("GetFee: db error", logger.ErrorField(err), logger.String("id", id))
		return Fee{}, err
	}
	return out, nil
}

func (s *PostgresStore) UpdateFee(ctx context.Context, f Fee) (Fee, error) {
	if vErr := f.Validate(); vErr != nil {
		logger.LogError("UpdateFee: validation failed", logger.ErrorField(vErr))
		return Fee{}, vErr
	}
	row := s.DB.QueryRow(ctx, qUpdateFee, f.ID, f.InvoiceID, f.AccountID, f.Amount, f.Currency, f.Type, f.Status, f.UpdatedAt, f.Metadata, f.PluginName)
	var out Fee
	if err := row.Scan(&out.ID, &out.InvoiceID, &out.AccountID, &out.Amount, &out.Currency, &out.Type, &out.Status, &out.CreatedAt, &out.UpdatedAt, &out.Metadata, &out.PluginName); err != nil {
		logger.LogError("UpdateFee: db error", logger.ErrorField(err), logger.Any("fee", f))
		return Fee{}, err
	}
	return out, nil
}

func (s *PostgresStore) DeleteFee(ctx context.Context, id string) error {
	_, err := s.DB.Exec(ctx, qDeleteFee, id)
	if err != nil {
		logger.LogError("DeleteFee: db error", logger.ErrorField(err), logger.String("id", id))
	}
	return err
}

func (s *PostgresStore) ListFees(ctx context.Context, page, pageSize int) ([]Fee, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 1000 {
		pageSize = 100
	}
	offset := (page - 1) * pageSize
	rows, err := s.DB.Query(ctx, qListFees, pageSize, offset)
	if err != nil {
		logger.LogError("ListFees: db error", logger.ErrorField(err))
		return nil, err
	}
	defer rows.Close()
	var out []Fee
	for rows.Next() {
		var f Fee
		if err := rows.Scan(&f.ID, &f.InvoiceID, &f.AccountID, &f.Amount, &f.Currency, &f.Type, &f.Status, &f.CreatedAt, &f.UpdatedAt, &f.Metadata, &f.PluginName); err != nil {
			logger.LogError("ListFees: scan error", logger.ErrorField(err))
			return nil, err
		}
		out = append(out, f)
	}
	return out, nil
}
