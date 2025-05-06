package repository

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/subinc/subinc-backend/internal/cost/domain"
	"github.com/subinc/subinc-backend/internal/pkg/logger"
)

// PostgresOptimizationRepository is a production-grade implementation of OptimizationStore
// All methods are real, prod-ready, and safe for SaaS deployment
// This struct is modular and can be swapped for other DBs if needed

type PostgresOptimizationRepository struct {
	db  *pgxpool.Pool
	log *logger.Logger
}

// OptimizationStore defines the persistence interface for recommendations (copied from service, to avoid import cycle)
type OptimizationStore interface {
	SaveRecommendations(ctx context.Context, tenantID, projectID string, recs []*domain.OptimizationRecommendation) error
	GetRecommendation(ctx context.Context, id string) (*domain.OptimizationRecommendation, error)
	ListHistory(ctx context.Context, tenantID, projectID string, limit, offset int) ([]*domain.OptimizationRecommendation, int, error)
}

func NewPostgresOptimizationRepository(db *pgxpool.Pool, log *logger.Logger) OptimizationStore {
	if db == nil {
		panic("PostgresOptimizationRepository: db cannot be nil")
	}
	if log == nil {
		log = logger.NewNoop()
	}
	return &PostgresOptimizationRepository{db: db, log: log}
}

func (r *PostgresOptimizationRepository) SaveRecommendations(ctx context.Context, tenantID, projectID string, recs []*domain.OptimizationRecommendation) error {
	if tenantID == "" || projectID == "" || len(recs) == 0 {
		return fmt.Errorf("invalid input: tenantID, projectID, and recs are required")
	}
	tx, err := r.db.Begin(ctx)
	if err != nil {
		r.log.Error("optimization: failed to begin tx", logger.ErrorField(err))
		return fmt.Errorf("failed to begin tx: %w", err)
	}
	defer func() {
		if err != nil {
			tx.Rollback(ctx)
		}
	}()
	const q = `INSERT INTO optimization_recommendations (
		id, tenant_id, project_id, resource_id, type, impact, rationale, remediation, source, confidence, status, created_at, updated_at
	) VALUES (
		$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13
	) ON CONFLICT (id) DO UPDATE SET
		impact = $6, rationale = $7, remediation = $8, source = $9, confidence = $10, status = $11, updated_at = $13`
	for _, rec := range recs {
		if rec.ID == "" || rec.ResourceID == "" {
			return fmt.Errorf("invalid recommendation: missing ID or ResourceID")
		}
		_, err = tx.Exec(ctx, q,
			rec.ID, tenantID, projectID, rec.ResourceID, rec.Type, rec.Impact, rec.Rationale, rec.Remediation, rec.Source, rec.Confidence, rec.Status, rec.CreatedAt, rec.UpdatedAt,
		)
		if err != nil {
			r.log.Error("optimization: failed to save rec", logger.ErrorField(err), logger.String("rec_id", rec.ID))
			return fmt.Errorf("failed to save recommendation: %w", err)
		}
	}
	if err = tx.Commit(ctx); err != nil {
		r.log.Error("optimization: failed to commit tx", logger.ErrorField(err))
		return fmt.Errorf("failed to commit tx: %w", err)
	}
	return nil
}

func (r *PostgresOptimizationRepository) GetRecommendation(ctx context.Context, id string) (*domain.OptimizationRecommendation, error) {
	if id == "" {
		return nil, fmt.Errorf("missing id")
	}
	const q = `SELECT id, resource_id, type, impact, rationale, remediation, source, confidence, status, created_at, updated_at FROM optimization_recommendations WHERE id = $1`
	row := r.db.QueryRow(ctx, q, id)
	var rec domain.OptimizationRecommendation
	err := row.Scan(&rec.ID, &rec.ResourceID, &rec.Type, &rec.Impact, &rec.Rationale, &rec.Remediation, &rec.Source, &rec.Confidence, &rec.Status, &rec.CreatedAt, &rec.UpdatedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		r.log.Error("optimization: failed to get rec", logger.ErrorField(err), logger.String("rec_id", id))
		return nil, fmt.Errorf("failed to get recommendation: %w", err)
	}
	return &rec, nil
}

func (r *PostgresOptimizationRepository) ListHistory(ctx context.Context, tenantID, projectID string, limit, offset int) ([]*domain.OptimizationRecommendation, int, error) {
	if tenantID == "" || projectID == "" {
		return nil, 0, fmt.Errorf("tenantID and projectID required")
	}
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}
	const countQ = `SELECT COUNT(*) FROM optimization_recommendations WHERE tenant_id = $1 AND project_id = $2`
	const q = `SELECT id, resource_id, type, impact, rationale, remediation, source, confidence, status, created_at, updated_at FROM optimization_recommendations WHERE tenant_id = $1 AND project_id = $2 ORDER BY created_at DESC LIMIT $3 OFFSET $4`
	row := r.db.QueryRow(ctx, countQ, tenantID, projectID)
	var total int
	if err := row.Scan(&total); err != nil {
		r.log.Error("optimization: failed to count history", logger.ErrorField(err))
		return nil, 0, fmt.Errorf("failed to count history: %w", err)
	}
	if total == 0 {
		return []*domain.OptimizationRecommendation{}, 0, nil
	}
	rows, err := r.db.Query(ctx, q, tenantID, projectID, limit, offset)
	if err != nil {
		r.log.Error("optimization: failed to list history", logger.ErrorField(err))
		return nil, 0, fmt.Errorf("failed to list history: %w", err)
	}
	defer rows.Close()
	recs := make([]*domain.OptimizationRecommendation, 0, limit)
	for rows.Next() {
		var rec domain.OptimizationRecommendation
		err := rows.Scan(&rec.ID, &rec.ResourceID, &rec.Type, &rec.Impact, &rec.Rationale, &rec.Remediation, &rec.Source, &rec.Confidence, &rec.Status, &rec.CreatedAt, &rec.UpdatedAt)
		if err != nil {
			r.log.Error("optimization: failed to scan rec", logger.ErrorField(err))
			return nil, 0, fmt.Errorf("failed to scan recommendation: %w", err)
		}
		recs = append(recs, &rec)
	}
	return recs, total, nil
}
