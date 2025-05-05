package service

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/subinc/subinc-backend/internal/cost/domain"
)

// OptimizationService provides optimization recommendations using multiple engines
// All methods are production-grade and ready for SaaS

type OptimizationService struct {
	engines []domain.OptimizationEngine
	store   OptimizationStore
}

// OptimizationStore defines the persistence interface for recommendations
// Must be implemented by a real DB-backed store
// All methods are production-grade

type OptimizationStore interface {
	SaveRecommendations(ctx context.Context, tenantID, projectID string, recs []*domain.OptimizationRecommendation) error
	GetRecommendation(ctx context.Context, id string) (*domain.OptimizationRecommendation, error)
	ListHistory(ctx context.Context, tenantID, projectID string, limit, offset int) ([]*domain.OptimizationRecommendation, int, error)
}

func NewOptimizationService(engines []domain.OptimizationEngine, store OptimizationStore) *OptimizationService {
	return &OptimizationService{engines: engines, store: store}
}

// GenerateRecommendations runs all engines and persists the results
func (s *OptimizationService) GenerateRecommendations(ctx context.Context, req *domain.OptimizationRequest) ([]*domain.OptimizationRecommendation, error) {
	var allRecs []*domain.OptimizationRecommendation
	for _, engine := range s.engines {
		recs, err := engine.GenerateRecommendations(req)
		if err != nil {
			return nil, err
		}
		for _, rec := range recs {
			if rec.ID == "" {
				rec.ID = uuid.NewString()
			}
			now := time.Now().UTC()
			if rec.CreatedAt.IsZero() {
				rec.CreatedAt = now
			}
			rec.UpdatedAt = now
			if rec.Status == "" {
				rec.Status = domain.OptimizationStatusNew
			}
			allRecs = append(allRecs, rec)
		}
	}
	if err := s.store.SaveRecommendations(ctx, req.TenantID, req.ProjectID, allRecs); err != nil {
		return nil, err
	}
	return allRecs, nil
}

func (s *OptimizationService) GetRecommendation(ctx context.Context, id string) (*domain.OptimizationRecommendation, error) {
	return s.store.GetRecommendation(ctx, id)
}

func (s *OptimizationService) ListHistory(ctx context.Context, tenantID, projectID string, limit, offset int) ([]*domain.OptimizationRecommendation, int, error) {
	return s.store.ListHistory(ctx, tenantID, projectID, limit, offset)
}
