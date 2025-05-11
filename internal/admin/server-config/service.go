package server_config

import (
	"context"
	"sync"
	"time"
)

// Service provides runtime CRUD, in-memory cache, and hot-reload for server config.
type Service struct {
	store   *Store
	cache   map[string]ServerConfig
	mu      sync.RWMutex
	refresh time.Duration
	stopCh  chan struct{}
}

func NewService(store *Store, refresh time.Duration) *Service {
	s := &Service{
		store:   store,
		cache:   make(map[string]ServerConfig),
		refresh: refresh,
		stopCh:  make(chan struct{}),
	}
	s.reload(context.Background())
	go s.autoReload()
	return s
}

func (s *Service) Get(ctx context.Context, key string) (ServerConfig, error) {
	s.mu.RLock()
	cfg, ok := s.cache[key]
	s.mu.RUnlock()
	if ok {
		return cfg, nil
	}
	cfg, err := s.store.Get(ctx, key)
	if err != nil {
		return ServerConfig{}, err
	}
	s.mu.Lock()
	s.cache[key] = cfg
	s.mu.Unlock()
	return cfg, nil
}

func (s *Service) Set(ctx context.Context, key, value, updatedBy string) (ServerConfig, error) {
	cfg, err := s.store.Set(ctx, key, value, updatedBy)
	if err != nil {
		return ServerConfig{}, err
	}
	s.mu.Lock()
	s.cache[key] = cfg
	s.mu.Unlock()
	return cfg, nil
}

func (s *Service) List(ctx context.Context) ([]ServerConfig, error) {
	return s.store.List(ctx)
}

func (s *Service) History(ctx context.Context, key string) ([]ServerConfigHistory, error) {
	return s.store.History(ctx, key)
}

func (s *Service) reload(ctx context.Context) {
	cfgs, err := s.store.List(ctx)
	if err != nil {
		return
	}
	s.mu.Lock()
	for _, cfg := range cfgs {
		s.cache[cfg.Key] = cfg
	}
	s.mu.Unlock()
}

func (s *Service) autoReload() {
	ticker := time.NewTicker(s.refresh)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			s.reload(context.Background())
		case <-s.stopCh:
			return
		}
	}
}

func (s *Service) Stop() {
	close(s.stopCh)
}
