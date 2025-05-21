package plugin

import (
	"errors"
	"fmt"
	"sync"
)

// Manager handles plugin registration, lookup, and lifecycle.
type Manager struct {
	plugins map[string]map[string]interface{}
	mu      sync.RWMutex
}

// NewManager creates a new plugin manager.
func NewManager() *Manager {
	return &Manager{
		plugins: make(map[string]map[string]interface{}),
	}
}

// RegisterPlugin registers a plugin with a specific type and name.
func (m *Manager) RegisterPlugin(pluginType string, plugin interface{}) error {
	if plugin == nil {
		return errors.New("plugin cannot be nil")
	}

	// Get plugin name through reflection or interface
	var name string
	if namer, ok := plugin.(interface{ Name() string }); ok {
		name = namer.Name()
	} else {
		return errors.New("plugin must implement Name() method")
	}

	if name == "" {
		return errors.New("plugin name cannot be empty")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Initialize the plugin type map if it doesn't exist
	if _, ok := m.plugins[pluginType]; !ok {
		m.plugins[pluginType] = make(map[string]interface{})
	}

	// Register the plugin
	m.plugins[pluginType][name] = plugin
	return nil
}

// UnregisterPlugin removes a plugin by type and name.
func (m *Manager) UnregisterPlugin(pluginType string, pluginName string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.plugins[pluginType]; !ok {
		return fmt.Errorf("plugin type %s not found", pluginType)
	}

	if _, ok := m.plugins[pluginType][pluginName]; !ok {
		return fmt.Errorf("plugin %s of type %s not found", pluginName, pluginType)
	}

	delete(m.plugins[pluginType], pluginName)
	return nil
}

// GetPlugin returns a plugin by type and name.
func (m *Manager) GetPlugin(pluginType string, name string) (interface{}, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if plugins, ok := m.plugins[pluginType]; ok {
		plugin, exists := plugins[name]
		return plugin, exists
	}

	return nil, false
}

// ListPlugins returns a list of plugin names by type.
func (m *Manager) ListPlugins(pluginType string) []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var result []string
	if plugins, ok := m.plugins[pluginType]; ok {
		for name := range plugins {
			result = append(result, name)
		}
	}

	return result
}

// InitializePlugins initializes all registered plugins with a configuration.
func (m *Manager) InitializePlugins(config map[string]interface{}) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for typeName, plugins := range m.plugins {
		for pluginName, plugin := range plugins {
			// Check if plugin implements Initialize method
			if initializer, ok := plugin.(interface {
				Initialize(map[string]interface{}) error
			}); ok {
				if err := initializer.Initialize(config); err != nil {
					return fmt.Errorf("failed to initialize plugin %s of type %s: %w", pluginName, typeName, err)
				}
			}
		}
	}

	return nil
}

// For handlers to convert the returned interface{} to the specific plugin type,
// they will need to use type assertions in their code.

// RegisterDefaultPlugins registers built-in plugins for common functionality.
func (m *Manager) RegisterDefaultPlugins() {
	// Register built-in plugins here if needed
}
