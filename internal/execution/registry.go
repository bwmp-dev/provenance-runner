package execution

import (
	"fmt"
	"strings"
)

type Registry struct {
	providers map[string]EnvironmentProvider
}

func NewRegistry(providers ...EnvironmentProvider) (*Registry, error) {
	registry := &Registry{providers: make(map[string]EnvironmentProvider, len(providers))}
	for _, provider := range providers {
		if provider == nil {
			return nil, fmt.Errorf("register provider: provider is nil")
		}
		name := strings.TrimSpace(provider.Name())
		if name == "" {
			return nil, fmt.Errorf("register provider: name is empty")
		}
		if _, exists := registry.providers[name]; exists {
			return nil, fmt.Errorf("register provider %q: duplicate name", name)
		}
		registry.providers[name] = provider
	}
	return registry, nil
}

func (r *Registry) Provider(name string) (EnvironmentProvider, bool) {
	if r == nil {
		return nil, false
	}
	provider, exists := r.providers[name]
	return provider, exists
}
