// Package analyzers provides diagnostic analyzers for Kubernetes resources.
// Each analyzer implements the Analyzer interface for extensibility.
package analyzers

import (
	"context"

	"github.com/mitzcore/rootkube/pkg/types"
	"k8s.io/client-go/kubernetes"
)

// Analyzer is the interface all diagnostic analyzers must implement.
// This design allows easy addition of new analyzers without modifying existing code.
type Analyzer interface {
	// Name returns the analyzer's identifier (e.g., "pod", "config", "network")
	Name() string

	// Supports returns true if this analyzer can analyze the given target kind.
	// This enables analyzers to opt-in to specific resource types.
	Supports(kind types.TargetKind) bool

	// Analyze performs the diagnostic analysis and returns findings.
	// Context is used for cancellation and timeouts.
	Analyze(ctx context.Context, client kubernetes.Interface, target types.Target, config types.AnalyzerConfig) ([]types.Finding, error)
}

// Registry holds all registered analyzers.
// Use Register() to add analyzers, GetAnalyzers() to retrieve them.
type Registry struct {
	analyzers []Analyzer
}

// NewRegistry creates an empty analyzer registry.
func NewRegistry() *Registry {
	return &Registry{
		analyzers: make([]Analyzer, 0),
	}
}

// Register adds an analyzer to the registry.
func (r *Registry) Register(a Analyzer) {
	r.analyzers = append(r.analyzers, a)
}

// GetAnalyzers returns all analyzers that support the given target kind.
func (r *Registry) GetAnalyzers(kind types.TargetKind) []Analyzer {
	var result []Analyzer
	for _, a := range r.analyzers {
		if a.Supports(kind) {
			result = append(result, a)
		}
	}
	return result
}

// DefaultRegistry creates a registry with all built-in analyzers.
func DefaultRegistry() *Registry {
	r := NewRegistry()
	
	// Register all built-in analyzers
	r.Register(NewPodAnalyzer())
	r.Register(NewEventsAnalyzer())
	r.Register(NewLogsAnalyzer())
	
	// Future: r.Register(NewConfigAnalyzer())
	// Future: r.Register(NewNetworkAnalyzer())
	// Future: r.Register(NewStorageAnalyzer())
	
	return r
}
