// Package types defines core data structures for rootkube.
// Designed for extensibility - new resource types (Service, Ingress) can be added easily.
package types

import (
	"time"
)

// TargetKind represents the type of Kubernetes resource being analyzed.
type TargetKind string

const (
	KindPod     TargetKind = "Pod"
	KindService TargetKind = "Service"
	KindIngress TargetKind = "Ingress"
	// Future: KindDeployment, KindStatefulSet, etc.
)

// Target represents the resource being analyzed.
// Extensible to support Pod, Service, Ingress, etc.
type Target struct {
	Kind      TargetKind
	Name      string
	Namespace string
}

// Severity indicates how critical a finding is.
type Severity string

const (
	SeverityCritical Severity = "CRITICAL" // Immediate action needed
	SeverityWarning  Severity = "WARNING"  // Potential issue
	SeverityInfo     Severity = "INFO"     // Informational
	SeverityOK       Severity = "OK"       // Check passed
)

// Finding represents a single diagnostic finding.
type Finding struct {
	Analyzer    string    // Which analyzer produced this
	Severity    Severity  // How critical
	Title       string    // Short description
	Detail      string    // Detailed explanation
	Suggestion  string    // How to fix (optional)
	Timestamp   time.Time // When the issue occurred (if known)
	RelatedObjs []string  // Related K8s objects (e.g., "ConfigMap/myconfig")
}

// AnalysisResult contains all findings from analyzing a target.
type AnalysisResult struct {
	Target    Target
	StartTime time.Time
	EndTime   time.Time
	Findings  []Finding
	RootCause *Finding  // Most likely root cause (nil if unclear)
	Timeline  []Event   // Correlated timeline of events
	Summary   string    // Human-readable summary
}

// Event represents a timestamped event in the timeline.
type Event struct {
	Timestamp time.Time
	Source    string // "k8s-event", "log", "probe", etc.
	Message   string
	Severity  Severity
}

// AnalyzerConfig holds configuration for analyzers.
type AnalyzerConfig struct {
	LogTailLines   int           // Number of log lines to fetch
	EventLookback  time.Duration // How far back to look for events
	EnableDebugPod bool          // Whether to spin up debug pods for network tests
	Timeout        time.Duration // Overall analysis timeout
}

// DefaultConfig returns sensible default configuration.
func DefaultConfig() AnalyzerConfig {
	return AnalyzerConfig{
		LogTailLines:   100,
		EventLookback:  time.Hour,
		EnableDebugPod: false, // Off by default, user can enable
		Timeout:        30 * time.Second,
	}
}
