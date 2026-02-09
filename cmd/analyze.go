// Package cmd provides CLI commands for rootkube.
package cmd

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/mitzcore/rootkube/pkg/analyzers"
	"github.com/mitzcore/rootkube/pkg/k8s"
	"github.com/mitzcore/rootkube/pkg/output"
	"github.com/mitzcore/rootkube/pkg/types"
	"github.com/spf13/cobra"
	"k8s.io/client-go/kubernetes"
)

var (
	namespace   string
	kubeconfig  string
	kubecontext string
	verbose     bool
	noColor     bool
	timeout     time.Duration
	logLines    int
)

// analyzeCmd represents the analyze command
var analyzeCmd = &cobra.Command{
	Use:   "analyze <pod-name>",
	Short: "Analyze a Kubernetes pod to find root cause of issues",
	Long: `Analyze a Kubernetes pod that is in CrashLoopBackOff, Error, or unhealthy state.

rootkube correlates pod status, events, logs, and configuration to identify
the most likely root cause of the problem.

Examples:
  # Analyze a pod in the current namespace
  rootkube analyze my-broken-pod

  # Analyze a pod in a specific namespace
  rootkube analyze my-broken-pod -n production

  # Analyze with verbose output
  rootkube analyze my-broken-pod -v

  # Analyze with custom kubeconfig
  rootkube analyze my-broken-pod --kubeconfig ~/.kube/custom-config`,
	Args: cobra.ExactArgs(1),
	RunE: runAnalyze,
}

func init() {
	// Add flags
	analyzeCmd.Flags().StringVarP(&namespace, "namespace", "n", "", "Kubernetes namespace (defaults to current context namespace)")
	analyzeCmd.Flags().StringVar(&kubeconfig, "kubeconfig", "", "Path to kubeconfig file")
	analyzeCmd.Flags().StringVar(&kubecontext, "context", "", "Kubernetes context to use")
	analyzeCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Show all findings including info and passed checks")
	analyzeCmd.Flags().BoolVar(&noColor, "no-color", false, "Disable colored output")
	analyzeCmd.Flags().DurationVar(&timeout, "timeout", 30*time.Second, "Analysis timeout")
	analyzeCmd.Flags().IntVar(&logLines, "log-lines", 100, "Number of log lines to analyze")
}

// GetAnalyzeCmd returns the analyze command for use in root command.
func GetAnalyzeCmd() *cobra.Command {
	return analyzeCmd
}

func runAnalyze(cmd *cobra.Command, args []string) error {
	podName := args[0]

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Initialize renderer
	useColors := !noColor && isTerminal()
	renderer := output.NewRenderer(useColors, verbose)

	renderer.Progress("Connecting to Kubernetes cluster...")

	// Create Kubernetes client
	client, err := k8s.NewClient(k8s.ClientConfig{
		Kubeconfig: kubeconfig,
		Context:    kubecontext,
	})
	if err != nil {
		return fmt.Errorf("failed to create Kubernetes client: %w", err)
	}

	// Determine namespace
	if namespace == "" {
		namespace = k8s.GetCurrentNamespace(kubeconfig)
	}

	// Create target
	target := types.Target{
		Kind:      types.KindPod,
		Name:      podName,
		Namespace: namespace,
	}

	// Create config
	config := types.AnalyzerConfig{
		LogTailLines:   logLines,
		EventLookback:  time.Hour,
		EnableDebugPod: false,
		Timeout:        timeout,
	}

	renderer.Progress(fmt.Sprintf("Analyzing pod %s/%s...", namespace, podName))

	// Run analysis
	result, err := RunAnalysis(ctx, client, target, config, renderer)
	if err != nil {
		return err
	}

	// Render results
	renderer.Render(result)

	return nil
}

// RunAnalysis performs the analysis using all registered analyzers.
// Exported for testing and programmatic use.
func RunAnalysis(
	ctx context.Context,
	client kubernetes.Interface,
	target types.Target,
	config types.AnalyzerConfig,
	renderer *output.Renderer,
) (*types.AnalysisResult, error) {
	startTime := time.Now()

	// Get analyzer registry
	registry := analyzers.DefaultRegistry()
	activeAnalyzers := registry.GetAnalyzers(target.Kind)

	if len(activeAnalyzers) == 0 {
		return nil, fmt.Errorf("no analyzers available for %s", target.Kind)
	}

	var allFindings []types.Finding

	// Run each analyzer
	for _, analyzer := range activeAnalyzers {
		if renderer != nil {
			renderer.Progress(fmt.Sprintf("Running %s analyzer...", analyzer.Name()))
		}

		findings, err := analyzer.Analyze(ctx, client, target, config)
		if err != nil {
			// Don't fail completely, just report the error as a finding
			allFindings = append(allFindings, types.Finding{
				Analyzer: analyzer.Name(),
				Severity: types.SeverityWarning,
				Title:    fmt.Sprintf("Analyzer '%s' encountered an error", analyzer.Name()),
				Detail:   err.Error(),
			})
			continue
		}

		allFindings = append(allFindings, findings...)
	}

	// Identify root cause (heuristic: first critical finding, preferring certain analyzers)
	rootCause := identifyRootCause(allFindings)

	return &types.AnalysisResult{
		Target:    target,
		StartTime: startTime,
		EndTime:   time.Now(),
		Findings:  allFindings,
		RootCause: rootCause,
	}, nil
}

// identifyRootCause applies heuristics to identify the most likely root cause.
func identifyRootCause(findings []types.Finding) *types.Finding {
	// Priority order for root cause identification:
	// 1. Pod analyzer critical findings (OOMKilled, CrashLoopBackOff, ImagePull)
	// 2. Logs analyzer critical findings (connection refused, auth errors)
	// 3. Events analyzer critical findings
	// 4. Any other critical finding

	analyzerPriority := map[string]int{
		"pod":    1,
		"logs":   2,
		"events": 3,
	}

	var bestCandidate *types.Finding
	bestPriority := 100

	for i, f := range findings {
		if f.Severity != types.SeverityCritical {
			continue
		}

		priority := analyzerPriority[f.Analyzer]
		if priority == 0 {
			priority = 50 // Default priority for unknown analyzers
		}

		if priority < bestPriority {
			bestPriority = priority
			bestCandidate = &findings[i]
		}
	}

	return bestCandidate
}

// isTerminal checks if stdout is a terminal
func isTerminal() bool {
	fileInfo, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return (fileInfo.Mode() & os.ModeCharDevice) != 0
}
