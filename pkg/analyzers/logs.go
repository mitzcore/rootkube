package analyzers

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"regexp"

	"github.com/mitzcore/rootkube/pkg/types"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// LogsAnalyzer fetches and analyzes container logs for error patterns.
type LogsAnalyzer struct {
	// Error patterns to look for in logs
	errorPatterns []*logPattern
}

type logPattern struct {
	regex      *regexp.Regexp
	severity   types.Severity
	title      string
	suggestion string
}

// NewLogsAnalyzer creates a new LogsAnalyzer with common error patterns.
func NewLogsAnalyzer() *LogsAnalyzer {
	return &LogsAnalyzer{
		errorPatterns: defaultLogPatterns(),
	}
}

func defaultLogPatterns() []*logPattern {
	return []*logPattern{
		// Connection errors
		{
			regex:      regexp.MustCompile(`(?i)(connection refused|ECONNREFUSED)`),
			severity:   types.SeverityCritical,
			title:      "Connection refused error",
			suggestion: "Target service may be down or not listening. Check Service endpoints and NetworkPolicies",
		},
		{
			regex:      regexp.MustCompile(`(?i)(connection timed out|ETIMEDOUT|context deadline exceeded)`),
			severity:   types.SeverityCritical,
			title:      "Connection timeout",
			suggestion: "Network connectivity issue. Check NetworkPolicies, DNS, and target service health",
		},
		
		// DNS errors
		{
			regex:      regexp.MustCompile(`(?i)(no such host|NXDOMAIN|could not resolve|DNS lookup failed)`),
			severity:   types.SeverityCritical,
			title:      "DNS resolution failure",
			suggestion: "DNS cannot resolve hostname. Check CoreDNS status and Service/ExternalName configuration",
		},
		
		// Auth errors
		{
			regex:      regexp.MustCompile(`(?i)(unauthorized|401|authentication failed|invalid credentials)`),
			severity:   types.SeverityCritical,
			title:      "Authentication failure",
			suggestion: "Check credentials in Secrets and service account configuration",
		},
		{
			regex:      regexp.MustCompile(`(?i)(forbidden|403|access denied|permission denied)`),
			severity:   types.SeverityCritical,
			title:      "Authorization failure",
			suggestion: "Check RBAC permissions, service account, and target resource ACLs",
		},
		
		// Database errors
		{
			regex:      regexp.MustCompile(`(?i)(database.*connection|cannot connect to (mysql|postgres|mongodb|redis))`),
			severity:   types.SeverityCritical,
			title:      "Database connection error",
			suggestion: "Check database service availability, connection string, and credentials",
		},
		
		// Out of memory
		{
			regex:      regexp.MustCompile(`(?i)(out of memory|OOM|cannot allocate memory|heap.*exhausted)`),
			severity:   types.SeverityCritical,
			title:      "Memory exhaustion",
			suggestion: "Application running out of memory. Increase memory limits or optimize memory usage",
		},
		
		// File/path errors
		{
			regex:      regexp.MustCompile(`(?i)(no such file or directory|ENOENT|file not found)`),
			severity:   types.SeverityWarning,
			title:      "File not found",
			suggestion: "Check volume mounts, ConfigMaps, and file paths in configuration",
		},
		{
			regex:      regexp.MustCompile(`(?i)(read-only file system|EROFS)`),
			severity:   types.SeverityWarning,
			title:      "Read-only filesystem",
			suggestion: "Container filesystem is read-only. Use emptyDir or PVC for writable paths",
		},
		
		// Generic errors
		{
			regex:      regexp.MustCompile(`(?i)(panic:|fatal|FATAL|segmentation fault|segfault)`),
			severity:   types.SeverityCritical,
			title:      "Application crash/panic",
			suggestion: "Application crashed. Review stack trace and fix application bug",
		},
		{
			regex:      regexp.MustCompile(`(?i)(exception|traceback|stack trace)`),
			severity:   types.SeverityWarning,
			title:      "Exception in application",
			suggestion: "Application threw an exception. Review the error message and stack trace",
		},
		
		// Config errors
		{
			regex:      regexp.MustCompile(`(?i)(missing.*environment|env.*not set|config.*not found)`),
			severity:   types.SeverityCritical,
			title:      "Missing configuration",
			suggestion: "Required environment variable or config file missing. Check ConfigMaps and Secrets",
		},
		{
			regex:      regexp.MustCompile(`(?i)(invalid.*config|configuration error|parse error|yaml|json.*error)`),
			severity:   types.SeverityCritical,
			title:      "Configuration parse error",
			suggestion: "Configuration syntax error. Validate ConfigMap/Secret contents",
		},

		// TLS/SSL errors
		{
			regex:      regexp.MustCompile(`(?i)(certificate.*expired|SSL|TLS|x509)`),
			severity:   types.SeverityCritical,
			title:      "TLS/Certificate error",
			suggestion: "Check certificate validity, trust chain, and Secret containing certs",
		},

		// Port binding
		{
			regex:      regexp.MustCompile(`(?i)(address already in use|EADDRINUSE|port.*in use)`),
			severity:   types.SeverityCritical,
			title:      "Port already in use",
			suggestion: "Another process is using the port. Check containerPort configuration and running processes",
		},
	}
}

func (a *LogsAnalyzer) Name() string {
	return "logs"
}

func (a *LogsAnalyzer) Supports(kind types.TargetKind) bool {
	// Logs are only relevant for Pods
	return kind == types.KindPod
}

func (a *LogsAnalyzer) Analyze(ctx context.Context, client kubernetes.Interface, target types.Target, config types.AnalyzerConfig) ([]types.Finding, error) {
	// First, get the pod to know which containers it has
	pod, err := client.CoreV1().Pods(target.Namespace).Get(ctx, target.Name, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get pod: %w", err)
	}

	var findings []types.Finding

	// Analyze logs for each container
	for _, container := range pod.Spec.Containers {
		containerFindings, err := a.analyzeContainerLogs(ctx, client, target, container.Name, config, false)
		if err != nil {
			findings = append(findings, types.Finding{
				Analyzer: a.Name(),
				Severity: types.SeverityWarning,
				Title:    fmt.Sprintf("Could not fetch logs for container '%s'", container.Name),
				Detail:   err.Error(),
			})
			continue
		}
		findings = append(findings, containerFindings...)
	}

	// Also check previous container logs if container has restarted
	for _, cs := range pod.Status.ContainerStatuses {
		if cs.RestartCount > 0 {
			prevFindings, err := a.analyzeContainerLogs(ctx, client, target, cs.Name, config, true)
			if err == nil {
				// Mark these as from previous instance
				for i := range prevFindings {
					prevFindings[i].Title = "[Previous] " + prevFindings[i].Title
				}
				findings = append(findings, prevFindings...)
			}
		}
	}

	return findings, nil
}

func (a *LogsAnalyzer) analyzeContainerLogs(
	ctx context.Context,
	client kubernetes.Interface,
	target types.Target,
	containerName string,
	config types.AnalyzerConfig,
	previous bool,
) ([]types.Finding, error) {
	tailLines := int64(config.LogTailLines)
	
	opts := &corev1.PodLogOptions{
		Container: containerName,
		TailLines: &tailLines,
		Previous:  previous,
	}

	req := client.CoreV1().Pods(target.Namespace).GetLogs(target.Name, opts)
	stream, err := req.Stream(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to stream logs: %w", err)
	}
	defer stream.Close()

	var findings []types.Finding
	matchedPatterns := make(map[string]int) // Deduplicate findings

	scanner := bufio.NewScanner(stream)
	// Increase buffer size for long log lines
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	lineCount := 0
	for scanner.Scan() {
		line := scanner.Text()
		lineCount++

		// Check against known error patterns
		for _, pattern := range a.errorPatterns {
			if pattern.regex.MatchString(line) {
				key := pattern.title
				matchedPatterns[key]++
				
				// Only report first occurrence of each pattern type
				if matchedPatterns[key] == 1 {
					findings = append(findings, types.Finding{
						Analyzer:   a.Name(),
						Severity:   pattern.severity,
						Title:      fmt.Sprintf("[%s] %s", containerName, pattern.title),
						Detail:     truncate(line, 200),
						Suggestion: pattern.suggestion,
					})
				}
			}
		}
	}

	if err := scanner.Err(); err != nil && err != io.EOF {
		return findings, fmt.Errorf("error reading logs: %w", err)
	}

	// Add summary of repeated patterns
	for title, count := range matchedPatterns {
		if count > 1 {
			findings = append(findings, types.Finding{
				Analyzer: a.Name(),
				Severity: types.SeverityInfo,
				Title:    fmt.Sprintf("Pattern '%s' occurred %d times", title, count),
				Detail:   "Multiple occurrences may indicate a recurring issue",
			})
		}
	}

	// Add log summary
	if lineCount == 0 {
		findings = append(findings, types.Finding{
			Analyzer: a.Name(),
			Severity: types.SeverityInfo,
			Title:    fmt.Sprintf("[%s] No logs available", containerName),
			Detail:   "Container has not produced any logs yet, or logs have been rotated",
		})
	} else if len(matchedPatterns) == 0 {
		findings = append(findings, types.Finding{
			Analyzer: a.Name(),
			Severity: types.SeverityOK,
			Title:    fmt.Sprintf("[%s] No error patterns detected in %d log lines", containerName, lineCount),
			Detail:   "Logs scanned, no known error patterns found",
		})
	}

	return findings, nil
}

// AddPattern allows adding custom log patterns.
func (a *LogsAnalyzer) AddPattern(pattern string, severity types.Severity, title, suggestion string) error {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return fmt.Errorf("invalid pattern: %w", err)
	}

	a.errorPatterns = append(a.errorPatterns, &logPattern{
		regex:      re,
		severity:   severity,
		title:      title,
		suggestion: suggestion,
	})

	return nil
}
