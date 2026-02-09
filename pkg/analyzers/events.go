package analyzers

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/mitzcore/rootkube/pkg/types"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// EventsAnalyzer fetches and analyzes Kubernetes events related to the target.
type EventsAnalyzer struct{}

// NewEventsAnalyzer creates a new EventsAnalyzer.
func NewEventsAnalyzer() *EventsAnalyzer {
	return &EventsAnalyzer{}
}

func (a *EventsAnalyzer) Name() string {
	return "events"
}

func (a *EventsAnalyzer) Supports(kind types.TargetKind) bool {
	// Events are relevant for all resource types
	return kind == types.KindPod || kind == types.KindService || kind == types.KindIngress
}

func (a *EventsAnalyzer) Analyze(ctx context.Context, client kubernetes.Interface, target types.Target, config types.AnalyzerConfig) ([]types.Finding, error) {
	// Fetch events for the target
	fieldSelector := fmt.Sprintf("involvedObject.name=%s,involvedObject.namespace=%s", target.Name, target.Namespace)
	
	events, err := client.CoreV1().Events(target.Namespace).List(ctx, metav1.ListOptions{
		FieldSelector: fieldSelector,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list events: %w", err)
	}

	var findings []types.Finding
	cutoff := time.Now().Add(-config.EventLookback)

	// Filter and analyze events
	var recentEvents []corev1.Event
	for _, event := range events.Items {
		eventTime := event.LastTimestamp.Time
		if eventTime.IsZero() {
			eventTime = event.EventTime.Time
		}
		if eventTime.After(cutoff) {
			recentEvents = append(recentEvents, event)
		}
	}

	if len(recentEvents) == 0 {
		findings = append(findings, types.Finding{
			Analyzer: a.Name(),
			Severity: types.SeverityInfo,
			Title:    "No recent events found",
			Detail:   fmt.Sprintf("No events in the last %v for %s/%s", config.EventLookback, target.Namespace, target.Name),
		})
		return findings, nil
	}

	// Group events by type and analyze
	warningEvents := make([]corev1.Event, 0)
	normalEvents := make([]corev1.Event, 0)

	for _, event := range recentEvents {
		if event.Type == corev1.EventTypeWarning {
			warningEvents = append(warningEvents, event)
		} else {
			normalEvents = append(normalEvents, event)
		}
	}

	// Analyze warning events - these are usually the important ones
	for _, event := range warningEvents {
		finding := a.analyzeEvent(event)
		findings = append(findings, finding)
	}

	// Summary of normal events
	if len(normalEvents) > 0 {
		findings = append(findings, types.Finding{
			Analyzer: a.Name(),
			Severity: types.SeverityInfo,
			Title:    fmt.Sprintf("%d normal events in the last %v", len(normalEvents), config.EventLookback),
			Detail:   a.summarizeNormalEvents(normalEvents),
		})
	}

	return findings, nil
}

func (a *EventsAnalyzer) analyzeEvent(event corev1.Event) types.Finding {
	eventTime := event.LastTimestamp.Time
	if eventTime.IsZero() {
		eventTime = event.EventTime.Time
	}

	severity := types.SeverityWarning
	suggestion := ""

	// Pattern match known event reasons
	switch event.Reason {
	// Scheduling issues
	case "FailedScheduling":
		severity = types.SeverityCritical
		suggestion = a.parseSchedulingFailure(event.Message)
	
	// Image issues
	case "Failed":
		if strings.Contains(event.Message, "ImagePullBackOff") || 
		   strings.Contains(event.Message, "ErrImagePull") ||
		   strings.Contains(event.Message, "pull image") {
			severity = types.SeverityCritical
			suggestion = "Check image name, tag, and registry credentials"
		} else if strings.Contains(event.Message, "CrashLoopBackOff") {
			severity = types.SeverityCritical
			suggestion = "Container is crashing repeatedly. Check logs for the root cause"
		}
	
	// Mount issues
	case "FailedMount":
		severity = types.SeverityCritical
		suggestion = "Check PVC status, ConfigMap/Secret existence, and volume permissions"
	
	// Probe failures
	case "Unhealthy":
		if strings.Contains(event.Message, "Readiness probe failed") {
			suggestion = "Readiness probe failing. Check the probe endpoint and application health"
		} else if strings.Contains(event.Message, "Liveness probe failed") {
			severity = types.SeverityCritical
			suggestion = "Liveness probe failing causes container restarts. Check probe config and application"
		} else if strings.Contains(event.Message, "Startup probe failed") {
			suggestion = "Startup probe failing. Application may need more time to start"
		}

	// Resource issues
	case "FailedCreate":
		severity = types.SeverityCritical
		suggestion = "Failed to create resource. Check RBAC permissions and resource quotas"

	// Eviction
	case "Evicted":
		severity = types.SeverityCritical
		suggestion = "Pod was evicted. Check node pressure conditions (disk, memory)"

	// OOM
	case "OOMKilling":
		severity = types.SeverityCritical
		suggestion = "Container exceeded memory limit. Increase memory limit or optimize application"

	// Network issues
	case "NetworkNotReady":
		severity = types.SeverityCritical
		suggestion = "Node network is not ready. Check CNI plugin and node status"

	// Preemption
	case "Preempted":
		suggestion = "Pod was preempted by higher-priority pod. Consider adjusting priority"
	}

	return types.Finding{
		Analyzer:   a.Name(),
		Severity:   severity,
		Title:      fmt.Sprintf("[Event] %s: %s", event.Reason, truncate(event.Message, 80)),
		Detail:     event.Message,
		Suggestion: suggestion,
		Timestamp:  eventTime,
	}
}

func (a *EventsAnalyzer) parseSchedulingFailure(message string) string {
	message = strings.ToLower(message)
	
	if strings.Contains(message, "insufficient cpu") {
		return "Cluster has insufficient CPU. Scale up nodes or reduce pod CPU requests"
	}
	if strings.Contains(message, "insufficient memory") {
		return "Cluster has insufficient memory. Scale up nodes or reduce pod memory requests"
	}
	if strings.Contains(message, "didn't match pod") && strings.Contains(message, "node selector") {
		return "No nodes match the pod's nodeSelector. Check node labels"
	}
	if strings.Contains(message, "taints") {
		return "Pod doesn't tolerate node taints. Add tolerations or remove taints"
	}
	if strings.Contains(message, "affinity") {
		return "Pod affinity/anti-affinity rules cannot be satisfied. Review affinity configuration"
	}
	if strings.Contains(message, "persistentvolumeclaim") && strings.Contains(message, "not found") {
		return "Referenced PVC doesn't exist. Create the PVC first"
	}
	if strings.Contains(message, "unbound") {
		return "PVC is not bound to a PV. Check StorageClass and PV availability"
	}

	return "Review scheduling constraints (resources, nodeSelector, affinity, tolerations)"
}

func (a *EventsAnalyzer) summarizeNormalEvents(events []corev1.Event) string {
	reasonCounts := make(map[string]int)
	for _, event := range events {
		reasonCounts[event.Reason]++
	}

	var parts []string
	for reason, count := range reasonCounts {
		parts = append(parts, fmt.Sprintf("%s: %d", reason, count))
	}

	return strings.Join(parts, ", ")
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
