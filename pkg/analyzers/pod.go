package analyzers

import (
	"context"
	"fmt"
	"strings"

	"github.com/mitzcore/rootkube/pkg/types"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// PodAnalyzer analyzes pod status, container states, and common failure patterns.
type PodAnalyzer struct{}

// NewPodAnalyzer creates a new PodAnalyzer.
func NewPodAnalyzer() *PodAnalyzer {
	return &PodAnalyzer{}
}

func (a *PodAnalyzer) Name() string {
	return "pod"
}

func (a *PodAnalyzer) Supports(kind types.TargetKind) bool {
	return kind == types.KindPod
}

func (a *PodAnalyzer) Analyze(ctx context.Context, client kubernetes.Interface, target types.Target, config types.AnalyzerConfig) ([]types.Finding, error) {
	// Fetch the pod
	pod, err := client.CoreV1().Pods(target.Namespace).Get(ctx, target.Name, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get pod %s/%s: %w", target.Namespace, target.Name, err)
	}

	var findings []types.Finding

	// Analyze pod phase
	findings = append(findings, a.analyzePodPhase(pod)...)

	// Analyze container statuses
	findings = append(findings, a.analyzeContainerStatuses(pod)...)

	// Analyze init containers
	findings = append(findings, a.analyzeInitContainers(pod)...)

	// Analyze conditions
	findings = append(findings, a.analyzeConditions(pod)...)

	// Analyze resource issues
	findings = append(findings, a.analyzeResources(pod)...)

	return findings, nil
}

func (a *PodAnalyzer) analyzePodPhase(pod *corev1.Pod) []types.Finding {
	var findings []types.Finding

	switch pod.Status.Phase {
	case corev1.PodPending:
		findings = append(findings, types.Finding{
			Analyzer:   a.Name(),
			Severity:   types.SeverityWarning,
			Title:      "Pod is in Pending state",
			Detail:     fmt.Sprintf("Pod has been pending. Reason: %s", pod.Status.Reason),
			Suggestion: "Check node resources, taints/tolerations, and PVC bindings",
		})
	case corev1.PodFailed:
		findings = append(findings, types.Finding{
			Analyzer:   a.Name(),
			Severity:   types.SeverityCritical,
			Title:      "Pod has failed",
			Detail:     fmt.Sprintf("Pod failed with reason: %s, message: %s", pod.Status.Reason, pod.Status.Message),
			Suggestion: "Check container logs and events for failure cause",
		})
	case corev1.PodSucceeded:
		findings = append(findings, types.Finding{
			Analyzer: a.Name(),
			Severity: types.SeverityInfo,
			Title:    "Pod has completed successfully",
			Detail:   "Pod ran to completion (this is expected for Jobs)",
		})
	case corev1.PodRunning:
		findings = append(findings, types.Finding{
			Analyzer: a.Name(),
			Severity: types.SeverityOK,
			Title:    "Pod is running",
			Detail:   fmt.Sprintf("Pod is in Running phase on node %s", pod.Spec.NodeName),
		})
	}

	return findings
}

func (a *PodAnalyzer) analyzeContainerStatuses(pod *corev1.Pod) []types.Finding {
	var findings []types.Finding

	for _, cs := range pod.Status.ContainerStatuses {
		// Check for CrashLoopBackOff
		if cs.State.Waiting != nil {
			reason := cs.State.Waiting.Reason
			message := cs.State.Waiting.Message

			switch reason {
			case "CrashLoopBackOff":
				findings = append(findings, types.Finding{
					Analyzer:   a.Name(),
					Severity:   types.SeverityCritical,
					Title:      fmt.Sprintf("Container '%s' is in CrashLoopBackOff", cs.Name),
					Detail:     fmt.Sprintf("Container has crashed %d times. Last state: %s", cs.RestartCount, message),
					Suggestion: "Check container logs for crash reason. Common causes: missing config, dependency unavailable, application error",
				})
			case "ImagePullBackOff", "ErrImagePull":
				findings = append(findings, types.Finding{
					Analyzer:    a.Name(),
					Severity:    types.SeverityCritical,
					Title:       fmt.Sprintf("Container '%s' cannot pull image", cs.Name),
					Detail:      fmt.Sprintf("Image: %s. Error: %s", cs.Image, message),
					Suggestion:  "Verify image name, tag, and registry credentials (imagePullSecrets)",
					RelatedObjs: []string{fmt.Sprintf("Image/%s", cs.Image)},
				})
			case "CreateContainerConfigError":
				findings = append(findings, types.Finding{
					Analyzer:   a.Name(),
					Severity:   types.SeverityCritical,
					Title:      fmt.Sprintf("Container '%s' has configuration error", cs.Name),
					Detail:     message,
					Suggestion: "Check ConfigMaps, Secrets, and volume mounts referenced by this container",
				})
			default:
				if reason != "" {
					findings = append(findings, types.Finding{
						Analyzer: a.Name(),
						Severity: types.SeverityWarning,
						Title:    fmt.Sprintf("Container '%s' is waiting: %s", cs.Name, reason),
						Detail:   message,
					})
				}
			}
		}

		// Check for terminated containers
		if cs.State.Terminated != nil {
			term := cs.State.Terminated
			
			// Check exit code
			if term.ExitCode != 0 {
				severity := types.SeverityWarning
				suggestion := ""
				
				switch term.ExitCode {
				case 137:
					severity = types.SeverityCritical
					suggestion = "Container was killed (likely OOMKilled). Increase memory limits or optimize application memory usage"
				case 1:
					suggestion = "Application error. Check logs for stack traces or error messages"
				case 126:
					suggestion = "Command not executable. Check container image and entrypoint"
				case 127:
					suggestion = "Command not found. Verify the command exists in the container image"
				case 128:
					suggestion = "Invalid exit code. Check application error handling"
				default:
					if term.ExitCode > 128 {
						suggestion = fmt.Sprintf("Container received signal %d. May indicate external termination", term.ExitCode-128)
					}
				}

				findings = append(findings, types.Finding{
					Analyzer:   a.Name(),
					Severity:   severity,
					Title:      fmt.Sprintf("Container '%s' terminated with exit code %d", cs.Name, term.ExitCode),
					Detail:     fmt.Sprintf("Reason: %s. Message: %s", term.Reason, term.Message),
					Suggestion: suggestion,
					Timestamp:  term.FinishedAt.Time,
				})
			}

			// Check specifically for OOMKilled
			if term.Reason == "OOMKilled" {
				findings = append(findings, types.Finding{
					Analyzer:   a.Name(),
					Severity:   types.SeverityCritical,
					Title:      fmt.Sprintf("Container '%s' was OOMKilled", cs.Name),
					Detail:     "Container exceeded its memory limit and was killed by the kernel",
					Suggestion: "Increase spec.containers[].resources.limits.memory or optimize application memory usage",
					Timestamp:  term.FinishedAt.Time,
				})
			}
		}

		// Check restart count
		if cs.RestartCount > 0 {
			severity := types.SeverityInfo
			if cs.RestartCount > 5 {
				severity = types.SeverityWarning
			}
			if cs.RestartCount > 10 {
				severity = types.SeverityCritical
			}

			findings = append(findings, types.Finding{
				Analyzer: a.Name(),
				Severity: severity,
				Title:    fmt.Sprintf("Container '%s' has restarted %d times", cs.Name, cs.RestartCount),
				Detail:   "Frequent restarts indicate instability",
			})
		}

		// Check if not ready
		if !cs.Ready && cs.State.Running != nil {
			findings = append(findings, types.Finding{
				Analyzer:   a.Name(),
				Severity:   types.SeverityWarning,
				Title:      fmt.Sprintf("Container '%s' is running but not ready", cs.Name),
				Detail:     "Container is running but readiness probe is failing",
				Suggestion: "Check readiness probe configuration and application health endpoints",
			})
		}
	}

	return findings
}

func (a *PodAnalyzer) analyzeInitContainers(pod *corev1.Pod) []types.Finding {
	var findings []types.Finding

	for _, cs := range pod.Status.InitContainerStatuses {
		if cs.State.Waiting != nil && cs.State.Waiting.Reason != "" {
			findings = append(findings, types.Finding{
				Analyzer:   a.Name(),
				Severity:   types.SeverityCritical,
				Title:      fmt.Sprintf("Init container '%s' is stuck: %s", cs.Name, cs.State.Waiting.Reason),
				Detail:     cs.State.Waiting.Message,
				Suggestion: "Init containers must complete before main containers start. Check init container logs",
			})
		}

		if cs.State.Terminated != nil && cs.State.Terminated.ExitCode != 0 {
			findings = append(findings, types.Finding{
				Analyzer:   a.Name(),
				Severity:   types.SeverityCritical,
				Title:      fmt.Sprintf("Init container '%s' failed with exit code %d", cs.Name, cs.State.Terminated.ExitCode),
				Detail:     fmt.Sprintf("Reason: %s", cs.State.Terminated.Reason),
				Suggestion: "Check init container logs. Main containers won't start until all init containers succeed",
			})
		}
	}

	return findings
}

func (a *PodAnalyzer) analyzeConditions(pod *corev1.Pod) []types.Finding {
	var findings []types.Finding

	for _, cond := range pod.Status.Conditions {
		if cond.Status == corev1.ConditionFalse {
			severity := types.SeverityWarning
			
			switch cond.Type {
			case corev1.PodScheduled:
				if cond.Reason == "Unschedulable" {
					severity = types.SeverityCritical
					findings = append(findings, types.Finding{
						Analyzer:   a.Name(),
						Severity:   severity,
						Title:      "Pod cannot be scheduled",
						Detail:     cond.Message,
						Suggestion: "Check node resources, taints/tolerations, nodeSelector, and affinity rules",
						Timestamp:  cond.LastTransitionTime.Time,
					})
				}
			case corev1.PodReady:
				findings = append(findings, types.Finding{
					Analyzer:   a.Name(),
					Severity:   severity,
					Title:      "Pod is not ready",
					Detail:     fmt.Sprintf("Reason: %s. Message: %s", cond.Reason, cond.Message),
					Suggestion: "Check readiness probes and container statuses",
					Timestamp:  cond.LastTransitionTime.Time,
				})
			case corev1.ContainersReady:
				findings = append(findings, types.Finding{
					Analyzer:   a.Name(),
					Severity:   severity,
					Title:      "Not all containers are ready",
					Detail:     cond.Message,
					Suggestion: "Check individual container statuses above",
					Timestamp:  cond.LastTransitionTime.Time,
				})
			}
		}
	}

	// Check for special annotations indicating issues
	if reason, ok := pod.Annotations["kubernetes.io/psp"]; ok {
		if strings.Contains(reason, "error") || strings.Contains(reason, "denied") {
			findings = append(findings, types.Finding{
				Analyzer:   a.Name(),
				Severity:   types.SeverityWarning,
				Title:      "Pod Security Policy issue detected",
				Detail:     reason,
				Suggestion: "Review PodSecurityPolicy or PodSecurityStandard settings",
			})
		}
	}

	return findings
}

func (a *PodAnalyzer) analyzeResources(pod *corev1.Pod) []types.Finding {
	var findings []types.Finding

	for _, container := range pod.Spec.Containers {
		// Check if resources are defined
		if container.Resources.Limits == nil && container.Resources.Requests == nil {
			findings = append(findings, types.Finding{
				Analyzer:   a.Name(),
				Severity:   types.SeverityInfo,
				Title:      fmt.Sprintf("Container '%s' has no resource limits/requests", container.Name),
				Detail:     "Without resource limits, container can consume unlimited resources or be killed unexpectedly",
				Suggestion: "Consider setting resources.requests and resources.limits for better resource management",
			})
		}
	}

	return findings
}
