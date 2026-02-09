// Package k8s provides Kubernetes client initialization and utilities.
package k8s

import (
	"fmt"
	"os"
	"path/filepath"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// ClientConfig holds configuration for the Kubernetes client.
type ClientConfig struct {
	// Kubeconfig is the path to the kubeconfig file. Empty uses default location.
	Kubeconfig string
	// Context is the kubeconfig context to use. Empty uses current context.
	Context string
}

// NewClient creates a Kubernetes client.
// It tries in-cluster config first, then falls back to kubeconfig.
func NewClient(cfg ClientConfig) (kubernetes.Interface, error) {
	// Try in-cluster config first (when running inside a pod)
	config, err := rest.InClusterConfig()
	if err == nil {
		return kubernetes.NewForConfig(config)
	}

	// Fall back to kubeconfig
	kubeconfigPath := cfg.Kubeconfig
	if kubeconfigPath == "" {
		// Use default location
		if home := homeDir(); home != "" {
			kubeconfigPath = filepath.Join(home, ".kube", "config")
		}
	}

	if kubeconfigPath == "" {
		return nil, fmt.Errorf("could not find kubeconfig")
	}

	// Build config from kubeconfig file
	loadingRules := &clientcmd.ClientConfigLoadingRules{ExplicitPath: kubeconfigPath}
	configOverrides := &clientcmd.ConfigOverrides{}
	
	if cfg.Context != "" {
		configOverrides.CurrentContext = cfg.Context
	}

	kubeConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, configOverrides)
	
	config, err = kubeConfig.ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to build config from kubeconfig: %w", err)
	}

	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create client: %w", err)
	}

	return client, nil
}

// GetCurrentNamespace returns the current namespace from kubeconfig or "default".
func GetCurrentNamespace(kubeconfig string) string {
	kubeconfigPath := kubeconfig
	if kubeconfigPath == "" {
		if home := homeDir(); home != "" {
			kubeconfigPath = filepath.Join(home, ".kube", "config")
		}
	}

	if kubeconfigPath == "" {
		return "default"
	}

	loadingRules := &clientcmd.ClientConfigLoadingRules{ExplicitPath: kubeconfigPath}
	configOverrides := &clientcmd.ConfigOverrides{}
	kubeConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, configOverrides)

	ns, _, err := kubeConfig.Namespace()
	if err != nil || ns == "" {
		return "default"
	}

	return ns
}

func homeDir() string {
	if h := os.Getenv("HOME"); h != "" {
		return h
	}
	// Windows
	return os.Getenv("USERPROFILE")
}
