package main

import (
	"fmt"
	"os"

	"github.com/mitzcore/rootkube/cmd"
	"github.com/spf13/cobra"
)

// Version information (set by build flags)
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "rootkube",
		Short: "Kubernetes root cause analysis tool",
		Long: `rootkube is a diagnostic tool that helps identify the root cause of 
Kubernetes pod failures by correlating pod status, events, logs, and configuration.

Instead of running 10+ commands and guessing, rootkube tells you the "single story"
of why your pod is broken.`,
		Version: fmt.Sprintf("%s (commit: %s, built: %s)", version, commit, date),
	}

	// Add commands
	rootCmd.AddCommand(cmd.GetAnalyzeCmd())
	rootCmd.AddCommand(versionCmd())

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("rootkube %s\n", version)
			fmt.Printf("  commit: %s\n", commit)
			fmt.Printf("  built:  %s\n", date)
		},
	}
}
