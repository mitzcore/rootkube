// Package output provides terminal rendering for analysis results.
package output

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/mitzcore/rootkube/pkg/types"
)

// ANSI color codes
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorPurple = "\033[35m"
	colorCyan   = "\033[36m"
	colorWhite  = "\033[37m"
	colorBold   = "\033[1m"
	colorDim    = "\033[2m"
)

// Symbols for different severity levels
const (
	symbolCritical = "✖"
	symbolWarning  = "⚠"
	symbolInfo     = "ℹ"
	symbolOK       = "✔"
	symbolBullet   = "•"
	symbolArrow    = "→"
)

// Renderer handles outputting analysis results to the terminal.
type Renderer struct {
	out       io.Writer
	useColors bool
	verbose   bool
}

// NewRenderer creates a new Renderer.
func NewRenderer(useColors, verbose bool) *Renderer {
	return &Renderer{
		out:       os.Stdout,
		useColors: useColors,
		verbose:   verbose,
	}
}

// Render outputs the analysis result to the terminal.
func (r *Renderer) Render(result *types.AnalysisResult) {
	r.printHeader(result)
	r.printSummary(result)
	r.printFindings(result)
	
	if result.RootCause != nil {
		r.printRootCause(result.RootCause)
	}
	
	r.printFooter(result)
}

func (r *Renderer) printHeader(result *types.AnalysisResult) {
	r.println("")
	r.printf("%s%s rootkube analysis %s%s\n", colorBold, colorCyan, colorReset, colorDim)
	r.println(strings.Repeat("─", 60))
	r.printf("%s%s Target: %s %s/%s%s\n", 
		colorReset, colorBold,
		result.Target.Kind, 
		result.Target.Namespace, 
		result.Target.Name,
		colorReset)
	r.printf("%sTime: %s%s\n", colorDim, result.StartTime.Format(time.RFC3339), colorReset)
	r.println(strings.Repeat("─", 60))
	r.println("")
}

func (r *Renderer) printSummary(result *types.AnalysisResult) {
	// Count findings by severity
	counts := make(map[types.Severity]int)
	for _, f := range result.Findings {
		counts[f.Severity]++
	}

	r.printf("%s%s SUMMARY%s\n", colorBold, colorWhite, colorReset)
	r.println("")

	if counts[types.SeverityCritical] > 0 {
		r.printf("  %s%s %s %d critical issue(s)%s\n", 
			colorRed, symbolCritical, colorBold, counts[types.SeverityCritical], colorReset)
	}
	if counts[types.SeverityWarning] > 0 {
		r.printf("  %s%s %d warning(s)%s\n", 
			colorYellow, symbolWarning, counts[types.SeverityWarning], colorReset)
	}
	if counts[types.SeverityInfo] > 0 {
		r.printf("  %s%s %d info%s\n", 
			colorBlue, symbolInfo, counts[types.SeverityInfo], colorReset)
	}
	if counts[types.SeverityOK] > 0 {
		r.printf("  %s%s %d check(s) passed%s\n", 
			colorGreen, symbolOK, counts[types.SeverityOK], colorReset)
	}

	if len(result.Findings) == 0 {
		r.printf("  %s%s No issues found%s\n", colorGreen, symbolOK, colorReset)
	}

	r.println("")
}

func (r *Renderer) printFindings(result *types.AnalysisResult) {
	if len(result.Findings) == 0 {
		return
	}

	r.printf("%s%s FINDINGS%s\n", colorBold, colorWhite, colorReset)
	r.println("")

	// Group findings by severity for better readability
	criticals := r.filterBySeverity(result.Findings, types.SeverityCritical)
	warnings := r.filterBySeverity(result.Findings, types.SeverityWarning)
	infos := r.filterBySeverity(result.Findings, types.SeverityInfo)
	oks := r.filterBySeverity(result.Findings, types.SeverityOK)

	// Print critical findings first (most important)
	for _, f := range criticals {
		r.printFinding(f)
	}

	// Then warnings
	for _, f := range warnings {
		r.printFinding(f)
	}

	// Then info (only in verbose mode or if no errors)
	if r.verbose || (len(criticals) == 0 && len(warnings) == 0) {
		for _, f := range infos {
			r.printFinding(f)
		}
	}

	// OKs only in verbose mode
	if r.verbose {
		for _, f := range oks {
			r.printFinding(f)
		}
	}
}

func (r *Renderer) printFinding(f types.Finding) {
	color, symbol := r.severityStyle(f.Severity)

	// Title line
	r.printf("%s%s %s%s%s", color, symbol, colorBold, f.Title, colorReset)
	if f.Analyzer != "" {
		r.printf(" %s[%s]%s", colorDim, f.Analyzer, colorReset)
	}
	r.println("")

	// Detail (indented)
	if f.Detail != "" {
		r.printf("  %s%s%s\n", colorDim, f.Detail, colorReset)
	}

	// Suggestion (indented with arrow)
	if f.Suggestion != "" {
		r.printf("  %s%s %s%s\n", colorCyan, symbolArrow, f.Suggestion, colorReset)
	}

	// Timestamp if available
	if !f.Timestamp.IsZero() {
		r.printf("  %sTime: %s%s\n", colorDim, f.Timestamp.Format("15:04:05"), colorReset)
	}

	// Related objects
	if len(f.RelatedObjs) > 0 {
		r.printf("  %sRelated: %s%s\n", colorDim, strings.Join(f.RelatedObjs, ", "), colorReset)
	}

	r.println("")
}

func (r *Renderer) printRootCause(f *types.Finding) {
	r.println(strings.Repeat("─", 60))
	r.printf("%s%s LIKELY ROOT CAUSE%s\n", colorBold, colorRed, colorReset)
	r.println("")
	
	r.printf("  %s%s%s %s%s\n", colorRed, symbolCritical, colorBold, f.Title, colorReset)
	if f.Detail != "" {
		r.printf("  %s%s\n", colorWhite, f.Detail)
	}
	if f.Suggestion != "" {
		r.printf("\n  %s%s Suggested Fix:%s\n", colorCyan, symbolArrow, colorReset)
		r.printf("  %s%s%s\n", colorCyan, f.Suggestion, colorReset)
	}
	r.println("")
}

func (r *Renderer) printFooter(result *types.AnalysisResult) {
	r.println(strings.Repeat("─", 60))
	duration := result.EndTime.Sub(result.StartTime)
	r.printf("%sAnalysis completed in %v%s\n", colorDim, duration.Round(time.Millisecond), colorReset)
	r.println("")
}

func (r *Renderer) filterBySeverity(findings []types.Finding, severity types.Severity) []types.Finding {
	var result []types.Finding
	for _, f := range findings {
		if f.Severity == severity {
			result = append(result, f)
		}
	}
	return result
}

func (r *Renderer) severityStyle(s types.Severity) (color, symbol string) {
	switch s {
	case types.SeverityCritical:
		return colorRed, symbolCritical
	case types.SeverityWarning:
		return colorYellow, symbolWarning
	case types.SeverityInfo:
		return colorBlue, symbolInfo
	case types.SeverityOK:
		return colorGreen, symbolOK
	default:
		return colorWhite, symbolBullet
	}
}

func (r *Renderer) printf(format string, args ...interface{}) {
	if !r.useColors {
		format = stripColors(format)
	}
	fmt.Fprintf(r.out, format, args...)
}

func (r *Renderer) println(s string) {
	if !r.useColors {
		s = stripColors(s)
	}
	fmt.Fprintln(r.out, s)
}

// stripColors removes ANSI color codes from a string.
func stripColors(s string) string {
	// Simple approach: remove all ANSI escape sequences
	result := s
	for _, code := range []string{
		colorReset, colorRed, colorGreen, colorYellow, colorBlue,
		colorPurple, colorCyan, colorWhite, colorBold, colorDim,
	} {
		result = strings.ReplaceAll(result, code, "")
	}
	return result
}

// Progress prints a progress message (for long-running operations).
func (r *Renderer) Progress(message string) {
	r.printf("%s%s %s%s\n", colorDim, symbolBullet, message, colorReset)
}
