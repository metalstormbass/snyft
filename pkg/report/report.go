package report

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/metalstormbass/snyft/pkg/models"
)

// Format represents the output format type
type Format string

const (
	FormatText     Format = "text"
	FormatMarkdown Format = "markdown"
	FormatJSON     Format = "json"
	FormatHTML     Format = "html"
)

// ANSI color codes (single source of truth for all formatters)
const (
	colorReset   = "\033[0m"
	colorRed     = "\033[31m"
	colorGreen   = "\033[32m"
	colorYellow  = "\033[33m"
	colorCyan    = "\033[36m"
	colorMagenta = "\033[35m"
	colorBold    = "\033[1m"
	colorDim     = "\033[2m"
)

// Spinner frames for animation
var spinnerFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

// Config holds configuration for report generation
type Config struct {
	Format         Format
	Verbose        bool
	Writer         io.Writer
	ShowProgress   bool
	ProgressWriter io.Writer // Where to write progress output; defaults to Writer if nil
}

// Reporter handles report generation
type Reporter struct {
	config          Config
	results         []models.AnalysisResult
	stats           ScanStats
	reportAISummary *models.ReportAISummary
	startTime       time.Time
	spinnerIdx      int
}

// ScanStats contains scan statistics
type ScanStats struct {
	StartTime      time.Time
	EndTime        time.Time
	TotalPackages  int
	HighRisk       int
	MediumRisk     int
	LowRisk        int
	ManifestFiles  int
	ScannedPath    string
	DirectDeps     int // Number of direct dependencies found (before filtering)
	TransitiveDeps int // Number of transitive dependencies found (before filtering)
}

// NewReporter creates a new reporter
func NewReporter(config Config) *Reporter {
	if config.Writer == nil {
		config.Writer = os.Stdout
	}
	if config.ProgressWriter == nil {
		config.ProgressWriter = config.Writer
	}
	return &Reporter{
		config:     config,
		stats:      ScanStats{StartTime: time.Now()},
		startTime:  time.Now(),
		spinnerIdx: 0,
	}
}

// SetScanPath sets the path that was scanned
func (r *Reporter) SetScanPath(path string) {
	r.stats.ScannedPath = path
}

// SetManifestCount sets the number of manifest files found
func (r *Reporter) SetManifestCount(count int) {
	r.stats.ManifestFiles = count
}

// SetDependencyCounts sets the direct and transitive dependency counts.
// These reflect the total found before any filtering is applied.
func (r *Reporter) SetDependencyCounts(direct, transitive int) {
	r.stats.DirectDeps = direct
	r.stats.TransitiveDeps = transitive
}

// SetReportAISummary sets the report-level AI summary.
// This summary is generated AFTER all packages are analyzed and synthesizes
// all findings into a holistic assessment. Displayed in the executive summary.
func (r *Reporter) SetReportAISummary(summary *models.ReportAISummary) {
	r.reportAISummary = summary
}

// AddResults adds analysis results to the report
func (r *Reporter) AddResults(results []models.AnalysisResult) {
	r.results = results
	r.stats.TotalPackages = len(results)
	r.stats.EndTime = time.Now()

	// Calculate risk distribution
	for _, result := range results {
		switch result.RiskLevel {
		case "HIGH":
			r.stats.HighRisk++
		case "MEDIUM":
			r.stats.MediumRisk++
		case "LOW":
			r.stats.LowRisk++
		}
	}
}

// Generate generates the report
func (r *Reporter) Generate() error {
	switch r.config.Format {
	case FormatText:
		return r.generateText()
	case FormatMarkdown:
		return r.generateMarkdown()
	case FormatJSON:
		return r.generateJSON()
	case FormatHTML:
		return r.generateHTML()
	default:
		return fmt.Errorf("unsupported format: %s", r.config.Format)
	}
}

// HasProgress returns true if the reporter is configured to show progress bars
func (r *Reporter) HasProgress() bool {
	return r.config.ShowProgress
}

// ShowProgress displays an enhanced progress indicator with time info and animations
func (r *Reporter) ShowProgress(current, total int, packageName string) {
	if !r.config.ShowProgress {
		return
	}

	// Calculate progress metrics
	percentage := int(float64(current) / float64(total) * 100)
	barWidth := 35
	filledWidth := int(float64(barWidth) * float64(current) / float64(total))

	// Create colored progress bar
	filledBar := colorGreen + strings.Repeat("━", filledWidth) + colorReset
	emptyBar := colorDim + strings.Repeat("━", barWidth-filledWidth) + colorReset
	bar := filledBar + emptyBar

	// Calculate time metrics
	elapsed := time.Since(r.startTime)
	rate := float64(current) / elapsed.Seconds()
	var eta string
	if current > 0 && rate > 0 {
		remaining := float64(total-current) / rate
		eta = formatProgressDuration(time.Duration(remaining * float64(time.Second)))
	} else {
		eta = "calculating..."
	}

	// Get spinner frame
	spinner := colorCyan + spinnerFrames[r.spinnerIdx%len(spinnerFrames)] + colorReset
	r.spinnerIdx++

	// Format package name with color
	pkgDisplay := colorYellow + truncate(packageName, 35) + colorReset

	// Build progress line with enhanced styling
	progressLine := fmt.Sprintf("\r\033[K%s %s[%s]%s %s%3d%%%s %s(%d/%d)%s │ %sElapsed:%s %s │ %sETA:%s %s │ %s%.1f pkg/s%s │ %s",
		spinner,
		colorDim, bar, colorReset,
		colorBold, percentage, colorReset,
		colorDim, current, total, colorReset,
		colorMagenta, colorReset, formatProgressDuration(elapsed),
		colorMagenta, colorReset, eta,
		colorCyan, rate, colorReset,
		pkgDisplay,
	)

	_, _ = fmt.Fprint(r.config.ProgressWriter, progressLine)
}

// formatProgressDuration formats a duration for display in progress bar
func formatProgressDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	minutes := int(d.Minutes())
	seconds := int(d.Seconds()) % 60
	return fmt.Sprintf("%dm%ds", minutes, seconds)
}

// ClearProgress clears the progress line
func (r *Reporter) ClearProgress() {
	if !r.config.ShowProgress {
		return
	}
	_, _ = fmt.Fprintf(r.config.ProgressWriter, "\r\033[K")
}

// truncate truncates a string to the specified length
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

// CriticalIssue represents a critical finding with package details
type CriticalIssue struct {
	PackageName    string
	PackageVersion string
	Ecosystem      string
	RiskLevel      string
	Description    string
	Evidence       string
	Severity       string
}

// RiskArea represents a structured key risk area finding
type RiskArea struct {
	Tag      string   // e.g. "HIGH RISK", "INSTALL SCRIPTS"
	Severity string   // "HIGH" or "MEDIUM"
	Count    int      // Number of affected packages
	Summary  string   // One-line summary
	Examples []string // Example package names (up to 3)
}

// extractCriticalIssues extracts top critical issues from analysis results
// Returns up to maxIssues most important findings with package context
func (r *Reporter) extractCriticalIssues(maxIssues int) []CriticalIssue {
	var issues []CriticalIssue

	// Prioritize HIGH risk packages first, then MEDIUM
	sortedResults := make([]models.AnalysisResult, len(r.results))
	copy(sortedResults, r.results)

	// Sort by risk level (HIGH > MEDIUM > LOW)
	for i := 0; i < len(sortedResults); i++ {
		for j := i + 1; j < len(sortedResults); j++ {
			swapNeeded := false

			if sortedResults[j].RiskLevel == "HIGH" && sortedResults[i].RiskLevel != "HIGH" {
				swapNeeded = true
			} else if sortedResults[j].RiskLevel == "MEDIUM" && sortedResults[i].RiskLevel == "LOW" {
				swapNeeded = true
			} else if sortedResults[i].RiskLevel == sortedResults[j].RiskLevel {
				iCritical := countCriticalFindings(sortedResults[i])
				jCritical := countCriticalFindings(sortedResults[j])
				if jCritical > iCritical {
					swapNeeded = true
				}
			}

			if swapNeeded {
				sortedResults[i], sortedResults[j] = sortedResults[j], sortedResults[i]
			}
		}
	}

	// Extract issues from top packages
	for _, result := range sortedResults {
		if result.RiskLevel != "HIGH" && result.RiskLevel != "MEDIUM" {
			continue
		}

		for _, finding := range result.Findings {
			if finding.Severity == "LOW" {
				continue
			}

			issue := CriticalIssue{
				PackageName:    result.Dependency.Name,
				PackageVersion: result.Dependency.Version,
				Ecosystem:      string(result.Dependency.Ecosystem),
				RiskLevel:      result.RiskLevel,
				Description:    finding.Description,
				Evidence:       finding.Evidence,
				Severity:       finding.Severity,
			}
			issues = append(issues, issue)
			break
		}

		if len(issues) >= maxIssues {
			break
		}
	}

	return issues
}

// countCriticalFindings counts HIGH and CRITICAL severity findings in a result
func countCriticalFindings(result models.AnalysisResult) int {
	count := 0
	for _, finding := range result.Findings {
		if finding.Severity == "HIGH" || finding.Severity == "CRITICAL" {
			count++
		}
	}
	return count
}

// generateRiskAreas builds structured risk area data from analysis results
func (r *Reporter) generateRiskAreas() []RiskArea {
	var areas []RiskArea

	// HIGH risk packages
	if r.stats.HighRisk > 0 {
		areas = append(areas, RiskArea{
			Tag:      "HIGH RISK",
			Severity: "HIGH",
			Count:    r.stats.HighRisk,
			Summary:  fmt.Sprintf("%d package%s with HIGH supply chain compromise risk", r.stats.HighRisk, pluralize(r.stats.HighRisk)),
		})
	}

	// Missing source code
	var missingSourcePkgs []string
	for _, result := range r.results {
		if !result.SourceCodeAvailable && result.RiskLevel != "LOW" {
			if len(missingSourcePkgs) < 3 {
				missingSourcePkgs = append(missingSourcePkgs, result.Dependency.Name)
			}
		}
	}
	if len(missingSourcePkgs) > 0 {
		areas = append(areas, RiskArea{
			Tag:      "UNVERIFIABLE SOURCE",
			Severity: "MEDIUM",
			Count:    len(missingSourcePkgs),
			Summary:  "Published artifacts cannot be audited or compared to source",
			Examples: missingSourcePkgs,
		})
	}

	// Install-time execution
	var installScriptPkgs []string
	for _, result := range r.results {
		if result.Metadata.HasInstallScripts {
			if len(installScriptPkgs) < 3 {
				installScriptPkgs = append(installScriptPkgs, result.Dependency.Name)
			}
		}
	}
	if len(installScriptPkgs) > 0 {
		areas = append(areas, RiskArea{
			Tag:      "INSTALL SCRIPTS",
			Severity: "MEDIUM",
			Count:    len(installScriptPkgs),
			Summary:  "Install scripts are a primary supply chain attack vector",
			Examples: installScriptPkgs,
		})
	}

	// Missing provenance
	missingProvenance := 0
	for _, result := range r.results {
		if result.SupplyChainScore != nil && result.SupplyChainScore.CategoryScores.Provenance.RiskPoints > 1 {
			missingProvenance++
		}
	}
	if missingProvenance > 0 {
		areas = append(areas, RiskArea{
			Tag:      "NO PROVENANCE",
			Severity: "MEDIUM",
			Count:    missingProvenance,
			Summary:  "No SLSA attestations, Sigstore signatures, or reproducible builds",
		})
	}

	// CI pipeline security issues
	var ciRiskPkgs []string
	for _, result := range r.results {
		if result.SupplyChainScore != nil && result.SupplyChainScore.CategoryScores.CIPipelineSecurity.RiskPoints > 1 {
			if len(ciRiskPkgs) < 3 {
				ciRiskPkgs = append(ciRiskPkgs, result.Dependency.Name)
			}
		}
	}
	if len(ciRiskPkgs) > 0 {
		areas = append(areas, RiskArea{
			Tag:      "CI PIPELINE",
			Severity: "MEDIUM",
			Count:    len(ciRiskPkgs),
			Summary:  "Insecure CI configs: unpinned actions, script injection, or self-hosted runners",
			Examples: ciRiskPkgs,
		})
	}

	return areas
}

// calculateOverallRisk determines the overall risk level from scan statistics
func (r *Reporter) calculateOverallRisk() string {
	if r.stats.TotalPackages == 0 {
		return "UNKNOWN"
	}

	highPct := float64(r.stats.HighRisk) / float64(r.stats.TotalPackages)
	mediumPct := float64(r.stats.MediumRisk) / float64(r.stats.TotalPackages)

	if highPct > 0.3 {
		return "HIGH"
	} else if highPct > 0 || mediumPct > 0.5 {
		return "MEDIUM"
	}
	return "LOW"
}

// getRiskImpactDescription returns a concise impact description for a severity level
func (r *Reporter) getRiskImpactDescription(severity string) string {
	switch severity {
	case "CRITICAL", "HIGH":
		return "Could lead to full system compromise or supply chain contamination"
	case "MEDIUM":
		return "Could enable lateral movement or unauthorized access"
	case "LOW":
		return "Limited impact, contributes to attack surface"
	default:
		return ""
	}
}

// getCategoryList returns the ordered list of supply chain security categories
func getCategoryList(scores models.CategoryScores) []struct {
	Name  string
	Score models.CategoryScore
} {
	return []struct {
		Name  string
		Score models.CategoryScore
	}{
		{"Publisher Control", scores.PublisherControl},
		{"Ownership Changes", scores.OwnershipChanges},
		{"Release Anomalies", scores.ReleaseAnomalies},
		{"Install Execution", scores.InstallExecution},
		{"Dependency Sprawl", scores.DependencySprawl},
		{"Provenance", scores.Provenance},
		{"Health", scores.Health},
		{"Governance", scores.Governance},
		{"Release Security", scores.ReleaseSecurity},
		{"Package Maturity", scores.PackageMaturity},
		{"CI Pipeline", scores.CIPipelineSecurity},
	}
}

func formatDuration(d time.Duration) string {
	if d < time.Second {
		return fmt.Sprintf("%dms", d.Milliseconds())
	}
	return fmt.Sprintf("%.2fs", d.Seconds())
}

func pluralize(count int) string {
	if count == 1 {
		return ""
	}
	return "s"
}

func pct(n, total int) float64 {
	if total == 0 {
		return 0
	}
	return float64(n) / float64(total) * 100
}
