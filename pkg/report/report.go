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

// Config holds configuration for report generation
type Config struct {
	Format      Format
	Verbose     bool
	Writer      io.Writer
	ShowProgress bool
}

// Reporter handles report generation
type Reporter struct {
	config  Config
	results []models.AnalysisResult
	stats   ScanStats
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
}

// NewReporter creates a new reporter
func NewReporter(config Config) *Reporter {
	if config.Writer == nil {
		config.Writer = os.Stdout
	}
	return &Reporter{
		config: config,
		stats:  ScanStats{StartTime: time.Now()},
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

// ShowProgress displays a progress indicator
func (r *Reporter) ShowProgress(current, total int, packageName string) {
	if !r.config.ShowProgress {
		return
	}

	percentage := int(float64(current) / float64(total) * 100)
	barWidth := 40
	filledWidth := int(float64(barWidth) * float64(current) / float64(total))

	bar := strings.Repeat("█", filledWidth) + strings.Repeat("░", barWidth-filledWidth)

	_, _ = fmt.Fprintf(r.config.Writer, "\r\033[K🔬 Analyzing [%s] %3d%% (%d/%d) %s",
		bar, percentage, current, total, truncate(packageName, 40))
}

// ClearProgress clears the progress line
func (r *Reporter) ClearProgress() {
	if !r.config.ShowProgress {
		return
	}
	_, _ = fmt.Fprintf(r.config.Writer, "\r\033[K")
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

// extractCriticalIssues extracts top critical issues from analysis results
// Returns up to maxIssues most important findings with package context
func (r *Reporter) extractCriticalIssues(maxIssues int) []CriticalIssue {
	var issues []CriticalIssue

	// Prioritize HIGH risk packages first, then MEDIUM
	sortedResults := make([]models.AnalysisResult, len(r.results))
	copy(sortedResults, r.results)

	// Sort by risk level (HIGH > MEDIUM > LOW)
	// Then by number of HIGH/CRITICAL severity findings
	for i := 0; i < len(sortedResults); i++ {
		for j := i + 1; j < len(sortedResults); j++ {
			swapNeeded := false

			// Compare risk levels
			if sortedResults[j].RiskLevel == "HIGH" && sortedResults[i].RiskLevel != "HIGH" {
				swapNeeded = true
			} else if sortedResults[j].RiskLevel == "MEDIUM" && sortedResults[i].RiskLevel == "LOW" {
				swapNeeded = true
			} else if sortedResults[i].RiskLevel == sortedResults[j].RiskLevel {
				// Same risk level - compare by number of critical findings
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
		// Only include HIGH and MEDIUM risk packages
		if result.RiskLevel != "HIGH" && result.RiskLevel != "MEDIUM" {
			continue
		}

		// Get most critical finding for this package
		for _, finding := range result.Findings {
			// Skip LOW severity findings in executive summary
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

			// Only take one finding per package for executive summary
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
