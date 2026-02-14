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

	fmt.Fprintf(r.config.Writer, "\r\033[K🔬 Analyzing [%s] %3d%% (%d/%d) %s",
		bar, percentage, current, total, truncate(packageName, 40))
}

// ClearProgress clears the progress line
func (r *Reporter) ClearProgress() {
	if !r.config.ShowProgress {
		return
	}
	fmt.Fprintf(r.config.Writer, "\r\033[K")
}

// truncate truncates a string to the specified length
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
