package report

import (
	"fmt"
	"io"
	"os"
	"sort"
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

// ANSI color codes
const (
	colorReset   = "\033[0m"
	colorGreen   = "\033[32m"
	colorCyan    = "\033[36m"
	colorYellow  = "\033[33m"
	colorDim     = "\033[2m"
	colorBold    = "\033[1m"
	colorMagenta = "\033[35m"
)

// Exported color codes for use by format-specific files.
const (
	ColorReset  = colorReset
	ColorRed    = "\033[31m"
	ColorYellow = colorYellow
	ColorGreen  = colorGreen
	ColorCyan   = colorCyan
	ColorBold   = colorBold
	ColorDim    = colorDim
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
	config     Config
	results    []models.AnalysisResult
	stats      ScanStats
	startTime  time.Time
	spinnerIdx int
}

// ScanStats contains scan statistics
type ScanStats struct {
	StartTime      time.Time
	EndTime        time.Time
	TotalPackages  int
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
		config:    config,
		stats:     ScanStats{StartTime: time.Now()},
		startTime: time.Now(),
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

// AddResults adds analysis results to the report
func (r *Reporter) AddResults(results []models.AnalysisResult) {
	r.results = results
	r.stats.TotalPackages = len(results)
	r.stats.EndTime = time.Now()
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

	percentage := int(float64(current) / float64(total) * 100)
	barWidth := 35
	filledWidth := int(float64(barWidth) * float64(current) / float64(total))

	filledBar := colorGreen + strings.Repeat("━", filledWidth) + colorReset
	emptyBar := colorDim + strings.Repeat("━", barWidth-filledWidth) + colorReset

	elapsed := time.Since(r.startTime)
	rate := float64(current) / elapsed.Seconds()
	eta := "calculating..."
	if current > 0 && rate > 0 {
		remaining := float64(total-current) / rate
		eta = formatProgressDuration(time.Duration(remaining * float64(time.Second)))
	}

	spinner := colorCyan + spinnerFrames[r.spinnerIdx%len(spinnerFrames)] + colorReset
	r.spinnerIdx++

	pkgDisplay := colorYellow + truncate(packageName, 35) + colorReset

	line := fmt.Sprintf("\r\033[K%s %s[%s%s]%s %s%3d%%%s %s(%d/%d)%s │ %sElapsed:%s %s │ %sETA:%s %s │ %s%.1f pkg/s%s │ %s",
		spinner,
		colorDim, filledBar, emptyBar, colorReset,
		colorBold, percentage, colorReset,
		colorDim, current, total, colorReset,
		colorMagenta, colorReset, formatProgressDuration(elapsed),
		colorMagenta, colorReset, eta,
		colorCyan, rate, colorReset,
		pkgDisplay,
	)

	_, _ = fmt.Fprint(r.config.ProgressWriter, line)
}

// ClearProgress clears the progress line
func (r *Reporter) ClearProgress() {
	if !r.config.ShowProgress {
		return
	}
	_, _ = fmt.Fprintf(r.config.ProgressWriter, "\r\033[K")
}

// CriticalIssue represents a critical finding with package details
type CriticalIssue struct {
	PackageName    string
	PackageVersion string
	Ecosystem      string
	Description    string
	Evidence       string
	Severity       string
	SourceURL      string
}

// extractCriticalIssues extracts top critical issues from analysis results.
// Returns up to maxIssues most important findings with package context.
func (r *Reporter) extractCriticalIssues(maxIssues int) []CriticalIssue {
	sorted := make([]models.AnalysisResult, len(r.results))
	copy(sorted, r.results)

	// Sort by critical finding count descending
	for i := 0; i < len(sorted); i++ {
		for j := i + 1; j < len(sorted); j++ {
			if countCriticalFindings(sorted[j]) > countCriticalFindings(sorted[i]) {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}

	var issues []CriticalIssue
	for _, result := range sorted {
		for _, finding := range result.Findings {
			if finding.Severity == "LOW" {
				continue
			}
			issues = append(issues, CriticalIssue{
				PackageName:    result.Dependency.Name,
				PackageVersion: result.Dependency.DisplayVersion(),
				Ecosystem:      string(result.Dependency.Ecosystem),
				Description:    finding.Description,
				Evidence:       finding.Evidence,
				Severity:       finding.Severity,
				SourceURL:      finding.SourceURL,
			})
			break // one finding per package
		}
		if len(issues) >= maxIssues {
			break
		}
	}
	return issues
}

// generateExecutiveNarrative builds a balanced, factual executive summary.
// Returns 3-5 sentences covering: packages scanned and key risk areas.
func (r *Reporter) generateExecutiveNarrative() string {
	var sb strings.Builder

	fmt.Fprintf(&sb, "Snyft scanned %d package%s for supply chain compromise risk.",
		r.stats.TotalPackages, pluralize(r.stats.TotalPackages))

	areas := r.generateRiskAreas()
	if len(areas) > 0 {
		sb.WriteString(" Key risk areas identified: ")
		for i, area := range areas {
			if i > 0 && i == len(areas)-1 {
				sb.WriteString(", and ")
			} else if i > 0 {
				sb.WriteString(", ")
			}
			sb.WriteString(strings.ToLower(area.Summary))
		}
		sb.WriteString(".")
	} else {
		sb.WriteString(" No critical supply chain risk factors identified.")
	}

	sb.WriteString(" This assessment evaluates the likelihood of compromise through supply chain attacks, not known CVEs or code vulnerabilities.")

	return sb.String()
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

// categoryEntry pairs a category name with its score for iteration.
type categoryEntry struct {
	Name  string
	Score models.CategoryScore
}

// categoryList returns the ordered list of supply chain categories from a score.
func categoryList(scores models.CategoryScores) []categoryEntry {
	return []categoryEntry{
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
	}
}

// categoryTooltips maps each supply chain risk category to a brief description
// of what it assesses and why it matters for compromise likelihood.
var categoryTooltips = map[string]string{
	"Publisher Control":  "Evaluates maintainer count, 2FA usage, and account security. Single maintainers are a single point of compromise via phishing or credential stuffing.",
	"Ownership Changes":  "Detects recent transfers of package ownership. Malicious actors acquire dormant or popular packages to inject compromised code.",
	"Release Anomalies":  "Flags unusual release patterns such as dormant packages suddenly publishing updates, a common indicator of account takeover.",
	"Install Execution":  "Checks for scripts that run during install (preinstall, postinstall). Install scripts are a primary vector for supply chain attacks.",
	"Dependency Sprawl":  "Measures the breadth of the dependency tree. More dependencies increase the attack surface for transitive compromise.",
	"Provenance":         "Verifies build integrity via SLSA attestations, Sigstore signatures, or reproducible builds. Without provenance, artifacts cannot be traced to source.",
	"Health":             "Assesses project activity, contributor count, and community engagement. Abandoned projects are more vulnerable to takeover.",
	"Governance":         "Checks for security policies, contribution guidelines, and governance structures that reduce single-point-of-failure risk.",
	"Release Security":   "Evaluates CI/CD pipeline integrity: branch protection, pinned actions, signed releases, and automated publishing workflows.",
	"Package Maturity":   "Considers package age, download volume, and version history. New or low-adoption packages carry higher unknown risk.",
}

// riskArea describes one aggregated risk finding across all packages.
// It uses plain text (no ANSI) so all formats can consume it directly.
type riskArea struct {
	Tag         string   // e.g. "HIGH RISK", "UNVERIFIABLE SOURCE"
	Summary     string   // one-line count summary
	Explanation string   // why it matters
	Examples    []string // affected package names (up to 3)
}

// generateRiskAreas collects cross-cutting risk patterns from results.
func (r *Reporter) generateRiskAreas() []riskArea {
	var areas []riskArea

	// Missing source code
	var missingSource int
	var missingSourcePkgs []string
	for _, result := range r.results {
		if !result.SourceCodeAvailable {
			missingSource++
			if len(missingSourcePkgs) < 3 {
				missingSourcePkgs = append(missingSourcePkgs, result.Dependency.Name)
			}
		}
	}
	if missingSource > 0 {
		areas = append(areas, riskArea{
			Tag:         "UNVERIFIABLE SOURCE",
			Summary:     fmt.Sprintf("%d package%s lack public source code", missingSource, pluralize(missingSource)),
			Explanation: "Published artifacts cannot be audited or compared to source, preventing independent verification of package contents.",
			Examples:    missingSourcePkgs,
		})
	}

	// Install-time execution
	var installScripts int
	var installScriptPkgs []string
	for _, result := range r.results {
		if result.Metadata.HasInstallScripts {
			installScripts++
			if len(installScriptPkgs) < 3 {
				installScriptPkgs = append(installScriptPkgs, result.Dependency.Name)
			}
		}
	}
	if installScripts > 0 {
		areas = append(areas, riskArea{
			Tag:         "INSTALL-TIME EXECUTION",
			Summary:     fmt.Sprintf("%d package%s execute code during installation", installScripts, pluralize(installScripts)),
			Explanation: "Install scripts are a primary supply chain attack vector. Compromised scripts execute arbitrary code before any application-level security controls.",
			Examples:    installScriptPkgs,
		})
	}

	// Missing provenance
	var missingProvenance int
	var missingProvenancePkgs []string
	for _, result := range r.results {
		if result.SupplyChainScore != nil && result.SupplyChainScore.CategoryScores.Provenance.RiskPoints > 1 {
			missingProvenance++
			if len(missingProvenancePkgs) < 3 {
				missingProvenancePkgs = append(missingProvenancePkgs, result.Dependency.Name)
			}
		}
	}
	if missingProvenance > 0 {
		areas = append(areas, riskArea{
			Tag:         "MISSING PROVENANCE",
			Summary:     fmt.Sprintf("%d package%s lack build provenance verification", missingProvenance, pluralize(missingProvenance)),
			Explanation: "Without SLSA attestations, Sigstore signatures, or reproducible builds, there is no way to verify that published artifacts were produced from the claimed source code.",
			Examples:    missingProvenancePkgs,
		})
	}

	// Release security (includes CI pipeline configuration risks)
	var releaseSecRisks int
	var releaseSecPkgs []string
	for _, result := range r.results {
		if result.SupplyChainScore != nil && result.SupplyChainScore.CategoryScores.ReleaseSecurity.RiskPoints > 1 {
			releaseSecRisks++
			if len(releaseSecPkgs) < 3 {
				releaseSecPkgs = append(releaseSecPkgs, result.Dependency.Name)
			}
		}
	}
	if releaseSecRisks > 0 {
		areas = append(areas, riskArea{
			Tag:         "RELEASE SECURITY",
			Summary:     fmt.Sprintf("%d package%s have critical release security issues", releaseSecRisks, pluralize(releaseSecRisks)),
			Explanation: "Missing CI/CD automation, no branch protection, unsigned releases, or insecure CI configurations (unpinned actions, script injection, self-hosted runners).",
			Examples:    releaseSecPkgs,
		})
	}

	return areas
}

// --- helpers ---

func formatProgressDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	return fmt.Sprintf("%dm%ds", int(d.Minutes()), int(d.Seconds())%60)
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
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

func centerText(text string, width int) string {
	if len(text) >= width {
		return text
	}
	left := (width - len(text)) / 2
	right := width - len(text) - left
	return strings.Repeat(" ", left) + text + strings.Repeat(" ", right)
}

func formatBool(b bool) string {
	if b {
		return ColorGreen + "✓ Yes" + ColorReset
	}
	return ColorRed + "✗ No" + ColorReset
}

func joinExamples(names []string) string {
	if len(names) == 0 {
		return ""
	}
	return strings.Join(names, ", ")
}

// severityOrdinal maps finding severity to a numeric value for sorting.
func severityOrdinal(severity string) int {
	switch severity {
	case "CRITICAL":
		return 4
	case "HIGH":
		return 3
	case "MEDIUM":
		return 2
	case "LOW":
		return 1
	default:
		return 0
	}
}

// sortedResults returns a copy of results sorted alphabetically by package name.
// Findings within each package are sorted by severity descending.
func (r *Reporter) sortedResults() []models.AnalysisResult {
	sorted := make([]models.AnalysisResult, len(r.results))
	copy(sorted, r.results)

	// Sort packages alphabetically by name
	sort.SliceStable(sorted, func(i, j int) bool {
		return sorted[i].Dependency.Name < sorted[j].Dependency.Name
	})

	// Sort findings within each result by severity descending
	for i := range sorted {
		if len(sorted[i].Findings) > 1 {
			sf := make([]models.Finding, len(sorted[i].Findings))
			copy(sf, sorted[i].Findings)
			sort.SliceStable(sf, func(a, b int) bool {
				return severityOrdinal(sf[a].Severity) > severityOrdinal(sf[b].Severity)
			})
			sorted[i].Findings = sf
		}
	}

	return sorted
}

func severityColor(severity string) string {
	switch severity {
	case "CRITICAL", "HIGH":
		return ColorRed
	case "MEDIUM":
		return ColorYellow
	case "LOW":
		return ColorGreen
	default:
		return ColorReset
	}
}

