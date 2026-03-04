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
	StartTime        time.Time
	EndTime          time.Time
	TotalPackages    int
	HighRisk         int
	MediumRisk       int
	LowRisk          int
	ManifestFiles    int
	ScannedPath      string
	DirectDeps       int // Number of direct dependencies found (before filtering)
	TransitiveDeps   int // Number of transitive dependencies found (before filtering)
	ScrapingOnlyPkgs int // Number of packages analyzed in scraping-only mode (reduced fidelity)
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

	for _, result := range results {
		switch result.RiskLevel {
		case "HIGH":
			r.stats.HighRisk++
		case "MEDIUM":
			r.stats.MediumRisk++
		case "LOW":
			r.stats.LowRisk++
		}
		if result.DataMode == models.DataModeScrapingOnly {
			r.stats.ScrapingOnlyPkgs++
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
	RiskLevel      string
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

	// Sort: HIGH > MEDIUM > LOW, then by critical finding count
	for i := 0; i < len(sorted); i++ {
		for j := i + 1; j < len(sorted); j++ {
			if shouldSwapRisk(sorted[i], sorted[j]) {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}

	var issues []CriticalIssue
	for _, result := range sorted {
		if result.RiskLevel != "HIGH" && result.RiskLevel != "MEDIUM" {
			continue
		}
		for _, finding := range result.Findings {
			if finding.Severity == "LOW" {
				continue
			}
			issues = append(issues, CriticalIssue{
				PackageName:    result.Dependency.Name,
				PackageVersion: result.Dependency.DisplayVersion(),
				Ecosystem:      string(result.Dependency.Ecosystem),
				RiskLevel:      result.RiskLevel,
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
// Returns 3-5 sentences covering: packages scanned, risk posture, key risk areas.
func (r *Reporter) generateExecutiveNarrative() string {
	var sb strings.Builder

	fmt.Fprintf(&sb, "Snyft scanned %d package%s for supply chain compromise risk.",
		r.stats.TotalPackages, pluralize(r.stats.TotalPackages))

	elevated := r.stats.HighRisk + r.stats.MediumRisk
	if elevated > 0 {
		fmt.Fprintf(&sb, " %d of %d", elevated, r.stats.TotalPackages)
		if elevated == 1 {
			sb.WriteString(" package shows")
		} else {
			sb.WriteString(" packages show")
		}
		sb.WriteString(" elevated supply chain risk")
		if r.stats.HighRisk > 0 && r.stats.MediumRisk > 0 {
			fmt.Fprintf(&sb, " (%d high, %d medium).", r.stats.HighRisk, r.stats.MediumRisk)
		} else if r.stats.HighRisk > 0 {
			fmt.Fprintf(&sb, " (%d high).", r.stats.HighRisk)
		} else {
			fmt.Fprintf(&sb, " (%d medium).", r.stats.MediumRisk)
		}
	} else {
		sb.WriteString(" No packages show elevated supply chain risk.")
	}

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
	}

	sb.WriteString(" This assessment evaluates the likelihood of compromise through supply chain attacks, not known CVEs or code vulnerabilities.")

	return sb.String()
}

// shouldSwapRisk returns true if b should be sorted before a.
func shouldSwapRisk(a, b models.AnalysisResult) bool {
	if b.RiskLevel == "HIGH" && a.RiskLevel != "HIGH" {
		return true
	}
	if b.RiskLevel == "MEDIUM" && a.RiskLevel == "LOW" {
		return true
	}
	if a.RiskLevel == b.RiskLevel {
		return countCriticalFindings(b) > countCriticalFindings(a)
	}
	return false
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
	"Publisher Control": "Checks: maintainer count (single = high risk), org vs personal account, verified org membership, maintainer account age (under 6mo flagged), email domain (personal vs organizational), package concentration (50+ packages = high-value target), commit/release signing, and org-level MFA enforcement.",
	"Ownership Changes": "Checks: commit author turnover (recent vs historical committers, 80%+ new = high risk), registry ownership transfer history (npm/PyPI), repo creation vs package publication date mismatch (90+ days = transfer signal), and repository age as fallback.",
	"Release Anomalies": "Checks: dormancy detection (1yr+ with no commits), dormancy reactivation (long gap then sudden release), release cadence spikes (release interval under 10% of average), and commit frequency anomalies (year-over-year comparison, e.g. under 5 commits then 20+).",
	"Install Execution": "Checks: presence of install-time script hooks (preinstall, install, postinstall for npm; setup.py for PyPI; pom.xml for Maven), and dangerous pattern analysis in scripts (network requests, filesystem modifications, binary execution, credential exfiltration).",
	"Dependency Sprawl": "Checks: transitive dependency count from lock files (package-lock.json, yarn.lock, poetry.lock) with thresholds at 10 and 50 deps. Falls back to direct dependency count from registry metadata (thresholds at 5 and 15 deps) when no lock file is available.",
	"Provenance":        "Checks: source code availability (public repo URL or source package in artifact), npm provenance attestations, Maven Central GPG signatures (.asc files), signed GitHub releases, and OSSF Scorecard Signed-Releases score.",
	"Health":            "Checks: bus factor from commit distribution (how many authors contribute 50% of commits), OSSF Contributors score as fallback, maintainer count as fallback. Also checks review oversight: branch protection with required reviewers, code review rate (75%+), and release documentation.",
	"Governance":        "Checks: repo archived/abandoned status (180+ days inactive = high risk), presence of SECURITY.md or .github/SECURITY.md, OSSF Security-Policy score, average issue response time (14 days or less = good), and branch protection or documented release process.",
	"Release Security":  "Checks: CI/CD automated publishing workflow, branch protection on default branch, signed releases, required PR reviews or code review rate, documented release process. Penalizes: CI/CD workflow risks (unpinned actions, dangerous triggers, script injection, excessive permissions, secrets in logs) and self-hosted runners.",
	"Package Maturity":  "Checks: package age (under 6mo = high risk, 6mo-2yr = moderate, 2yr+ = low), staleness since last commit or registry update (1yr+ = high risk), and release cadence regularity via coefficient of variation (CV over 2.0 = highly irregular, over 1.0 = somewhat irregular). Final score is the worst of all three.",
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

	if r.stats.HighRisk > 0 {
		var highPkgs []string
		for _, result := range r.results {
			if result.RiskLevel == "HIGH" {
				if len(highPkgs) < 3 {
					highPkgs = append(highPkgs, result.Dependency.Name)
				}
			}
		}
		areas = append(areas, riskArea{
			Tag:     "HIGH RISK",
			Summary: fmt.Sprintf("%d package%s with HIGH supply chain compromise risk", r.stats.HighRisk, pluralize(r.stats.HighRisk)),
			Explanation: "Patterns matching known supply chain attack vectors, " +
				"weak publisher controls or single points of compromise, " +
				"missing build integrity verification.",
			Examples: highPkgs,
		})
	}

	// Missing source code
	var missingSource int
	var missingSourcePkgs []string
	for _, result := range r.results {
		if !result.SourceCodeAvailable && result.RiskLevel != "LOW" {
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

// formatDownloads formats a download count with K/M/B suffixes for readability.
func formatDownloads(count int64) string {
	switch {
	case count >= 1_000_000_000:
		return fmt.Sprintf("%.1fB", float64(count)/1_000_000_000)
	case count >= 1_000_000:
		return fmt.Sprintf("%.1fM", float64(count)/1_000_000)
	case count >= 1_000:
		return fmt.Sprintf("%.1fK", float64(count)/1_000)
	default:
		return fmt.Sprintf("%d", count)
	}
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

// gradientStop defines an RGB color at a specific score value for gradient interpolation.
type gradientStop struct {
	score    int
	r, g, b int
}

// scoreGradientStops defines the color gradient from green (low risk) to red (high risk).
// Colors are chosen to match the existing theme palette where possible.
var scoreGradientStops = []gradientStop{
	{0, 82, 183, 136},   // forest green #52b788 (matches theme)
	{5, 132, 204, 22},   // lime/yellow-green
	{10, 245, 158, 11},  // amber #f59e0b (matches theme)
	{15, 249, 115, 22},  // orange #f97316
	{20, 239, 68, 68},   // red #ef4444 (matches theme)
}

// scoreGradientRGB returns interpolated RGB values for a score in the 0-20 range.
func scoreGradientRGB(score int) (int, int, int) {
	if score <= 0 {
		s := scoreGradientStops[0]
		return s.r, s.g, s.b
	}
	last := scoreGradientStops[len(scoreGradientStops)-1]
	if score >= last.score {
		return last.r, last.g, last.b
	}
	for i := 1; i < len(scoreGradientStops); i++ {
		if score <= scoreGradientStops[i].score {
			lo := scoreGradientStops[i-1]
			hi := scoreGradientStops[i]
			t := float64(score-lo.score) / float64(hi.score-lo.score)
			r := int(float64(lo.r) + t*float64(hi.r-lo.r))
			g := int(float64(lo.g) + t*float64(hi.g-lo.g))
			b := int(float64(lo.b) + t*float64(hi.b-lo.b))
			return r, g, b
		}
	}
	return last.r, last.g, last.b
}

// scoreColor returns a truecolor ANSI escape for the score's position on the gradient.
func scoreColor(score int) string {
	r, g, b := scoreGradientRGB(score)
	return fmt.Sprintf("\033[38;2;%d;%d;%dm", r, g, b)
}

// scoreColorCSS returns a CSS rgb() color string for the score's position on the gradient.
func scoreColorCSS(score int) string {
	r, g, b := scoreGradientRGB(score)
	return fmt.Sprintf("rgb(%d,%d,%d)", r, g, b)
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

// sortedResults returns a copy of results sorted by risk score descending.
// Packages with higher supply chain risk scores appear first. When scores
// are equal, packages are sorted by risk level (HIGH > MEDIUM > LOW).
// Findings within each package are also sorted by severity descending.
func (r *Reporter) sortedResults() []models.AnalysisResult {
	sorted := make([]models.AnalysisResult, len(r.results))
	copy(sorted, r.results)

	// Sort packages by risk score descending
	sort.SliceStable(sorted, func(i, j int) bool {
		si, sj := 0, 0
		if sorted[i].SupplyChainScore != nil {
			si = sorted[i].SupplyChainScore.TotalScore
		}
		if sorted[j].SupplyChainScore != nil {
			sj = sorted[j].SupplyChainScore.TotalScore
		}
		if si != sj {
			return si > sj
		}
		return riskOrdinal(sorted[i].RiskLevel) > riskOrdinal(sorted[j].RiskLevel)
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

func riskColor(level string) string {
	switch level {
	case "HIGH":
		return ColorRed
	case "MEDIUM":
		return ColorYellow
	case "LOW":
		return ColorGreen
	default:
		return ColorReset
	}
}

func riskIcon(level string) string {
	switch level {
	case "HIGH":
		return "🔴"
	case "MEDIUM":
		return "🟡"
	case "LOW":
		return "🟢"
	default:
		return "⚪"
	}
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

func calculateOverallRisk(stats ScanStats) string {
	if stats.TotalPackages == 0 {
		return "UNKNOWN"
	}
	highPct := float64(stats.HighRisk) / float64(stats.TotalPackages)
	mediumPct := float64(stats.MediumRisk) / float64(stats.TotalPackages)
	if highPct > 0.3 {
		return "HIGH"
	}
	if highPct > 0 || mediumPct > 0.5 {
		return "MEDIUM"
	}
	return "LOW"
}

// maxScore returns the max score for a supply chain score, with backward compatibility.
func maxScore(sc *models.SupplyChainScore) int {
	if sc.MaxScore > 0 {
		return sc.MaxScore
	}
	return 22
}

