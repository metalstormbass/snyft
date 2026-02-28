package report

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/metalstormbass/snyft/pkg/models"
)

// Box drawing characters
const (
	BoxTopLeft     = "┌"
	BoxTopRight    = "┐"
	BoxBottomLeft  = "└"
	BoxBottomRight = "┘"
	BoxHorizontal  = "─"
	BoxVertical    = "│"
	BoxTeeLeft     = "├"
	BoxTeeRight    = "┤"
)

func (r *Reporter) generateText() error {
	w := r.config.Writer

	r.printHeader(w)
	r.printExecutiveSummary(w)

	if !r.config.Verbose {
		r.printFormatHint(w)
		return nil
	}

	p(w, "")
	r.printSectionHeader(w, "DETAILED FINDINGS")
	p(w, "")

	for _, result := range r.results {
		r.printPackageResult(w, result)
	}

	r.printRiskSummary(w)
	return nil
}

// --- sections ---

func (r *Reporter) printHeader(w io.Writer) {
	width := 80
	title := " SNYFT SUPPLY CHAIN SECURITY REPORT "
	timestamp := " Generated: " + time.Now().Format("2006-01-02 15:04:05") + " "
	border := strings.Repeat(BoxHorizontal, width-2)

	f(w, "%s%s%s%s%s\n", ColorBold+ColorCyan, BoxTopLeft, border, BoxTopRight, ColorReset)
	f(w, "%s%s%s%s%s\n", ColorBold+ColorCyan+BoxVertical, centerText(title, width-2), BoxVertical, ColorReset, "")
	f(w, "%s%s%s%s%s\n", ColorCyan+BoxVertical, centerText(timestamp, width-2), BoxVertical, ColorReset, "")
	f(w, "%s%s%s%s%s\n", ColorCyan, BoxBottomLeft, border, BoxBottomRight, ColorReset)
}

func (r *Reporter) printExecutiveSummary(w io.Writer) {
	p(w, "")
	r.printSectionHeader(w, "EXECUTIVE SUMMARY")
	p(w, "")

	// Brief description
	f(w, "  %sSupply Chain Risk Assessment%s\n", ColorBold, ColorReset)
	p(w, "  Evaluates compromise likelihood through supply chain attacks—NOT known CVEs.")
	p(w, "")

	// Scan overview
	f(w, "  %sPackages Scanned:%s  %d\n", ColorBold, ColorReset, r.stats.TotalPackages)
	if r.stats.DirectDeps > 0 || r.stats.TransitiveDeps > 0 {
		f(w, "  %sDirect / Transitive:%s %d / %d\n", ColorBold, ColorReset, r.stats.DirectDeps, r.stats.TransitiveDeps)
	}
	f(w, "  %sManifest Files:%s    %d\n", ColorBold, ColorReset, r.stats.ManifestFiles)
	f(w, "  %sScan Path:%s         %s\n", ColorBold, ColorReset, r.stats.ScannedPath)
	p(w, "")

	// Risk distribution - compact table
	f(w, "  %sRisk Distribution:%s\n", ColorBold, ColorReset)
	r.printRiskLine(w, "HIGH", r.stats.HighRisk)
	r.printRiskLine(w, "MEDIUM", r.stats.MediumRisk)
	r.printRiskLine(w, "LOW", r.stats.LowRisk)
	p(w, "")

	// Overall risk + duration
	overall := calculateOverallRisk(r.stats)
	duration := r.stats.EndTime.Sub(r.stats.StartTime)
	f(w, "  %sOverall Risk:%s %s%s%s", ColorBold, ColorReset, riskColor(overall)+ColorBold, overall, ColorReset)
	f(w, "    %sDuration:%s %s\n", ColorBold, ColorReset, formatDuration(duration))

	// Alerts
	if r.stats.HighRisk > 0 {
		p(w, "")
		f(w, "  %s⚠  %d HIGH risk package%s — immediate review recommended%s\n",
			ColorRed+ColorBold, r.stats.HighRisk, pluralize(r.stats.HighRisk), ColorReset)
	}
	if r.stats.MediumRisk > 0 {
		if r.stats.HighRisk == 0 {
			p(w, "")
		}
		f(w, "  %s⚠  %d MEDIUM risk package%s — monitoring recommended%s\n",
			ColorYellow+ColorBold, r.stats.MediumRisk, pluralize(r.stats.MediumRisk), ColorReset)
	}

	// Top priority findings
	criticalIssues := r.extractCriticalIssues(5)
	if len(criticalIssues) > 0 {
		p(w, "")
		f(w, "  %sTop Priority Findings:%s\n", ColorBold, ColorReset)
		p(w, "")

		for i, issue := range criticalIssues {
			ic := riskColor(issue.RiskLevel)
			f(w, "    %s%d.%s %s%s@%s%s (%s)\n",
				ColorBold, i+1, ColorReset,
				ic+ColorBold, issue.PackageName, issue.PackageVersion, ColorReset,
				issue.Ecosystem)
			f(w, "       %s[%s]%s %s\n",
				severityColor(issue.Severity), issue.Severity, ColorReset,
				issue.Description)
			if issue.Evidence != "" {
				f(w, "       %sEvidence:%s %s\n", ColorDim, ColorReset, issue.Evidence)
			}
			if i < len(criticalIssues)-1 {
				p(w, "")
			}
		}
	}
}

func (r *Reporter) printRiskLine(w io.Writer, level string, count int) {
	c := riskColor(level)
	label := fmt.Sprintf("%-6s", level)
	pct := ""
	if count > 0 && r.stats.TotalPackages > 0 {
		pct = fmt.Sprintf(" (%.0f%%)", float64(count)/float64(r.stats.TotalPackages)*100)
	}
	f(w, "    %s●%s %s  %s%3d%s%s\n", c, ColorReset, label, c, count, pct, ColorReset)
}

func (r *Reporter) printFormatHint(w io.Writer) {
	scanPath := r.stats.ScannedPath
	if scanPath == "" {
		scanPath = "<path>"
	}

	p(w, "")
	f(w, "  %s%s%s\n", ColorDim, strings.Repeat("─", 78), ColorReset)
	p(w, "")
	f(w, "  %sDetailed report:%s  snyft scan %s -v\n", ColorBold, ColorReset, scanPath)
	f(w, "  %sExport:%s          snyft scan %s -f html -o report.html\n", ColorBold, ColorReset, scanPath)
	p(w, "")
}

func (r *Reporter) printPackageResult(w io.Writer, result models.AnalysisResult) {
	rc := riskColor(result.RiskLevel)
	icon := riskIcon(result.RiskLevel)

	transitiveLabel := ""
	if result.Dependency.IsTransitive {
		transitiveLabel = fmt.Sprintf(" %s(transitive)%s", ColorDim, ColorReset)
	}

	// Package header
	f(w, "%s %s┌%s %s%s@%s%s (%s)%s\n",
		icon, rc, strings.Repeat("─", 68),
		ColorBold, result.Dependency.Name, result.Dependency.Version, ColorReset,
		result.Dependency.Ecosystem, transitiveLabel)

	f(w, "%s│%s  Risk: %s%s%s", rc, ColorReset, rc+ColorBold, result.RiskLevel, ColorReset)

	// Supply chain score inline
	if result.SupplyChainScore != nil {
		ms := maxScore(result.SupplyChainScore)
		f(w, "    Score: %d/%d", result.SupplyChainScore.TotalScore, ms)
	}
	p(w, "")

	// Key metadata on one line
	var meta []string
	if result.RepositoryURL != "" {
		meta = append(meta, "Repo: "+result.RepositoryURL)
	}
	meta = append(meta, "Source: "+formatBool(result.SourceCodeAvailable))
	if result.BuildInfrastructure != "" {
		meta = append(meta, "Build: "+result.BuildInfrastructure)
	}
	for _, m := range meta {
		f(w, "%s│%s  %s\n", rc, ColorReset, m)
	}

	if result.Metadata.HasSelfHosted {
		f(w, "%s│%s  %s⚠  Self-hosted runners detected%s\n",
			rc, ColorReset, ColorRed+ColorBold, ColorReset)
	}

	// Category scores table (verbose)
	if r.config.Verbose && result.SupplyChainScore != nil {
		f(w, "%s│%s\n", rc, ColorReset)
		r.printCategoryScoreTable(w, result.SupplyChainScore.CategoryScores, rc)
	}

	// Findings
	if len(result.Findings) > 0 {
		f(w, "%s│%s\n", rc, ColorReset)
		f(w, "%s│%s  %sFindings:%s\n", rc, ColorReset, ColorBold, ColorReset)
		for _, finding := range result.Findings {
			sc := severityColor(finding.Severity)
			f(w, "%s│%s    %s[%s]%s %s\n", rc, ColorReset, sc, finding.Severity, ColorReset, finding.Description)
			if finding.SourceURL != "" {
				f(w, "%s│%s      %sSource:%s %s\n", rc, ColorReset, ColorDim, ColorReset, finding.SourceURL)
			}
			if finding.Evidence != "" && r.config.Verbose {
				f(w, "%s│%s      %sEvidence:%s %s\n", rc, ColorReset, ColorDim, ColorReset, finding.Evidence)
			}
			if finding.Methodology != "" && r.config.Verbose {
				f(w, "%s│%s      %sMethod:%s %s\n", rc, ColorReset, ColorDim, ColorReset, finding.Methodology)
			}
		}
	}

	f(w, "%s└%s\n", rc, strings.Repeat("─", 76)+ColorReset)
	p(w, "")
}

func (r *Reporter) printCategoryScoreTable(w io.Writer, scores models.CategoryScores, bc string) {
	categories := categoryList(scores)

	f(w, "%s│%s    %-20s  %5s  %4s  %s\n", bc, ColorReset, "Category", "Score", "Risk", "Status")
	f(w, "%s│%s    %s\n", bc, ColorReset, strings.Repeat("─", 50))

	for _, cat := range categories {
		if cat.Score.Skipped {
			f(w, "%s│%s    %-20s  %5s  %s○%s   %sSKIP%s\n",
				bc, ColorReset, cat.Name, "  - ", ColorDim, ColorReset, ColorDim, ColorReset)
			continue
		}

		icon := scoreIcon(cat.Score.RiskPoints)
		verified := "✓"
		if !cat.Score.Verified {
			verified = "?"
		}
		f(w, "%s│%s    %-20s  %s  %s   %s\n",
			bc, ColorReset, cat.Name, fmt.Sprintf("%d/2", cat.Score.Score), icon, verified)

		if r.config.Verbose && cat.Score.Description != "" {
			f(w, "%s│%s      %s%s%s\n", bc, ColorReset, ColorDim, cat.Score.Description, ColorReset)
		}
		if r.config.Verbose {
			for _, check := range cat.Score.ChecksPerformed {
				si := checkStatusIcon(check.Status)
				f(w, "%s│%s      %s  %s %s: %s%s\n",
					bc, ColorReset, ColorDim, si, check.Name, check.Detail, ColorReset)
			}
		}
	}
}

func (r *Reporter) printRiskSummary(w io.Writer) {
	p(w, "")
	r.printSectionHeader(w, "KEY RISK AREAS")
	p(w, "")

	areas := r.generateRiskAreas()
	if len(areas) == 0 {
		f(w, "  %s✓%s No critical supply chain risk factors identified.\n", ColorGreen, ColorReset)
		return
	}

	for i, area := range areas {
		tag := fmt.Sprintf("%s[%s]%s", ColorRed+ColorBold, area.Tag, ColorReset)
		if area.Tag != "HIGH RISK" {
			tag = fmt.Sprintf("%s[%s]%s", ColorYellow+ColorBold, area.Tag, ColorReset)
		}
		f(w, "  %s%d.%s %s %s\n", ColorBold, i+1, ColorReset, tag, area.Summary)
		f(w, "     %s%s%s\n", ColorDim, area.Explanation, ColorReset)
		if area.Examples != "" {
			f(w, "     %sAffected:%s %s\n", ColorDim, ColorReset, area.Examples)
		}
		p(w, "")
	}
}

func (r *Reporter) printSectionHeader(w io.Writer, title string) {
	width := 80
	pad := strings.Repeat("─", (width-len(title)-2)/2)
	f(w, "%s%s %s %s%s\n", ColorBold+ColorCyan, pad, title, pad, ColorReset)
}

// --- small helpers ---

func scoreIcon(riskPoints int) string {
	switch riskPoints {
	case 0:
		return ColorGreen + "●" + ColorReset
	case 1:
		return ColorYellow + "●" + ColorReset
	case 2:
		return ColorRed + "●" + ColorReset
	default:
		return "○"
	}
}

func checkStatusIcon(status string) string {
	switch status {
	case "PASS":
		return ColorGreen + "✓" + ColorReset
	case "FAIL":
		return ColorRed + "✗" + ColorReset
	case "SKIPPED":
		return ColorDim + "○" + ColorReset
	case "UNAVAILABLE":
		return ColorYellow + "?" + ColorReset
	default:
		return "·"
	}
}

// Shorthand writers to reduce noise in format functions.
func f(w io.Writer, format string, a ...interface{}) {
	_, _ = fmt.Fprintf(w, format, a...)
}

func p(w io.Writer, s string) {
	_, _ = fmt.Fprintln(w, s)
}
