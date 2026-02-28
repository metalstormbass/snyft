package report

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/metalstormbass/snyft/pkg/models"
)

// ANSI color codes
const (
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorYellow = "\033[33m"
	ColorGreen  = "\033[32m"
	ColorCyan   = "\033[36m"
	ColorBold   = "\033[1m"
	ColorDim    = "\033[2m"
)

// Box drawing characters
const (
	BoxTopLeft     = "┌"
	BoxTopRight    = "┓"
	BoxBottomLeft  = "└"
	BoxBottomRight = "┘"
	BoxHorizontal  = "─"
	BoxVertical    = "│"
	BoxTeeLeft     = "├"
	BoxTeeRight    = "┤"
)

// generateText generates a text report with professional formatting
func (r *Reporter) generateText() error {
	w := r.config.Writer

	// Header
	r.printHeader(w)

	// Executive Summary
	r.printExecutiveSummary(w)

	if !r.config.Verbose {
		// Summary-only mode: show header + executive summary + format hint
		r.printFormatHint(w)
		return nil
	}

	// Detailed Findings
	_, _ = fmt.Fprintln(w)
	r.printSectionHeader(w, "DETAILED FINDINGS")
	_, _ = fmt.Fprintln(w)

	for _, result := range r.results {
		r.printPackageResult(w, result)
	}

	// Risk Summary
	r.printRiskSummary(w)

	return nil
}

// printFormatHint prints guidance on how to get more detailed output
func (r *Reporter) printFormatHint(w io.Writer) {
	scanPath := r.stats.ScannedPath
	if scanPath == "" {
		scanPath = "<path>"
	}

	_, _ = fmt.Fprintln(w)
	_, _ = fmt.Fprintf(w, "%s%s%s\n", ColorDim, strings.Repeat("─", 78), ColorReset)
	_, _ = fmt.Fprintln(w)
	_, _ = fmt.Fprintf(w, "  %sFor the full detailed report:%s\n", ColorBold, ColorReset)
	_, _ = fmt.Fprintf(w, "    snyft scan %s -v\n", scanPath)
	_, _ = fmt.Fprintln(w)
	_, _ = fmt.Fprintf(w, "  %sExport formats:%s\n", ColorBold, ColorReset)
	_, _ = fmt.Fprintf(w, "    snyft scan %s -f html -o report.html\n", scanPath)
	_, _ = fmt.Fprintf(w, "    snyft scan %s -f json -o report.json\n", scanPath)
	_, _ = fmt.Fprintf(w, "    snyft scan %s -f markdown -o report.md\n", scanPath)
	_, _ = fmt.Fprintln(w)
}

// printHeader prints the report header
func (r *Reporter) printHeader(w io.Writer) {
	width := 80
	title := " SNYFT SUPPLY CHAIN SECURITY REPORT "
	timestamp := " Generated: " + time.Now().Format("2006-01-02 15:04:05") + " "

	_, _ = fmt.Fprintf(w, "%s%s%s%s%s\n",
		ColorBold+ColorCyan,
		BoxTopLeft,
		strings.Repeat(BoxHorizontal, width-2),
		BoxTopRight,
		ColorReset)

	_, _ = fmt.Fprintf(w, "%s%s%s%s%s\n",
		ColorBold+ColorCyan+BoxVertical,
		centerText(title, width-2),
		BoxVertical,
		ColorReset,
		"")

	_, _ = fmt.Fprintf(w, "%s%s%s%s%s\n",
		ColorCyan+BoxVertical,
		centerText(timestamp, width-2),
		BoxVertical,
		ColorReset,
		"")

	_, _ = fmt.Fprintf(w, "%s%s%s%s%s\n",
		ColorCyan,
		BoxBottomLeft,
		strings.Repeat(BoxHorizontal, width-2),
		BoxBottomRight,
		ColorReset)
}

// printExecutiveSummary prints the executive summary section
func (r *Reporter) printExecutiveSummary(w io.Writer) {
	_, _ = fmt.Fprintln(w)
	r.printSectionHeader(w, "EXECUTIVE SUMMARY")
	_, _ = fmt.Fprintln(w)

	// Risk Assessment Overview
	_, _ = fmt.Fprintf(w, "  %sSupply Chain Risk Assessment%s\n", ColorBold, ColorReset)
	_, _ = fmt.Fprintln(w, "  This report evaluates the likelihood that software packages could be")
	_, _ = fmt.Fprintln(w, "  compromised through supply chain attacks. It assesses risk factors such")
	_, _ = fmt.Fprintln(w, "  as maintainer practices, ownership changes, and build integrity—NOT known")
	_, _ = fmt.Fprintln(w, "  CVEs or code vulnerabilities.")
	_, _ = fmt.Fprintln(w)

	// Calculate overall risk level
	overallRisk := r.calculateOverallRisk()

	// Summary box
	_, _ = fmt.Fprintf(w, "%s  Total Packages Scanned:%s %d\n", ColorBold, ColorReset, r.stats.TotalPackages)
	if r.stats.DirectDeps > 0 || r.stats.TransitiveDeps > 0 {
		_, _ = fmt.Fprintf(w, "%s  Direct Dependencies:%s    %d\n", ColorBold, ColorReset, r.stats.DirectDeps)
		_, _ = fmt.Fprintf(w, "%s  Transitive Dependencies:%s %d\n", ColorBold, ColorReset, r.stats.TransitiveDeps)
	}
	_, _ = fmt.Fprintf(w, "%s  Manifest Files Found:%s   %d\n", ColorBold, ColorReset, r.stats.ManifestFiles)
	_, _ = fmt.Fprintf(w, "%s  Scan Path:%s             %s\n", ColorBold, ColorReset, r.stats.ScannedPath)
	_, _ = fmt.Fprintln(w)

	// Risk distribution with colors
	_, _ = fmt.Fprintf(w, "  %sRisk Distribution:%s\n", ColorBold, ColorReset)
	_, _ = fmt.Fprintf(w, "    %s●%s HIGH Risk:   %s%3d packages%s ", ColorRed, ColorReset, ColorRed, r.stats.HighRisk, ColorReset)
	if r.stats.HighRisk > 0 {
		_, _ = fmt.Fprintf(w, "(%s%.1f%%%s)", ColorRed, float64(r.stats.HighRisk)/float64(r.stats.TotalPackages)*100, ColorReset)
	}
	_, _ = fmt.Fprintln(w)

	_, _ = fmt.Fprintf(w, "    %s●%s MEDIUM Risk: %s%3d packages%s ", ColorYellow, ColorReset, ColorYellow, r.stats.MediumRisk, ColorReset)
	if r.stats.MediumRisk > 0 {
		_, _ = fmt.Fprintf(w, "(%s%.1f%%%s)", ColorYellow, float64(r.stats.MediumRisk)/float64(r.stats.TotalPackages)*100, ColorReset)
	}
	_, _ = fmt.Fprintln(w)

	_, _ = fmt.Fprintf(w, "    %s●%s LOW Risk:    %s%3d packages%s ", ColorGreen, ColorReset, ColorGreen, r.stats.LowRisk, ColorReset)
	if r.stats.LowRisk > 0 {
		_, _ = fmt.Fprintf(w, "(%s%.1f%%%s)", ColorGreen, float64(r.stats.LowRisk)/float64(r.stats.TotalPackages)*100, ColorReset)
	}
	_, _ = fmt.Fprintln(w)
	_, _ = fmt.Fprintln(w)

	// Overall risk assessment
	riskColor := ColorGreen
	switch overallRisk {
	case "HIGH":
		riskColor = ColorRed
	case "MEDIUM":
		riskColor = ColorYellow
	}
	_, _ = fmt.Fprintf(w, "  %sOverall Risk Level:%s %s%s%s\n", ColorBold, ColorReset, riskColor+ColorBold, overallRisk, ColorReset)

	// Performance stats
	duration := r.stats.EndTime.Sub(r.stats.StartTime)
	_, _ = fmt.Fprintf(w, "  %sScan Duration:%s      %s\n", ColorBold, ColorReset, formatDuration(duration))
	if r.stats.TotalPackages > 0 {
		avgTime := duration / time.Duration(r.stats.TotalPackages)
		_, _ = fmt.Fprintf(w, "  %sAverage per Package:%s %s\n", ColorBold, ColorReset, formatDuration(avgTime))
	}

	// Risk Impact Summary
	if r.stats.HighRisk > 0 || r.stats.MediumRisk > 0 {
		_, _ = fmt.Fprintln(w)
		_, _ = fmt.Fprintf(w, "  %sRisk Impact Summary:%s\n", ColorBold, ColorReset)
		if r.stats.HighRisk > 0 {
			_, _ = fmt.Fprintf(w, "  %s⚠  ATTENTION REQUIRED:%s %d package%s identified with HIGH supply chain risk.\n",
				ColorRed+ColorBold, ColorReset, r.stats.HighRisk, pluralize(r.stats.HighRisk))
			_, _ = fmt.Fprintln(w, "     These packages exhibit patterns commonly associated with compromised")
			_, _ = fmt.Fprintln(w, "     dependencies and require immediate review.")
		}
		if r.stats.MediumRisk > 0 {
			_, _ = fmt.Fprintf(w, "  %s⚠  MONITORING RECOMMENDED:%s %d package%s with MEDIUM risk factors.\n",
				ColorYellow+ColorBold, ColorReset, r.stats.MediumRisk, pluralize(r.stats.MediumRisk))
			_, _ = fmt.Fprintln(w, "     These packages show some concerning patterns that warrant closer monitoring.")
		}
	}

	// Key Findings - Critical Issues
	criticalIssues := r.extractCriticalIssues(5)
	if len(criticalIssues) > 0 {
		_, _ = fmt.Fprintln(w)
		_, _ = fmt.Fprintf(w, "  %sTop Priority Findings:%s\n", ColorBold, ColorReset)
		_, _ = fmt.Fprintln(w, "  The following issues represent the highest supply chain compromise risks:")
		_, _ = fmt.Fprintln(w)

		for i, issue := range criticalIssues {
			issueColor := r.getRiskColor(issue.RiskLevel)
			_, _ = fmt.Fprintf(w, "    %s%d.%s %s%s@%s%s (%s)\n",
				ColorBold, i+1, ColorReset,
				issueColor+ColorBold, issue.PackageName, issue.PackageVersion, ColorReset,
				issue.Ecosystem)
			_, _ = fmt.Fprintf(w, "       %s[%s SEVERITY]%s %s\n",
				r.getSeverityColor(issue.Severity), issue.Severity, ColorReset,
				issue.Description)
			if issue.Evidence != "" {
				_, _ = fmt.Fprintf(w, "       %sEvidence:%s %s\n",
					ColorDim, ColorReset, issue.Evidence)
			}
			// Add impact context
			impact := r.getRiskImpactDescription(issue.Severity)
			if impact != "" {
				_, _ = fmt.Fprintf(w, "       %sImpact:%s %s\n",
					ColorDim, ColorReset, impact)
			}
			if i < len(criticalIssues)-1 {
				_, _ = fmt.Fprintln(w)
			}
		}
	}

}

// printSectionHeader prints a section header
func (r *Reporter) printSectionHeader(w io.Writer, title string) {
	width := 80
	_, _ = fmt.Fprintf(w, "%s%s%s%s\n",
		ColorBold+ColorCyan,
		strings.Repeat("─", (width-len(title)-2)/2),
		" "+title+" ",
		strings.Repeat("─", (width-len(title)-2)/2)+ColorReset)
}

// printPackageResult prints a single package analysis result
func (r *Reporter) printPackageResult(w io.Writer, result models.AnalysisResult) {
	// Package header with risk indicator
	riskColor := r.getRiskColor(result.RiskLevel)
	riskIcon := r.getRiskIcon(result.RiskLevel)

	transitiveLabel := ""
	if result.Dependency.IsTransitive {
		transitiveLabel = fmt.Sprintf(" %s(transitive)%s", ColorDim, ColorReset)
	}

	_, _ = fmt.Fprintf(w, "%s%s┌%s Package: %s%s@%s%s (%s)%s\n",
		riskColor,
		riskIcon,
		strings.Repeat("─", 70),
		ColorBold,
		result.Dependency.Name,
		result.Dependency.Version,
		ColorReset,
		result.Dependency.Ecosystem,
		transitiveLabel)

	_, _ = fmt.Fprintf(w, "%s│%s\n", riskColor, ColorReset)

	// Risk level badge
	_, _ = fmt.Fprintf(w, "%s│%s  %sRisk Level:%s %s%s%s\n",
		riskColor, ColorReset,
		ColorBold, ColorReset,
		riskColor+ColorBold, result.RiskLevel, ColorReset)

	// Supply chain score if available
	if result.SupplyChainScore != nil {
		scoreStr := fmt.Sprintf("%d/22 points (%s%s%s risk)",
			result.SupplyChainScore.TotalScore,
			r.getRiskColor(result.SupplyChainScore.RiskLevel),
			result.SupplyChainScore.RiskLevel,
			ColorReset)

		_, _ = fmt.Fprintf(w, "%s│%s  %sSupply Chain Score:%s %s\n",
			riskColor, ColorReset,
			ColorBold, ColorReset,
			scoreStr)
	}

	// Repository and source info
	if result.RepositoryURL != "" {
		_, _ = fmt.Fprintf(w, "%s│%s  %sRepository:%s %s\n",
			riskColor, ColorReset,
			ColorBold, ColorReset,
			result.RepositoryURL)
	}

	_, _ = fmt.Fprintf(w, "%s│%s  %sSource Available:%s %s\n",
		riskColor, ColorReset,
		ColorBold, ColorReset,
		formatBool(result.SourceCodeAvailable))

	if result.BuildInfrastructure != "" {
		_, _ = fmt.Fprintf(w, "%s│%s  %sBuild Infrastructure:%s %s\n",
			riskColor, ColorReset,
			ColorBold, ColorReset,
			result.BuildInfrastructure)
	}

	// Show self-hosted runner warning prominently
	if result.Metadata.HasSelfHosted {
		_, _ = fmt.Fprintf(w, "%s│%s  %s⚠  Self-hosted runners: build environment not controlled by trusted provider%s\n",
			riskColor, ColorReset,
			ColorRed+ColorBold, ColorReset)
	}

	// Supply chain category scores (in verbose mode)
	if r.config.Verbose && result.SupplyChainScore != nil {
		_, _ = fmt.Fprintf(w, "%s│%s\n", riskColor, ColorReset)
		_, _ = fmt.Fprintf(w, "%s│%s  %sSupply Chain Security Analysis:%s\n",
			riskColor, ColorReset,
			ColorBold, ColorReset)
		_, _ = fmt.Fprintf(w, "%s│%s\n", riskColor, ColorReset)

		r.printCategoryScoreTable(w, result.SupplyChainScore.CategoryScores, riskColor)
	}

	// Findings
	if len(result.Findings) > 0 {
		_, _ = fmt.Fprintf(w, "%s│%s\n", riskColor, ColorReset)
		_, _ = fmt.Fprintf(w, "%s│%s  %sRisk Findings:%s\n",
			riskColor, ColorReset,
			ColorBold, ColorReset)

		for i, finding := range result.Findings {
			sevColor := r.getSeverityColor(finding.Severity)
			_, _ = fmt.Fprintf(w, "%s│%s    %s[%s]%s %s\n",
				riskColor, ColorReset,
				sevColor, finding.Severity, ColorReset,
				finding.Description)

			if finding.Evidence != "" && r.config.Verbose {
				_, _ = fmt.Fprintf(w, "%s│%s       %sEvidence:%s %s\n",
					riskColor, ColorReset,
					ColorDim, ColorReset,
					finding.Evidence)
			}

			if finding.Methodology != "" && r.config.Verbose {
				_, _ = fmt.Fprintf(w, "%s│%s       %sMethodology:%s %s\n",
					riskColor, ColorReset,
					ColorDim, ColorReset,
					finding.Methodology)
			}

			if i < len(result.Findings)-1 {
				_, _ = fmt.Fprintf(w, "%s│%s\n", riskColor, ColorReset)
			}
		}
	}

	_, _ = fmt.Fprintf(w, "%s└%s\n", riskColor, strings.Repeat("─", 76)+ColorReset)
	_, _ = fmt.Fprintln(w)
}

// printCategoryScoreTable prints category scores in a table format
func (r *Reporter) printCategoryScoreTable(w io.Writer, scores models.CategoryScores, borderColor string) {
	categories := []struct {
		name  string
		score models.CategoryScore
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
		{"CI Pipeline Security", scores.CIPipelineSecurity},
	}

	// Table header
	_, _ = fmt.Fprintf(w, "%s│%s    %-20s  %s  %s  %s\n",
		borderColor, ColorReset,
		"Category", "Score", "Risk", "Status")

	_, _ = fmt.Fprintf(w, "%s│%s    %s\n",
		borderColor, ColorReset,
		strings.Repeat("─", 45))

	// Table rows
	for _, cat := range categories {
		scoreIcon := r.getScoreIcon(cat.score.RiskPoints)
		verifiedIcon := "✓"
		if !cat.score.Verified {
			verifiedIcon = "?"
		}

		_, _ = fmt.Fprintf(w, "%s│%s    %-20s  %s  %s  %s\n",
			borderColor, ColorReset,
			cat.name,
			fmt.Sprintf("%d/2", cat.score.Score),
			scoreIcon,
			verifiedIcon)

		if r.config.Verbose && cat.score.Description != "" {
			_, _ = fmt.Fprintf(w, "%s│%s      %s%s%s\n",
				borderColor, ColorReset,
				ColorDim, cat.score.Description, ColorReset)
		}

		// Show individual sub-checks in verbose mode
		if r.config.Verbose && len(cat.score.ChecksPerformed) > 0 {
			for _, check := range cat.score.ChecksPerformed {
				statusIcon := r.getCheckStatusIcon(check.Status)
				_, _ = fmt.Fprintf(w, "%s│%s      %s  %s %s: %s%s\n",
					borderColor, ColorReset,
					ColorDim, statusIcon, check.Name, check.Detail, ColorReset)
			}
		}
	}
}

// getCheckStatusIcon returns a compact icon for a sub-check status
func (r *Reporter) getCheckStatusIcon(status string) string {
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

// printRiskSummary prints key risk areas based on findings
func (r *Reporter) printRiskSummary(w io.Writer) {
	_, _ = fmt.Fprintln(w)
	r.printSectionHeader(w, "KEY RISK AREAS")
	_, _ = fmt.Fprintln(w)

	riskAreas := r.generateRiskAreas()

	if len(riskAreas) == 0 {
		_, _ = fmt.Fprintf(w, "  %s✓%s No critical supply chain risk factors identified.\n",
			ColorGreen, ColorReset)
		return
	}

	for i, area := range riskAreas {
		_, _ = fmt.Fprintf(w, "  %s%d.%s %s\n", ColorBold, i+1, ColorReset, area)
		_, _ = fmt.Fprintln(w)
	}
}

// Helper functions

func (r *Reporter) getRiskColor(riskLevel string) string {
	switch riskLevel {
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

func (r *Reporter) getRiskIcon(riskLevel string) string {
	switch riskLevel {
	case "HIGH":
		return " 🔴 "
	case "MEDIUM":
		return " 🟡 "
	case "LOW":
		return " 🟢 "
	default:
		return " ⚪ "
	}
}

func (r *Reporter) getSeverityColor(severity string) string {
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

func (r *Reporter) getScoreIcon(riskPoints int) string {
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

func (r *Reporter) generateRiskAreas() []string {
	var areas []string

	// HIGH risk packages
	if r.stats.HighRisk > 0 {
		areas = append(areas, fmt.Sprintf(
			"%s[HIGH RISK]%s %d package%s identified with HIGH supply chain compromise risk.\n"+
				"   %sRisk factors include:%s\n"+
				"   • Patterns matching known supply chain attack vectors\n"+
				"   • Weak publisher controls or single points of compromise\n"+
				"   • Missing build integrity verification",
			ColorRed+ColorBold, ColorReset, r.stats.HighRisk, pluralize(r.stats.HighRisk),
			ColorBold, ColorReset))
	}

	// Missing source code
	missingSource := 0
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
		examplePkgs := ""
		if len(missingSourcePkgs) > 0 {
			examplePkgs = fmt.Sprintf(" (e.g., %s)", strings.Join(missingSourcePkgs, ", "))
		}
		areas = append(areas, fmt.Sprintf(
			"%s[UNVERIFIABLE SOURCE]%s %d package%s lack public source code%s.\n"+
				"   %sRisk:%s Published artifacts cannot be audited or compared to source.\n"+
				"   This prevents independent verification of package contents.",
			ColorYellow+ColorBold, ColorReset, missingSource, pluralize(missingSource), examplePkgs,
			ColorBold, ColorReset))
	}

	// Install-time execution
	installScripts := 0
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
		examplePkgs := ""
		if len(installScriptPkgs) > 0 {
			examplePkgs = fmt.Sprintf(" (e.g., %s)", strings.Join(installScriptPkgs, ", "))
		}
		areas = append(areas, fmt.Sprintf(
			"%s[INSTALL-TIME EXECUTION]%s %d package%s execute code during installation%s.\n"+
				"   %sRisk:%s Install scripts are a primary supply chain attack vector.\n"+
				"   Compromised install scripts can execute arbitrary code before any\n"+
				"   application-level security controls are in place.",
			ColorYellow+ColorBold, ColorReset, installScripts, pluralize(installScripts), examplePkgs,
			ColorBold, ColorReset))
	}

	// Missing provenance
	missingProvenance := 0
	for _, result := range r.results {
		if result.SupplyChainScore != nil && result.SupplyChainScore.CategoryScores.Provenance.RiskPoints > 1 {
			missingProvenance++
		}
	}
	if missingProvenance > 0 {
		areas = append(areas, fmt.Sprintf(
			"%s[MISSING PROVENANCE]%s %d package%s lack build provenance verification.\n"+
				"   %sRisk:%s Without SLSA attestations, Sigstore signatures, or reproducible\n"+
				"   builds, there is no way to verify that published artifacts were produced\n"+
				"   from the claimed source code by a trusted build system.",
			ColorYellow+ColorBold, ColorReset, missingProvenance, pluralize(missingProvenance),
			ColorBold, ColorReset))
	}

	// CI pipeline security issues
	ciRisks := 0
	var ciRiskPkgs []string
	for _, result := range r.results {
		if result.SupplyChainScore != nil && result.SupplyChainScore.CategoryScores.CIPipelineSecurity.RiskPoints > 1 {
			ciRisks++
			if len(ciRiskPkgs) < 3 {
				ciRiskPkgs = append(ciRiskPkgs, result.Dependency.Name)
			}
		}
	}
	if ciRisks > 0 {
		examplePkgs := ""
		if len(ciRiskPkgs) > 0 {
			examplePkgs = fmt.Sprintf(" (e.g., %s)", strings.Join(ciRiskPkgs, ", "))
		}
		areas = append(areas, fmt.Sprintf(
			"%s[CI PIPELINE SECURITY]%s %d package%s have critical CI/CD configuration issues%s.\n"+
				"   %sRisk:%s Insecure CI configurations are a direct supply chain attack vector.\n"+
				"   Unpinned actions can be hijacked, script injection enables remote code execution,\n"+
				"   and self-hosted runners give attackers control over build environments.",
			ColorYellow+ColorBold, ColorReset, ciRisks, pluralize(ciRisks), examplePkgs,
			ColorBold, ColorReset))
	}

	return areas
}

func centerText(text string, width int) string {
	if len(text) >= width {
		return text
	}
	leftPad := (width - len(text)) / 2
	rightPad := width - len(text) - leftPad
	return strings.Repeat(" ", leftPad) + text + strings.Repeat(" ", rightPad)
}

func formatBool(b bool) string {
	if b {
		return ColorGreen + "✓ Yes" + ColorReset
	}
	return ColorRed + "✗ No" + ColorReset
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

func (r *Reporter) getRiskImpactDescription(severity string) string {
	switch severity {
	case "CRITICAL", "HIGH":
		return "If compromised, could lead to full system compromise, data exfiltration, or supply chain contamination"
	case "MEDIUM":
		return "If compromised, could enable lateral movement or unauthorized access to sensitive resources"
	case "LOW":
		return "Limited impact if compromised, but contributes to overall attack surface"
	default:
		return ""
	}
}
