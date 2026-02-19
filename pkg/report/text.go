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

	// AI Executive Summary (if available from any package)
	r.printAIExecutiveSummary(w)
}

// printAIExecutiveSummary prints AI-powered executive insights if available
func (r *Reporter) printAIExecutiveSummary(w io.Writer) {
	// Find the first package with AI analysis that has an executive summary
	var executiveSummary *models.ExecutiveExplanation
	for _, result := range r.results {
		if result.AIAnalysis != nil && result.AIAnalysis.ExecutiveSummary != nil {
			executiveSummary = result.AIAnalysis.ExecutiveSummary
			break
		}
	}

	if executiveSummary == nil {
		return
	}

	fmt.Fprintln(w)
	fmt.Fprintf(w, "  %s🤖 AI-Powered Risk Assessment%s\n", ColorBold+ColorCyan, ColorReset)
	fmt.Fprintln(w)

	// Summary
	fmt.Fprintf(w, "  %s%s%s\n", ColorBold, executiveSummary.Summary, ColorReset)
	fmt.Fprintln(w)

	// Key Risks
	if len(executiveSummary.KeyRisks) > 0 {
		fmt.Fprintf(w, "  %sKey Risks Identified:%s\n", ColorBold, ColorReset)
		for _, risk := range executiveSummary.KeyRisks {
			fmt.Fprintf(w, "    %s•%s %s\n", ColorRed, ColorReset, risk)
		}
		fmt.Fprintln(w)
	}

	// Business Impact
	if executiveSummary.BusinessImpact != "" {
		fmt.Fprintf(w, "  %sBusiness Impact:%s\n", ColorBold, ColorReset)
		fmt.Fprintf(w, "  %s\n", executiveSummary.BusinessImpact)
		fmt.Fprintln(w)
	}

	// Recommended Action
	if executiveSummary.RecommendedAction != "" {
		fmt.Fprintf(w, "  %sRecommended Action:%s\n", ColorBold, ColorReset)
		fmt.Fprintf(w, "  %s\n", executiveSummary.RecommendedAction)
		fmt.Fprintln(w)
	}

	// Confidence
	confidencePct := executiveSummary.Confidence * 100
	confidenceColor := ColorGreen
	if confidencePct < 50 {
		confidenceColor = ColorYellow
	}
	fmt.Fprintf(w, "  %sAI Confidence:%s %s%.0f%%%s\n",
		ColorBold, ColorReset, confidenceColor, confidencePct, ColorReset)
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

	_, _ = fmt.Fprintf(w, "%s%s┌%s Package: %s%s@%s%s (%s)\n",
		riskColor,
		riskIcon,
		strings.Repeat("─", 70),
		ColorBold,
		result.Dependency.Name,
		result.Dependency.Version,
		ColorReset,
		result.Dependency.Ecosystem)

	_, _ = fmt.Fprintf(w, "%s│%s\n", riskColor, ColorReset)

	// Risk level badge
	_, _ = fmt.Fprintf(w, "%s│%s  %sRisk Level:%s %s%s%s\n",
		riskColor, ColorReset,
		ColorBold, ColorReset,
		riskColor+ColorBold, result.RiskLevel, ColorReset)

	// Supply chain score if available
	if result.SupplyChainScore != nil {
		_, _ = fmt.Fprintf(w, "%s│%s  %sSupply Chain Score:%s %d/20 points (%s%s%s risk)\n",
			riskColor, ColorReset,
			ColorBold, ColorReset,
			result.SupplyChainScore.TotalScore,
			r.getRiskColor(result.SupplyChainScore.RiskLevel),
			result.SupplyChainScore.RiskLevel,
			ColorReset)
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

			if i < len(result.Findings)-1 {
				_, _ = fmt.Fprintf(w, "%s│%s\n", riskColor, ColorReset)
			}
		}
	}

	// AI Analysis (if available)
	if result.AIAnalysis != nil {
		r.printPackageAIAnalysis(w, result.AIAnalysis, riskColor)
	}

	_, _ = fmt.Fprintf(w, "%s└%s\n", riskColor, strings.Repeat("─", 76)+ColorReset)
	_, _ = fmt.Fprintln(w)
}

// printPackageAIAnalysis prints AI analysis results for a package
func (r *Reporter) printPackageAIAnalysis(w io.Writer, aiAnalysis *models.AIAnalysisResult, borderColor string) {
	if aiAnalysis == nil {
		return
	}

	// Attack Pattern Matches
	if len(aiAnalysis.AttackPatterns) > 0 {
		_, _ = fmt.Fprintf(w, "%s│%s\n", borderColor, ColorReset)
		_, _ = fmt.Fprintf(w, "%s│%s  %s🤖 AI-Detected Attack Patterns:%s\n",
			borderColor, ColorReset,
			ColorBold+ColorCyan, ColorReset)

		for i, pattern := range aiAnalysis.AttackPatterns {
			sevColor := r.getSeverityColor(pattern.Severity)
			_, _ = fmt.Fprintf(w, "%s│%s    %s[%s]%s %s\n",
				borderColor, ColorReset,
				sevColor, pattern.Severity, ColorReset,
				pattern.PatternName)

			if pattern.Description != "" && r.config.Verbose {
				_, _ = fmt.Fprintf(w, "%s│%s       %s%s%s\n",
					borderColor, ColorReset,
					ColorDim, pattern.Description, ColorReset)
			}

			// Show confidence
			confidencePct := pattern.Confidence * 100
			_, _ = fmt.Fprintf(w, "%s│%s       %sConfidence: %.0f%%%s\n",
				borderColor, ColorReset,
				ColorDim, confidencePct, ColorReset)

			// Always show academic source for AI findings - required for traceability
			if pattern.AcademicSource != "" {
				_, _ = fmt.Fprintf(w, "%s│%s       %sSource: %s%s\n",
					borderColor, ColorReset,
					ColorDim, pattern.AcademicSource, ColorReset)
			}

			// Show evidence in verbose mode
			if r.config.Verbose && len(pattern.Evidence) > 0 {
				_, _ = fmt.Fprintf(w, "%s│%s       %sEvidence:%s\n",
					borderColor, ColorReset,
					ColorDim, ColorReset)
				for _, evidence := range pattern.Evidence {
					_, _ = fmt.Fprintf(w, "%s│%s         %s• %s%s\n",
						borderColor, ColorReset,
						ColorDim, evidence, ColorReset)
				}
			}

			// Show mitigation advice if available
			if pattern.MitigationAdvice != "" && r.config.Verbose {
				_, _ = fmt.Fprintf(w, "%s│%s       %sMitigation: %s%s\n",
					borderColor, ColorReset,
					ColorDim+ColorGreen, pattern.MitigationAdvice, ColorReset)
			}

			if i < len(aiAnalysis.AttackPatterns)-1 {
				_, _ = fmt.Fprintf(w, "%s│%s\n", borderColor, ColorReset)
			}
		}
	}

	// AI Analysis Notes
	if aiAnalysis.AnalysisNotes != "" && r.config.Verbose {
		_, _ = fmt.Fprintf(w, "%s│%s\n", borderColor, ColorReset)
		_, _ = fmt.Fprintf(w, "%s│%s  %s🤖 AI Analysis Notes:%s\n",
			borderColor, ColorReset,
			ColorBold+ColorCyan, ColorReset)
		_, _ = fmt.Fprintf(w, "%s│%s  %s%s%s\n",
			borderColor, ColorReset,
			ColorDim, aiAnalysis.AnalysisNotes, ColorReset)
	}
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
