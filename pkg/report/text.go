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
	fmt.Fprintln(w)
	r.printSectionHeader(w, "DETAILED FINDINGS")
	fmt.Fprintln(w)

	for _, result := range r.results {
		r.printPackageResult(w, result)
	}

	// Recommendations
	r.printRecommendations(w)

	return nil
}

// printHeader prints the report header
func (r *Reporter) printHeader(w io.Writer) {
	width := 80
	title := " SNYFT SUPPLY CHAIN SECURITY REPORT "
	timestamp := " Generated: " + time.Now().Format("2006-01-02 15:04:05") + " "

	fmt.Fprintf(w, "%s%s%s%s%s\n",
		ColorBold+ColorCyan,
		BoxTopLeft,
		strings.Repeat(BoxHorizontal, width-2),
		BoxTopRight,
		ColorReset)

	fmt.Fprintf(w, "%s%s%s%s%s\n",
		ColorBold+ColorCyan+BoxVertical,
		centerText(title, width-2),
		BoxVertical,
		ColorReset,
		"")

	fmt.Fprintf(w, "%s%s%s%s%s\n",
		ColorCyan+BoxVertical,
		centerText(timestamp, width-2),
		BoxVertical,
		ColorReset,
		"")

	fmt.Fprintf(w, "%s%s%s%s%s\n",
		ColorCyan,
		BoxBottomLeft,
		strings.Repeat(BoxHorizontal, width-2),
		BoxBottomRight,
		ColorReset)
}

// printExecutiveSummary prints the executive summary section
func (r *Reporter) printExecutiveSummary(w io.Writer) {
	fmt.Fprintln(w)
	r.printSectionHeader(w, "EXECUTIVE SUMMARY")
	fmt.Fprintln(w)

	// Calculate overall risk level
	overallRisk := r.calculateOverallRisk()

	// Summary box
	fmt.Fprintf(w, "%s  Total Packages Scanned:%s %d\n", ColorBold, ColorReset, r.stats.TotalPackages)
	fmt.Fprintf(w, "%s  Manifest Files Found:%s   %d\n", ColorBold, ColorReset, r.stats.ManifestFiles)
	fmt.Fprintf(w, "%s  Scan Path:%s             %s\n", ColorBold, ColorReset, r.stats.ScannedPath)
	fmt.Fprintln(w)

	// Risk distribution with colors
	fmt.Fprintf(w, "  %sRisk Distribution:%s\n", ColorBold, ColorReset)
	fmt.Fprintf(w, "    %s●%s HIGH Risk:   %s%3d packages%s ", ColorRed, ColorReset, ColorRed, r.stats.HighRisk, ColorReset)
	if r.stats.HighRisk > 0 {
		fmt.Fprintf(w, "(%s%.1f%%%s)", ColorRed, float64(r.stats.HighRisk)/float64(r.stats.TotalPackages)*100, ColorReset)
	}
	fmt.Fprintln(w)

	fmt.Fprintf(w, "    %s●%s MEDIUM Risk: %s%3d packages%s ", ColorYellow, ColorReset, ColorYellow, r.stats.MediumRisk, ColorReset)
	if r.stats.MediumRisk > 0 {
		fmt.Fprintf(w, "(%s%.1f%%%s)", ColorYellow, float64(r.stats.MediumRisk)/float64(r.stats.TotalPackages)*100, ColorReset)
	}
	fmt.Fprintln(w)

	fmt.Fprintf(w, "    %s●%s LOW Risk:    %s%3d packages%s ", ColorGreen, ColorReset, ColorGreen, r.stats.LowRisk, ColorReset)
	if r.stats.LowRisk > 0 {
		fmt.Fprintf(w, "(%s%.1f%%%s)", ColorGreen, float64(r.stats.LowRisk)/float64(r.stats.TotalPackages)*100, ColorReset)
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w)

	// Overall risk assessment
	riskColor := ColorGreen
	if overallRisk == "HIGH" {
		riskColor = ColorRed
	} else if overallRisk == "MEDIUM" {
		riskColor = ColorYellow
	}
	fmt.Fprintf(w, "  %sOverall Risk Level:%s %s%s%s\n", ColorBold, ColorReset, riskColor+ColorBold, overallRisk, ColorReset)

	// Performance stats
	duration := r.stats.EndTime.Sub(r.stats.StartTime)
	fmt.Fprintf(w, "  %sScan Duration:%s      %s\n", ColorBold, ColorReset, formatDuration(duration))
	if r.stats.TotalPackages > 0 {
		avgTime := duration / time.Duration(r.stats.TotalPackages)
		fmt.Fprintf(w, "  %sAverage per Package:%s %s\n", ColorBold, ColorReset, formatDuration(avgTime))
	}

	// Key Findings - Critical Issues
	criticalIssues := r.extractCriticalIssues(5)
	if len(criticalIssues) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintf(w, "  %sKey Findings:%s\n", ColorBold, ColorReset)
		fmt.Fprintln(w)

		for i, issue := range criticalIssues {
			issueColor := r.getRiskColor(issue.RiskLevel)
			fmt.Fprintf(w, "    %s%d.%s %s%s@%s%s (%s)\n",
				ColorBold, i+1, ColorReset,
				issueColor+ColorBold, issue.PackageName, issue.PackageVersion, ColorReset,
				issue.Ecosystem)
			fmt.Fprintf(w, "       %s[%s]%s %s\n",
				r.getSeverityColor(issue.Severity), issue.Severity, ColorReset,
				issue.Description)
			if issue.Evidence != "" {
				fmt.Fprintf(w, "       %sEvidence:%s %s\n",
					ColorDim, ColorReset, issue.Evidence)
			}
			if i < len(criticalIssues)-1 {
				fmt.Fprintln(w)
			}
		}
	}
}

// printSectionHeader prints a section header
func (r *Reporter) printSectionHeader(w io.Writer, title string) {
	width := 80
	fmt.Fprintf(w, "%s%s%s%s\n",
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

	fmt.Fprintf(w, "%s%s┌%s Package: %s%s@%s%s (%s)\n",
		riskColor,
		riskIcon,
		strings.Repeat("─", 70),
		ColorBold,
		result.Dependency.Name,
		result.Dependency.Version,
		ColorReset,
		result.Dependency.Ecosystem)

	fmt.Fprintf(w, "%s│%s\n", riskColor, ColorReset)

	// Risk level badge
	fmt.Fprintf(w, "%s│%s  %sRisk Level:%s %s%s%s\n",
		riskColor, ColorReset,
		ColorBold, ColorReset,
		riskColor+ColorBold, result.RiskLevel, ColorReset)

	// Supply chain score if available
	if result.SupplyChainScore != nil {
		fmt.Fprintf(w, "%s│%s  %sSupply Chain Score:%s %d/14 points (%s%s%s risk)\n",
			riskColor, ColorReset,
			ColorBold, ColorReset,
			result.SupplyChainScore.TotalScore,
			r.getRiskColor(result.SupplyChainScore.RiskLevel),
			result.SupplyChainScore.RiskLevel,
			ColorReset)
	}

	// Repository and source info
	if result.RepositoryURL != "" {
		fmt.Fprintf(w, "%s│%s  %sRepository:%s %s\n",
			riskColor, ColorReset,
			ColorBold, ColorReset,
			result.RepositoryURL)
	}

	fmt.Fprintf(w, "%s│%s  %sSource Available:%s %s\n",
		riskColor, ColorReset,
		ColorBold, ColorReset,
		formatBool(result.SourceCodeAvailable))

	if result.BuildInfrastructure != "" {
		fmt.Fprintf(w, "%s│%s  %sBuild Infrastructure:%s %s\n",
			riskColor, ColorReset,
			ColorBold, ColorReset,
			result.BuildInfrastructure)
	}

	// Supply chain category scores (in verbose mode)
	if r.config.Verbose && result.SupplyChainScore != nil {
		fmt.Fprintf(w, "%s│%s\n", riskColor, ColorReset)
		fmt.Fprintf(w, "%s│%s  %sSupply Chain Security Analysis:%s\n",
			riskColor, ColorReset,
			ColorBold, ColorReset)
		fmt.Fprintf(w, "%s│%s\n", riskColor, ColorReset)

		r.printCategoryScoreTable(w, result.SupplyChainScore.CategoryScores, riskColor)
	}

	// Findings
	if len(result.Findings) > 0 {
		fmt.Fprintf(w, "%s│%s\n", riskColor, ColorReset)
		fmt.Fprintf(w, "%s│%s  %sRisk Findings:%s\n",
			riskColor, ColorReset,
			ColorBold, ColorReset)

		for i, finding := range result.Findings {
			sevColor := r.getSeverityColor(finding.Severity)
			fmt.Fprintf(w, "%s│%s    %s[%s]%s %s\n",
				riskColor, ColorReset,
				sevColor, finding.Severity, ColorReset,
				finding.Description)

			if finding.Evidence != "" && r.config.Verbose {
				fmt.Fprintf(w, "%s│%s       %sEvidence:%s %s\n",
					riskColor, ColorReset,
					ColorDim, ColorReset,
					finding.Evidence)
			}

			if i < len(result.Findings)-1 {
				fmt.Fprintf(w, "%s│%s\n", riskColor, ColorReset)
			}
		}
	}

	fmt.Fprintf(w, "%s└%s\n", riskColor, strings.Repeat("─", 76)+ColorReset)
	fmt.Fprintln(w)
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
	}

	// Table header
	fmt.Fprintf(w, "%s│%s    %-20s  %s  %s  %s\n",
		borderColor, ColorReset,
		"Category", "Score", "Risk", "Status")

	fmt.Fprintf(w, "%s│%s    %s\n",
		borderColor, ColorReset,
		strings.Repeat("─", 45))

	// Table rows
	for _, cat := range categories {
		scoreIcon := r.getScoreIcon(cat.score.RiskPoints)
		verifiedIcon := "✓"
		if !cat.score.Verified {
			verifiedIcon = "?"
		}

		fmt.Fprintf(w, "%s│%s    %-20s  %s  %s  %s\n",
			borderColor, ColorReset,
			cat.name,
			fmt.Sprintf("%d/2", cat.score.Score),
			scoreIcon,
			verifiedIcon)

		if r.config.Verbose && cat.score.Description != "" {
			fmt.Fprintf(w, "%s│%s      %s%s%s\n",
				borderColor, ColorReset,
				ColorDim, cat.score.Description, ColorReset)
		}
	}
}

// printRecommendations prints recommendations based on findings
func (r *Reporter) printRecommendations(w io.Writer) {
	fmt.Fprintln(w)
	r.printSectionHeader(w, "RECOMMENDATIONS")
	fmt.Fprintln(w)

	recommendations := r.generateRecommendations()

	if len(recommendations) == 0 {
		fmt.Fprintf(w, "  %s✓%s No critical issues found. Continue monitoring dependencies for changes.\n",
			ColorGreen, ColorReset)
		return
	}

	for i, rec := range recommendations {
		fmt.Fprintf(w, "  %s%d.%s %s\n", ColorBold, i+1, ColorReset, rec)
		fmt.Fprintln(w)
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

func (r *Reporter) generateRecommendations() []string {
	var recs []string

	if r.stats.HighRisk > 0 {
		recs = append(recs, fmt.Sprintf(
			"%sImmediate Action Required:%s Review and address %d HIGH risk packages. "+
				"Consider finding alternative packages or implementing additional security controls.",
			ColorRed+ColorBold, ColorReset, r.stats.HighRisk))
	}

	// Count packages with missing source code
	missingSource := 0
	for _, result := range r.results {
		if !result.SourceCodeAvailable {
			missingSource++
		}
	}
	if missingSource > 0 {
		recs = append(recs, fmt.Sprintf(
			"%d packages lack publicly available source code. "+
				"Verify these packages are from trusted publishers.",
			missingSource))
	}

	// Count packages with install scripts
	installScripts := 0
	for _, result := range r.results {
		if result.Metadata.HasInstallScripts {
			installScripts++
		}
	}
	if installScripts > 0 {
		recs = append(recs, fmt.Sprintf(
			"%d packages execute install-time scripts. "+
				"Review these scripts for potentially dangerous operations.",
			installScripts))
	}

	// Check for missing provenance
	missingProvenance := 0
	for _, result := range r.results {
		if result.SupplyChainScore != nil && result.SupplyChainScore.CategoryScores.Provenance.RiskPoints > 1 {
			missingProvenance++
		}
	}
	if missingProvenance > 0 {
		recs = append(recs, fmt.Sprintf(
			"%d packages lack build provenance attestations. "+
				"Consider using packages with SLSA attestations or Sigstore signatures.",
			missingProvenance))
	}

	return recs
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
