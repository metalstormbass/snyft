package report

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/metalstormbass/snyft/pkg/models"
)

// generateText generates a text report with clean, scannable formatting
func (r *Reporter) generateText() error {
	w := r.config.Writer

	r.printHeader(w)
	r.printExecutiveSummary(w)

	if !r.config.Verbose {
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

	// Key Risk Areas
	r.printRiskSummary(w)

	return nil
}

// printHeader prints a clean report header
func (r *Reporter) printHeader(w io.Writer) {
	_, _ = fmt.Fprintf(w, "\n%sSNYFT — Supply Chain Risk Report%s\n", colorBold, colorReset)
	_, _ = fmt.Fprintf(w, "%sGenerated: %s%s\n", colorDim, time.Now().Format("2006-01-02 15:04:05"), colorReset)
	_, _ = fmt.Fprintf(w, "%s%s\n", colorDim+strings.Repeat("─", 70), colorReset)
}

// printSectionHeader prints a section divider with title
func (r *Reporter) printSectionHeader(w io.Writer, title string) {
	line := strings.Repeat("─", 70-len(title)-3)
	_, _ = fmt.Fprintf(w, "%s── %s %s%s\n", colorBold+colorCyan, title, line, colorReset)
}

// printExecutiveSummary prints the executive summary section
func (r *Reporter) printExecutiveSummary(w io.Writer) {
	_, _ = fmt.Fprintln(w)
	r.printSectionHeader(w, "EXECUTIVE SUMMARY")
	_, _ = fmt.Fprintln(w)

	// Scan info - compact
	_, _ = fmt.Fprintf(w, "  %sPath:%s       %s\n", colorBold, colorReset, r.stats.ScannedPath)

	pkgInfo := fmt.Sprintf("%d", r.stats.TotalPackages)
	if r.stats.DirectDeps > 0 || r.stats.TransitiveDeps > 0 {
		pkgInfo += fmt.Sprintf(" (%d direct, %d transitive)", r.stats.DirectDeps, r.stats.TransitiveDeps)
	}
	_, _ = fmt.Fprintf(w, "  %sPackages:%s   %s\n", colorBold, colorReset, pkgInfo)

	duration := r.stats.EndTime.Sub(r.stats.StartTime)
	_, _ = fmt.Fprintf(w, "  %sManifests:%s  %d  %s·%s  %s\n",
		colorBold, colorReset, r.stats.ManifestFiles,
		colorDim, colorReset, formatDuration(duration))
	_, _ = fmt.Fprintln(w)

	// Risk distribution - compact colored block
	overallRisk := r.calculateOverallRisk()
	_, _ = fmt.Fprintf(w, "  %sRisk:%s       %s%d HIGH%s   %s%d MEDIUM%s   %s%d LOW%s",
		colorBold, colorReset,
		colorRed+colorBold, r.stats.HighRisk, colorReset,
		colorYellow+colorBold, r.stats.MediumRisk, colorReset,
		colorGreen+colorBold, r.stats.LowRisk, colorReset)
	_, _ = fmt.Fprintln(w)

	riskColor := riskToColor(overallRisk)
	_, _ = fmt.Fprintf(w, "  %sOverall:%s    %s%s%s\n",
		colorBold, colorReset, riskColor+colorBold, overallRisk, colorReset)

	// Risk Impact Summary
	if r.stats.HighRisk > 0 || r.stats.MediumRisk > 0 {
		_, _ = fmt.Fprintln(w)
		if r.stats.HighRisk > 0 {
			_, _ = fmt.Fprintf(w, "  %s⚠  %d package%s require immediate review (HIGH risk)%s\n",
				colorRed+colorBold, r.stats.HighRisk, pluralize(r.stats.HighRisk), colorReset)
		}
		if r.stats.MediumRisk > 0 {
			_, _ = fmt.Fprintf(w, "  %s⚠  %d package%s warrant monitoring (MEDIUM risk)%s\n",
				colorYellow, r.stats.MediumRisk, pluralize(r.stats.MediumRisk), colorReset)
		}
	}

	// Top Priority Findings
	criticalIssues := r.extractCriticalIssues(5)
	if len(criticalIssues) > 0 {
		_, _ = fmt.Fprintln(w)
		_, _ = fmt.Fprintf(w, "  %sTop Priority Findings:%s\n", colorBold, colorReset)
		_, _ = fmt.Fprintln(w)

		for i, issue := range criticalIssues {
			issueColor := riskToColor(issue.RiskLevel)
			_, _ = fmt.Fprintf(w, "    %s%d.%s %s%s@%s%s (%s)%s%s%s\n",
				colorBold, i+1, colorReset,
				colorBold, issue.PackageName, issue.PackageVersion, colorReset,
				issue.Ecosystem,
				strings.Repeat(" ", maxInt(1, 50-len(issue.PackageName)-len(issue.PackageVersion)-len(issue.Ecosystem)-5)),
				issueColor+colorBold, issue.RiskLevel+colorReset)
			_, _ = fmt.Fprintf(w, "       %s[%s]%s %s\n",
				severityColor(issue.Severity), issue.Severity, colorReset,
				issue.Description)
			if issue.Evidence != "" {
				_, _ = fmt.Fprintf(w, "       %sEvidence:%s %s\n",
					colorDim, colorReset, issue.Evidence)
			}
			if i < len(criticalIssues)-1 {
				_, _ = fmt.Fprintln(w)
			}
		}
	}

	// AI Executive Summary
	r.printAIExecutiveSummary(w)
}

// printAIExecutiveSummary prints the report-level AI summary
func (r *Reporter) printAIExecutiveSummary(w io.Writer) {
	if r.reportAISummary == nil {
		return
	}
	summary := r.reportAISummary

	_, _ = fmt.Fprintln(w)
	_, _ = fmt.Fprintf(w, "  %s🤖 AI Risk Assessment%s\n", colorBold+colorCyan, colorReset)
	_, _ = fmt.Fprintln(w)
	_, _ = fmt.Fprintf(w, "  %s\n", summary.OverallAssessment)

	if len(summary.KeyThreats) > 0 {
		_, _ = fmt.Fprintln(w)
		_, _ = fmt.Fprintf(w, "  %sKey Threats:%s\n", colorBold, colorReset)
		for _, threat := range summary.KeyThreats {
			_, _ = fmt.Fprintf(w, "    %s•%s %s\n", colorRed, colorReset, threat)
		}
	}

	if len(summary.CrossPatterns) > 0 {
		_, _ = fmt.Fprintln(w)
		_, _ = fmt.Fprintf(w, "  %sCross-Package Patterns:%s\n", colorBold, colorReset)
		for _, pattern := range summary.CrossPatterns {
			_, _ = fmt.Fprintf(w, "    %s•%s %s\n", colorYellow, colorReset, pattern)
		}
	}

	if len(summary.PriorityPackages) > 0 {
		_, _ = fmt.Fprintln(w)
		_, _ = fmt.Fprintf(w, "  %sPriority Packages:%s\n", colorBold, colorReset)
		for _, pkg := range summary.PriorityPackages {
			_, _ = fmt.Fprintf(w, "    %s•%s %s\n", colorRed, colorReset, pkg)
		}
	}

	if summary.RiskPosture != "" {
		_, _ = fmt.Fprintf(w, "  %sRisk Posture:%s %s\n", colorBold, colorReset, summary.RiskPosture)
	}

	confidencePct := summary.Confidence * 100
	confidenceColor := colorGreen
	if confidencePct < 50 {
		confidenceColor = colorYellow
	}
	_, _ = fmt.Fprintf(w, "  %sConfidence:%s %s%.0f%%%s\n",
		colorDim, colorReset, confidenceColor, confidencePct, colorReset)
}

// printPackageResult prints a single package analysis result
func (r *Reporter) printPackageResult(w io.Writer, result models.AnalysisResult) {
	rColor := riskToColor(result.RiskLevel)

	transitiveLabel := ""
	if result.Dependency.IsTransitive {
		transitiveLabel = fmt.Sprintf(" %s(transitive)%s", colorDim, colorReset)
	}

	// Package header line with score and risk
	scoreStr := ""
	if result.SupplyChainScore != nil {
		scoreStr = fmt.Sprintf("%d/22", result.SupplyChainScore.TotalScore)
		if result.SupplyChainScore.AIAdjustment != 0 {
			adjSign := "+"
			if result.SupplyChainScore.AIAdjustment < 0 {
				adjSign = ""
			}
			scoreStr += fmt.Sprintf(" %s[AI %s%d]%s", colorCyan, adjSign, result.SupplyChainScore.AIAdjustment, colorReset)
		}
	}

	_, _ = fmt.Fprintf(w, "  %s%s@%s%s (%s)%s",
		colorBold, result.Dependency.Name, result.Dependency.Version, colorReset,
		result.Dependency.Ecosystem, transitiveLabel)

	if scoreStr != "" {
		padding := maxInt(1, 55-len(result.Dependency.Name)-len(result.Dependency.Version)-len(string(result.Dependency.Ecosystem))-5)
		_, _ = fmt.Fprintf(w, "%s%s  %s%s%s\n",
			strings.Repeat(" ", padding),
			scoreStr,
			rColor+colorBold, result.RiskLevel, colorReset)
	} else {
		_, _ = fmt.Fprintf(w, "  %s%s%s\n", rColor+colorBold, result.RiskLevel, colorReset)
	}

	_, _ = fmt.Fprintf(w, "  %s%s%s\n", colorDim, strings.Repeat("─", 68), colorReset)

	// Package details - compact
	if result.RepositoryURL != "" {
		_, _ = fmt.Fprintf(w, "  %sRepo:%s %s\n", colorDim, colorReset, result.RepositoryURL)
	}
	_, _ = fmt.Fprintf(w, "  %sSource:%s %s", colorDim, colorReset, formatBool(result.SourceCodeAvailable))
	if result.BuildInfrastructure != "" {
		_, _ = fmt.Fprintf(w, "  %s·%s  %sBuild:%s %s", colorDim, colorReset, colorDim, colorReset, result.BuildInfrastructure)
	}
	_, _ = fmt.Fprintln(w)

	if result.Metadata.HasSelfHosted {
		_, _ = fmt.Fprintf(w, "  %s⚠  Self-hosted runners detected%s\n", colorRed+colorBold, colorReset)
	}

	// Category scores table - two columns
	if r.config.Verbose && result.SupplyChainScore != nil {
		_, _ = fmt.Fprintln(w)
		r.printCategoryScoreTable(w, result.SupplyChainScore.CategoryScores)
	}

	// Findings
	if len(result.Findings) > 0 {
		_, _ = fmt.Fprintln(w)
		for _, finding := range result.Findings {
			sColor := severityColor(finding.Severity)
			_, _ = fmt.Fprintf(w, "  %s[%s]%s %s\n",
				sColor, finding.Severity, colorReset,
				finding.Description)

			if finding.Evidence != "" && r.config.Verbose {
				_, _ = fmt.Fprintf(w, "    %sEvidence:%s %s\n", colorDim, colorReset, finding.Evidence)
			}
			if finding.Methodology != "" && r.config.Verbose {
				_, _ = fmt.Fprintf(w, "    %sMethodology:%s %s\n", colorDim, colorReset, finding.Methodology)
			}
		}
	}

	// AI Analysis
	if result.AIAnalysis != nil {
		r.printPackageAIAnalysis(w, result.AIAnalysis)
	}

	_, _ = fmt.Fprintln(w)
}

// printPackageAIAnalysis prints AI analysis results for a package
func (r *Reporter) printPackageAIAnalysis(w io.Writer, aiAnalysis *models.AIAnalysisResult) {
	if aiAnalysis == nil {
		return
	}

	// Deep Analysis
	if aiAnalysis.DeepAnalysis != nil {
		da := aiAnalysis.DeepAnalysis
		_, _ = fmt.Fprintln(w)
		_, _ = fmt.Fprintf(w, "  %s🤖 AI Deep Analysis:%s\n", colorBold+colorCyan, colorReset)

		if da.RiskAssessment != "" {
			_, _ = fmt.Fprintf(w, "  %s\n", da.RiskAssessment)
		}

		if len(da.CompoundRisks) > 0 {
			_, _ = fmt.Fprintf(w, "  %sCompound Risks:%s\n", colorBold, colorReset)
			for _, cr := range da.CompoundRisks {
				sColor := severityColor(cr.RiskLevel)
				_, _ = fmt.Fprintf(w, "    %s[%s]%s %s\n", sColor, cr.RiskLevel, colorReset, cr.Pattern)
				if cr.Explanation != "" {
					_, _ = fmt.Fprintf(w, "      %s%s%s\n", colorDim, cr.Explanation, colorReset)
				}
				if len(cr.Contributing) > 0 {
					_, _ = fmt.Fprintf(w, "      %sSignals: %s%s\n", colorDim, strings.Join(cr.Contributing, ", "), colorReset)
				}
			}
		}

		if len(da.BehaviorFindings) > 0 {
			_, _ = fmt.Fprintf(w, "  %sBehavioral Anomalies:%s\n", colorBold, colorReset)
			for _, bf := range da.BehaviorFindings {
				_, _ = fmt.Fprintf(w, "    • %s\n", bf)
			}
		}

		if len(da.MissedByRules) > 0 {
			_, _ = fmt.Fprintf(w, "  %sInsights Beyond Rules:%s\n", colorBold, colorReset)
			for _, insight := range da.MissedByRules {
				_, _ = fmt.Fprintf(w, "    • %s\n", insight)
			}
		}

		_, _ = fmt.Fprintf(w, "  %sConfidence: %.0f%%%s\n", colorDim, da.Confidence*100, colorReset)
	}

	// Attack Patterns
	if len(aiAnalysis.AttackPatterns) > 0 {
		_, _ = fmt.Fprintln(w)
		_, _ = fmt.Fprintf(w, "  %s🤖 Attack Patterns:%s\n", colorBold+colorCyan, colorReset)

		for _, pattern := range aiAnalysis.AttackPatterns {
			sColor := severityColor(pattern.Severity)
			_, _ = fmt.Fprintf(w, "    %s[%s]%s %s %s(%.0f%%)%s\n",
				sColor, pattern.Severity, colorReset,
				pattern.PatternName,
				colorDim, pattern.Confidence*100, colorReset)

			if pattern.Description != "" && r.config.Verbose {
				_, _ = fmt.Fprintf(w, "      %s%s%s\n", colorDim, pattern.Description, colorReset)
			}
			if pattern.AcademicSource != "" {
				_, _ = fmt.Fprintf(w, "      %sSource: %s%s\n", colorDim, pattern.AcademicSource, colorReset)
			}
			if r.config.Verbose && len(pattern.Evidence) > 0 {
				for _, evidence := range pattern.Evidence {
					_, _ = fmt.Fprintf(w, "      %s• %s%s\n", colorDim, evidence, colorReset)
				}
			}
		}
	}

	// Analysis Notes
	if aiAnalysis.AnalysisNotes != "" && r.config.Verbose {
		_, _ = fmt.Fprintln(w)
		_, _ = fmt.Fprintf(w, "  %s🤖 Notes:%s %s%s%s\n", colorBold+colorCyan, colorReset, colorDim, aiAnalysis.AnalysisNotes, colorReset)
	}
}

// printCategoryScoreTable prints category scores in a compact two-column table
func (r *Reporter) printCategoryScoreTable(w io.Writer, scores models.CategoryScores) {
	categories := getCategoryList(scores)

	// Print in two columns
	half := (len(categories) + 1) / 2
	for i := 0; i < half; i++ {
		left := categories[i]
		leftStr := fmt.Sprintf("  %-19s %d/2 %s",
			left.Name, left.Score.Score, scoreIcon(left.Score.RiskPoints))

		if i+half < len(categories) {
			right := categories[i+half]
			rightStr := fmt.Sprintf("%-19s %d/2 %s",
				right.Name, right.Score.Score, scoreIcon(right.Score.RiskPoints))
			_, _ = fmt.Fprintf(w, "%s  %s│%s  %s\n", leftStr, colorDim, colorReset, rightStr)
		} else {
			_, _ = fmt.Fprintf(w, "%s\n", leftStr)
		}
	}

	// Show detailed sub-checks in verbose mode
	if r.config.Verbose {
		for _, cat := range categories {
			if cat.Score.Description != "" {
				_, _ = fmt.Fprintf(w, "  %s%s: %s%s\n", colorDim, cat.Name, cat.Score.Description, colorReset)
			}
			for _, check := range cat.Score.ChecksPerformed {
				statusIcon := checkStatusIcon(check.Status)
				_, _ = fmt.Fprintf(w, "    %s %s: %s%s%s\n",
					statusIcon, check.Name, colorDim, check.Detail, colorReset)
			}
		}
	}
}

// printRiskSummary prints key risk areas
func (r *Reporter) printRiskSummary(w io.Writer) {
	_, _ = fmt.Fprintln(w)
	r.printSectionHeader(w, "KEY RISK AREAS")
	_, _ = fmt.Fprintln(w)

	riskAreas := r.generateRiskAreas()

	if len(riskAreas) == 0 {
		_, _ = fmt.Fprintf(w, "  %s✓%s No critical supply chain risk factors identified.\n", colorGreen, colorReset)
		return
	}

	for i, area := range riskAreas {
		tagColor := colorYellow
		if area.Severity == "HIGH" {
			tagColor = colorRed
		}
		_, _ = fmt.Fprintf(w, "  %s%d.%s %s[%s]%s %s\n",
			colorBold, i+1, colorReset,
			tagColor+colorBold, area.Tag, colorReset,
			area.Summary)
		if len(area.Examples) > 0 {
			_, _ = fmt.Fprintf(w, "     %se.g., %s%s\n",
				colorDim, strings.Join(area.Examples, ", "), colorReset)
		}
		_, _ = fmt.Fprintln(w)
	}
}

// printFormatHint prints guidance on how to get more detailed output
func (r *Reporter) printFormatHint(w io.Writer) {
	scanPath := r.stats.ScannedPath
	if scanPath == "" {
		scanPath = "<path>"
	}

	_, _ = fmt.Fprintln(w)
	_, _ = fmt.Fprintf(w, "%s%s%s\n", colorDim, strings.Repeat("─", 70), colorReset)
	_, _ = fmt.Fprintln(w)
	_, _ = fmt.Fprintf(w, "  %sFull report:%s  snyft scan %s -v\n", colorBold, colorReset, scanPath)
	_, _ = fmt.Fprintf(w, "  %sExport:%s      snyft scan %s -f html -o report.html\n", colorBold, colorReset, scanPath)
	_, _ = fmt.Fprintln(w)
}

// Helper functions

func riskToColor(riskLevel string) string {
	switch riskLevel {
	case "HIGH":
		return colorRed
	case "MEDIUM":
		return colorYellow
	case "LOW":
		return colorGreen
	default:
		return colorReset
	}
}

func severityColor(severity string) string {
	switch severity {
	case "CRITICAL", "HIGH":
		return colorRed
	case "MEDIUM":
		return colorYellow
	case "LOW":
		return colorGreen
	default:
		return colorReset
	}
}

func scoreIcon(riskPoints int) string {
	switch riskPoints {
	case 0:
		return colorGreen + "●" + colorReset
	case 1:
		return colorYellow + "●" + colorReset
	case 2:
		return colorRed + "●" + colorReset
	default:
		return "○"
	}
}

func checkStatusIcon(status string) string {
	switch status {
	case "PASS":
		return colorGreen + "✓" + colorReset
	case "FAIL":
		return colorRed + "✗" + colorReset
	case "SKIPPED":
		return colorDim + "○" + colorReset
	case "UNAVAILABLE":
		return colorYellow + "?" + colorReset
	default:
		return "·"
	}
}

func formatBool(b bool) string {
	if b {
		return colorGreen + "✓ Yes" + colorReset
	}
	return colorRed + "✗ No" + colorReset
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
