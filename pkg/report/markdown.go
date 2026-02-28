package report

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/metalstormbass/snyft/pkg/models"
)

// generateMarkdown generates a clean markdown report
func (r *Reporter) generateMarkdown() error {
	w := r.config.Writer

	_, _ = fmt.Fprintln(w, "# Snyft Supply Chain Risk Report")
	_, _ = fmt.Fprintln(w)
	_, _ = fmt.Fprintf(w, "_Generated: %s_\n", time.Now().Format("2006-01-02 15:04:05"))
	_, _ = fmt.Fprintln(w)

	// Executive Summary
	_, _ = fmt.Fprintln(w, "## Executive Summary")
	_, _ = fmt.Fprintln(w)

	// Scan overview table
	duration := r.stats.EndTime.Sub(r.stats.StartTime)
	_, _ = fmt.Fprintf(w, "| | |\n|---|---|\n")
	_, _ = fmt.Fprintf(w, "| **Path** | `%s` |\n", r.stats.ScannedPath)
	_, _ = fmt.Fprintf(w, "| **Packages** | %d", r.stats.TotalPackages)
	if r.stats.DirectDeps > 0 || r.stats.TransitiveDeps > 0 {
		_, _ = fmt.Fprintf(w, " (%d direct, %d transitive)", r.stats.DirectDeps, r.stats.TransitiveDeps)
	}
	_, _ = fmt.Fprintln(w, " |")
	_, _ = fmt.Fprintf(w, "| **Manifests** | %d |\n", r.stats.ManifestFiles)
	_, _ = fmt.Fprintf(w, "| **Duration** | %s |\n", formatDuration(duration))
	_, _ = fmt.Fprintf(w, "| **Overall Risk** | **%s** |\n", r.calculateOverallRisk())
	_, _ = fmt.Fprintln(w)

	// Risk distribution
	_, _ = fmt.Fprintln(w, "### Risk Distribution")
	_, _ = fmt.Fprintln(w)
	_, _ = fmt.Fprintln(w, "| Level | Count | % |")
	_, _ = fmt.Fprintln(w, "|-------|------:|---:|")
	_, _ = fmt.Fprintf(w, "| 🔴 HIGH | %d | %.1f%% |\n",
		r.stats.HighRisk, pct(r.stats.HighRisk, r.stats.TotalPackages))
	_, _ = fmt.Fprintf(w, "| 🟡 MEDIUM | %d | %.1f%% |\n",
		r.stats.MediumRisk, pct(r.stats.MediumRisk, r.stats.TotalPackages))
	_, _ = fmt.Fprintf(w, "| 🟢 LOW | %d | %.1f%% |\n",
		r.stats.LowRisk, pct(r.stats.LowRisk, r.stats.TotalPackages))
	_, _ = fmt.Fprintln(w)

	// Top Priority Findings
	criticalIssues := r.extractCriticalIssues(5)
	if len(criticalIssues) > 0 {
		_, _ = fmt.Fprintln(w, "### Top Priority Findings")
		_, _ = fmt.Fprintln(w)

		for i, issue := range criticalIssues {
			riskIcon := mdRiskIcon(issue.RiskLevel)
			_, _ = fmt.Fprintf(w, "%d. %s **%s@%s** (%s) — %s\n",
				i+1, riskIcon, issue.PackageName, issue.PackageVersion,
				issue.Ecosystem, issue.RiskLevel)
			_, _ = fmt.Fprintf(w, "   - **[%s]** %s\n", issue.Severity, issue.Description)
			if issue.Evidence != "" {
				_, _ = fmt.Fprintf(w, "   - *Evidence:* %s\n", issue.Evidence)
			}
			_, _ = fmt.Fprintln(w)
		}
	}

	// AI Executive Summary
	r.printMarkdownAIExecutiveSummary(w)

	_, _ = fmt.Fprintln(w, "---")
	_, _ = fmt.Fprintln(w)

	// Detailed Findings
	_, _ = fmt.Fprintln(w, "## Detailed Findings")
	_, _ = fmt.Fprintln(w)

	for _, result := range r.results {
		r.printMarkdownPackage(w, result)
	}

	// Key Risk Areas
	_, _ = fmt.Fprintln(w, "## Key Risk Areas")
	_, _ = fmt.Fprintln(w)

	riskAreas := r.generateRiskAreas()
	if len(riskAreas) == 0 {
		_, _ = fmt.Fprintln(w, "No critical supply chain risk factors identified.")
	} else {
		for i, area := range riskAreas {
			exStr := ""
			if len(area.Examples) > 0 {
				exStr = fmt.Sprintf(" (e.g., %s)", strings.Join(area.Examples, ", "))
			}
			_, _ = fmt.Fprintf(w, "%d. **[%s]** %s%s\n", i+1, area.Tag, area.Summary, exStr)
		}
	}
	_, _ = fmt.Fprintln(w)

	return nil
}

// printMarkdownAIExecutiveSummary prints the report-level AI summary in markdown
func (r *Reporter) printMarkdownAIExecutiveSummary(w io.Writer) {
	if r.reportAISummary == nil {
		return
	}
	summary := r.reportAISummary

	_, _ = fmt.Fprintln(w, "### 🤖 AI Risk Assessment")
	_, _ = fmt.Fprintln(w)
	_, _ = fmt.Fprintf(w, "%s\n", summary.OverallAssessment)
	_, _ = fmt.Fprintln(w)

	if len(summary.KeyThreats) > 0 {
		_, _ = fmt.Fprintln(w, "**Key Threats:**")
		for _, threat := range summary.KeyThreats {
			_, _ = fmt.Fprintf(w, "- %s\n", threat)
		}
		_, _ = fmt.Fprintln(w)
	}

	if len(summary.CrossPatterns) > 0 {
		_, _ = fmt.Fprintln(w, "**Cross-Package Patterns:**")
		for _, pattern := range summary.CrossPatterns {
			_, _ = fmt.Fprintf(w, "- %s\n", pattern)
		}
		_, _ = fmt.Fprintln(w)
	}

	if len(summary.PriorityPackages) > 0 {
		_, _ = fmt.Fprintln(w, "**Priority Packages:**")
		for _, pkg := range summary.PriorityPackages {
			_, _ = fmt.Fprintf(w, "- %s\n", pkg)
		}
		_, _ = fmt.Fprintln(w)
	}

	if summary.RiskPosture != "" {
		_, _ = fmt.Fprintf(w, "**Risk Posture:** %s\n", summary.RiskPosture)
		_, _ = fmt.Fprintln(w)
	}

	_, _ = fmt.Fprintf(w, "_AI Confidence: %.0f%%_\n", summary.Confidence*100)
	_, _ = fmt.Fprintln(w)
}

// printMarkdownPackage prints a package in markdown format
func (r *Reporter) printMarkdownPackage(w io.Writer, result models.AnalysisResult) {
	riskIcon := mdRiskIcon(result.RiskLevel)

	transitiveLabel := ""
	if result.Dependency.IsTransitive {
		transitiveLabel = " _(transitive)_"
	}

	// Package header
	scoreStr := ""
	if result.SupplyChainScore != nil {
		scoreStr = fmt.Sprintf(" — %d/22 pts", result.SupplyChainScore.TotalScore)
		if result.SupplyChainScore.AIAdjustment != 0 {
			adjSign := "+"
			if result.SupplyChainScore.AIAdjustment < 0 {
				adjSign = ""
			}
			scoreStr += fmt.Sprintf(" [AI %s%d]", adjSign, result.SupplyChainScore.AIAdjustment)
		}
	}

	_, _ = fmt.Fprintf(w, "### %s %s@%s (%s)%s%s\n",
		riskIcon,
		result.Dependency.Name,
		result.Dependency.Version,
		result.Dependency.Ecosystem,
		transitiveLabel,
		scoreStr)
	_, _ = fmt.Fprintln(w)

	_, _ = fmt.Fprintf(w, "**Risk Level:** %s\n", result.RiskLevel)

	if result.RepositoryURL != "" {
		_, _ = fmt.Fprintf(w, "**Repository:** %s\n", result.RepositoryURL)
	}
	_, _ = fmt.Fprintf(w, "**Source Available:** %v\n", result.SourceCodeAvailable)
	if result.BuildInfrastructure != "" {
		_, _ = fmt.Fprintf(w, "**Build Infrastructure:** %s\n", result.BuildInfrastructure)
	}
	_, _ = fmt.Fprintln(w)

	// Category scores
	if r.config.Verbose && result.SupplyChainScore != nil {
		_, _ = fmt.Fprintln(w, "| Category | Score | Risk |")
		_, _ = fmt.Fprintln(w, "|----------|------:|:----:|")

		for _, cat := range getCategoryList(result.SupplyChainScore.CategoryScores) {
			icon := "🟢"
			switch cat.Score.RiskPoints {
			case 2:
				icon = "🔴"
			case 1:
				icon = "🟡"
			}
			_, _ = fmt.Fprintf(w, "| %s | %d/2 | %s |\n", cat.Name, cat.Score.Score, icon)
		}
		_, _ = fmt.Fprintln(w)
	}

	// Findings
	if len(result.Findings) > 0 {
		_, _ = fmt.Fprintln(w, "**Findings:**")
		_, _ = fmt.Fprintln(w)
		for _, finding := range result.Findings {
			_, _ = fmt.Fprintf(w, "- **[%s]** %s\n", finding.Severity, finding.Description)
			if finding.Evidence != "" && r.config.Verbose {
				_, _ = fmt.Fprintf(w, "  - *Evidence:* %s\n", finding.Evidence)
			}
			if finding.Methodology != "" && r.config.Verbose {
				_, _ = fmt.Fprintf(w, "  - *Methodology:* %s\n", finding.Methodology)
			}
		}
		_, _ = fmt.Fprintln(w)
	}

	// AI Analysis
	if result.AIAnalysis != nil {
		r.printMarkdownPackageAIAnalysis(w, result.AIAnalysis)
	}

	_, _ = fmt.Fprintln(w, "---")
	_, _ = fmt.Fprintln(w)
}

// printMarkdownPackageAIAnalysis prints AI analysis results for a package in markdown
func (r *Reporter) printMarkdownPackageAIAnalysis(w io.Writer, aiAnalysis *models.AIAnalysisResult) {
	if aiAnalysis == nil {
		return
	}

	if aiAnalysis.DeepAnalysis != nil {
		da := aiAnalysis.DeepAnalysis
		_, _ = fmt.Fprintln(w, "**🤖 AI Deep Analysis:**")
		_, _ = fmt.Fprintln(w)

		if da.RiskAssessment != "" {
			_, _ = fmt.Fprintf(w, "%s\n\n", da.RiskAssessment)
		}

		if len(da.CompoundRisks) > 0 {
			for _, cr := range da.CompoundRisks {
				_, _ = fmt.Fprintf(w, "- **[%s]** %s\n", cr.RiskLevel, cr.Pattern)
				if cr.Explanation != "" {
					_, _ = fmt.Fprintf(w, "  - %s\n", cr.Explanation)
				}
			}
			_, _ = fmt.Fprintln(w)
		}

		if len(da.BehaviorFindings) > 0 {
			for _, bf := range da.BehaviorFindings {
				_, _ = fmt.Fprintf(w, "- %s\n", bf)
			}
			_, _ = fmt.Fprintln(w)
		}

		if len(da.MissedByRules) > 0 {
			for _, insight := range da.MissedByRules {
				_, _ = fmt.Fprintf(w, "- %s\n", insight)
			}
			_, _ = fmt.Fprintln(w)
		}

		_, _ = fmt.Fprintf(w, "_Confidence: %.0f%%_\n\n", da.Confidence*100)
	}

	if len(aiAnalysis.AttackPatterns) > 0 {
		_, _ = fmt.Fprintln(w, "**🤖 Attack Patterns:**")
		_, _ = fmt.Fprintln(w)
		for _, pattern := range aiAnalysis.AttackPatterns {
			_, _ = fmt.Fprintf(w, "- **[%s]** %s (%.0f%%)\n",
				pattern.Severity, pattern.PatternName, pattern.Confidence*100)
			if pattern.AcademicSource != "" {
				_, _ = fmt.Fprintf(w, "  - _Source: %s_\n", pattern.AcademicSource)
			}
			if pattern.Description != "" && r.config.Verbose {
				_, _ = fmt.Fprintf(w, "  - %s\n", pattern.Description)
			}
			if r.config.Verbose && len(pattern.Evidence) > 0 {
				for _, evidence := range pattern.Evidence {
					_, _ = fmt.Fprintf(w, "  - %s\n", evidence)
				}
			}
		}
		_, _ = fmt.Fprintln(w)
	}

	if aiAnalysis.AnalysisNotes != "" && r.config.Verbose {
		_, _ = fmt.Fprintf(w, "_AI Notes: %s_\n\n", aiAnalysis.AnalysisNotes)
	}
}

// mdRiskIcon returns a markdown-safe risk icon
func mdRiskIcon(riskLevel string) string {
	switch riskLevel {
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
