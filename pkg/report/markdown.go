package report

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/metalstormbass/snyft/pkg/models"
)

// generateMarkdown generates a markdown report
func (r *Reporter) generateMarkdown() error {
	w := r.config.Writer

	// Header
	_, _ = fmt.Fprintln(w, "# SNYFT Supply Chain Security Report")
	_, _ = fmt.Fprintln(w)
	_, _ = fmt.Fprintf(w, "**Generated:** %s\n", time.Now().Format("2006-01-02 15:04:05"))
	_, _ = fmt.Fprintln(w)
	_, _ = fmt.Fprintln(w, "---")
	_, _ = fmt.Fprintln(w)

	// Executive Summary
	_, _ = fmt.Fprintln(w, "## Executive Summary")
	_, _ = fmt.Fprintln(w)
	_, _ = fmt.Fprintln(w, "### Supply Chain Risk Assessment")
	_, _ = fmt.Fprintln(w)
	_, _ = fmt.Fprintln(w, "This report evaluates the **likelihood that software packages could be compromised** through supply chain attacks. It assesses risk factors such as maintainer practices, ownership changes, and build integrity—**NOT** known CVEs or code vulnerabilities.")
	_, _ = fmt.Fprintln(w)
	_, _ = fmt.Fprintln(w, "### Scan Overview")
	_, _ = fmt.Fprintln(w)
	_, _ = fmt.Fprintf(w, "- **Total Packages Scanned:** %d\n", r.stats.TotalPackages)
	_, _ = fmt.Fprintf(w, "- **Manifest Files Found:** %d\n", r.stats.ManifestFiles)
	_, _ = fmt.Fprintf(w, "- **Scan Path:** `%s`\n", r.stats.ScannedPath)
	_, _ = fmt.Fprintln(w)

	_, _ = fmt.Fprintln(w, "### Risk Distribution")
	_, _ = fmt.Fprintln(w)
	_, _ = fmt.Fprintf(w, "| Risk Level | Count | Percentage |\n")
	_, _ = fmt.Fprintf(w, "|------------|-------|------------|\n")
	_, _ = fmt.Fprintf(w, "| 🔴 HIGH    | %d    | %.1f%%     |\n",
		r.stats.HighRisk, float64(r.stats.HighRisk)/float64(r.stats.TotalPackages)*100)
	_, _ = fmt.Fprintf(w, "| 🟡 MEDIUM  | %d    | %.1f%%     |\n",
		r.stats.MediumRisk, float64(r.stats.MediumRisk)/float64(r.stats.TotalPackages)*100)
	_, _ = fmt.Fprintf(w, "| 🟢 LOW     | %d    | %.1f%%     |\n",
		r.stats.LowRisk, float64(r.stats.LowRisk)/float64(r.stats.TotalPackages)*100)
	_, _ = fmt.Fprintln(w)

	duration := r.stats.EndTime.Sub(r.stats.StartTime)
	_, _ = fmt.Fprintf(w, "**Overall Risk Level:** %s\n", r.calculateOverallRisk())
	_, _ = fmt.Fprintf(w, "**Scan Duration:** %s\n", formatDuration(duration))
	_, _ = fmt.Fprintln(w)

	// Risk Impact Summary
	if r.stats.HighRisk > 0 || r.stats.MediumRisk > 0 {
		_, _ = fmt.Fprintln(w, "### Risk Impact Summary")
		_, _ = fmt.Fprintln(w)
		if r.stats.HighRisk > 0 {
			_, _ = fmt.Fprintf(w, "> ⚠️  **ATTENTION REQUIRED:** %d package%s identified with HIGH supply chain risk.\n",
				r.stats.HighRisk, pluralize(r.stats.HighRisk))
			_, _ = fmt.Fprintln(w, "> These packages exhibit patterns commonly associated with compromised dependencies and require immediate review.")
			_, _ = fmt.Fprintln(w)
		}
		if r.stats.MediumRisk > 0 {
			_, _ = fmt.Fprintf(w, "> ⚠️  **MONITORING RECOMMENDED:** %d package%s with MEDIUM risk factors.\n",
				r.stats.MediumRisk, pluralize(r.stats.MediumRisk))
			_, _ = fmt.Fprintln(w, "> These packages show some concerning patterns that warrant closer monitoring.")
			_, _ = fmt.Fprintln(w)
		}
	}

	// Key Findings - Critical Issues
	criticalIssues := r.extractCriticalIssues(5)
	if len(criticalIssues) > 0 {
		_, _ = fmt.Fprintln(w, "### Top Priority Findings")
		_, _ = fmt.Fprintln(w)
		_, _ = fmt.Fprintln(w, "The following issues represent the highest supply chain compromise risks:")
		_, _ = fmt.Fprintln(w)

		for i, issue := range criticalIssues {
			riskIcon := r.getRiskIcon(issue.RiskLevel)
			_, _ = fmt.Fprintf(w, "%d. %s **%s@%s** (%s)\n",
				i+1, riskIcon, issue.PackageName, issue.PackageVersion, issue.Ecosystem)
			_, _ = fmt.Fprintf(w, "   - **[%s SEVERITY]** %s\n", issue.Severity, issue.Description)
			if issue.Evidence != "" {
				_, _ = fmt.Fprintf(w, "   - *Evidence:* %s\n", issue.Evidence)
			}
			impact := r.getRiskImpactDescription(issue.Severity)
			if impact != "" {
				_, _ = fmt.Fprintf(w, "   - *Impact:* %s\n", impact)
			}
			_, _ = fmt.Fprintln(w)
		}
	}

	_, _ = fmt.Fprintln(w, "---")
	_, _ = fmt.Fprintln(w)

	// Detailed Findings
	_, _ = fmt.Fprintln(w, "## Detailed Findings")
	_, _ = fmt.Fprintln(w)

	for _, result := range r.results {
		r.printMarkdownPackage(w, result)
	}

	// Recommendations
	_, _ = fmt.Fprintln(w, "## Recommendations")
	_, _ = fmt.Fprintln(w)

	recommendations := r.generateRecommendations()
	if len(recommendations) == 0 {
		_, _ = fmt.Fprintln(w, "✓ No critical issues found. Continue monitoring dependencies for changes.")
	} else {
		for i, rec := range recommendations {
			// Remove ANSI codes from recommendations
			cleanRec := strings.ReplaceAll(rec, ColorRed, "")
			cleanRec = strings.ReplaceAll(cleanRec, ColorYellow, "")
			cleanRec = strings.ReplaceAll(cleanRec, ColorGreen, "")
			cleanRec = strings.ReplaceAll(cleanRec, ColorBold, "")
			cleanRec = strings.ReplaceAll(cleanRec, ColorReset, "")
			_, _ = fmt.Fprintf(w, "%d. %s\n", i+1, cleanRec)
			_, _ = fmt.Fprintln(w)
		}
	}

	return nil
}

// printMarkdownPackage prints a package in markdown format
func (r *Reporter) printMarkdownPackage(w io.Writer, result models.AnalysisResult) {
	riskIcon := r.getRiskIcon(result.RiskLevel)

	_, _ = fmt.Fprintf(w, "### %s %s@%s (%s)\n",
		riskIcon,
		result.Dependency.Name,
		result.Dependency.Version,
		result.Dependency.Ecosystem)
	_, _ = fmt.Fprintln(w)

	_, _ = fmt.Fprintf(w, "**Risk Level:** %s\n", result.RiskLevel)

	if result.SupplyChainScore != nil {
		_, _ = fmt.Fprintf(w, "**Supply Chain Score:** %d/14 points (%s risk)\n",
			result.SupplyChainScore.TotalScore,
			result.SupplyChainScore.RiskLevel)
	}

	if result.RepositoryURL != "" {
		_, _ = fmt.Fprintf(w, "**Repository:** %s\n", result.RepositoryURL)
	}

	_, _ = fmt.Fprintf(w, "**Source Available:** %v\n", result.SourceCodeAvailable)

	if result.BuildInfrastructure != "" {
		_, _ = fmt.Fprintf(w, "**Build Infrastructure:** %s\n", result.BuildInfrastructure)
	}

	// Supply chain scores
	if r.config.Verbose && result.SupplyChainScore != nil {
		_, _ = fmt.Fprintln(w)
		_, _ = fmt.Fprintln(w, "#### Supply Chain Security Analysis")
		_, _ = fmt.Fprintln(w)
		_, _ = fmt.Fprintln(w, "| Category | Score | Risk | Status |")
		_, _ = fmt.Fprintln(w, "|----------|-------|------|--------|")

		categories := []struct {
			name  string
			score models.CategoryScore
		}{
			{"Publisher Control", result.SupplyChainScore.CategoryScores.PublisherControl},
			{"Ownership Changes", result.SupplyChainScore.CategoryScores.OwnershipChanges},
			{"Release Anomalies", result.SupplyChainScore.CategoryScores.ReleaseAnomalies},
			{"Install Execution", result.SupplyChainScore.CategoryScores.InstallExecution},
			{"Dependency Sprawl", result.SupplyChainScore.CategoryScores.DependencySprawl},
			{"Provenance", result.SupplyChainScore.CategoryScores.Provenance},
			{"Health", result.SupplyChainScore.CategoryScores.Health},
		}

		for _, cat := range categories {
			scoreIcon := "🟢"
			switch cat.score.RiskPoints {
			case 2:
				scoreIcon = "🔴"
			case 1:
				scoreIcon = "🟡"
			}

			verifiedIcon := "✓"
			if !cat.score.Verified {
				verifiedIcon = "?"
			}

			_, _ = fmt.Fprintf(w, "| %s | %d/2 | %s | %s |\n",
				cat.name, cat.score.Score, scoreIcon, verifiedIcon)
		}
		_, _ = fmt.Fprintln(w)
	}

	// Findings
	if len(result.Findings) > 0 {
		_, _ = fmt.Fprintln(w)
		_, _ = fmt.Fprintln(w, "#### Risk Findings")
		_, _ = fmt.Fprintln(w)

		for _, finding := range result.Findings {
			_, _ = fmt.Fprintf(w, "- **[%s]** %s\n", finding.Severity, finding.Description)
			if finding.Evidence != "" && r.config.Verbose {
				_, _ = fmt.Fprintf(w, "  - *Evidence:* %s\n", finding.Evidence)
			}
		}
		_, _ = fmt.Fprintln(w)
	}

	_, _ = fmt.Fprintln(w, "---")
	_, _ = fmt.Fprintln(w)
}
