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
	fmt.Fprintln(w, "# SNYFT Supply Chain Security Report")
	fmt.Fprintln(w)
	fmt.Fprintf(w, "**Generated:** %s\n", time.Now().Format("2006-01-02 15:04:05"))
	fmt.Fprintln(w)
	fmt.Fprintln(w, "---")
	fmt.Fprintln(w)

	// Executive Summary
	fmt.Fprintln(w, "## Executive Summary")
	fmt.Fprintln(w)
	fmt.Fprintf(w, "- **Total Packages Scanned:** %d\n", r.stats.TotalPackages)
	fmt.Fprintf(w, "- **Manifest Files Found:** %d\n", r.stats.ManifestFiles)
	fmt.Fprintf(w, "- **Scan Path:** `%s`\n", r.stats.ScannedPath)
	fmt.Fprintln(w)

	fmt.Fprintln(w, "### Risk Distribution")
	fmt.Fprintln(w)
	fmt.Fprintf(w, "| Risk Level | Count | Percentage |\n")
	fmt.Fprintf(w, "|------------|-------|------------|\n")
	fmt.Fprintf(w, "| 🔴 HIGH    | %d    | %.1f%%     |\n",
		r.stats.HighRisk, float64(r.stats.HighRisk)/float64(r.stats.TotalPackages)*100)
	fmt.Fprintf(w, "| 🟡 MEDIUM  | %d    | %.1f%%     |\n",
		r.stats.MediumRisk, float64(r.stats.MediumRisk)/float64(r.stats.TotalPackages)*100)
	fmt.Fprintf(w, "| 🟢 LOW     | %d    | %.1f%%     |\n",
		r.stats.LowRisk, float64(r.stats.LowRisk)/float64(r.stats.TotalPackages)*100)
	fmt.Fprintln(w)

	duration := r.stats.EndTime.Sub(r.stats.StartTime)
	fmt.Fprintf(w, "**Overall Risk Level:** %s\n", r.calculateOverallRisk())
	fmt.Fprintf(w, "**Scan Duration:** %s\n", formatDuration(duration))
	fmt.Fprintln(w)

	// Key Findings - Critical Issues
	criticalIssues := r.extractCriticalIssues(5)
	if len(criticalIssues) > 0 {
		fmt.Fprintln(w, "### Key Findings")
		fmt.Fprintln(w)
		fmt.Fprintln(w, "Critical issues requiring immediate attention:")
		fmt.Fprintln(w)

		for i, issue := range criticalIssues {
			riskIcon := r.getRiskIcon(issue.RiskLevel)
			fmt.Fprintf(w, "%d. %s **%s@%s** (%s)\n",
				i+1, riskIcon, issue.PackageName, issue.PackageVersion, issue.Ecosystem)
			fmt.Fprintf(w, "   - **[%s]** %s\n", issue.Severity, issue.Description)
			if issue.Evidence != "" {
				fmt.Fprintf(w, "   - *Evidence:* %s\n", issue.Evidence)
			}
			fmt.Fprintln(w)
		}
	}

	fmt.Fprintln(w, "---")
	fmt.Fprintln(w)

	// Detailed Findings
	fmt.Fprintln(w, "## Detailed Findings")
	fmt.Fprintln(w)

	for _, result := range r.results {
		r.printMarkdownPackage(w, result)
	}

	// Recommendations
	fmt.Fprintln(w, "## Recommendations")
	fmt.Fprintln(w)

	recommendations := r.generateRecommendations()
	if len(recommendations) == 0 {
		fmt.Fprintln(w, "✓ No critical issues found. Continue monitoring dependencies for changes.")
	} else {
		for i, rec := range recommendations {
			// Remove ANSI codes from recommendations
			cleanRec := strings.ReplaceAll(rec, ColorRed, "")
			cleanRec = strings.ReplaceAll(cleanRec, ColorYellow, "")
			cleanRec = strings.ReplaceAll(cleanRec, ColorGreen, "")
			cleanRec = strings.ReplaceAll(cleanRec, ColorBold, "")
			cleanRec = strings.ReplaceAll(cleanRec, ColorReset, "")
			fmt.Fprintf(w, "%d. %s\n", i+1, cleanRec)
			fmt.Fprintln(w)
		}
	}

	return nil
}

// printMarkdownPackage prints a package in markdown format
func (r *Reporter) printMarkdownPackage(w io.Writer, result models.AnalysisResult) {
	riskIcon := r.getRiskIcon(result.RiskLevel)

	fmt.Fprintf(w, "### %s %s@%s (%s)\n",
		riskIcon,
		result.Dependency.Name,
		result.Dependency.Version,
		result.Dependency.Ecosystem)
	fmt.Fprintln(w)

	fmt.Fprintf(w, "**Risk Level:** %s\n", result.RiskLevel)

	if result.SupplyChainScore != nil {
		fmt.Fprintf(w, "**Supply Chain Score:** %d/14 points (%s risk)\n",
			result.SupplyChainScore.TotalScore,
			result.SupplyChainScore.RiskLevel)
	}

	if result.RepositoryURL != "" {
		fmt.Fprintf(w, "**Repository:** %s\n", result.RepositoryURL)
	}

	fmt.Fprintf(w, "**Source Available:** %v\n", result.SourceCodeAvailable)

	if result.BuildInfrastructure != "" {
		fmt.Fprintf(w, "**Build Infrastructure:** %s\n", result.BuildInfrastructure)
	}

	// Supply chain scores
	if r.config.Verbose && result.SupplyChainScore != nil {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "#### Supply Chain Security Analysis")
		fmt.Fprintln(w)
		fmt.Fprintln(w, "| Category | Score | Risk | Status |")
		fmt.Fprintln(w, "|----------|-------|------|--------|")

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
			if cat.score.RiskPoints == 2 {
				scoreIcon = "🔴"
			} else if cat.score.RiskPoints == 1 {
				scoreIcon = "🟡"
			}

			verifiedIcon := "✓"
			if !cat.score.Verified {
				verifiedIcon = "?"
			}

			fmt.Fprintf(w, "| %s | %d/2 | %s | %s |\n",
				cat.name, cat.score.Score, scoreIcon, verifiedIcon)
		}
		fmt.Fprintln(w)
	}

	// Findings
	if len(result.Findings) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "#### Risk Findings")
		fmt.Fprintln(w)

		for _, finding := range result.Findings {
			fmt.Fprintf(w, "- **[%s]** %s\n", finding.Severity, finding.Description)
			if finding.Evidence != "" && r.config.Verbose {
				fmt.Fprintf(w, "  - *Evidence:* %s\n", finding.Evidence)
			}
		}
		fmt.Fprintln(w)
	}

	fmt.Fprintln(w, "---")
	fmt.Fprintln(w)
}
