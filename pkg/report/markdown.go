package report

import (
	"fmt"
	"io"
	"time"

	"github.com/metalstormbass/snyft/pkg/models"
)

func (r *Reporter) generateMarkdown() error {
	w := r.config.Writer

	// Title
	p(w, "# Snyft Supply Chain Risk Report")
	p(w, "")
	f(w, "**Generated:** %s\n", time.Now().Format("2006-01-02 15:04:05"))
	p(w, "")

	// Executive Summary
	p(w, "## Executive Summary")
	p(w, "")
	p(w, "Evaluates **compromise likelihood** through supply chain attacks—**not** known CVEs or code vulnerabilities.")
	p(w, "")

	// Scan overview
	f(w, "| Metric | Value |\n")
	f(w, "|--------|-------|\n")
	f(w, "| Packages Scanned | %d |\n", r.stats.TotalPackages)
	if r.stats.DirectDeps > 0 || r.stats.TransitiveDeps > 0 {
		f(w, "| Direct Dependencies | %d |\n", r.stats.DirectDeps)
		f(w, "| Transitive Dependencies | %d |\n", r.stats.TransitiveDeps)
	}
	f(w, "| Manifest Files | %d |\n", r.stats.ManifestFiles)
	f(w, "| Scan Path | `%s` |\n", r.stats.ScannedPath)
	p(w, "")

	// Risk distribution
	p(w, "### Risk Distribution")
	p(w, "")
	f(w, "| Level | Count | %% |\n")
	f(w, "|-------|------:|---:|\n")

	total := r.stats.TotalPackages
	pctStr := func(n int) string {
		if total == 0 {
			return "0.0"
		}
		return fmt.Sprintf("%.1f", float64(n)/float64(total)*100)
	}
	f(w, "| %s HIGH | %d | %s%% |\n", riskIcon("HIGH"), r.stats.HighRisk, pctStr(r.stats.HighRisk))
	f(w, "| %s MEDIUM | %d | %s%% |\n", riskIcon("MEDIUM"), r.stats.MediumRisk, pctStr(r.stats.MediumRisk))
	f(w, "| %s LOW | %d | %s%% |\n", riskIcon("LOW"), r.stats.LowRisk, pctStr(r.stats.LowRisk))
	p(w, "")

	overall := calculateOverallRisk(r.stats)
	duration := r.stats.EndTime.Sub(r.stats.StartTime)
	f(w, "**Overall Risk:** %s · **Duration:** %s\n", overall, formatDuration(duration))
	p(w, "")

	// Alerts
	if r.stats.HighRisk > 0 {
		f(w, "> ⚠️ **%d HIGH risk** package%s — immediate review recommended.\n\n", r.stats.HighRisk, pluralize(r.stats.HighRisk))
	}
	if r.stats.MediumRisk > 0 {
		f(w, "> ⚠️ **%d MEDIUM risk** package%s — monitoring recommended.\n\n", r.stats.MediumRisk, pluralize(r.stats.MediumRisk))
	}

	// Top findings
	criticalIssues := r.extractCriticalIssues(5)
	if len(criticalIssues) > 0 {
		p(w, "### Top Priority Findings")
		p(w, "")
		for i, issue := range criticalIssues {
			f(w, "%d. %s **%s@%s** (%s) — **[%s]** %s\n",
				i+1, riskIcon(issue.RiskLevel),
				issue.PackageName, issue.PackageVersion, issue.Ecosystem,
				issue.Severity, issue.Description)
			if issue.Evidence != "" {
				f(w, "   - *Evidence:* %s\n", issue.Evidence)
			}
		}
		p(w, "")
	}

	p(w, "---")
	p(w, "")

	// Detailed Findings
	p(w, "## Detailed Findings")
	p(w, "")
	for _, result := range r.sortedResults() {
		r.printMarkdownPackage(w, result)
	}

	// Key Risk Areas
	p(w, "## Key Risk Areas")
	p(w, "")
	areas := r.generateRiskAreas()
	if len(areas) == 0 {
		p(w, "✓ No critical supply chain risk factors identified.")
	} else {
		for i, area := range areas {
			f(w, "%d. **[%s]** %s\n", i+1, area.Tag, area.Summary)
			f(w, "   %s\n", area.Explanation)
			if len(area.Examples) > 0 {
				f(w, "   Affected: %s\n", joinExamples(area.Examples))
			}
			p(w, "")
		}
	}

	return nil
}

func (r *Reporter) printMarkdownPackage(w io.Writer, result models.AnalysisResult) {
	icon := riskIcon(result.RiskLevel)
	transitive := ""
	if result.Dependency.IsTransitive {
		transitive = " *(transitive)*"
	}

	f(w, "### %s %s@%s (%s)%s\n", icon, result.Dependency.Name, result.Dependency.DisplayVersion(),
		result.Dependency.Ecosystem, transitive)
	p(w, "")

	f(w, "**Risk:** %s", result.RiskLevel)
	if result.SupplyChainScore != nil {
		ms := maxScore(result.SupplyChainScore)
		f(w, " · **Score:** %d/%d", result.SupplyChainScore.TotalScore, ms)
	}
	p(w, "")

	if result.RepositoryURL != "" {
		f(w, "**Repo:** %s\n", result.RepositoryURL)
	}
	f(w, "**Source Available:** %v\n", result.SourceCodeAvailable)
	if result.BuildInfrastructure != "" {
		f(w, "**Build:** %s\n", result.BuildInfrastructure)
	}

	// Category scores (verbose)
	if r.config.Verbose && result.SupplyChainScore != nil {
		p(w, "")
		p(w, "#### Category Scores")
		p(w, "")
		p(w, "| Category | Score | Risk | Verified |")
		p(w, "|----------|------:|:----:|:--------:|")

		for _, cat := range categoryList(result.SupplyChainScore.CategoryScores) {
			if cat.Score.Skipped {
				f(w, "| %s | - | ⚪ | SKIP |\n", cat.Name)
				continue
			}
			icon := "🟢"
			switch cat.Score.RiskPoints {
			case 2:
				icon = "🔴"
			case 1:
				icon = "🟡"
			}
			verified := "✓"
			if !cat.Score.Verified {
				verified = "?"
			}
			f(w, "| %s | %d/2 | %s | %s |\n", cat.Name, cat.Score.Score, icon, verified)
		}
		p(w, "")
	}

	// Findings
	if len(result.Findings) > 0 {
		p(w, "")
		p(w, "#### Risk Findings")
		p(w, "")
		for _, finding := range result.Findings {
			f(w, "- **[%s]** %s\n", finding.Severity, finding.Description)
			if finding.SourceURL != "" {
				f(w, "  - *Source:* [%s](%s)\n", finding.SourceURL, finding.SourceURL)
			}
			if finding.Evidence != "" && r.config.Verbose {
				f(w, "  - *Evidence:* %s\n", finding.Evidence)
			}
			if finding.Methodology != "" && r.config.Verbose {
				f(w, "  - *Methodology:* %s\n", finding.Methodology)
			}
		}
		p(w, "")
	}

	p(w, "---")
	p(w, "")
}
