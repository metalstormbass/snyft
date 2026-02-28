package report

import (
	"fmt"
	"html"
	"io"
	"strings"
	"time"

	"github.com/metalstormbass/snyft/pkg/models"
)

// generateHTML generates an HTML report
func (r *Reporter) generateHTML() error {
	w := r.config.Writer

	// HTML header
	if _, err := fmt.Fprintln(w, "<!DOCTYPE html>"); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, "<html lang=\"en\">"); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, "<head>"); err != nil {
		return err
	}
	_, _ = fmt.Fprintln(w, "  <meta charset=\"UTF-8\">")
	_, _ = fmt.Fprintln(w, "  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">")
	_, _ = fmt.Fprintln(w, "  <title>Snyft Supply Chain Risk Report</title>")
	_, _ = fmt.Fprintln(w, "  <style>")
	r.printHTMLStyles(w)
	_, _ = fmt.Fprintln(w, "  </style>")
	_, _ = fmt.Fprintln(w, "</head>")
	_, _ = fmt.Fprintln(w, "<body>")

	// Header
	_, _ = fmt.Fprintln(w, "  <div class=\"container\">")
	_, _ = fmt.Fprintln(w, "    <header>")
	_, _ = fmt.Fprintln(w, "      <h1>Snyft Supply Chain Risk Report</h1>")
	if _, err := fmt.Fprintf(w, "      <p class=\"timestamp\">Generated: %s</p>\n", time.Now().Format("2006-01-02 15:04:05")); err != nil {
		return err
	}
	_, _ = fmt.Fprintln(w, "    </header>")

	// Executive Summary
	if err := r.printHTMLExecutiveSummary(w); err != nil {
		return err
	}

	// Detailed Findings
	_, _ = fmt.Fprintln(w, "    <section>")
	_, _ = fmt.Fprintln(w, "      <h2>Detailed Findings</h2>")

	for _, result := range r.results {
		r.printHTMLPackage(w, result)
	}

	_, _ = fmt.Fprintln(w, "    </section>")

	// Key Risk Areas
	_, _ = fmt.Fprintln(w, "    <section>")
	_, _ = fmt.Fprintln(w, "      <h2>Key Risk Areas</h2>")

	riskAreas := r.generateRiskAreas()
	if len(riskAreas) == 0 {
		_, _ = fmt.Fprintln(w, "      <p class=\"success\">✓ No critical supply chain risk factors identified.</p>")
	} else {
		_, _ = fmt.Fprintln(w, "      <ol class=\"recommendations\">")
		for _, area := range riskAreas {
			cleanArea := stripANSI(area)
			if _, err := fmt.Fprintf(w, "        <li>%s</li>\n", html.EscapeString(cleanArea)); err != nil {
				return err
			}
		}
		_, _ = fmt.Fprintln(w, "      </ol>")
	}

	_, _ = fmt.Fprintln(w, "    </section>")

	// Footer
	_, _ = fmt.Fprintln(w, "  </div>")
	_, _ = fmt.Fprintln(w, "</body>")
	_, _ = fmt.Fprintln(w, "</html>")

	return nil
}

// printHTMLStyles prints CSS styles
func (r *Reporter) printHTMLStyles(w io.Writer) {
	_, _ = fmt.Fprintln(w, `
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
      line-height: 1.5;
      color: #333;
      background: #f5f5f5;
      margin: 0;
      padding: 20px;
      font-size: 14px;
    }
    .container {
      max-width: 1000px;
      margin: 0 auto;
      background: white;
      padding: 30px;
      border-radius: 8px;
      box-shadow: 0 2px 10px rgba(0,0,0,0.1);
    }
    header {
      border-bottom: 3px solid #00a8e8;
      padding-bottom: 12px;
      margin-bottom: 20px;
    }
    h1 { color: #00a8e8; margin: 0 0 5px 0; font-size: 22px; }
    .timestamp { color: #666; margin: 0; font-size: 13px; }
    h2 { color: #333; border-bottom: 2px solid #eee; padding-bottom: 6px; margin-top: 20px; font-size: 18px; }
    h3 { font-size: 15px; margin: 10px 0 8px 0; }
    h4 { font-size: 14px; margin: 8px 0 6px 0; }
    .summary {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 12px;
      margin: 12px 0;
    }
    .summary-card {
      background: #f9f9f9;
      padding: 14px;
      border-radius: 5px;
      border-left: 4px solid #00a8e8;
    }
    .summary-card h3 {
      margin: 0 0 6px 0;
      font-size: 12px;
      color: #666;
      text-transform: uppercase;
    }
    .summary-card .value {
      font-size: 24px;
      font-weight: bold;
      color: #333;
    }
    .package {
      border: 1px solid #ddd;
      border-radius: 5px;
      padding: 14px;
      margin: 10px 0;
    }
    .package.high { border-left: 4px solid #dc3545; }
    .package.medium { border-left: 4px solid #ffc107; }
    .package.low { border-left: 4px solid #28a745; }
    .package-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 8px;
    }
    .package-name { font-size: 16px; font-weight: bold; color: #333; }
    .badge {
      display: inline-block;
      padding: 3px 8px;
      border-radius: 3px;
      font-size: 11px;
      font-weight: bold;
      text-transform: uppercase;
    }
    .badge.high { background: #dc3545; color: white; }
    .badge.medium { background: #ffc107; color: #333; }
    .badge.low { background: #28a745; color: white; }
    .package-details {
      display: flex;
      flex-wrap: wrap;
      gap: 8px 20px;
      margin: 6px 0;
      font-size: 13px;
      color: #555;
    }
    .detail-label { font-weight: bold; color: #666; }
    .category-scores { margin: 10px 0; }
    .category-scores table {
      width: 100%;
      border-collapse: collapse;
      font-size: 13px;
    }
    .category-scores th,
    .category-scores td {
      padding: 4px 8px;
      text-align: left;
      border-bottom: 1px solid #eee;
    }
    .category-scores th { background: #f9f9f9; font-weight: bold; }
    .findings { margin: 8px 0; }
    .finding {
      background: #fff3cd;
      border-left: 3px solid #ffc107;
      padding: 8px 10px;
      margin: 6px 0;
      border-radius: 3px;
      font-size: 13px;
    }
    .finding.high { background: #f8d7da; border-left-color: #dc3545; }
    .finding-severity { font-weight: bold; text-transform: uppercase; font-size: 11px; }
    .recommendations { padding-left: 20px; }
    .recommendations li { margin: 8px 0; line-height: 1.6; }
    .success { color: #28a745; font-weight: bold; }
  `)
}

// printHTMLExecutiveSummary prints the executive summary in HTML
func (r *Reporter) printHTMLExecutiveSummary(w io.Writer) error {
	_, _ = fmt.Fprintln(w, "    <section>")
	_, _ = fmt.Fprintln(w, "      <h2>Executive Summary</h2>")

	duration := r.stats.EndTime.Sub(r.stats.StartTime)
	overallRisk := r.calculateOverallRisk()
	riskColor := "#28a745"
	switch overallRisk {
	case "HIGH":
		riskColor = "#dc3545"
	case "MEDIUM":
		riskColor = "#ffc107"
	}

	_, _ = fmt.Fprintln(w, "      <div class=\"summary\">")
	if _, err := fmt.Fprintf(w, "        <div class=\"summary-card\">\n"); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(w, "          <h3>Overall Risk</h3>\n")
	_, _ = fmt.Fprintf(w, "          <div class=\"value\" style=\"color: %s;\">%s</div>\n", riskColor, overallRisk)
	_, _ = fmt.Fprintf(w, "        </div>\n")

	_, _ = fmt.Fprintf(w, "        <div class=\"summary-card\">\n")
	_, _ = fmt.Fprintf(w, "          <h3>Packages</h3>\n")
	_, _ = fmt.Fprintf(w, "          <div class=\"value\">%d</div>\n", r.stats.TotalPackages)
	if r.stats.TotalPackages > 0 {
		_, _ = fmt.Fprintf(w, "          <div style=\"font-size: 13px; color: #666; margin-top: 4px;\">")
		_, _ = fmt.Fprintf(w, "<span style=\"color: #dc3545;\">%d high</span> · ", r.stats.HighRisk)
		_, _ = fmt.Fprintf(w, "<span style=\"color: #b8860b;\">%d med</span> · ", r.stats.MediumRisk)
		_, _ = fmt.Fprintf(w, "<span style=\"color: #28a745;\">%d low</span>", r.stats.LowRisk)
		_, _ = fmt.Fprintf(w, "</div>\n")
		if r.stats.DirectDeps > 0 || r.stats.TransitiveDeps > 0 {
			_, _ = fmt.Fprintf(w, "          <div style=\"font-size: 12px; color: #888; margin-top: 2px;\">%d direct · %d transitive</div>\n",
				r.stats.DirectDeps, r.stats.TransitiveDeps)
		}
	}
	_, _ = fmt.Fprintf(w, "        </div>\n")

	_, _ = fmt.Fprintf(w, "        <div class=\"summary-card\">\n")
	_, _ = fmt.Fprintf(w, "          <h3>Scan Duration</h3>\n")
	_, _ = fmt.Fprintf(w, "          <div class=\"value\" style=\"font-size: 20px;\">%s</div>\n", formatDuration(duration))
	_, _ = fmt.Fprintf(w, "        </div>\n")

	_, _ = fmt.Fprintln(w, "      </div>")

	// Key Findings - Critical Issues
	criticalIssues := r.extractCriticalIssues(5)
	if len(criticalIssues) > 0 {
		_, _ = fmt.Fprintln(w, "      <div style=\"margin-top: 15px;\">")
		_, _ = fmt.Fprintln(w, "        <h3>Top Priority Findings</h3>")

		for i, issue := range criticalIssues {
			issueClass := "medium"
			if issue.RiskLevel == "HIGH" {
				issueClass = "high"
			}

			_, _ = fmt.Fprintf(w, "        <div class=\"finding %s\">\n", issueClass)
			_, _ = fmt.Fprintf(w, "          <span class=\"finding-severity\">[%s]</span> ",
				html.EscapeString(issue.Severity))
			_, _ = fmt.Fprintf(w, "<strong>%d. %s@%s</strong> <span style=\"color: #666;\">(%s)</span> — %s\n",
				i+1, html.EscapeString(issue.PackageName), html.EscapeString(issue.PackageVersion),
				issue.Ecosystem, html.EscapeString(issue.Description))
			_, _ = fmt.Fprintln(w, "        </div>")
		}

		_, _ = fmt.Fprintln(w, "      </div>")
	}

	_, _ = fmt.Fprintln(w, "    </section>")
	return nil
}

// printHTMLPackage prints a package in HTML format
func (r *Reporter) printHTMLPackage(w io.Writer, result models.AnalysisResult) {
	riskClass := "low"
	switch result.RiskLevel {
	case "HIGH":
		riskClass = "high"
	case "MEDIUM":
		riskClass = "medium"
	}

	_, _ = fmt.Fprintf(w, "      <div class=\"package %s\">\n", riskClass)
	_, _ = fmt.Fprintln(w, "        <div class=\"package-header\">")
	transitiveLabel := ""
	if result.Dependency.IsTransitive {
		transitiveLabel = " <span style=\"font-size: 11px; color: #888; font-weight: normal;\">(transitive)</span>"
	}
	_, _ = fmt.Fprintf(w, "          <div class=\"package-name\">%s@%s%s</div>\n",
		html.EscapeString(result.Dependency.Name),
		html.EscapeString(result.Dependency.Version),
		transitiveLabel)
	_, _ = fmt.Fprintf(w, "          <span class=\"badge %s\">%s</span>\n", riskClass, result.RiskLevel)
	_, _ = fmt.Fprintln(w, "        </div>")

	_, _ = fmt.Fprintln(w, "        <div class=\"package-details\">")
	_, _ = fmt.Fprintf(w, "          <span><span class=\"detail-label\">Ecosystem:</span> %s</span>\n",
		result.Dependency.Ecosystem)

	if result.SupplyChainScore != nil {
		scoreStr := fmt.Sprintf("%d/22", result.SupplyChainScore.TotalScore)
		_, _ = fmt.Fprintf(w, "          <span><span class=\"detail-label\">Score:</span> %s</span>\n", scoreStr)
	}

	if result.RepositoryURL != "" {
		_, _ = fmt.Fprintf(w, "          <span><span class=\"detail-label\">Repo:</span> <a href=\"%s\" target=\"_blank\">link</a></span>\n",
			html.EscapeString(result.RepositoryURL))
	}

	sourceAvailable := "No"
	if result.SourceCodeAvailable {
		sourceAvailable = "Yes"
	}
	_, _ = fmt.Fprintf(w, "          <span><span class=\"detail-label\">Source:</span> %s</span>\n",
		sourceAvailable)

	_, _ = fmt.Fprintln(w, "        </div>")

	// Category scores
	if r.config.Verbose && result.SupplyChainScore != nil {
		_, _ = fmt.Fprintln(w, "        <div class=\"category-scores\">")
		_, _ = fmt.Fprintln(w, "          <h4>Supply Chain Security Analysis</h4>")
		_, _ = fmt.Fprintln(w, "          <table>")
		_, _ = fmt.Fprintln(w, "            <tr><th>Category</th><th>Score</th><th>Risk</th><th>Status</th></tr>")

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
			{"Governance", result.SupplyChainScore.CategoryScores.Governance},
			{"Release Security", result.SupplyChainScore.CategoryScores.ReleaseSecurity},
			{"Package Maturity", result.SupplyChainScore.CategoryScores.PackageMaturity},
			{"CI Pipeline Security", result.SupplyChainScore.CategoryScores.CIPipelineSecurity},
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

			_, _ = fmt.Fprintf(w, "            <tr><td>%s</td><td>%d/2</td><td>%s</td><td>%s</td></tr>\n",
				html.EscapeString(cat.name), cat.score.Score, scoreIcon, verifiedIcon)
		}

		_, _ = fmt.Fprintln(w, "          </table>")
		_, _ = fmt.Fprintln(w, "        </div>")
	}

	// Findings
	if len(result.Findings) > 0 {
		_, _ = fmt.Fprintln(w, "        <div class=\"findings\">")
		_, _ = fmt.Fprintln(w, "          <h4>Risk Findings</h4>")

		for _, finding := range result.Findings {
			findingClass := "medium"
			if finding.Severity == "HIGH" || finding.Severity == "CRITICAL" {
				findingClass = "high"
			}

			_, _ = fmt.Fprintf(w, "          <div class=\"finding %s\">\n", findingClass)
			_, _ = fmt.Fprintf(w, "            <span class=\"finding-severity\">[%s]</span> %s\n",
				html.EscapeString(finding.Severity),
				html.EscapeString(finding.Description))

			if finding.Evidence != "" && r.config.Verbose {
				_, _ = fmt.Fprintf(w, "            <div style=\"margin-top: 5px; font-size: 12px; color: #666;\">Evidence: %s</div>\n",
					html.EscapeString(finding.Evidence))
			}

			if finding.Methodology != "" && r.config.Verbose {
				_, _ = fmt.Fprintf(w, "            <div style=\"margin-top: 3px; font-size: 11px; color: #888;\">Methodology: %s</div>\n",
					html.EscapeString(finding.Methodology))
			}

			_, _ = fmt.Fprintln(w, "          </div>")
		}

		_, _ = fmt.Fprintln(w, "        </div>")
	}

	_, _ = fmt.Fprintln(w, "      </div>")
}

// stripANSI removes ANSI color codes from a string
func stripANSI(s string) string {
	s = strings.ReplaceAll(s, ColorRed, "")
	s = strings.ReplaceAll(s, ColorYellow, "")
	s = strings.ReplaceAll(s, ColorGreen, "")
	s = strings.ReplaceAll(s, ColorCyan, "")
	s = strings.ReplaceAll(s, ColorBold, "")
	s = strings.ReplaceAll(s, ColorDim, "")
	s = strings.ReplaceAll(s, ColorReset, "")
	return s
}
