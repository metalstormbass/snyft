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
	fmt.Fprintln(w, "<!DOCTYPE html>")
	fmt.Fprintln(w, "<html lang=\"en\">")
	fmt.Fprintln(w, "<head>")
	fmt.Fprintln(w, "  <meta charset=\"UTF-8\">")
	fmt.Fprintln(w, "  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">")
	fmt.Fprintln(w, "  <title>SNYFT Supply Chain Security Report</title>")
	fmt.Fprintln(w, "  <style>")
	r.printHTMLStyles(w)
	fmt.Fprintln(w, "  </style>")
	fmt.Fprintln(w, "</head>")
	fmt.Fprintln(w, "<body>")

	// Header
	fmt.Fprintln(w, "  <div class=\"container\">")
	fmt.Fprintln(w, "    <header>")
	fmt.Fprintln(w, "      <h1>SNYFT Supply Chain Security Report</h1>")
	fmt.Fprintf(w, "      <p class=\"timestamp\">Generated: %s</p>\n", time.Now().Format("2006-01-02 15:04:05"))
	fmt.Fprintln(w, "    </header>")

	// Executive Summary
	r.printHTMLExecutiveSummary(w)

	// Detailed Findings
	fmt.Fprintln(w, "    <section>")
	fmt.Fprintln(w, "      <h2>Detailed Findings</h2>")

	for _, result := range r.results {
		r.printHTMLPackage(w, result)
	}

	fmt.Fprintln(w, "    </section>")

	// Recommendations
	fmt.Fprintln(w, "    <section>")
	fmt.Fprintln(w, "      <h2>Recommendations</h2>")

	recommendations := r.generateRecommendations()
	if len(recommendations) == 0 {
		fmt.Fprintln(w, "      <p class=\"success\">✓ No critical issues found. Continue monitoring dependencies for changes.</p>")
	} else {
		fmt.Fprintln(w, "      <ol class=\"recommendations\">")
		for _, rec := range recommendations {
			cleanRec := stripANSI(rec)
			fmt.Fprintf(w, "        <li>%s</li>\n", html.EscapeString(cleanRec))
		}
		fmt.Fprintln(w, "      </ol>")
	}

	fmt.Fprintln(w, "    </section>")

	// Footer
	fmt.Fprintln(w, "  </div>")
	fmt.Fprintln(w, "</body>")
	fmt.Fprintln(w, "</html>")

	return nil
}

// printHTMLStyles prints CSS styles
func (r *Reporter) printHTMLStyles(w io.Writer) {
	fmt.Fprintln(w, `
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
      line-height: 1.6;
      color: #333;
      background: #f5f5f5;
      margin: 0;
      padding: 20px;
    }
    .container {
      max-width: 1200px;
      margin: 0 auto;
      background: white;
      padding: 40px;
      border-radius: 8px;
      box-shadow: 0 2px 10px rgba(0,0,0,0.1);
    }
    header {
      border-bottom: 3px solid #00a8e8;
      padding-bottom: 20px;
      margin-bottom: 30px;
    }
    h1 {
      color: #00a8e8;
      margin: 0 0 10px 0;
    }
    .timestamp {
      color: #666;
      margin: 0;
    }
    h2 {
      color: #333;
      border-bottom: 2px solid #eee;
      padding-bottom: 10px;
      margin-top: 30px;
    }
    .summary {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 20px;
      margin: 20px 0;
    }
    .summary-card {
      background: #f9f9f9;
      padding: 20px;
      border-radius: 5px;
      border-left: 4px solid #00a8e8;
    }
    .summary-card h3 {
      margin: 0 0 10px 0;
      font-size: 14px;
      color: #666;
      text-transform: uppercase;
    }
    .summary-card .value {
      font-size: 28px;
      font-weight: bold;
      color: #333;
    }
    .risk-distribution {
      margin: 20px 0;
    }
    .risk-bar {
      display: flex;
      align-items: center;
      margin: 10px 0;
    }
    .risk-label {
      width: 100px;
      font-weight: bold;
    }
    .risk-label.high { color: #dc3545; }
    .risk-label.medium { color: #ffc107; }
    .risk-label.low { color: #28a745; }
    .risk-count {
      width: 60px;
      text-align: right;
      margin-right: 10px;
    }
    .risk-percentage {
      color: #666;
      font-size: 14px;
    }
    .package {
      border: 1px solid #ddd;
      border-radius: 5px;
      padding: 20px;
      margin: 20px 0;
    }
    .package.high { border-left: 5px solid #dc3545; }
    .package.medium { border-left: 5px solid #ffc107; }
    .package.low { border-left: 5px solid #28a745; }
    .package-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 15px;
    }
    .package-name {
      font-size: 20px;
      font-weight: bold;
      color: #333;
    }
    .badge {
      display: inline-block;
      padding: 5px 12px;
      border-radius: 3px;
      font-size: 12px;
      font-weight: bold;
      text-transform: uppercase;
    }
    .badge.high { background: #dc3545; color: white; }
    .badge.medium { background: #ffc107; color: #333; }
    .badge.low { background: #28a745; color: white; }
    .package-details {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
      gap: 15px;
      margin: 15px 0;
    }
    .detail-item {
      font-size: 14px;
    }
    .detail-label {
      font-weight: bold;
      color: #666;
    }
    .category-scores {
      margin: 15px 0;
    }
    .category-scores table {
      width: 100%;
      border-collapse: collapse;
      font-size: 14px;
    }
    .category-scores th,
    .category-scores td {
      padding: 8px;
      text-align: left;
      border-bottom: 1px solid #eee;
    }
    .category-scores th {
      background: #f9f9f9;
      font-weight: bold;
    }
    .findings {
      margin: 15px 0;
    }
    .finding {
      background: #fff3cd;
      border-left: 3px solid #ffc107;
      padding: 10px;
      margin: 10px 0;
      border-radius: 3px;
    }
    .finding.high {
      background: #f8d7da;
      border-left-color: #dc3545;
    }
    .finding-severity {
      font-weight: bold;
      text-transform: uppercase;
      font-size: 12px;
    }
    .recommendations {
      padding-left: 20px;
    }
    .recommendations li {
      margin: 15px 0;
      line-height: 1.8;
    }
    .success {
      color: #28a745;
      font-weight: bold;
    }
  `)
}

// printHTMLExecutiveSummary prints the executive summary in HTML
func (r *Reporter) printHTMLExecutiveSummary(w io.Writer) {
	fmt.Fprintln(w, "    <section>")
	fmt.Fprintln(w, "      <h2>Executive Summary</h2>")

	duration := r.stats.EndTime.Sub(r.stats.StartTime)

	fmt.Fprintln(w, "      <div class=\"summary\">")
	fmt.Fprintf(w, "        <div class=\"summary-card\">\n")
	fmt.Fprintf(w, "          <h3>Total Packages</h3>\n")
	fmt.Fprintf(w, "          <div class=\"value\">%d</div>\n", r.stats.TotalPackages)
	fmt.Fprintf(w, "        </div>\n")

	fmt.Fprintf(w, "        <div class=\"summary-card\">\n")
	fmt.Fprintf(w, "          <h3>High Risk</h3>\n")
	fmt.Fprintf(w, "          <div class=\"value\" style=\"color: #dc3545;\">%d</div>\n", r.stats.HighRisk)
	fmt.Fprintf(w, "        </div>\n")

	fmt.Fprintf(w, "        <div class=\"summary-card\">\n")
	fmt.Fprintf(w, "          <h3>Medium Risk</h3>\n")
	fmt.Fprintf(w, "          <div class=\"value\" style=\"color: #ffc107;\">%d</div>\n", r.stats.MediumRisk)
	fmt.Fprintf(w, "        </div>\n")

	fmt.Fprintf(w, "        <div class=\"summary-card\">\n")
	fmt.Fprintf(w, "          <h3>Low Risk</h3>\n")
	fmt.Fprintf(w, "          <div class=\"value\" style=\"color: #28a745;\">%d</div>\n", r.stats.LowRisk)
	fmt.Fprintf(w, "        </div>\n")

	fmt.Fprintf(w, "        <div class=\"summary-card\">\n")
	fmt.Fprintf(w, "          <h3>Scan Duration</h3>\n")
	fmt.Fprintf(w, "          <div class=\"value\" style=\"font-size: 20px;\">%s</div>\n", formatDuration(duration))
	fmt.Fprintf(w, "        </div>\n")

	fmt.Fprintf(w, "        <div class=\"summary-card\">\n")
	fmt.Fprintf(w, "          <h3>Overall Risk</h3>\n")
	overallRisk := r.calculateOverallRisk()
	riskColor := "#28a745"
	if overallRisk == "HIGH" {
		riskColor = "#dc3545"
	} else if overallRisk == "MEDIUM" {
		riskColor = "#ffc107"
	}
	fmt.Fprintf(w, "          <div class=\"value\" style=\"color: %s;\">%s</div>\n", riskColor, overallRisk)
	fmt.Fprintf(w, "        </div>\n")

	fmt.Fprintln(w, "      </div>")

	// Risk distribution
	fmt.Fprintln(w, "      <div class=\"risk-distribution\">")
	fmt.Fprintln(w, "        <h3>Risk Distribution</h3>")

	if r.stats.TotalPackages > 0 {
		fmt.Fprintln(w, "        <div class=\"risk-bar\">")
		fmt.Fprintln(w, "          <span class=\"risk-label high\">HIGH</span>")
		fmt.Fprintf(w, "          <span class=\"risk-count\">%d</span>\n", r.stats.HighRisk)
		fmt.Fprintf(w, "          <span class=\"risk-percentage\">(%.1f%%)</span>\n",
			float64(r.stats.HighRisk)/float64(r.stats.TotalPackages)*100)
		fmt.Fprintln(w, "        </div>")

		fmt.Fprintln(w, "        <div class=\"risk-bar\">")
		fmt.Fprintln(w, "          <span class=\"risk-label medium\">MEDIUM</span>")
		fmt.Fprintf(w, "          <span class=\"risk-count\">%d</span>\n", r.stats.MediumRisk)
		fmt.Fprintf(w, "          <span class=\"risk-percentage\">(%.1f%%)</span>\n",
			float64(r.stats.MediumRisk)/float64(r.stats.TotalPackages)*100)
		fmt.Fprintln(w, "        </div>")

		fmt.Fprintln(w, "        <div class=\"risk-bar\">")
		fmt.Fprintln(w, "          <span class=\"risk-label low\">LOW</span>")
		fmt.Fprintf(w, "          <span class=\"risk-count\">%d</span>\n", r.stats.LowRisk)
		fmt.Fprintf(w, "          <span class=\"risk-percentage\">(%.1f%%)</span>\n",
			float64(r.stats.LowRisk)/float64(r.stats.TotalPackages)*100)
		fmt.Fprintln(w, "        </div>")
	}

	fmt.Fprintln(w, "      </div>")
	fmt.Fprintln(w, "    </section>")
}

// printHTMLPackage prints a package in HTML format
func (r *Reporter) printHTMLPackage(w io.Writer, result models.AnalysisResult) {
	riskClass := "low"
	if result.RiskLevel == "HIGH" {
		riskClass = "high"
	} else if result.RiskLevel == "MEDIUM" {
		riskClass = "medium"
	}

	fmt.Fprintf(w, "      <div class=\"package %s\">\n", riskClass)
	fmt.Fprintln(w, "        <div class=\"package-header\">")
	fmt.Fprintf(w, "          <div class=\"package-name\">%s@%s</div>\n",
		html.EscapeString(result.Dependency.Name),
		html.EscapeString(result.Dependency.Version))
	fmt.Fprintf(w, "          <span class=\"badge %s\">%s</span>\n", riskClass, result.RiskLevel)
	fmt.Fprintln(w, "        </div>")

	fmt.Fprintln(w, "        <div class=\"package-details\">")
	fmt.Fprintf(w, "          <div class=\"detail-item\"><span class=\"detail-label\">Ecosystem:</span> %s</div>\n",
		result.Dependency.Ecosystem)

	if result.SupplyChainScore != nil {
		fmt.Fprintf(w, "          <div class=\"detail-item\"><span class=\"detail-label\">Supply Chain Score:</span> %d/14 points</div>\n",
			result.SupplyChainScore.TotalScore)
	}

	if result.RepositoryURL != "" {
		fmt.Fprintf(w, "          <div class=\"detail-item\"><span class=\"detail-label\">Repository:</span> <a href=\"%s\" target=\"_blank\">%s</a></div>\n",
			html.EscapeString(result.RepositoryURL),
			html.EscapeString(result.RepositoryURL))
	}

	sourceAvailable := "No"
	if result.SourceCodeAvailable {
		sourceAvailable = "Yes"
	}
	fmt.Fprintf(w, "          <div class=\"detail-item\"><span class=\"detail-label\">Source Available:</span> %s</div>\n",
		sourceAvailable)

	fmt.Fprintln(w, "        </div>")

	// Category scores
	if r.config.Verbose && result.SupplyChainScore != nil {
		fmt.Fprintln(w, "        <div class=\"category-scores\">")
		fmt.Fprintln(w, "          <h4>Supply Chain Security Analysis</h4>")
		fmt.Fprintln(w, "          <table>")
		fmt.Fprintln(w, "            <tr><th>Category</th><th>Score</th><th>Risk</th><th>Status</th></tr>")

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

			fmt.Fprintf(w, "            <tr><td>%s</td><td>%d/2</td><td>%s</td><td>%s</td></tr>\n",
				html.EscapeString(cat.name), cat.score.Score, scoreIcon, verifiedIcon)
		}

		fmt.Fprintln(w, "          </table>")
		fmt.Fprintln(w, "        </div>")
	}

	// Findings
	if len(result.Findings) > 0 {
		fmt.Fprintln(w, "        <div class=\"findings\">")
		fmt.Fprintln(w, "          <h4>Risk Findings</h4>")

		for _, finding := range result.Findings {
			findingClass := "medium"
			if finding.Severity == "HIGH" || finding.Severity == "CRITICAL" {
				findingClass = "high"
			}

			fmt.Fprintf(w, "          <div class=\"finding %s\">\n", findingClass)
			fmt.Fprintf(w, "            <span class=\"finding-severity\">[%s]</span> %s\n",
				html.EscapeString(finding.Severity),
				html.EscapeString(finding.Description))

			if finding.Evidence != "" && r.config.Verbose {
				fmt.Fprintf(w, "            <div style=\"margin-top: 5px; font-size: 12px; color: #666;\">Evidence: %s</div>\n",
					html.EscapeString(finding.Evidence))
			}

			fmt.Fprintln(w, "          </div>")
		}

		fmt.Fprintln(w, "        </div>")
	}

	fmt.Fprintln(w, "      </div>")
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
