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
	_, _ = fmt.Fprintln(w, "  <title>SNYFT Supply Chain Security Report</title>")
	_, _ = fmt.Fprintln(w, "  <style>")
	r.printHTMLStyles(w)
	_, _ = fmt.Fprintln(w, "  </style>")
	_, _ = fmt.Fprintln(w, "</head>")
	_, _ = fmt.Fprintln(w, "<body>")

	// Header
	_, _ = fmt.Fprintln(w, "  <div class=\"container\">")
	_, _ = fmt.Fprintln(w, "    <header>")
	_, _ = fmt.Fprintln(w, "      <h1>SNYFT Supply Chain Security Report</h1>")
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

	// Recommendations
	_, _ = fmt.Fprintln(w, "    <section>")
	_, _ = fmt.Fprintln(w, "      <h2>Recommendations</h2>")

	recommendations := r.generateRecommendations()
	if len(recommendations) == 0 {
		_, _ = fmt.Fprintln(w, "      <p class=\"success\">✓ No critical issues found. Continue monitoring dependencies for changes.</p>")
	} else {
		_, _ = fmt.Fprintln(w, "      <ol class=\"recommendations\">")
		for _, rec := range recommendations {
			cleanRec := stripANSI(rec)
			if _, err := fmt.Fprintf(w, "        <li>%s</li>\n", html.EscapeString(cleanRec)); err != nil {
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
func (r *Reporter) printHTMLExecutiveSummary(w io.Writer) error {
	_, _ = fmt.Fprintln(w, "    <section>")
	_, _ = fmt.Fprintln(w, "      <h2>Executive Summary</h2>")

	// Risk Assessment Overview
	_, _ = fmt.Fprintln(w, "      <div style=\"background: #f0f8ff; border-left: 4px solid #00a8e8; padding: 15px; margin: 20px 0; border-radius: 5px;\">")
	_, _ = fmt.Fprintln(w, "        <h3 style=\"margin-top: 0;\">Supply Chain Risk Assessment</h3>")
	_, _ = fmt.Fprintln(w, "        <p>This report evaluates the <strong>likelihood that software packages could be compromised</strong> through supply chain attacks. ")
	_, _ = fmt.Fprintln(w, "        It assesses risk factors such as maintainer practices, ownership changes, and build integrity—<strong>NOT</strong> known CVEs or code vulnerabilities.</p>")
	_, _ = fmt.Fprintln(w, "      </div>")

	duration := r.stats.EndTime.Sub(r.stats.StartTime)

	_, _ = fmt.Fprintln(w, "      <div class=\"summary\">")
	if _, err := fmt.Fprintf(w, "        <div class=\"summary-card\">\n"); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(w, "          <h3>Total Packages</h3>\n")
	_, _ = fmt.Fprintf(w, "          <div class=\"value\">%d</div>\n", r.stats.TotalPackages)
	_, _ = fmt.Fprintf(w, "        </div>\n")

	_, _ = fmt.Fprintf(w, "        <div class=\"summary-card\">\n")
	_, _ = fmt.Fprintf(w, "          <h3>High Risk</h3>\n")
	_, _ = fmt.Fprintf(w, "          <div class=\"value\" style=\"color: #dc3545;\">%d</div>\n", r.stats.HighRisk)
	_, _ = fmt.Fprintf(w, "        </div>\n")

	_, _ = fmt.Fprintf(w, "        <div class=\"summary-card\">\n")
	_, _ = fmt.Fprintf(w, "          <h3>Medium Risk</h3>\n")
	_, _ = fmt.Fprintf(w, "          <div class=\"value\" style=\"color: #ffc107;\">%d</div>\n", r.stats.MediumRisk)
	_, _ = fmt.Fprintf(w, "        </div>\n")

	_, _ = fmt.Fprintf(w, "        <div class=\"summary-card\">\n")
	_, _ = fmt.Fprintf(w, "          <h3>Low Risk</h3>\n")
	_, _ = fmt.Fprintf(w, "          <div class=\"value\" style=\"color: #28a745;\">%d</div>\n", r.stats.LowRisk)
	_, _ = fmt.Fprintf(w, "        </div>\n")

	_, _ = fmt.Fprintf(w, "        <div class=\"summary-card\">\n")
	_, _ = fmt.Fprintf(w, "          <h3>Scan Duration</h3>\n")
	_, _ = fmt.Fprintf(w, "          <div class=\"value\" style=\"font-size: 20px;\">%s</div>\n", formatDuration(duration))
	_, _ = fmt.Fprintf(w, "        </div>\n")

	_, _ = fmt.Fprintf(w, "        <div class=\"summary-card\">\n")
	_, _ = fmt.Fprintf(w, "          <h3>Overall Risk</h3>\n")
	overallRisk := r.calculateOverallRisk()
	riskColor := "#28a745"
	switch overallRisk {
	case "HIGH":
		riskColor = "#dc3545"
	case "MEDIUM":
		riskColor = "#ffc107"
	}
	_, _ = fmt.Fprintf(w, "          <div class=\"value\" style=\"color: %s;\">%s</div>\n", riskColor, overallRisk)
	_, _ = fmt.Fprintf(w, "        </div>\n")

	_, _ = fmt.Fprintln(w, "      </div>")

	// Risk distribution
	_, _ = fmt.Fprintln(w, "      <div class=\"risk-distribution\">")
	_, _ = fmt.Fprintln(w, "        <h3>Risk Distribution</h3>")

	if r.stats.TotalPackages > 0 {
		_, _ = fmt.Fprintln(w, "        <div class=\"risk-bar\">")
		_, _ = fmt.Fprintln(w, "          <span class=\"risk-label high\">HIGH</span>")
		_, _ = fmt.Fprintf(w, "          <span class=\"risk-count\">%d</span>\n", r.stats.HighRisk)
		_, _ = fmt.Fprintf(w, "          <span class=\"risk-percentage\">(%.1f%%)</span>\n",
			float64(r.stats.HighRisk)/float64(r.stats.TotalPackages)*100)
		_, _ = fmt.Fprintln(w, "        </div>")

		_, _ = fmt.Fprintln(w, "        <div class=\"risk-bar\">")
		_, _ = fmt.Fprintln(w, "          <span class=\"risk-label medium\">MEDIUM</span>")
		_, _ = fmt.Fprintf(w, "          <span class=\"risk-count\">%d</span>\n", r.stats.MediumRisk)
		_, _ = fmt.Fprintf(w, "          <span class=\"risk-percentage\">(%.1f%%)</span>\n",
			float64(r.stats.MediumRisk)/float64(r.stats.TotalPackages)*100)
		_, _ = fmt.Fprintln(w, "        </div>")

		_, _ = fmt.Fprintln(w, "        <div class=\"risk-bar\">")
		_, _ = fmt.Fprintln(w, "          <span class=\"risk-label low\">LOW</span>")
		_, _ = fmt.Fprintf(w, "          <span class=\"risk-count\">%d</span>\n", r.stats.LowRisk)
		_, _ = fmt.Fprintf(w, "          <span class=\"risk-percentage\">(%.1f%%)</span>\n",
			float64(r.stats.LowRisk)/float64(r.stats.TotalPackages)*100)
		_, _ = fmt.Fprintln(w, "        </div>")
	}

	_, _ = fmt.Fprintln(w, "      </div>")

	// Risk Impact Summary
	if r.stats.HighRisk > 0 || r.stats.MediumRisk > 0 {
		_, _ = fmt.Fprintln(w, "      <div style=\"margin-top: 20px;\">")
		_, _ = fmt.Fprintln(w, "        <h3>Risk Impact Summary</h3>")
		if r.stats.HighRisk > 0 {
			_, _ = fmt.Fprintf(w, "        <div style=\"background: #fff3cd; border-left: 4px solid #dc3545; padding: 15px; margin: 10px 0; border-radius: 5px;\">\n")
			_, _ = fmt.Fprintf(w, "          <strong style=\"color: #dc3545;\">⚠️ ATTENTION REQUIRED:</strong> %d package%s identified with HIGH supply chain risk.<br>\n",
				r.stats.HighRisk, pluralize(r.stats.HighRisk))
			_, _ = fmt.Fprintln(w, "          These packages exhibit patterns commonly associated with compromised dependencies and require immediate review.")
			_, _ = fmt.Fprintln(w, "        </div>")
		}
		if r.stats.MediumRisk > 0 {
			_, _ = fmt.Fprintf(w, "        <div style=\"background: #fff9e6; border-left: 4px solid #ffc107; padding: 15px; margin: 10px 0; border-radius: 5px;\">\n")
			_, _ = fmt.Fprintf(w, "          <strong style=\"color: #ffc107;\">⚠️ MONITORING RECOMMENDED:</strong> %d package%s with MEDIUM risk factors.<br>\n",
				r.stats.MediumRisk, pluralize(r.stats.MediumRisk))
			_, _ = fmt.Fprintln(w, "          These packages show some concerning patterns that warrant closer monitoring.")
			_, _ = fmt.Fprintln(w, "        </div>")
		}
		_, _ = fmt.Fprintln(w, "      </div>")
	}

	// Key Findings - Critical Issues
	criticalIssues := r.extractCriticalIssues(5)
	if len(criticalIssues) > 0 {
		_, _ = fmt.Fprintln(w, "      <div style=\"margin-top: 30px;\">")
		_, _ = fmt.Fprintln(w, "        <h3>Top Priority Findings</h3>")
		_, _ = fmt.Fprintln(w, "        <p style=\"color: #666; margin-bottom: 15px;\">The following issues represent the highest supply chain compromise risks:</p>")

		for i, issue := range criticalIssues {
			issueClass := "medium"
			if issue.RiskLevel == "HIGH" {
				issueClass = "high"
			}

			_, _ = fmt.Fprintf(w, "        <div class=\"finding %s\" style=\"margin: 10px 0;\">\n", issueClass)
			_, _ = fmt.Fprintf(w, "          <div style=\"font-weight: bold; margin-bottom: 5px;\">%d. %s@%s <span style=\"color: #666; font-weight: normal;\">(%s)</span></div>\n",
				i+1, html.EscapeString(issue.PackageName), html.EscapeString(issue.PackageVersion), issue.Ecosystem)
			_, _ = fmt.Fprintf(w, "          <div><span class=\"finding-severity\">[%s SEVERITY]</span> %s</div>\n",
				html.EscapeString(issue.Severity), html.EscapeString(issue.Description))
			if issue.Evidence != "" {
				_, _ = fmt.Fprintf(w, "          <div style=\"margin-top: 5px; font-size: 12px; color: #666;\"><strong>Evidence:</strong> %s</div>\n",
					html.EscapeString(issue.Evidence))
			}
			impact := r.getRiskImpactDescription(issue.Severity)
			if impact != "" {
				_, _ = fmt.Fprintf(w, "          <div style=\"margin-top: 5px; font-size: 12px; color: #666; font-style: italic;\"><strong>Impact:</strong> %s</div>\n",
					html.EscapeString(impact))
			}
			_, _ = fmt.Fprintln(w, "        </div>")
		}

		_, _ = fmt.Fprintln(w, "      </div>")
	}

	// AI Executive Summary
	r.printHTMLAIExecutiveSummary(w)

	_, _ = fmt.Fprintln(w, "    </section>")
	return nil
}

// printHTMLAIExecutiveSummary prints AI-powered executive insights in HTML
func (r *Reporter) printHTMLAIExecutiveSummary(w io.Writer) {
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

	_, _ = fmt.Fprintln(w, "      <div style=\"margin-top: 30px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 25px; border-radius: 10px;\">")
	_, _ = fmt.Fprintln(w, "        <h3 style=\"margin-top: 0; color: white;\">🤖 AI-Powered Risk Assessment</h3>")
	_, _ = fmt.Fprintf(w, "        <p style=\"font-size: 16px; line-height: 1.8;\">%s</p>\n", html.EscapeString(executiveSummary.Summary))

	// Key Risks
	if len(executiveSummary.KeyRisks) > 0 {
		_, _ = fmt.Fprintln(w, "        <div style=\"background: rgba(255,255,255,0.1); padding: 15px; border-radius: 5px; margin-top: 15px;\">")
		_, _ = fmt.Fprintln(w, "          <h4 style=\"margin-top: 0; color: white;\">Key Risks Identified:</h4>")
		_, _ = fmt.Fprintln(w, "          <ul style=\"margin: 10px 0; padding-left: 20px;\">")
		for _, risk := range executiveSummary.KeyRisks {
			_, _ = fmt.Fprintf(w, "            <li style=\"margin: 8px 0;\">%s</li>\n", html.EscapeString(risk))
		}
		_, _ = fmt.Fprintln(w, "          </ul>")
		_, _ = fmt.Fprintln(w, "        </div>")
	}

	// Business Impact
	if executiveSummary.BusinessImpact != "" {
		_, _ = fmt.Fprintln(w, "        <div style=\"background: rgba(255,255,255,0.1); padding: 15px; border-radius: 5px; margin-top: 15px;\">")
		_, _ = fmt.Fprintln(w, "          <h4 style=\"margin-top: 0; color: white;\">Business Impact:</h4>")
		_, _ = fmt.Fprintf(w, "          <p style=\"margin: 0;\">%s</p>\n", html.EscapeString(executiveSummary.BusinessImpact))
		_, _ = fmt.Fprintln(w, "        </div>")
	}

	// Recommended Action
	if executiveSummary.RecommendedAction != "" {
		_, _ = fmt.Fprintln(w, "        <div style=\"background: rgba(255,255,255,0.1); padding: 15px; border-radius: 5px; margin-top: 15px;\">")
		_, _ = fmt.Fprintln(w, "          <h4 style=\"margin-top: 0; color: white;\">Recommended Action:</h4>")
		_, _ = fmt.Fprintf(w, "          <p style=\"margin: 0;\">%s</p>\n", html.EscapeString(executiveSummary.RecommendedAction))
		_, _ = fmt.Fprintln(w, "        </div>")
	}

	// Confidence
	confidencePct := executiveSummary.Confidence * 100
	_, _ = fmt.Fprintf(w, "        <div style=\"margin-top: 15px; font-size: 14px; opacity: 0.9;\">")
	_, _ = fmt.Fprintf(w, "          <em>AI Confidence: %.0f%%</em>", confidencePct)
	_, _ = fmt.Fprintln(w, "        </div>")
	_, _ = fmt.Fprintln(w, "      </div>")
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
	_, _ = fmt.Fprintf(w, "          <div class=\"package-name\">%s@%s</div>\n",
		html.EscapeString(result.Dependency.Name),
		html.EscapeString(result.Dependency.Version))
	_, _ = fmt.Fprintf(w, "          <span class=\"badge %s\">%s</span>\n", riskClass, result.RiskLevel)
	_, _ = fmt.Fprintln(w, "        </div>")

	_, _ = fmt.Fprintln(w, "        <div class=\"package-details\">")
	_, _ = fmt.Fprintf(w, "          <div class=\"detail-item\"><span class=\"detail-label\">Ecosystem:</span> %s</div>\n",
		result.Dependency.Ecosystem)

	if result.SupplyChainScore != nil {
		_, _ = fmt.Fprintf(w, "          <div class=\"detail-item\"><span class=\"detail-label\">Supply Chain Score:</span> %d/20 points</div>\n",
			result.SupplyChainScore.TotalScore)
	}

	if result.RepositoryURL != "" {
		_, _ = fmt.Fprintf(w, "          <div class=\"detail-item\"><span class=\"detail-label\">Repository:</span> <a href=\"%s\" target=\"_blank\">%s</a></div>\n",
			html.EscapeString(result.RepositoryURL),
			html.EscapeString(result.RepositoryURL))
	}

	sourceAvailable := "No"
	if result.SourceCodeAvailable {
		sourceAvailable = "Yes"
	}
	_, _ = fmt.Fprintf(w, "          <div class=\"detail-item\"><span class=\"detail-label\">Source Available:</span> %s</div>\n",
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

			_, _ = fmt.Fprintln(w, "          </div>")
		}

		_, _ = fmt.Fprintln(w, "        </div>")
	}

	// AI Analysis
	if result.AIAnalysis != nil {
		r.printHTMLPackageAIAnalysis(w, result.AIAnalysis)
	}

	_, _ = fmt.Fprintln(w, "      </div>")
}

// printHTMLPackageAIAnalysis prints AI analysis results for a package in HTML
func (r *Reporter) printHTMLPackageAIAnalysis(w io.Writer, aiAnalysis *models.AIAnalysisResult) {
	if aiAnalysis == nil {
		return
	}

	// Attack Pattern Matches
	if len(aiAnalysis.AttackPatterns) > 0 {
		_, _ = fmt.Fprintln(w, "        <div style=\"margin-top: 20px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 15px; border-radius: 5px;\">")
		_, _ = fmt.Fprintln(w, "          <h4 style=\"color: white; margin-top: 0;\">🤖 AI-Detected Attack Patterns</h4>")

		for _, pattern := range aiAnalysis.AttackPatterns {
			bgColor := "#fff9e6"
			if pattern.Severity == "HIGH" || pattern.Severity == "CRITICAL" {
				bgColor = "#ffe6e6"
			}

			_, _ = fmt.Fprintf(w, "          <div style=\"background: %s; padding: 12px; margin: 10px 0; border-radius: 5px; border-left: 4px solid #dc3545;\">\n", bgColor)
			_, _ = fmt.Fprintf(w, "            <div style=\"font-weight: bold; margin-bottom: 5px;\">\n")
			_, _ = fmt.Fprintf(w, "              <span style=\"color: #dc3545;\">[%s]</span> %s\n",
				html.EscapeString(pattern.Severity), html.EscapeString(pattern.PatternName))
			_, _ = fmt.Fprintln(w, "            </div>")

			if pattern.Description != "" && r.config.Verbose {
				_, _ = fmt.Fprintf(w, "            <div style=\"font-size: 13px; color: #666; margin: 5px 0;\">%s</div>\n",
					html.EscapeString(pattern.Description))
			}

			confidencePct := pattern.Confidence * 100
			_, _ = fmt.Fprintf(w, "            <div style=\"font-size: 12px; color: #666; margin-top: 5px;\">Confidence: %.0f%%</div>\n", confidencePct)

			// Always show academic source for AI findings - required for traceability
			if pattern.AcademicSource != "" {
				_, _ = fmt.Fprintf(w, "            <div style=\"font-size: 12px; color: #555; margin-top: 5px; font-style: italic;\">Source: %s</div>\n",
					html.EscapeString(pattern.AcademicSource))
			}

			if r.config.Verbose && len(pattern.Evidence) > 0 {
				_, _ = fmt.Fprintln(w, "            <div style=\"font-size: 12px; color: #666; margin-top: 8px;\">")
				_, _ = fmt.Fprintln(w, "              <strong>Evidence:</strong>")
				_, _ = fmt.Fprintln(w, "              <ul style=\"margin: 5px 0; padding-left: 20px;\">")
				for _, evidence := range pattern.Evidence {
					_, _ = fmt.Fprintf(w, "                <li>%s</li>\n", html.EscapeString(evidence))
				}
				_, _ = fmt.Fprintln(w, "              </ul>")
				_, _ = fmt.Fprintln(w, "            </div>")
			}

			if pattern.MitigationAdvice != "" && r.config.Verbose {
				_, _ = fmt.Fprintf(w, "            <div style=\"font-size: 12px; color: #28a745; margin-top: 8px;\">")
				_, _ = fmt.Fprintf(w, "              <strong>Mitigation:</strong> %s", html.EscapeString(pattern.MitigationAdvice))
				_, _ = fmt.Fprintln(w, "            </div>")
			}

			_, _ = fmt.Fprintln(w, "          </div>")
		}

		_, _ = fmt.Fprintln(w, "        </div>")
	}

	// Semantic Findings
	if len(aiAnalysis.SemanticFindings) > 0 && r.config.Verbose {
		_, _ = fmt.Fprintln(w, "        <div style=\"margin-top: 20px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 15px; border-radius: 5px;\">")
		_, _ = fmt.Fprintln(w, "          <h4 style=\"color: white; margin-top: 0;\">🤖 AI-Detected Code Patterns</h4>")

		for _, finding := range aiAnalysis.SemanticFindings {
			bgColor := "#fff9e6"
			if finding.Severity == "HIGH" || finding.Severity == "CRITICAL" {
				bgColor = "#ffe6e6"
			}

			_, _ = fmt.Fprintf(w, "          <div style=\"background: %s; padding: 12px; margin: 10px 0; border-radius: 5px; border-left: 4px solid #ffc107;\">\n", bgColor)
			_, _ = fmt.Fprintf(w, "            <div style=\"font-weight: bold; margin-bottom: 5px;\">\n")
			_, _ = fmt.Fprintf(w, "              <span style=\"color: #dc3545;\">[%s]</span> %s\n",
				html.EscapeString(finding.Severity), html.EscapeString(finding.Type))
			_, _ = fmt.Fprintln(w, "            </div>")

			if finding.Description != "" {
				_, _ = fmt.Fprintf(w, "            <div style=\"font-size: 13px; color: #666; margin: 5px 0;\">%s</div>\n",
					html.EscapeString(finding.Description))
			}

			confidencePct := finding.Confidence * 100
			_, _ = fmt.Fprintf(w, "            <div style=\"font-size: 12px; color: #666; margin-top: 5px;\">Confidence: %.0f%%</div>\n", confidencePct)

			if finding.FilePath != "" {
				location := finding.FilePath
				if finding.LineNumber > 0 {
					location = fmt.Sprintf("%s:%d", location, finding.LineNumber)
				}
				_, _ = fmt.Fprintf(w, "            <div style=\"font-size: 12px; color: #666; margin-top: 5px;\">Location: <code>%s</code></div>\n",
					html.EscapeString(location))
			}

			if finding.Evidence != "" {
				_, _ = fmt.Fprintf(w, "            <div style=\"font-size: 12px; color: #666; margin-top: 5px;\">Evidence: %s</div>\n",
					html.EscapeString(finding.Evidence))
			}

			if finding.RiskExplanation != "" {
				_, _ = fmt.Fprintf(w, "            <div style=\"font-size: 12px; color: #dc3545; margin-top: 5px;\">Risk: %s</div>\n",
					html.EscapeString(finding.RiskExplanation))
			}

			_, _ = fmt.Fprintln(w, "          </div>")
		}

		_, _ = fmt.Fprintln(w, "        </div>")
	}

	// AI Analysis Notes
	if aiAnalysis.AnalysisNotes != "" && r.config.Verbose {
		_, _ = fmt.Fprintln(w, "        <div style=\"margin-top: 20px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 15px; border-radius: 5px;\">")
		_, _ = fmt.Fprintln(w, "          <h4 style=\"color: white; margin-top: 0;\">🤖 AI Analysis Notes</h4>")
		_, _ = fmt.Fprintf(w, "          <p style=\"color: white; margin: 0;\">%s</p>\n", html.EscapeString(aiAnalysis.AnalysisNotes))
		_, _ = fmt.Fprintln(w, "        </div>")
	}
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
