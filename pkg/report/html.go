package report

import (
	"fmt"
	"html"
	"io"
	"strings"
	"time"

	"github.com/metalstormbass/snyft/pkg/models"
)

// generateHTML generates a clean HTML report
func (r *Reporter) generateHTML() error {
	w := r.config.Writer

	_, _ = fmt.Fprintln(w, `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Snyft Supply Chain Risk Report</title>
  <style>`)
	r.printHTMLStyles(w)
	_, _ = fmt.Fprintln(w, `  </style>
</head>
<body>
<div class="container">`)

	// Header
	_, _ = fmt.Fprintln(w, `  <header>`)
	_, _ = fmt.Fprintln(w, `    <h1>Snyft Supply Chain Risk Report</h1>`)
	_, _ = fmt.Fprintf(w, "    <p class=\"meta\">Generated: %s</p>\n", time.Now().Format("2006-01-02 15:04:05"))
	_, _ = fmt.Fprintln(w, `  </header>`)

	// Executive Summary
	r.printHTMLExecutiveSummary(w)

	// Detailed Findings
	_, _ = fmt.Fprintln(w, `  <section>`)
	_, _ = fmt.Fprintln(w, `    <h2>Detailed Findings</h2>`)
	for _, result := range r.results {
		r.printHTMLPackage(w, result)
	}
	_, _ = fmt.Fprintln(w, `  </section>`)

	// Key Risk Areas
	_, _ = fmt.Fprintln(w, `  <section>`)
	_, _ = fmt.Fprintln(w, `    <h2>Key Risk Areas</h2>`)
	riskAreas := r.generateRiskAreas()
	if len(riskAreas) == 0 {
		_, _ = fmt.Fprintln(w, `    <p class="ok">No critical supply chain risk factors identified.</p>`)
	} else {
		_, _ = fmt.Fprintln(w, `    <ol>`)
		for _, area := range riskAreas {
			exStr := ""
			if len(area.Examples) > 0 {
				exStr = fmt.Sprintf(" <span class=\"dim\">(e.g., %s)</span>",
					html.EscapeString(strings.Join(area.Examples, ", ")))
			}
			cls := "tag-med"
			if area.Severity == "HIGH" {
				cls = "tag-high"
			}
			_, _ = fmt.Fprintf(w, "      <li><span class=\"%s\">[%s]</span> %s%s</li>\n",
				cls, html.EscapeString(area.Tag), html.EscapeString(area.Summary), exStr)
		}
		_, _ = fmt.Fprintln(w, `    </ol>`)
	}
	_, _ = fmt.Fprintln(w, `  </section>`)

	_, _ = fmt.Fprintln(w, `</div>
</body>
</html>`)

	return nil
}

// printHTMLStyles prints clean CSS styles
func (r *Reporter) printHTMLStyles(w io.Writer) {
	_, _ = fmt.Fprint(w, `
    * { box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      line-height: 1.5; color: #333; background: #f5f5f5;
      margin: 0; padding: 20px; font-size: 14px;
    }
    .container { max-width: 960px; margin: 0 auto; background: #fff; padding: 28px; border-radius: 8px; box-shadow: 0 1px 6px rgba(0,0,0,.08); }
    header { border-bottom: 3px solid #0078d4; padding-bottom: 10px; margin-bottom: 20px; }
    h1 { color: #0078d4; margin: 0 0 4px; font-size: 20px; }
    .meta { color: #888; margin: 0; font-size: 13px; }
    h2 { color: #222; border-bottom: 2px solid #eee; padding-bottom: 5px; margin-top: 24px; font-size: 17px; }
    h3 { font-size: 15px; margin: 12px 0 6px; }
    h4 { font-size: 13px; margin: 8px 0 4px; }

    /* Summary cards */
    .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: 10px; margin: 12px 0; }
    .card { background: #fafafa; padding: 12px; border-radius: 5px; border-left: 3px solid #0078d4; }
    .card-label { font-size: 11px; text-transform: uppercase; color: #888; margin: 0; }
    .card-value { font-size: 22px; font-weight: 700; margin: 2px 0 0; }
    .card .sub { font-size: 12px; color: #888; }

    /* Risk colors */
    .high { color: #d32f2f; }
    .med { color: #e6a100; }
    .low { color: #2e7d32; }
    .tag-high { font-weight: 700; color: #d32f2f; }
    .tag-med { font-weight: 700; color: #e6a100; }
    .dim { color: #999; }
    .ok { color: #2e7d32; font-weight: 600; }

    /* Package cards */
    .pkg { border: 1px solid #e0e0e0; border-radius: 5px; padding: 12px; margin: 10px 0; }
    .pkg.risk-high { border-left: 4px solid #d32f2f; }
    .pkg.risk-med { border-left: 4px solid #e6a100; }
    .pkg.risk-low { border-left: 4px solid #2e7d32; }
    .pkg-head { display: flex; justify-content: space-between; align-items: center; }
    .pkg-name { font-size: 15px; font-weight: 700; }
    .badge { display: inline-block; padding: 2px 8px; border-radius: 3px; font-size: 11px; font-weight: 700; color: #fff; }
    .badge-high { background: #d32f2f; }
    .badge-med { background: #e6a100; color: #333; }
    .badge-low { background: #2e7d32; }
    .pkg-meta { display: flex; flex-wrap: wrap; gap: 6px 16px; font-size: 13px; color: #666; margin: 6px 0; }
    .lbl { font-weight: 600; color: #888; }

    /* Tables */
    table { width: 100%; border-collapse: collapse; font-size: 13px; margin: 6px 0; }
    th, td { padding: 4px 8px; text-align: left; border-bottom: 1px solid #eee; }
    th { background: #fafafa; font-weight: 600; font-size: 12px; text-transform: uppercase; color: #888; }

    /* Findings */
    .finding { padding: 6px 10px; margin: 4px 0; border-radius: 3px; font-size: 13px; border-left: 3px solid #e6a100; background: #fffde7; }
    .finding.sev-high { border-left-color: #d32f2f; background: #fce4ec; }
    .finding-sev { font-weight: 700; font-size: 11px; text-transform: uppercase; }

    /* AI sections */
    .ai-box { background: #f3f0ff; border-left: 3px solid #6b5ce7; padding: 12px; border-radius: 5px; margin: 10px 0; font-size: 13px; }
    .ai-box h4 { color: #6b5ce7; margin-top: 0; }
    .ai-box ul { margin: 4px 0; padding-left: 20px; }

    ol { padding-left: 20px; }
    ol li { margin: 6px 0; }
    a { color: #0078d4; }
`)
}

// printHTMLExecutiveSummary prints the executive summary in HTML
func (r *Reporter) printHTMLExecutiveSummary(w io.Writer) {
	_, _ = fmt.Fprintln(w, `  <section>`)
	_, _ = fmt.Fprintln(w, `    <h2>Executive Summary</h2>`)

	duration := r.stats.EndTime.Sub(r.stats.StartTime)
	overallRisk := r.calculateOverallRisk()
	riskClass := htmlRiskClass(overallRisk)

	// Summary cards
	_, _ = fmt.Fprintln(w, `    <div class="cards">`)

	_, _ = fmt.Fprintf(w, `      <div class="card"><p class="card-label">Overall Risk</p><p class="card-value %s">%s</p></div>`+"\n",
		riskClass, overallRisk)

	_, _ = fmt.Fprintf(w, `      <div class="card"><p class="card-label">Packages</p><p class="card-value">%d</p>`, r.stats.TotalPackages)
	if r.stats.TotalPackages > 0 {
		_, _ = fmt.Fprintf(w, `<p class="sub"><span class="high">%d high</span> · <span class="med">%d med</span> · <span class="low">%d low</span></p>`,
			r.stats.HighRisk, r.stats.MediumRisk, r.stats.LowRisk)
		if r.stats.DirectDeps > 0 || r.stats.TransitiveDeps > 0 {
			_, _ = fmt.Fprintf(w, `<p class="sub">%d direct · %d transitive</p>`, r.stats.DirectDeps, r.stats.TransitiveDeps)
		}
	}
	_, _ = fmt.Fprintln(w, `</div>`)

	_, _ = fmt.Fprintf(w, `      <div class="card"><p class="card-label">Duration</p><p class="card-value" style="font-size:18px">%s</p></div>`+"\n",
		formatDuration(duration))

	_, _ = fmt.Fprintln(w, `    </div>`)

	// Top Priority Findings
	criticalIssues := r.extractCriticalIssues(5)
	if len(criticalIssues) > 0 {
		_, _ = fmt.Fprintln(w, `    <h3>Top Priority Findings</h3>`)
		for i, issue := range criticalIssues {
			cls := "finding"
			if issue.RiskLevel == "HIGH" || issue.Severity == "HIGH" || issue.Severity == "CRITICAL" {
				cls = "finding sev-high"
			}
			_, _ = fmt.Fprintf(w, `    <div class="%s"><span class="finding-sev">[%s]</span> <strong>%d. %s@%s</strong> <span class="dim">(%s)</span> — %s</div>`+"\n",
				cls,
				html.EscapeString(issue.Severity),
				i+1,
				html.EscapeString(issue.PackageName),
				html.EscapeString(issue.PackageVersion),
				html.EscapeString(issue.Ecosystem),
				html.EscapeString(issue.Description))
		}
	}

	// AI Executive Summary
	r.printHTMLAIExecutiveSummary(w)

	_, _ = fmt.Fprintln(w, `  </section>`)
}

// printHTMLAIExecutiveSummary prints the report-level AI summary in HTML
func (r *Reporter) printHTMLAIExecutiveSummary(w io.Writer) {
	if r.reportAISummary == nil {
		return
	}
	summary := r.reportAISummary

	_, _ = fmt.Fprintln(w, `    <div class="ai-box">`)
	_, _ = fmt.Fprintln(w, `      <h4>🤖 AI Risk Assessment</h4>`)
	_, _ = fmt.Fprintf(w, "      <p>%s</p>\n", html.EscapeString(summary.OverallAssessment))

	if len(summary.KeyThreats) > 0 {
		_, _ = fmt.Fprintln(w, `      <strong>Key Threats:</strong><ul>`)
		for _, threat := range summary.KeyThreats {
			_, _ = fmt.Fprintf(w, "        <li>%s</li>\n", html.EscapeString(threat))
		}
		_, _ = fmt.Fprintln(w, `      </ul>`)
	}

	if len(summary.CrossPatterns) > 0 {
		_, _ = fmt.Fprintln(w, `      <strong>Cross-Package Patterns:</strong><ul>`)
		for _, pattern := range summary.CrossPatterns {
			_, _ = fmt.Fprintf(w, "        <li>%s</li>\n", html.EscapeString(pattern))
		}
		_, _ = fmt.Fprintln(w, `      </ul>`)
	}

	if len(summary.PriorityPackages) > 0 {
		_, _ = fmt.Fprintln(w, `      <strong>Priority Packages:</strong><ul>`)
		for _, pkg := range summary.PriorityPackages {
			_, _ = fmt.Fprintf(w, "        <li>%s</li>\n", html.EscapeString(pkg))
		}
		_, _ = fmt.Fprintln(w, `      </ul>`)
	}

	if summary.RiskPosture != "" {
		_, _ = fmt.Fprintf(w, "      <p><strong>Risk Posture:</strong> %s</p>\n", html.EscapeString(summary.RiskPosture))
	}

	_, _ = fmt.Fprintf(w, "      <p class=\"dim\">Confidence: %.0f%%</p>\n", summary.Confidence*100)
	_, _ = fmt.Fprintln(w, `    </div>`)
}

// printHTMLPackage prints a package in HTML format
func (r *Reporter) printHTMLPackage(w io.Writer, result models.AnalysisResult) {
	riskClass := htmlRiskClass(result.RiskLevel)
	badgeClass := "badge-" + riskClass

	_, _ = fmt.Fprintf(w, "    <div class=\"pkg risk-%s\">\n", riskClass)

	// Header
	_, _ = fmt.Fprintln(w, `      <div class="pkg-head">`)
	transitiveLabel := ""
	if result.Dependency.IsTransitive {
		transitiveLabel = ` <span class="dim">(transitive)</span>`
	}
	_, _ = fmt.Fprintf(w, "        <span class=\"pkg-name\">%s@%s%s</span>\n",
		html.EscapeString(result.Dependency.Name),
		html.EscapeString(result.Dependency.Version),
		transitiveLabel)
	_, _ = fmt.Fprintf(w, "        <span class=\"badge %s\">%s</span>\n", badgeClass, result.RiskLevel)
	_, _ = fmt.Fprintln(w, `      </div>`)

	// Meta
	_, _ = fmt.Fprintln(w, `      <div class="pkg-meta">`)
	_, _ = fmt.Fprintf(w, "        <span><span class=\"lbl\">Ecosystem:</span> %s</span>\n", result.Dependency.Ecosystem)
	if result.SupplyChainScore != nil {
		scoreStr := fmt.Sprintf("%d/22", result.SupplyChainScore.TotalScore)
		if result.SupplyChainScore.AIAdjustment != 0 {
			adjSign := "+"
			if result.SupplyChainScore.AIAdjustment < 0 {
				adjSign = ""
			}
			scoreStr += fmt.Sprintf(` <span style="color:#6b5ce7">[AI %s%d]</span>`, adjSign, result.SupplyChainScore.AIAdjustment)
		}
		_, _ = fmt.Fprintf(w, "        <span><span class=\"lbl\">Score:</span> %s</span>\n", scoreStr)
	}
	if result.RepositoryURL != "" {
		_, _ = fmt.Fprintf(w, "        <span><span class=\"lbl\">Repo:</span> <a href=\"%s\" target=\"_blank\">link</a></span>\n",
			html.EscapeString(result.RepositoryURL))
	}
	src := "No"
	if result.SourceCodeAvailable {
		src = "Yes"
	}
	_, _ = fmt.Fprintf(w, "        <span><span class=\"lbl\">Source:</span> %s</span>\n", src)
	_, _ = fmt.Fprintln(w, `      </div>`)

	// Category scores
	if r.config.Verbose && result.SupplyChainScore != nil {
		_, _ = fmt.Fprintln(w, `      <table>`)
		_, _ = fmt.Fprintln(w, `        <tr><th>Category</th><th>Score</th><th>Risk</th></tr>`)
		for _, cat := range getCategoryList(result.SupplyChainScore.CategoryScores) {
			icon := "🟢"
			switch cat.Score.RiskPoints {
			case 2:
				icon = "🔴"
			case 1:
				icon = "🟡"
			}
			_, _ = fmt.Fprintf(w, "        <tr><td>%s</td><td>%d/2</td><td>%s</td></tr>\n",
				html.EscapeString(cat.Name), cat.Score.Score, icon)
		}
		_, _ = fmt.Fprintln(w, `      </table>`)
	}

	// Findings
	if len(result.Findings) > 0 {
		for _, finding := range result.Findings {
			cls := "finding"
			if finding.Severity == "HIGH" || finding.Severity == "CRITICAL" {
				cls = "finding sev-high"
			}
			_, _ = fmt.Fprintf(w, "      <div class=\"%s\"><span class=\"finding-sev\">[%s]</span> %s",
				cls, html.EscapeString(finding.Severity), html.EscapeString(finding.Description))
			if finding.Evidence != "" && r.config.Verbose {
				_, _ = fmt.Fprintf(w, " <span class=\"dim\">— %s</span>", html.EscapeString(finding.Evidence))
			}
			_, _ = fmt.Fprintln(w, "</div>")
		}
	}

	// AI Analysis
	if result.AIAnalysis != nil {
		r.printHTMLPackageAIAnalysis(w, result.AIAnalysis)
	}

	_, _ = fmt.Fprintln(w, `    </div>`)
}

// printHTMLPackageAIAnalysis prints AI analysis results for a package in HTML
func (r *Reporter) printHTMLPackageAIAnalysis(w io.Writer, aiAnalysis *models.AIAnalysisResult) {
	if aiAnalysis == nil {
		return
	}

	// Deep Analysis
	if aiAnalysis.DeepAnalysis != nil {
		da := aiAnalysis.DeepAnalysis
		_, _ = fmt.Fprintln(w, `      <div class="ai-box">`)
		_, _ = fmt.Fprintln(w, `        <h4>🤖 AI Deep Analysis</h4>`)

		if da.RiskAssessment != "" {
			_, _ = fmt.Fprintf(w, "        <p>%s</p>\n", html.EscapeString(da.RiskAssessment))
		}

		if len(da.CompoundRisks) > 0 {
			for _, cr := range da.CompoundRisks {
				cls := "tag-med"
				if cr.RiskLevel == "HIGH" {
					cls = "tag-high"
				}
				_, _ = fmt.Fprintf(w, "        <p><span class=\"%s\">[%s]</span> %s</p>\n",
					cls, html.EscapeString(cr.RiskLevel), html.EscapeString(cr.Pattern))
			}
		}

		if len(da.BehaviorFindings) > 0 {
			_, _ = fmt.Fprintln(w, `        <ul>`)
			for _, bf := range da.BehaviorFindings {
				_, _ = fmt.Fprintf(w, "          <li>%s</li>\n", html.EscapeString(bf))
			}
			_, _ = fmt.Fprintln(w, `        </ul>`)
		}

		if len(da.MissedByRules) > 0 && r.config.Verbose {
			_, _ = fmt.Fprintln(w, `        <ul>`)
			for _, insight := range da.MissedByRules {
				_, _ = fmt.Fprintf(w, "          <li>%s</li>\n", html.EscapeString(insight))
			}
			_, _ = fmt.Fprintln(w, `        </ul>`)
		}

		_, _ = fmt.Fprintf(w, "        <p class=\"dim\">Confidence: %.0f%%</p>\n", da.Confidence*100)
		_, _ = fmt.Fprintln(w, `      </div>`)
	}

	// Attack Patterns
	if len(aiAnalysis.AttackPatterns) > 0 {
		_, _ = fmt.Fprintln(w, `      <div class="ai-box">`)
		_, _ = fmt.Fprintln(w, `        <h4>🤖 Attack Patterns</h4>`)

		for _, pattern := range aiAnalysis.AttackPatterns {
			cls := "tag-med"
			if pattern.Severity == "HIGH" || pattern.Severity == "CRITICAL" {
				cls = "tag-high"
			}
			_, _ = fmt.Fprintf(w, "        <p><span class=\"%s\">[%s]</span> <strong>%s</strong> <span class=\"dim\">(%.0f%%)</span></p>\n",
				cls, html.EscapeString(pattern.Severity), html.EscapeString(pattern.PatternName), pattern.Confidence*100)

			if pattern.Description != "" && r.config.Verbose {
				_, _ = fmt.Fprintf(w, "        <p class=\"dim\">%s</p>\n", html.EscapeString(pattern.Description))
			}
			if pattern.AcademicSource != "" {
				_, _ = fmt.Fprintf(w, "        <p class=\"dim\"><em>Source: %s</em></p>\n", html.EscapeString(pattern.AcademicSource))
			}
		}

		_, _ = fmt.Fprintln(w, `      </div>`)
	}

	// Notes
	if aiAnalysis.AnalysisNotes != "" && r.config.Verbose {
		_, _ = fmt.Fprintln(w, `      <div class="ai-box">`)
		_, _ = fmt.Fprintf(w, "        <p class=\"dim\">%s</p>\n", html.EscapeString(aiAnalysis.AnalysisNotes))
		_, _ = fmt.Fprintln(w, `      </div>`)
	}
}

// htmlRiskClass returns a CSS class name for a risk level
func htmlRiskClass(riskLevel string) string {
	switch riskLevel {
	case "HIGH":
		return "high"
	case "MEDIUM":
		return "med"
	case "LOW":
		return "low"
	default:
		return "low"
	}
}
