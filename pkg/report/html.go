package report

import (
	"fmt"
	"html"
	"io"
	"time"

	"github.com/metalstormbass/snyft/pkg/models"
)

func (r *Reporter) generateHTML() error {
	w := r.config.Writer

	// Document start
	if _, err := fmt.Fprintln(w, `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Snyft Supply Chain Risk Report</title>
  <style>`); err != nil {
		return err
	}
	r.printHTMLStyles(w)
	if _, err := fmt.Fprintln(w, `  </style>
</head>
<body>
  <div class="container">`); err != nil {
		return err
	}

	// Header
	f(w, "    <header>\n")
	f(w, "      <h1>Snyft Supply Chain Risk Report</h1>\n")
	f(w, "      <p class=\"timestamp\">Generated: %s</p>\n", time.Now().Format("2006-01-02 15:04:05"))
	f(w, "    </header>\n")

	// Executive Summary
	if err := r.printHTMLExecutiveSummary(w); err != nil {
		return err
	}

	// Detailed Findings
	f(w, "    <section>\n")
	f(w, "      <h2>Detailed Findings</h2>\n")
	for _, result := range r.results {
		r.printHTMLPackage(w, result)
	}
	f(w, "    </section>\n")

	// Key Risk Areas
	f(w, "    <section>\n")
	f(w, "      <h2>Key Risk Areas</h2>\n")
	areas := r.generateRiskAreas()
	if len(areas) == 0 {
		f(w, "      <p class=\"success\">✓ No critical supply chain risk factors identified.</p>\n")
	} else {
		f(w, "      <ol class=\"risk-areas\">\n")
		for _, area := range areas {
			f(w, "        <li><strong>[%s]</strong> %s<br><span class=\"dim\">%s</span>",
				html.EscapeString(area.Tag),
				html.EscapeString(area.Summary),
				html.EscapeString(area.Explanation))
			if area.Examples != "" {
				f(w, "<br><span class=\"dim\">Affected: %s</span>", html.EscapeString(area.Examples))
			}
			f(w, "</li>\n")
		}
		f(w, "      </ol>\n")
	}
	f(w, "    </section>\n")

	// Document end
	f(w, "  </div>\n</body>\n</html>\n")
	return nil
}

func (r *Reporter) printHTMLStyles(w io.Writer) {
	f(w, `
    * { box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      line-height: 1.5; color: #333; background: #f5f5f5;
      margin: 0; padding: 20px; font-size: 14px;
    }
    .container {
      max-width: 960px; margin: 0 auto; background: #fff;
      padding: 28px; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.08);
    }
    header { border-bottom: 3px solid #00a8e8; padding-bottom: 10px; margin-bottom: 20px; }
    h1 { color: #00a8e8; margin: 0 0 4px; font-size: 22px; }
    .timestamp { color: #666; margin: 0; font-size: 13px; }
    h2 { color: #333; border-bottom: 2px solid #eee; padding-bottom: 6px; margin-top: 24px; font-size: 17px; }
    h3 { font-size: 15px; margin: 12px 0 6px; }
    h4 { font-size: 14px; margin: 10px 0 6px; }
    .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 10px; margin: 12px 0; }
    .card { background: #f9f9f9; padding: 12px; border-radius: 5px; border-left: 4px solid #00a8e8; }
    .card h3 { margin: 0 0 4px; font-size: 11px; color: #888; text-transform: uppercase; letter-spacing: 0.5px; }
    .card .val { font-size: 22px; font-weight: bold; }
    .card .sub { font-size: 12px; color: #666; margin-top: 2px; }
    .pkg { border: 1px solid #ddd; border-radius: 5px; padding: 12px; margin: 8px 0; }
    .pkg.high { border-left: 4px solid #dc3545; }
    .pkg.medium { border-left: 4px solid #ffc107; }
    .pkg.low { border-left: 4px solid #28a745; }
    .pkg-head { display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px; }
    .pkg-name { font-size: 15px; font-weight: bold; }
    .badge { display: inline-block; padding: 2px 8px; border-radius: 3px; font-size: 11px; font-weight: bold; text-transform: uppercase; }
    .badge.high { background: #dc3545; color: #fff; }
    .badge.medium { background: #ffc107; color: #333; }
    .badge.low { background: #28a745; color: #fff; }
    .meta { display: flex; flex-wrap: wrap; gap: 6px 16px; font-size: 13px; color: #555; margin: 4px 0; }
    .meta b { color: #666; }
    table { width: 100%%; border-collapse: collapse; font-size: 13px; margin: 6px 0; }
    th, td { padding: 4px 8px; text-align: left; border-bottom: 1px solid #eee; }
    th { background: #f9f9f9; font-weight: 600; }
    .finding { padding: 6px 10px; margin: 4px 0; border-radius: 3px; font-size: 13px; border-left: 3px solid #ffc107; background: #fff3cd; }
    .finding.high { border-left-color: #dc3545; background: #f8d7da; }
    .finding-sev { font-weight: bold; text-transform: uppercase; font-size: 11px; }
    .risk-areas { padding-left: 20px; }
    .risk-areas li { margin: 8px 0; line-height: 1.6; }
    .success { color: #28a745; font-weight: bold; }
    .dim { color: #888; font-size: 13px; }
`)
}

func (r *Reporter) printHTMLExecutiveSummary(w io.Writer) error {
	overall := calculateOverallRisk(r.stats)
	duration := r.stats.EndTime.Sub(r.stats.StartTime)

	riskCol := "#28a745"
	switch overall {
	case "HIGH":
		riskCol = "#dc3545"
	case "MEDIUM":
		riskCol = "#ffc107"
	}

	f(w, "    <section>\n")
	f(w, "      <h2>Executive Summary</h2>\n")

	// Summary cards
	f(w, "      <div class=\"cards\">\n")

	// Overall risk card
	f(w, "        <div class=\"card\"><h3>Overall Risk</h3><div class=\"val\" style=\"color:%s\">%s</div></div>\n", riskCol, overall)

	// Packages card
	f(w, "        <div class=\"card\"><h3>Packages</h3><div class=\"val\">%d</div>\n", r.stats.TotalPackages)
	if r.stats.TotalPackages > 0 {
		f(w, "          <div class=\"sub\"><span style=\"color:#dc3545\">%d high</span> · <span style=\"color:#b8860b\">%d med</span> · <span style=\"color:#28a745\">%d low</span></div>\n",
			r.stats.HighRisk, r.stats.MediumRisk, r.stats.LowRisk)
	}
	if r.stats.DirectDeps > 0 || r.stats.TransitiveDeps > 0 {
		f(w, "          <div class=\"sub\">%d direct · %d transitive</div>\n", r.stats.DirectDeps, r.stats.TransitiveDeps)
	}
	f(w, "        </div>\n")

	// Duration card
	f(w, "        <div class=\"card\"><h3>Duration</h3><div class=\"val\" style=\"font-size:18px\">%s</div></div>\n", formatDuration(duration))
	f(w, "      </div>\n")

	// Top findings
	criticalIssues := r.extractCriticalIssues(5)
	if len(criticalIssues) > 0 {
		f(w, "      <div style=\"margin-top:12px\">\n")
		f(w, "        <h3>Top Priority Findings</h3>\n")
		for i, issue := range criticalIssues {
			cls := "medium"
			if issue.RiskLevel == "HIGH" {
				cls = "high"
			}
			f(w, "        <div class=\"finding %s\">\n", cls)
			f(w, "          <span class=\"finding-sev\">[%s]</span> <strong>%d. %s@%s</strong> <span class=\"dim\">(%s)</span> — %s\n",
				html.EscapeString(issue.Severity), i+1,
				html.EscapeString(issue.PackageName), html.EscapeString(issue.PackageVersion),
				issue.Ecosystem, html.EscapeString(issue.Description))
			f(w, "        </div>\n")
		}
		f(w, "      </div>\n")
	}

	f(w, "    </section>\n")
	return nil
}

func (r *Reporter) printHTMLPackage(w io.Writer, result models.AnalysisResult) {
	cls := "low"
	switch result.RiskLevel {
	case "HIGH":
		cls = "high"
	case "MEDIUM":
		cls = "medium"
	}

	f(w, "      <div class=\"pkg %s\">\n", cls)

	// Header
	f(w, "        <div class=\"pkg-head\">\n")
	transitive := ""
	if result.Dependency.IsTransitive {
		transitive = " <span class=\"dim\">(transitive)</span>"
	}
	f(w, "          <div class=\"pkg-name\">%s@%s%s</div>\n",
		html.EscapeString(result.Dependency.Name),
		html.EscapeString(result.Dependency.Version), transitive)
	f(w, "          <span class=\"badge %s\">%s</span>\n", cls, result.RiskLevel)
	f(w, "        </div>\n")

	// Metadata
	f(w, "        <div class=\"meta\">\n")
	f(w, "          <span><b>Ecosystem:</b> %s</span>\n", result.Dependency.Ecosystem)
	if result.SupplyChainScore != nil {
		ms := maxScore(result.SupplyChainScore)
		f(w, "          <span><b>Score:</b> %d/%d</span>\n", result.SupplyChainScore.TotalScore, ms)
	}
	if result.RepositoryURL != "" {
		f(w, "          <span><b>Repo:</b> <a href=\"%s\" target=\"_blank\">link</a></span>\n",
			html.EscapeString(result.RepositoryURL))
	}
	src := "No"
	if result.SourceCodeAvailable {
		src = "Yes"
	}
	f(w, "          <span><b>Source:</b> %s</span>\n", src)
	f(w, "        </div>\n")

	// Category scores (verbose)
	if r.config.Verbose && result.SupplyChainScore != nil {
		f(w, "        <div>\n")
		f(w, "          <h4>Category Scores</h4>\n")
		f(w, "          <table>\n")
		f(w, "            <tr><th>Category</th><th>Score</th><th>Risk</th><th>Verified</th></tr>\n")
		for _, cat := range categoryList(result.SupplyChainScore.CategoryScores) {
			if cat.Score.Skipped {
				f(w, "            <tr style=\"opacity:0.5\"><td>%s</td><td>-</td><td>⚪</td><td>SKIP</td></tr>\n",
					html.EscapeString(cat.Name))
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
			f(w, "            <tr><td>%s</td><td>%d/2</td><td>%s</td><td>%s</td></tr>\n",
				html.EscapeString(cat.Name), cat.Score.Score, icon, verified)
		}
		f(w, "          </table>\n")
		f(w, "        </div>\n")
	}

	// Findings
	if len(result.Findings) > 0 {
		f(w, "        <div>\n")
		f(w, "          <h4>Risk Findings</h4>\n")
		for _, finding := range result.Findings {
			fc := "medium"
			if finding.Severity == "HIGH" || finding.Severity == "CRITICAL" {
				fc = "high"
			}
			f(w, "          <div class=\"finding %s\">\n", fc)
			f(w, "            <span class=\"finding-sev\">[%s]</span> %s\n",
				html.EscapeString(finding.Severity), html.EscapeString(finding.Description))
			if finding.SourceURL != "" {
				f(w, "            <div style=\"margin-top:3px;font-size:12px\">Source: <a href=\"%s\" target=\"_blank\">%s</a></div>\n",
					html.EscapeString(finding.SourceURL), html.EscapeString(finding.SourceURL))
			}
			if finding.Evidence != "" && r.config.Verbose {
				f(w, "            <div class=\"dim\" style=\"margin-top:3px\">Evidence: %s</div>\n",
					html.EscapeString(finding.Evidence))
			}
			if finding.Methodology != "" && r.config.Verbose {
				f(w, "            <div class=\"dim\" style=\"margin-top:2px;font-size:11px\">Method: %s</div>\n",
					html.EscapeString(finding.Methodology))
			}
			f(w, "          </div>\n")
		}
		f(w, "        </div>\n")
	}

	f(w, "      </div>\n")
}
