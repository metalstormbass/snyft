package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/metalstormbass/snyft/pkg/models"
)

// Box drawing characters
const (
	BoxTopLeft     = "┌"
	BoxTopRight    = "┐"
	BoxBottomLeft  = "└"
	BoxBottomRight = "┘"
	BoxHorizontal  = "─"
	BoxVertical    = "│"
	BoxTeeLeft     = "├"
	BoxTeeRight    = "┤"
)

func (r *Reporter) generateText() error {
	w := r.config.Writer

	r.printHeader(w)
	r.printSummaryLine(w)

	f(w, "  %s%s%s\n", ColorDim, strings.Repeat("─", 76), ColorReset)
	p(w, "")

	for _, result := range r.results {
		r.printPackageResult(w, result)
	}

	if r.config.Verbose {
		r.printRiskSummary(w)
	}

	r.printFormatHint(w)
	return nil
}

// --- sections ---

func (r *Reporter) printHeader(w io.Writer) {
	width := 80
	title := " SNYFT SUPPLY CHAIN RISK REPORT "
	border := strings.Repeat(BoxHorizontal, width-2)

	f(w, "%s%s%s%s%s\n", ColorBold+ColorCyan, BoxTopLeft, border, BoxTopRight, ColorReset)
	f(w, "%s%s%s%s%s\n", ColorBold+ColorCyan+BoxVertical, centerText(title, width-2), BoxVertical, ColorReset, "")
	f(w, "%s%s%s%s%s\n", ColorCyan, BoxBottomLeft, border, BoxBottomRight, ColorReset)
}

func (r *Reporter) printSummaryLine(w io.Writer) {
	duration := r.stats.EndTime.Sub(r.stats.StartTime)

	f(w, "\n  %s%d%s package%s scanned",
		ColorBold, r.stats.TotalPackages, ColorReset, pluralize(r.stats.TotalPackages))

	if r.stats.HighRisk > 0 {
		f(w, "  %s●%s %d high", ColorRed, ColorReset, r.stats.HighRisk)
	}
	if r.stats.MediumRisk > 0 {
		f(w, "  %s●%s %d medium", ColorYellow, ColorReset, r.stats.MediumRisk)
	}
	if r.stats.LowRisk > 0 {
		f(w, "  %s●%s %d low", ColorGreen, ColorReset, r.stats.LowRisk)
	}

	f(w, "  %s%s%s\n\n", ColorDim, formatDuration(duration), ColorReset)
}

func (r *Reporter) printPackageResult(w io.Writer, result models.AnalysisResult) {
	rc := riskColor(result.RiskLevel)
	icon := riskIcon(result.RiskLevel)

	// Package name@version
	nameVer := fmt.Sprintf("%s@%s", result.Dependency.Name, result.Dependency.Version)
	eco := string(result.Dependency.Ecosystem)

	// Score with color based on numeric value
	scoreStr := ""
	if result.SupplyChainScore != nil {
		ms := maxScore(result.SupplyChainScore)
		sc := scoreColor(result.SupplyChainScore.TotalScore)
		scoreStr = fmt.Sprintf("%s%2d%s/%d", sc+ColorBold, result.SupplyChainScore.TotalScore, ColorReset, ms)
	}

	// Transitive label
	transitive := ""
	if result.Dependency.IsTransitive {
		transitive = fmt.Sprintf(" %s(transitive)%s", ColorDim, ColorReset)
	}

	// Package header line: icon name@version  ecosystem  score  RISK
	f(w, "  %s %s%-35s%s  %-5s  %s  %s%s%s%s\n",
		icon, ColorBold, nameVer, ColorReset, eco,
		scoreStr, rc+ColorBold, result.RiskLevel, ColorReset, transitive)

	// Verbose: show metadata
	if r.config.Verbose {
		var meta []string
		if result.RepositoryURL != "" {
			meta = append(meta, "Repo: "+result.RepositoryURL)
		}
		meta = append(meta, "Source: "+formatBool(result.SourceCodeAvailable))
		if result.BuildInfrastructure != "" {
			meta = append(meta, "Build: "+result.BuildInfrastructure)
		}
		f(w, "     %s%s%s\n", ColorDim, strings.Join(meta, "  "), ColorReset)

		if result.Metadata.HasSelfHosted {
			f(w, "     %s⚠  Self-hosted runners detected%s\n", ColorRed+ColorBold, ColorReset)
		}
	}

	// Verbose: category score table
	if r.config.Verbose && result.SupplyChainScore != nil {
		r.printCategoryScoreTable(w, result.SupplyChainScore.CategoryScores)
	}

	// Findings with tree-drawing connectors
	if len(result.Findings) > 0 {
		for i, finding := range result.Findings {
			sc := severityColor(finding.Severity)
			isLast := i == len(result.Findings)-1

			connector := "├─"
			if isLast {
				connector = "└─"
			}

			f(w, "     %s %s[%s]%s %s\n",
				connector, sc, finding.Severity, ColorReset, finding.Description)

			// Source URL — dimmed/gray
			if finding.SourceURL != "" {
				cont := "│ "
				if isLast {
					cont = "  "
				}
				pad := strings.Repeat(" ", len(finding.Severity)+3)
				f(w, "     %s %s%s%s%s\n",
					cont, pad, ColorDim, finding.SourceURL, ColorReset)
			}

			// Verbose: evidence and methodology
			if r.config.Verbose {
				cont := "│ "
				if isLast {
					cont = "  "
				}
				pad := strings.Repeat(" ", len(finding.Severity)+3)
				if finding.Evidence != "" {
					f(w, "     %s %s%sEvidence: %s%s\n",
						cont, pad, ColorDim, finding.Evidence, ColorReset)
				}
				if finding.Methodology != "" {
					f(w, "     %s %s%sMethod: %s%s\n",
						cont, pad, ColorDim, finding.Methodology, ColorReset)
				}
			}
		}
	}

	p(w, "")
}

func (r *Reporter) printCategoryScoreTable(w io.Writer, scores models.CategoryScores) {
	categories := categoryList(scores)

	p(w, "")
	f(w, "     %-20s  %5s  %4s  %s\n", "Category", "Score", "Risk", "Status")
	f(w, "     %s\n", strings.Repeat("─", 50))

	for _, cat := range categories {
		if cat.Score.Skipped {
			f(w, "     %-20s  %5s  %s○%s   %sSKIP%s\n",
				cat.Name, "  - ", ColorDim, ColorReset, ColorDim, ColorReset)
			continue
		}

		icon := scoreIcon(cat.Score.RiskPoints)
		verified := "✓"
		if !cat.Score.Verified {
			verified = "?"
		}
		f(w, "     %-20s  %s  %s   %s\n",
			cat.Name, fmt.Sprintf("%d/2", cat.Score.Score), icon, verified)

		if r.config.Verbose && cat.Score.Description != "" {
			f(w, "       %s%s%s\n", ColorDim, cat.Score.Description, ColorReset)
		}
		if r.config.Verbose {
			for _, check := range cat.Score.ChecksPerformed {
				si := checkStatusIcon(check.Status)
				f(w, "       %s  %s %s: %s%s\n",
					ColorDim, si, check.Name, check.Detail, ColorReset)
			}
		}
	}
	p(w, "")
}

func (r *Reporter) printRiskSummary(w io.Writer) {
	p(w, "")
	r.printSectionHeader(w, "KEY RISK AREAS")
	p(w, "")

	areas := r.generateRiskAreas()
	if len(areas) == 0 {
		f(w, "  %s✓%s No critical supply chain risk factors identified.\n", ColorGreen, ColorReset)
		return
	}

	for i, area := range areas {
		tag := fmt.Sprintf("%s[%s]%s", ColorRed+ColorBold, area.Tag, ColorReset)
		if area.Tag != "HIGH RISK" {
			tag = fmt.Sprintf("%s[%s]%s", ColorYellow+ColorBold, area.Tag, ColorReset)
		}
		f(w, "  %s%d.%s %s %s\n", ColorBold, i+1, ColorReset, tag, area.Summary)
		f(w, "     %s%s%s\n", ColorDim, area.Explanation, ColorReset)
		if len(area.Examples) > 0 {
			f(w, "     %sAffected:%s %s\n", ColorDim, ColorReset, joinExamples(area.Examples))
		}
		p(w, "")
	}
}

func (r *Reporter) printSectionHeader(w io.Writer, title string) {
	width := 80
	pad := strings.Repeat("─", (width-len(title)-2)/2)
	f(w, "%s%s %s %s%s\n", ColorBold+ColorCyan, pad, title, pad, ColorReset)
}

func (r *Reporter) printFormatHint(w io.Writer) {
	scanPath := r.stats.ScannedPath
	if scanPath == "" {
		scanPath = "<path>"
	}

	f(w, "  %s%s%s\n", ColorDim, strings.Repeat("─", 76), ColorReset)
	if !r.config.Verbose {
		f(w, "  %sDetailed report:%s  snyft scan %s -v\n", ColorBold, ColorReset, scanPath)
	}
	f(w, "  %sExport:%s          snyft scan %s -f html -o report.html\n", ColorBold, ColorReset, scanPath)
	p(w, "")
}

// --- small helpers ---

func scoreIcon(riskPoints int) string {
	switch riskPoints {
	case 0:
		return ColorGreen + "●" + ColorReset
	case 1:
		return ColorYellow + "●" + ColorReset
	case 2:
		return ColorRed + "●" + ColorReset
	default:
		return "○"
	}
}

func checkStatusIcon(status string) string {
	switch status {
	case "PASS":
		return ColorGreen + "✓" + ColorReset
	case "FAIL":
		return ColorRed + "✗" + ColorReset
	case "SKIPPED":
		return ColorDim + "○" + ColorReset
	case "UNAVAILABLE":
		return ColorYellow + "?" + ColorReset
	default:
		return "·"
	}
}

// Shorthand writers to reduce noise in format functions.
func f(w io.Writer, format string, a ...interface{}) {
	_, _ = fmt.Fprintf(w, format, a...)
}

func p(w io.Writer, s string) {
	_, _ = fmt.Fprintln(w, s)
}
