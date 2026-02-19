package report

import (
	"encoding/json"
	"fmt"
)

// JSONReport represents the JSON output structure
type JSONReport struct {
	Metadata struct {
		GeneratedAt   string `json:"generated_at"`
		ScanPath      string `json:"scan_path"`
		ManifestFiles int    `json:"manifest_files"`
	} `json:"metadata"`
	Summary struct {
		TotalPackages int     `json:"total_packages"`
		HighRisk      int     `json:"high_risk"`
		MediumRisk    int     `json:"medium_risk"`
		LowRisk       int     `json:"low_risk"`
		OverallRisk   string  `json:"overall_risk"`
		ScanDuration  float64 `json:"scan_duration_seconds"`
	} `json:"summary"`
	ExecutiveSummary struct {
		KeyFindings      []JSONCriticalIssue              `json:"key_findings"`
		Summary          string                           `json:"summary"`
		AIInsights       *JSONAIExecutiveSummary          `json:"ai_insights,omitempty"`
	} `json:"executive_summary"`
	Results       interface{} `json:"results"`
	KeyRiskAreas []string    `json:"key_risk_areas"`
}

// JSONAIExecutiveSummary represents AI-powered executive insights in JSON
type JSONAIExecutiveSummary struct {
	Summary           string   `json:"summary"`
	KeyRisks          []string `json:"key_risks"`
	BusinessImpact    string   `json:"business_impact"`
	RecommendedAction string   `json:"recommended_action"`
	Confidence        float64  `json:"confidence"`
	GeneratedAt       string   `json:"generated_at"`
}

// JSONCriticalIssue represents a critical issue in JSON format
type JSONCriticalIssue struct {
	PackageName    string `json:"package_name"`
	PackageVersion string `json:"package_version"`
	Ecosystem      string `json:"ecosystem"`
	RiskLevel      string `json:"risk_level"`
	Severity       string `json:"severity"`
	Description    string `json:"description"`
	Evidence       string `json:"evidence,omitempty"`
	Impact         string `json:"impact,omitempty"`
}

// generateJSON generates a JSON report
func (r *Reporter) generateJSON() error {
	report := JSONReport{
		Results: r.results,
	}

	// Metadata
	report.Metadata.GeneratedAt = r.stats.EndTime.Format("2006-01-02T15:04:05Z07:00")
	report.Metadata.ScanPath = r.stats.ScannedPath
	report.Metadata.ManifestFiles = r.stats.ManifestFiles

	// Summary
	report.Summary.TotalPackages = r.stats.TotalPackages
	report.Summary.HighRisk = r.stats.HighRisk
	report.Summary.MediumRisk = r.stats.MediumRisk
	report.Summary.LowRisk = r.stats.LowRisk
	report.Summary.OverallRisk = r.calculateOverallRisk()
	report.Summary.ScanDuration = r.stats.EndTime.Sub(r.stats.StartTime).Seconds()

	// Executive Summary with Key Findings
	criticalIssues := r.extractCriticalIssues(5)
	report.ExecutiveSummary.KeyFindings = make([]JSONCriticalIssue, len(criticalIssues))
	for i, issue := range criticalIssues {
		report.ExecutiveSummary.KeyFindings[i] = JSONCriticalIssue{
			PackageName:    issue.PackageName,
			PackageVersion: issue.PackageVersion,
			Ecosystem:      issue.Ecosystem,
			RiskLevel:      issue.RiskLevel,
			Severity:       issue.Severity,
			Description:    issue.Description,
			Evidence:       issue.Evidence,
			Impact:         r.getRiskImpactDescription(issue.Severity),
		}
	}

	// Generate professional summary text
	if len(criticalIssues) > 0 {
		report.ExecutiveSummary.Summary = fmt.Sprintf(
			"Supply Chain Risk Assessment: Scanned %d packages and identified %d with elevated supply chain compromise risk. "+
				"%d packages are HIGH risk (immediate attention required), %d are MEDIUM risk (monitoring recommended). "+
				"This assessment evaluates likelihood of compromise through supply chain attacks, not known CVEs.",
			r.stats.TotalPackages, r.stats.HighRisk+r.stats.MediumRisk, r.stats.HighRisk, r.stats.MediumRisk)
	} else {
		report.ExecutiveSummary.Summary = fmt.Sprintf(
			"Supply Chain Risk Assessment: Scanned %d packages with overall risk level: %s. "+
				"This assessment evaluates likelihood of compromise through supply chain attacks, not known CVEs.",
			r.stats.TotalPackages, r.calculateOverallRisk())
	}

	// Add AI Executive Summary if available
	for _, result := range r.results {
		if result.AIAnalysis != nil && result.AIAnalysis.ExecutiveSummary != nil {
			aiExec := result.AIAnalysis.ExecutiveSummary
			report.ExecutiveSummary.AIInsights = &JSONAIExecutiveSummary{
				Summary:        aiExec.Summary,
				KeyRisks:       aiExec.KeyRisks,
				BusinessImpact: aiExec.BusinessImpact,
				Confidence:     aiExec.Confidence,
				GeneratedAt:    aiExec.GeneratedAt.Format("2006-01-02T15:04:05Z07:00"),
			}
			break // Only include the first one found
		}
	}

	// Key Risk Areas — strip ANSI escape codes so JSON consumers get plain text
	rawAreas := r.generateRiskAreas()
	cleanAreas := make([]string, len(rawAreas))
	for i, area := range rawAreas {
		cleanAreas[i] = stripANSI(area)
	}
	report.KeyRiskAreas = cleanAreas

	// Encode JSON
	encoder := json.NewEncoder(r.config.Writer)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}
