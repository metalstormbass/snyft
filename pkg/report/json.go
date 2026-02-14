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
		KeyFindings []JSONCriticalIssue `json:"key_findings"`
		Summary     string              `json:"summary"`
	} `json:"executive_summary"`
	Results         interface{} `json:"results"`
	Recommendations []string    `json:"recommendations"`
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
		}
	}

	// Generate summary text
	if len(criticalIssues) > 0 {
		report.ExecutiveSummary.Summary = fmt.Sprintf(
			"Found %d critical issues across %d packages. %d packages are HIGH risk, %d are MEDIUM risk.",
			len(criticalIssues), r.stats.TotalPackages, r.stats.HighRisk, r.stats.MediumRisk)
	} else {
		report.ExecutiveSummary.Summary = fmt.Sprintf(
			"Scanned %d packages. Overall risk level is %s.",
			r.stats.TotalPackages, r.calculateOverallRisk())
	}

	// Recommendations
	report.Recommendations = r.generateRecommendations()

	// Encode JSON
	encoder := json.NewEncoder(r.config.Writer)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}
