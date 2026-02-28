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
		TotalPackages          int     `json:"total_packages"`
		DirectDependencies     int     `json:"direct_dependencies"`
		TransitiveDependencies int     `json:"transitive_dependencies"`
		HighRisk               int     `json:"high_risk"`
		MediumRisk             int     `json:"medium_risk"`
		LowRisk                int     `json:"low_risk"`
		OverallRisk            string  `json:"overall_risk"`
		ScanDuration           float64 `json:"scan_duration_seconds"`
	} `json:"summary"`
	ExecutiveSummary struct {
		KeyFindings []JSONCriticalIssue `json:"key_findings"`
		Summary     string              `json:"summary"`
	} `json:"executive_summary"`
	Results      interface{}   `json:"results"`
	KeyRiskAreas []JSONRiskArea `json:"key_risk_areas"`
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
	SourceURL      string `json:"source_url,omitempty"`
}

// JSONRiskArea represents a risk area in JSON format
type JSONRiskArea struct {
	Tag         string   `json:"tag"`
	Summary     string   `json:"summary"`
	Explanation string   `json:"explanation"`
	Examples    []string `json:"examples,omitempty"`
}

func (r *Reporter) generateJSON() error {
	report := JSONReport{
		Results: r.sortedResults(),
	}

	// Metadata
	report.Metadata.GeneratedAt = r.stats.EndTime.Format("2006-01-02T15:04:05Z07:00")
	report.Metadata.ScanPath = r.stats.ScannedPath
	report.Metadata.ManifestFiles = r.stats.ManifestFiles

	// Summary
	report.Summary.TotalPackages = r.stats.TotalPackages
	report.Summary.DirectDependencies = r.stats.DirectDeps
	report.Summary.TransitiveDependencies = r.stats.TransitiveDeps
	report.Summary.HighRisk = r.stats.HighRisk
	report.Summary.MediumRisk = r.stats.MediumRisk
	report.Summary.LowRisk = r.stats.LowRisk
	report.Summary.OverallRisk = calculateOverallRisk(r.stats)
	report.Summary.ScanDuration = r.stats.EndTime.Sub(r.stats.StartTime).Seconds()

	// Executive Summary
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
			SourceURL:      issue.SourceURL,
		}
	}

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
			r.stats.TotalPackages, calculateOverallRisk(r.stats))
	}

	// Key Risk Areas
	areas := r.generateRiskAreas()
	report.KeyRiskAreas = make([]JSONRiskArea, len(areas))
	for i, area := range areas {
		report.KeyRiskAreas[i] = JSONRiskArea(area)
	}

	encoder := json.NewEncoder(r.config.Writer)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}
