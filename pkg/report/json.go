package report

import (
	"encoding/json"
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
	Results         interface{} `json:"results"`
	Recommendations []string    `json:"recommendations"`
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

	// Recommendations
	report.Recommendations = r.generateRecommendations()

	// Encode JSON
	encoder := json.NewEncoder(r.config.Writer)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}
