package report

import (
	"encoding/json"
	"fmt"
)

// JSONReport represents the JSON output structure
type JSONReport struct {
	Metadata         JSONMetadata         `json:"metadata"`
	Summary          JSONSummary          `json:"summary"`
	ExecutiveSummary JSONExecutiveSummary `json:"executive_summary"`
	Results          []JSONPackageResult  `json:"results"`
	KeyRiskAreas     []JSONRiskArea       `json:"key_risk_areas"`
}

// JSONMetadata holds report metadata
type JSONMetadata struct {
	GeneratedAt   string `json:"generated_at"`
	ScanPath      string `json:"scan_path"`
	ManifestFiles int    `json:"manifest_files"`
}

// JSONSummary holds scan summary statistics
type JSONSummary struct {
	TotalPackages          int     `json:"total_packages"`
	DirectDependencies     int     `json:"direct_dependencies"`
	TransitiveDependencies int     `json:"transitive_dependencies"`
	HighRisk               int     `json:"high_risk"`
	MediumRisk             int     `json:"medium_risk"`
	LowRisk                int     `json:"low_risk"`
	OverallRisk            string  `json:"overall_risk"`
	ScanDurationSeconds    float64 `json:"scan_duration_seconds"`
}

// JSONExecutiveSummary holds the executive summary
type JSONExecutiveSummary struct {
	KeyFindings []JSONCriticalIssue        `json:"key_findings"`
	Summary     string                     `json:"summary"`
	AIInsights  *JSONAIExecutiveSummary    `json:"ai_insights,omitempty"`
}

// JSONAIExecutiveSummary represents report-level AI insights in JSON
type JSONAIExecutiveSummary struct {
	OverallAssessment string   `json:"overall_assessment"`
	KeyThreats        []string `json:"key_threats"`
	CrossPatterns     []string `json:"cross_patterns,omitempty"`
	PriorityPackages  []string `json:"priority_packages,omitempty"`
	RiskPosture       string   `json:"risk_posture"`
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

// JSONPackageResult is a typed wrapper for package results in JSON output
type JSONPackageResult struct {
	Name               string      `json:"name"`
	Version            string      `json:"version"`
	Ecosystem          string      `json:"ecosystem"`
	IsTransitive       bool        `json:"is_transitive"`
	RiskLevel          string      `json:"risk_level"`
	RiskScore          int         `json:"risk_score"`
	RepositoryURL      string      `json:"repository_url,omitempty"`
	SourceAvailable    bool        `json:"source_available"`
	BuildInfra         string      `json:"build_infrastructure,omitempty"`
	SupplyChainScore   *int        `json:"supply_chain_score,omitempty"`
	SupplyChainDetails interface{} `json:"supply_chain_details,omitempty"`
	Findings           interface{} `json:"findings,omitempty"`
	AIAnalysis         interface{} `json:"ai_analysis,omitempty"`
}

// JSONRiskArea represents a structured risk area in JSON output
type JSONRiskArea struct {
	Tag      string   `json:"tag"`
	Severity string   `json:"severity"`
	Count    int      `json:"count"`
	Summary  string   `json:"summary"`
	Examples []string `json:"examples,omitempty"`
}

// generateJSON generates a JSON report
func (r *Reporter) generateJSON() error {
	report := JSONReport{}

	// Metadata
	report.Metadata = JSONMetadata{
		GeneratedAt:   r.stats.EndTime.Format("2006-01-02T15:04:05Z07:00"),
		ScanPath:      r.stats.ScannedPath,
		ManifestFiles: r.stats.ManifestFiles,
	}

	// Summary
	report.Summary = JSONSummary{
		TotalPackages:          r.stats.TotalPackages,
		DirectDependencies:     r.stats.DirectDeps,
		TransitiveDependencies: r.stats.TransitiveDeps,
		HighRisk:               r.stats.HighRisk,
		MediumRisk:             r.stats.MediumRisk,
		LowRisk:                r.stats.LowRisk,
		OverallRisk:            r.calculateOverallRisk(),
		ScanDurationSeconds:    r.stats.EndTime.Sub(r.stats.StartTime).Seconds(),
	}

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

	// Summary text
	if len(criticalIssues) > 0 {
		report.ExecutiveSummary.Summary = fmt.Sprintf(
			"Scanned %d packages: %d HIGH risk, %d MEDIUM risk. "+
				"Assesses supply chain compromise likelihood, not known CVEs.",
			r.stats.TotalPackages, r.stats.HighRisk, r.stats.MediumRisk)
	} else {
		report.ExecutiveSummary.Summary = fmt.Sprintf(
			"Scanned %d packages. Overall risk: %s. "+
				"Assesses supply chain compromise likelihood, not known CVEs.",
			r.stats.TotalPackages, r.calculateOverallRisk())
	}

	// AI insights
	if r.reportAISummary != nil {
		report.ExecutiveSummary.AIInsights = &JSONAIExecutiveSummary{
			OverallAssessment: r.reportAISummary.OverallAssessment,
			KeyThreats:        r.reportAISummary.KeyThreats,
			CrossPatterns:     r.reportAISummary.CrossPatterns,
			PriorityPackages:  r.reportAISummary.PriorityPackages,
			RiskPosture:       r.reportAISummary.RiskPosture,
			Confidence:        r.reportAISummary.Confidence,
			GeneratedAt:       r.reportAISummary.GeneratedAt.Format("2006-01-02T15:04:05Z07:00"),
		}
	}

	// Package results - typed
	report.Results = make([]JSONPackageResult, len(r.results))
	for i, result := range r.results {
		pkg := JSONPackageResult{
			Name:            result.Dependency.Name,
			Version:         result.Dependency.Version,
			Ecosystem:       string(result.Dependency.Ecosystem),
			IsTransitive:    result.Dependency.IsTransitive,
			RiskLevel:       result.RiskLevel,
			RiskScore:       result.RiskScore,
			RepositoryURL:   result.RepositoryURL,
			SourceAvailable: result.SourceCodeAvailable,
			BuildInfra:      result.BuildInfrastructure,
		}
		if result.SupplyChainScore != nil {
			score := result.SupplyChainScore.TotalScore
			pkg.SupplyChainScore = &score
			pkg.SupplyChainDetails = result.SupplyChainScore
		}
		if len(result.Findings) > 0 {
			pkg.Findings = result.Findings
		}
		if result.AIAnalysis != nil {
			pkg.AIAnalysis = result.AIAnalysis
		}
		report.Results[i] = pkg
	}

	// Key Risk Areas - structured
	riskAreas := r.generateRiskAreas()
	report.KeyRiskAreas = make([]JSONRiskArea, len(riskAreas))
	for i, area := range riskAreas {
		report.KeyRiskAreas[i] = JSONRiskArea{
			Tag:      area.Tag,
			Severity: area.Severity,
			Count:    area.Count,
			Summary:  area.Summary,
			Examples: area.Examples,
		}
	}

	encoder := json.NewEncoder(r.config.Writer)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}
