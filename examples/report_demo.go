package main

import (
	"fmt"
	"os"

	"github.com/metalstormbass/snyft/pkg/models"
	"github.com/metalstormbass/snyft/pkg/report"
)

// This demo shows the new executive summary format with specific examples
func main() {
	// Create sample analysis results with realistic data
	results := []models.AnalysisResult{
		{
			Dependency: models.Dependency{
				Name:      "express",
				Version:   "4.17.1",
				Ecosystem: models.EcosystemNPM,
			},
			RiskLevel:           "HIGH",
			SourceCodeAvailable: true,
			RepositoryURL:       "https://github.com/expressjs/express",
			Findings: []models.Finding{
				{
					Severity:    "HIGH",
					Category:    "Publisher Control",
					Description: "Single maintainer without 2FA enabled",
					Evidence:    "Package controlled by 1 maintainer (dougwilson) without two-factor authentication",
					Check:       "publisher_control",
				},
				{
					Severity:    "MEDIUM",
					Category:    "Install Execution",
					Description: "Package executes install-time scripts",
					Evidence:    "postinstall script detected: 'node scripts/setup.js'",
					Check:       "install_scripts",
				},
			},
			SupplyChainScore: &models.SupplyChainScore{
				TotalScore: 9,
				RiskLevel:  "HIGH",
				CategoryScores: models.CategoryScores{
					PublisherControl: models.CategoryScore{
						Score:       2,
						RiskPoints:  2,
						Description: "Single maintainer, no 2FA",
						Verified:    true,
					},
				},
			},
			Metadata: models.PackageMetadata{
				HasInstallScripts: true,
			},
		},
		{
			Dependency: models.Dependency{
				Name:      "lodash",
				Version:   "4.17.21",
				Ecosystem: models.EcosystemNPM,
			},
			RiskLevel:           "MEDIUM",
			SourceCodeAvailable: true,
			RepositoryURL:       "https://github.com/lodash/lodash",
			Findings: []models.Finding{
				{
					Severity:    "MEDIUM",
					Category:    "Provenance",
					Description: "Missing build provenance attestation",
					Evidence:    "No SLSA attestation or npm provenance found for this package version",
					Check:       "provenance",
				},
			},
			SupplyChainScore: &models.SupplyChainScore{
				TotalScore: 6,
				RiskLevel:  "MEDIUM",
			},
		},
		{
			Dependency: models.Dependency{
				Name:      "request",
				Version:   "2.88.2",
				Ecosystem: models.EcosystemNPM,
			},
			RiskLevel:           "HIGH",
			SourceCodeAvailable: true,
			RepositoryURL:       "https://github.com/request/request",
			Findings: []models.Finding{
				{
					Severity:    "HIGH",
					Category:    "Release Anomalies",
					Description: "Dormant package reactivated after long period",
					Evidence:    "Package was inactive for 2 years (2020-2022), then suddenly released version 2.88.2",
					Check:       "release_anomalies",
				},
			},
			SupplyChainScore: &models.SupplyChainScore{
				TotalScore: 10,
				RiskLevel:  "HIGH",
			},
		},
		{
			Dependency: models.Dependency{
				Name:      "react",
				Version:   "18.2.0",
				Ecosystem: models.EcosystemNPM,
			},
			RiskLevel:           "LOW",
			SourceCodeAvailable: true,
			RepositoryURL:       "https://github.com/facebook/react",
			Findings: []models.Finding{
				{
					Severity:    "LOW",
					Category:    "Health",
					Description: "Healthy project with strong community",
					Evidence:    "Bus factor: 15, code review rate: 98%, active CI/CD",
					Check:       "health",
				},
			},
			SupplyChainScore: &models.SupplyChainScore{
				TotalScore: 2,
				RiskLevel:  "LOW",
			},
		},
	}

	// Generate reports in all formats
	formats := []struct {
		name   string
		format report.Format
	}{
		{"Text", report.FormatText},
		{"Markdown", report.FormatMarkdown},
		{"JSON", report.FormatJSON},
		{"HTML", report.FormatHTML},
	}

	for _, f := range formats {
		fmt.Printf("\n%s\n%s\n", f.name+" Format Demo", "===================")

		reporter := report.NewReporter(report.Config{
			Format:  f.format,
			Verbose: false,
			Writer:  os.Stdout,
		})

		// Simulate scan statistics
		reporter.SetScanPath("/path/to/project")
		reporter.SetManifestCount(2)

		// Add results
		reporter.AddResults(results)

		// Generate report
		if err := reporter.Generate(); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "Error generating %s report: %v\n", f.name, err)
		}

		fmt.Println()
	}
}
