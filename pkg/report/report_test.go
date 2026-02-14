package report

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/metalstormbass/snyft/pkg/models"
)

// Test: Executive summary includes key findings with specific package examples
// Justification: Users need to quickly identify the most critical issues without
//                reading through all package details
// Source: User requirements for improved report formatting
// Methodology: Extract top 5 critical findings and display with package details
// Result: Verifies executive summary shows package names, versions, and evidence
func TestExecutiveSummaryWithKeyFindings(t *testing.T) {
	// Create test results with various risk levels
	results := []models.AnalysisResult{
		{
			Dependency: models.Dependency{
				Name:      "express",
				Version:   "4.17.1",
				Ecosystem: models.EcosystemNPM,
			},
			RiskLevel: "HIGH",
			Findings: []models.Finding{
				{
					Severity:    "HIGH",
					Category:    "Publisher Control",
					Description: "Single maintainer with no 2FA enabled",
					Evidence:    "Package maintained by single developer 'john-smith' without two-factor authentication",
				},
			},
			SupplyChainScore: &models.SupplyChainScore{
				TotalScore: 10,
				RiskLevel:  "HIGH",
			},
		},
		{
			Dependency: models.Dependency{
				Name:      "lodash",
				Version:   "4.17.21",
				Ecosystem: models.EcosystemNPM,
			},
			RiskLevel: "MEDIUM",
			Findings: []models.Finding{
				{
					Severity:    "MEDIUM",
					Category:    "Provenance",
					Description: "Missing build provenance attestation",
					Evidence:    "No SLSA attestation or Sigstore signature found",
				},
			},
			SupplyChainScore: &models.SupplyChainScore{
				TotalScore: 6,
				RiskLevel:  "MEDIUM",
			},
		},
		{
			Dependency: models.Dependency{
				Name:      "react",
				Version:   "18.2.0",
				Ecosystem: models.EcosystemNPM,
			},
			RiskLevel: "LOW",
			Findings: []models.Finding{
				{
					Severity:    "LOW",
					Category:    "Health",
					Description: "Active community with good bus factor",
					Evidence:    "12 core maintainers, >100 contributors",
				},
			},
			SupplyChainScore: &models.SupplyChainScore{
				TotalScore: 2,
				RiskLevel:  "LOW",
			},
		},
	}

	// Test text format
	t.Run("Text format includes key findings", func(t *testing.T) {
		buf := &bytes.Buffer{}
		reporter := NewReporter(Config{
			Format:  FormatText,
			Verbose: false,
			Writer:  buf,
		})
		reporter.stats.StartTime = time.Now().Add(-5 * time.Second)
		reporter.stats.EndTime = time.Now()
		reporter.AddResults(results)

		err := reporter.Generate()
		if err != nil {
			t.Fatalf("Generate() failed: %v", err)
		}

		output := buf.String()

		// Verify executive summary exists
		if !strings.Contains(output, "EXECUTIVE SUMMARY") {
			t.Error("Output missing 'EXECUTIVE SUMMARY' section")
		}

		// Verify key findings section exists
		if !strings.Contains(output, "Key Findings:") {
			t.Error("Output missing 'Key Findings' section")
		}

		// Verify HIGH risk package is shown with specific details
		if !strings.Contains(output, "express@4.17.1") {
			t.Error("Output missing specific package 'express@4.17.1'")
		}

		// Verify evidence is included
		if !strings.Contains(output, "Evidence:") {
			t.Error("Output missing evidence details")
		}

		// Verify finding description is shown
		if !strings.Contains(output, "Single maintainer") {
			t.Error("Output missing finding description")
		}
	})

	// Test markdown format
	t.Run("Markdown format includes key findings", func(t *testing.T) {
		buf := &bytes.Buffer{}
		reporter := NewReporter(Config{
			Format:  FormatMarkdown,
			Verbose: false,
			Writer:  buf,
		})
		reporter.stats.StartTime = time.Now().Add(-5 * time.Second)
		reporter.stats.EndTime = time.Now()
		reporter.AddResults(results)

		err := reporter.Generate()
		if err != nil {
			t.Fatalf("Generate() failed: %v", err)
		}

		output := buf.String()

		// Verify key findings section
		if !strings.Contains(output, "### Key Findings") {
			t.Error("Markdown output missing '### Key Findings' section")
		}

		// Verify package with evidence
		if !strings.Contains(output, "**express@4.17.1**") {
			t.Error("Markdown output missing bold package name")
		}

		if !strings.Contains(output, "*Evidence:*") {
			t.Error("Markdown output missing evidence marker")
		}
	})

	// Test JSON format
	t.Run("JSON format includes executive summary", func(t *testing.T) {
		buf := &bytes.Buffer{}
		reporter := NewReporter(Config{
			Format:  FormatJSON,
			Verbose: false,
			Writer:  buf,
		})
		reporter.stats.StartTime = time.Now().Add(-5 * time.Second)
		reporter.stats.EndTime = time.Now()
		reporter.AddResults(results)

		err := reporter.Generate()
		if err != nil {
			t.Fatalf("Generate() failed: %v", err)
		}

		output := buf.String()

		// Verify executive_summary field exists
		if !strings.Contains(output, `"executive_summary"`) {
			t.Error("JSON output missing 'executive_summary' field")
		}

		// Verify key_findings array exists
		if !strings.Contains(output, `"key_findings"`) {
			t.Error("JSON output missing 'key_findings' array")
		}

		// Verify package details in JSON
		if !strings.Contains(output, `"express"`) {
			t.Error("JSON output missing package name")
		}

		if !strings.Contains(output, `"4.17.1"`) {
			t.Error("JSON output missing package version")
		}
	})

	// Test HTML format
	t.Run("HTML format includes key findings", func(t *testing.T) {
		buf := &bytes.Buffer{}
		reporter := NewReporter(Config{
			Format:  FormatHTML,
			Verbose: false,
			Writer:  buf,
		})
		reporter.stats.StartTime = time.Now().Add(-5 * time.Second)
		reporter.stats.EndTime = time.Now()
		reporter.AddResults(results)

		err := reporter.Generate()
		if err != nil {
			t.Fatalf("Generate() failed: %v", err)
		}

		output := buf.String()

		// Verify key findings heading
		if !strings.Contains(output, "<h3>Key Findings</h3>") {
			t.Error("HTML output missing key findings heading")
		}

		// Verify package is displayed
		if !strings.Contains(output, "express@4.17.1") {
			t.Error("HTML output missing package details")
		}

		// Verify evidence section
		if !strings.Contains(output, "Evidence:") {
			t.Error("HTML output missing evidence section")
		}
	})
}

// Test: extractCriticalIssues prioritizes HIGH risk over MEDIUM
// Justification: Executive summary should show most critical issues first
// Source: User requirements for prioritized findings
// Methodology: Sort results by risk level and severity
// Result: Verifies HIGH risk packages appear before MEDIUM risk
func TestExtractCriticalIssuesPriority(t *testing.T) {
	results := []models.AnalysisResult{
		{
			Dependency:  models.Dependency{Name: "low-pkg", Version: "1.0.0"},
			RiskLevel:   "LOW",
			Findings:    []models.Finding{{Severity: "LOW", Description: "Low issue"}},
		},
		{
			Dependency:  models.Dependency{Name: "medium-pkg", Version: "2.0.0"},
			RiskLevel:   "MEDIUM",
			Findings:    []models.Finding{{Severity: "MEDIUM", Description: "Medium issue"}},
		},
		{
			Dependency:  models.Dependency{Name: "high-pkg", Version: "3.0.0"},
			RiskLevel:   "HIGH",
			Findings:    []models.Finding{{Severity: "HIGH", Description: "High issue"}},
		},
	}

	reporter := NewReporter(Config{})
	reporter.AddResults(results)

	issues := reporter.extractCriticalIssues(5)

	// Should extract 2 issues (HIGH and MEDIUM, not LOW)
	if len(issues) != 2 {
		t.Errorf("Expected 2 critical issues, got %d", len(issues))
	}

	// First issue should be HIGH risk
	if issues[0].RiskLevel != "HIGH" {
		t.Errorf("Expected first issue to be HIGH risk, got %s", issues[0].RiskLevel)
	}

	if issues[0].PackageName != "high-pkg" {
		t.Errorf("Expected first package to be 'high-pkg', got %s", issues[0].PackageName)
	}

	// Second issue should be MEDIUM risk
	if issues[1].RiskLevel != "MEDIUM" {
		t.Errorf("Expected second issue to be MEDIUM risk, got %s", issues[1].RiskLevel)
	}
}

// Test: extractCriticalIssues respects maxIssues limit
// Justification: Executive summary should be concise, showing top N issues only
// Source: User requirements for top 3-5 critical issues
// Methodology: Limit returned issues to maxIssues parameter
// Result: Verifies only top N issues are returned
func TestExtractCriticalIssuesLimit(t *testing.T) {
	results := make([]models.AnalysisResult, 10)
	for i := 0; i < 10; i++ {
		results[i] = models.AnalysisResult{
			Dependency: models.Dependency{
				Name:    "pkg-" + string(rune('a'+i)),
				Version: "1.0.0",
			},
			RiskLevel: "HIGH",
			Findings: []models.Finding{
				{Severity: "HIGH", Description: "Issue " + string(rune('a'+i))},
			},
		}
	}

	reporter := NewReporter(Config{})
	reporter.AddResults(results)

	// Request only 3 issues
	issues := reporter.extractCriticalIssues(3)

	if len(issues) != 3 {
		t.Errorf("Expected 3 issues, got %d", len(issues))
	}
}
