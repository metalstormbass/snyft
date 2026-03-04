package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/metalstormbass/snyft/pkg/models"
)

// Test: Confidence percentage displayed in HTML report
// Justification: Users need to see confidence at a glance to interpret risk scores.
//   A package scoring 5/20 with 30% confidence is very different from one scoring
//   5/20 with 100% confidence — the former may be low only because checks couldn't run.
// Source: OSSF Scorecard methodology — transparent data availability
// Methodology: Generate HTML for a package with known confidence, verify the
//   confidence percentage appears in the output
// Result: HTML output contains "Confidence:" label with percentage value
func TestHTMLReport_ShowsConfidencePercentage(t *testing.T) {
	var buf bytes.Buffer
	reporter := NewReporter(Config{
		Format: FormatHTML,
		Writer: &buf,
	})

	results := []models.AnalysisResult{
		{
			Dependency: models.Dependency{
				Name:      "test-pkg",
				Version:   "1.0.0",
				Ecosystem: models.EcosystemNPM,
			},
			RiskLevel:            "MEDIUM",
			ConfidencePercentage: 40.0,
			SupplyChainScore: &models.SupplyChainScore{
				TotalScore:   10,
				MaxScore:     19,
				ActiveChecks: 10,
				RiskLevel:    "MEDIUM",
			},
		},
	}

	reporter.AddResults(results)
	if err := reporter.Generate(); err != nil {
		t.Fatalf("Failed to generate HTML: %v", err)
	}

	html := buf.String()

	if !strings.Contains(html, "Confidence:") {
		t.Error("HTML output should contain 'Confidence:' label")
	}
	if !strings.Contains(html, "40%") {
		t.Error("HTML output should contain '40%' confidence value")
	}
}

// Test: Confidence percentage color coding in HTML
// Justification: Visual color coding helps users quickly identify packages with
//   low confidence assessments that may need further investigation.
// Source: UX best practices for risk visualization
// Methodology: Generate HTML with low confidence (< 50%), verify red color is used
// Result: Low confidence shows red color (#ef4444)
func TestHTMLReport_ConfidenceColorCoding_Low(t *testing.T) {
	var buf bytes.Buffer
	reporter := NewReporter(Config{
		Format: FormatHTML,
		Writer: &buf,
	})

	results := []models.AnalysisResult{
		{
			Dependency: models.Dependency{
				Name:      "low-conf-pkg",
				Version:   "1.0.0",
				Ecosystem: models.EcosystemNPM,
			},
			RiskLevel:            "HIGH",
			ConfidencePercentage: 30.0,
			SupplyChainScore: &models.SupplyChainScore{
				TotalScore:   12,
				MaxScore:     19,
				ActiveChecks: 10,
				RiskLevel:    "HIGH",
			},
		},
	}

	reporter.AddResults(results)
	if err := reporter.Generate(); err != nil {
		t.Fatalf("Failed to generate HTML: %v", err)
	}

	html := buf.String()

	// Low confidence (< 50%) should use red color
	if !strings.Contains(html, "#ef4444") {
		t.Error("Low confidence (30%) should use red color (#ef4444)")
	}
}

// Test: High confidence shows green color
// Justification: Visual differentiation between high and low confidence
// Source: UX best practices for risk visualization
// Methodology: Generate HTML with high confidence (>= 75%), verify green color
// Result: High confidence shows green color (#52b788)
func TestHTMLReport_ConfidenceColorCoding_High(t *testing.T) {
	var buf bytes.Buffer
	reporter := NewReporter(Config{
		Format: FormatHTML,
		Writer: &buf,
	})

	results := []models.AnalysisResult{
		{
			Dependency: models.Dependency{
				Name:      "high-conf-pkg",
				Version:   "2.0.0",
				Ecosystem: models.EcosystemNPM,
			},
			RiskLevel:            "LOW",
			ConfidencePercentage: 90.0,
			SupplyChainScore: &models.SupplyChainScore{
				TotalScore:   4,
				MaxScore:     19,
				ActiveChecks: 10,
				RiskLevel:    "LOW",
			},
		},
	}

	reporter.AddResults(results)
	if err := reporter.Generate(); err != nil {
		t.Fatalf("Failed to generate HTML: %v", err)
	}

	html := buf.String()

	// High confidence (>= 75%) should use green color
	if !strings.Contains(html, "#52b788") {
		t.Error("High confidence (90%) should use green color (#52b788)")
	}
}
