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
//
//	reading through all package details
//
// Source: User requirements for improved report formatting
// Methodology: Extract top 5 critical findings and display with package details
// Result: Verifies executive summary shows package names, versions, and evidence
func TestExecutiveSummaryWithKeyFindings(t *testing.T) {
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

	t.Run("Text format includes package results", func(t *testing.T) {
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

		// Check summary line with package count
		if !strings.Contains(output, "packages scanned") {
			t.Error("Output missing package count in summary line")
		}

		// Check risk counts in summary
		if !strings.Contains(output, "high") {
			t.Error("Output missing high risk count in summary")
		}

		// Check package listing
		if !strings.Contains(output, "express@4.17.1") {
			t.Error("Output missing specific package 'express@4.17.1'")
		}

		// Check findings are shown under packages
		if !strings.Contains(output, "Single maintainer") {
			t.Error("Output missing finding description")
		}
	})

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

		if !strings.Contains(output, "### Top Priority Findings") {
			t.Error("Markdown output missing '### Top Priority Findings' section")
		}

		if !strings.Contains(output, "**express@4.17.1**") {
			t.Error("Markdown output missing bold package name")
		}

		if !strings.Contains(output, "*Evidence:*") {
			t.Error("Markdown output missing evidence marker")
		}
	})

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

		if !strings.Contains(output, `"executive_summary"`) {
			t.Error("JSON output missing 'executive_summary' field")
		}

		if !strings.Contains(output, `"key_findings"`) {
			t.Error("JSON output missing 'key_findings' array")
		}

		if !strings.Contains(output, `"express"`) {
			t.Error("JSON output missing package name")
		}

		if !strings.Contains(output, `"4.17.1"`) {
			t.Error("JSON output missing package version")
		}
	})

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

		if !strings.Contains(output, "Top Priority Findings") {
			t.Error("HTML output missing top priority findings heading")
		}

		if !strings.Contains(output, "express@4.17.1") {
			t.Error("HTML output missing package details")
		}

		if !strings.Contains(output, "Single maintainer") {
			t.Error("HTML output missing finding description")
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
			Dependency: models.Dependency{Name: "low-pkg", Version: "1.0.0"},
			RiskLevel:  "LOW",
			Findings:   []models.Finding{{Severity: "LOW", Description: "Low issue"}},
		},
		{
			Dependency: models.Dependency{Name: "medium-pkg", Version: "2.0.0"},
			RiskLevel:  "MEDIUM",
			Findings:   []models.Finding{{Severity: "MEDIUM", Description: "Medium issue"}},
		},
		{
			Dependency: models.Dependency{Name: "high-pkg", Version: "3.0.0"},
			RiskLevel:  "HIGH",
			Findings:   []models.Finding{{Severity: "HIGH", Description: "High issue"}},
		},
	}

	reporter := NewReporter(Config{})
	reporter.AddResults(results)

	issues := reporter.extractCriticalIssues(5)

	if len(issues) != 2 {
		t.Errorf("Expected 2 critical issues, got %d", len(issues))
	}

	if issues[0].RiskLevel != "HIGH" {
		t.Errorf("Expected first issue to be HIGH risk, got %s", issues[0].RiskLevel)
	}

	if issues[0].PackageName != "high-pkg" {
		t.Errorf("Expected first package to be 'high-pkg', got %s", issues[0].PackageName)
	}

	if issues[1].RiskLevel != "MEDIUM" {
		t.Errorf("Expected second issue to be MEDIUM risk, got %s", issues[1].RiskLevel)
	}
}

// Test: Progress bar writes to ProgressWriter, not report Writer, for non-text formats
// Justification: When using HTML/JSON/markdown output, progress must not corrupt the
//
//	structured output on stdout. Progress must go to a separate writer
//	(stderr in production) so users see analysis progress without
//	interfering with piped output.
//
// Source: Supply chain analysis UX requirement - users must see progress during slow
//
//	scans to know the tool hasn't hung
//
// Methodology: Configure reporter with separate Writer and ProgressWriter, verify
//
//	progress output goes only to ProgressWriter
//
// Result: Progress bar output appears in ProgressWriter; report Writer is untouched
func TestProgressBarUsesProgressWriter(t *testing.T) {
	t.Run("Progress goes to ProgressWriter not report Writer", func(t *testing.T) {
		reportBuf := &bytes.Buffer{}
		progressBuf := &bytes.Buffer{}

		reporter := NewReporter(Config{
			Format:         FormatHTML,
			Writer:         reportBuf,
			ProgressWriter: progressBuf,
			ShowProgress:   true,
		})

		reporter.ShowProgress(1, 5, "express@4.17.1")
		reporter.ShowProgress(2, 5, "lodash@4.17.21")

		if progressBuf.Len() == 0 {
			t.Error("Expected progress output in ProgressWriter, got nothing")
		}
		if reportBuf.Len() != 0 {
			t.Errorf("Expected no progress in report Writer, got %d bytes", reportBuf.Len())
		}

		progressOutput := progressBuf.String()
		if !strings.Contains(progressOutput, "lodash") {
			t.Error("Progress output should contain package name 'lodash'")
		}
	})

	t.Run("ClearProgress uses ProgressWriter", func(t *testing.T) {
		reportBuf := &bytes.Buffer{}
		progressBuf := &bytes.Buffer{}

		reporter := NewReporter(Config{
			Format:         FormatHTML,
			Writer:         reportBuf,
			ProgressWriter: progressBuf,
			ShowProgress:   true,
		})

		reporter.ClearProgress()

		if progressBuf.Len() == 0 {
			t.Error("ClearProgress should write to ProgressWriter")
		}
		if reportBuf.Len() != 0 {
			t.Error("ClearProgress should not write to report Writer")
		}
	})

	t.Run("ProgressWriter defaults to Writer when nil", func(t *testing.T) {
		buf := &bytes.Buffer{}

		reporter := NewReporter(Config{
			Format:       FormatText,
			Writer:       buf,
			ShowProgress: true,
		})

		reporter.ShowProgress(1, 3, "react@18.2.0")

		if buf.Len() == 0 {
			t.Error("When ProgressWriter is nil, progress should go to Writer")
		}
	})
}

// Test: Progress bar shows for HTML format with ShowProgress enabled
// Justification: Non-text output formats need visible progress especially with
//
//	slow scans. Without progress, users think the tool is hung.
//
// Source: User report of missing progress bar with --format html
// Methodology: Verify ShowProgress produces output even for HTML format when enabled
// Result: Progress bar contains spinner, percentage, and package name
func TestProgressBarShowsForHTMLFormat(t *testing.T) {
	progressBuf := &bytes.Buffer{}
	htmlBuf := &bytes.Buffer{}

	reporter := NewReporter(Config{
		Format:         FormatHTML,
		Writer:         htmlBuf,
		ProgressWriter: progressBuf,
		ShowProgress:   true,
	})

	reporter.ShowProgress(3, 10, "express@4.17.1")

	output := progressBuf.String()

	if !strings.Contains(output, "30%") {
		t.Error("Progress bar should show 30% for 3/10")
	}

	if !strings.Contains(output, "express") {
		t.Error("Progress bar should show package name")
	}

	if !strings.Contains(output, "(3/10)") {
		t.Error("Progress bar should show count (3/10)")
	}

	if htmlBuf.Len() != 0 {
		t.Error("Progress should not be written to HTML output writer")
	}
}

// Test: Progress bar does not write when ShowProgress is false
// Justification: Disabling progress must produce zero output to avoid
//
//	corrupting piped or redirected structured output
//
// Source: Defensive test for ShowProgress guard
// Methodology: Call ShowProgress and ClearProgress with ShowProgress=false
// Result: Both ProgressWriter and Writer remain empty
func TestProgressBarDisabledProducesNoOutput(t *testing.T) {
	reportBuf := &bytes.Buffer{}
	progressBuf := &bytes.Buffer{}

	reporter := NewReporter(Config{
		Format:         FormatHTML,
		Writer:         reportBuf,
		ProgressWriter: progressBuf,
		ShowProgress:   false,
	})

	reporter.ShowProgress(1, 5, "express@4.17.1")
	reporter.ClearProgress()

	if progressBuf.Len() != 0 {
		t.Error("Progress should not write when ShowProgress is false")
	}
	if reportBuf.Len() != 0 {
		t.Error("Report writer should not receive progress when ShowProgress is false")
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

	issues := reporter.extractCriticalIssues(3)

	if len(issues) != 3 {
		t.Errorf("Expected 3 issues, got %d", len(issues))
	}
}

// Test: packageSlug generates valid HTML-safe slugs from package names
// Justification: Package names in anchor links must be valid HTML IDs so that
//
//	clicking a package name in the summary correctly navigates to
//	the package's detail section, enabling quick risk triage
//
// Source: HTML Living Standard, "The id attribute" (WHATWG)
// Methodology: Convert package names containing @, /, and other special
//
//	characters into lowercase alphanumeric slugs with hyphens
//
// Result: Slugs contain only [a-z0-9-] and have no leading/trailing hyphens
func TestPackageSlug(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"express", "express"},
		{"lodash", "lodash"},
		{"@angular/core", "angular-core"},
		{"@types/node", "types-node"},
		{"my-package", "my-package"},
		{"CamelCase", "camelcase"},
		{"some_pkg_123", "some-pkg-123"},
	}

	for _, tt := range tests {
		got := packageSlug(tt.input)
		if got != tt.want {
			t.Errorf("packageSlug(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

// Test: HTML report detail sections have navigable package IDs
// Justification: Package detail sections need stable IDs so users can
//
//	navigate directly to specific packages for triage.
//
// Source: "Backstabber's Knife Collection" (Ohm et al., 2020) - rapid
//
//	identification of risky packages is critical for incident response
//
// Methodology: Generate an HTML report with HIGH, MEDIUM, and LOW packages,
//
//	verify detail sections have id attributes and summary shows count only
//
// Result: Each package detail section has an id="pkg-<slug>" attribute
func TestHTMLReportPackageDetailIDs(t *testing.T) {
	results := []models.AnalysisResult{
		{
			Dependency: models.Dependency{
				Name:      "express",
				Version:   "4.17.1",
				Ecosystem: models.EcosystemNPM,
			},
			RiskLevel: "HIGH",
			Findings: []models.Finding{
				{Severity: "HIGH", Description: "Single maintainer"},
			},
			SupplyChainScore: &models.SupplyChainScore{TotalScore: 10, RiskLevel: "HIGH"},
		},
		{
			Dependency: models.Dependency{
				Name:      "@angular/core",
				Version:   "16.0.0",
				Ecosystem: models.EcosystemNPM,
			},
			RiskLevel: "MEDIUM",
			Findings: []models.Finding{
				{Severity: "MEDIUM", Description: "Missing provenance"},
			},
			SupplyChainScore: &models.SupplyChainScore{TotalScore: 6, RiskLevel: "MEDIUM"},
		},
		{
			Dependency: models.Dependency{
				Name:      "react",
				Version:   "18.2.0",
				Ecosystem: models.EcosystemNPM,
			},
			RiskLevel: "LOW",
			Findings: []models.Finding{
				{Severity: "LOW", Description: "Well maintained"},
			},
			SupplyChainScore: &models.SupplyChainScore{TotalScore: 2, RiskLevel: "LOW"},
		},
	}

	buf := &bytes.Buffer{}
	reporter := NewReporter(Config{
		Format: FormatHTML,
		Writer: buf,
	})
	reporter.stats.StartTime = time.Now().Add(-5 * time.Second)
	reporter.stats.EndTime = time.Now()
	reporter.AddResults(results)

	err := reporter.Generate()
	if err != nil {
		t.Fatalf("Generate() failed: %v", err)
	}

	output := buf.String()

	// Verify summary shows count only, not individual package names
	if strings.Contains(output, `class="pkg-links"`) {
		t.Error("Summary should not contain package name listings (pkg-links)")
	}

	// Verify package detail sections have id attributes for navigation
	if !strings.Contains(output, `id="pkg-express"`) {
		t.Error("Package detail section missing id='pkg-express'")
	}
	if !strings.Contains(output, `id="pkg-angular-core"`) {
		t.Error("Package detail section missing id='pkg-angular-core'")
	}
	if !strings.Contains(output, `id="pkg-react"`) {
		t.Error("Package detail section missing id='pkg-react'")
	}

	// Verify toggle function uses string-based slugs
	if !strings.Contains(output, `onclick="toggle('express')"`) {
		t.Error("Package header missing onclick with slug-based toggle")
	}
	if !strings.Contains(output, `onclick="toggle('angular-core')"`) {
		t.Error("Package header missing onclick with slug-based toggle for scoped package")
	}
}
