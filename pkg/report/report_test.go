package report

import (
	"bytes"
	"fmt"
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

	t.Run("Text format compact output hides findings", func(t *testing.T) {
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

		// Default (non-verbose) output should NOT show detailed findings
		if strings.Contains(output, "Single maintainer") {
			t.Error("Default output should not show finding details (use --verbose)")
		}

		// Should hint at verbose flag
		if !strings.Contains(output, "-v") {
			t.Error("Default output should hint at -v for detailed report")
		}
	})

	t.Run("Text format verbose output shows findings", func(t *testing.T) {
		buf := &bytes.Buffer{}
		reporter := NewReporter(Config{
			Format:  FormatText,
			Verbose: true,
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

		// Verbose output should show findings
		if !strings.Contains(output, "Single maintainer") {
			t.Error("Verbose output missing finding description")
		}

		// Verbose output should show evidence
		if !strings.Contains(output, "Evidence:") {
			t.Error("Verbose output missing evidence details")
		}
	})

	t.Run("Markdown format includes executive narrative", func(t *testing.T) {
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

		if !strings.Contains(output, "### Risk Assessment") {
			t.Error("Markdown output missing '### Risk Assessment' section")
		}

		if !strings.Contains(output, "scanned 3 packages") {
			t.Error("Markdown output missing package count in narrative")
		}

		if !strings.Contains(output, "elevated supply chain risk") {
			t.Error("Markdown output missing risk posture in narrative")
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

	t.Run("HTML format includes executive narrative", func(t *testing.T) {
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

		if !strings.Contains(output, "Executive Summary") {
			t.Error("HTML output missing Executive Summary heading")
		}

		if !strings.Contains(output, "exec-narrative") {
			t.Error("HTML output missing exec-narrative CSS class")
		}

		if !strings.Contains(output, "scanned 3 packages") {
			t.Error("HTML output missing package count in narrative")
		}

		if !strings.Contains(output, "elevated supply chain risk") {
			t.Error("HTML output missing risk posture in narrative")
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

// Test: Key Risk Areas show package names as clickable anchor links
// Justification: When the Key Risk Areas section flags patterns like "HIGH RISK"
//
//	or "INSTALL-TIME EXECUTION", users need to see which specific
//	packages are affected and navigate directly to their details for
//	triage. Plain-text package lists without links force manual
//	scrolling, slowing incident response.
//
// Source: "Backstabber's Knife Collection" (Ohm et al., 2020) - rapid
//
//	identification of risky packages is critical for incident response
//
// Methodology: Generate an HTML report with packages that trigger multiple risk
//
//	areas (HIGH risk, install scripts, missing provenance), then verify
//	the Key Risk Areas section renders package names as anchor links
//	matching the #pkg-<slug> pattern used in package detail sections.
//
// Result: Each package name in Key Risk Areas links to its detail via #pkg-<slug>
func TestHTMLRiskAreasClickableLinks(t *testing.T) {
	results := []models.AnalysisResult{
		{
			Dependency: models.Dependency{
				Name:      "evil-pkg",
				Version:   "1.0.0",
				Ecosystem: models.EcosystemNPM,
			},
			RiskLevel:           "HIGH",
			SourceCodeAvailable: false,
			Metadata:            models.PackageMetadata{HasInstallScripts: true},
			Findings: []models.Finding{
				{Severity: "HIGH", Description: "Single maintainer"},
			},
			SupplyChainScore: &models.SupplyChainScore{
				TotalScore: 14,
				RiskLevel:  "HIGH",
				CategoryScores: models.CategoryScores{
					Provenance:      models.CategoryScore{RiskPoints: 2, Score: 2},
					ReleaseSecurity: models.CategoryScore{RiskPoints: 2, Score: 2},
				},
			},
		},
		{
			Dependency: models.Dependency{
				Name:      "@shady/lib",
				Version:   "0.1.0",
				Ecosystem: models.EcosystemNPM,
			},
			RiskLevel:           "HIGH",
			SourceCodeAvailable: false,
			Metadata:            models.PackageMetadata{HasInstallScripts: true},
			Findings: []models.Finding{
				{Severity: "HIGH", Description: "Recent ownership transfer"},
			},
			SupplyChainScore: &models.SupplyChainScore{
				TotalScore: 12,
				RiskLevel:  "HIGH",
				CategoryScores: models.CategoryScores{
					Provenance:      models.CategoryScore{RiskPoints: 2, Score: 2},
					ReleaseSecurity: models.CategoryScore{RiskPoints: 2, Score: 2},
				},
			},
		},
		{
			Dependency: models.Dependency{
				Name:      "safe-pkg",
				Version:   "2.0.0",
				Ecosystem: models.EcosystemNPM,
			},
			RiskLevel:           "LOW",
			SourceCodeAvailable: true,
			Findings: []models.Finding{
				{Severity: "LOW", Description: "Well maintained"},
			},
			SupplyChainScore: &models.SupplyChainScore{
				TotalScore: 1,
				RiskLevel:  "LOW",
				CategoryScores: models.CategoryScores{
					Provenance:      models.CategoryScore{RiskPoints: 0, Score: 0},
					ReleaseSecurity: models.CategoryScore{RiskPoints: 0, Score: 0},
				},
			},
		},
	}

	buf := &bytes.Buffer{}
	reporter := NewReporter(Config{
		Format: FormatHTML,
		Writer: buf,
	})
	reporter.stats.StartTime = time.Now().Add(-3 * time.Second)
	reporter.stats.EndTime = time.Now()
	reporter.AddResults(results)

	err := reporter.Generate()
	if err != nil {
		t.Fatalf("Generate() failed: %v", err)
	}

	output := buf.String()

	// Verify "HIGH RISK" area lists package names as clickable links
	if !strings.Contains(output, `<a href="#pkg-evil-pkg">evil-pkg</a>`) {
		t.Error("Key Risk Areas: HIGH RISK section missing clickable link for 'evil-pkg'")
	}
	if !strings.Contains(output, `<a href="#pkg-shady-lib">@shady/lib</a>`) {
		t.Error("Key Risk Areas: HIGH RISK section missing clickable link for '@shady/lib'")
	}

	// Verify "UNVERIFIABLE SOURCE" area lists affected packages as links
	if !strings.Contains(output, `Affected:`) {
		t.Error("Key Risk Areas missing 'Affected:' label for package examples")
	}

	// Verify "INSTALL-TIME EXECUTION" area lists affected packages as links
	// Both evil-pkg and @shady/lib have install scripts
	if !strings.Contains(output, `<a href="#pkg-evil-pkg">evil-pkg</a>`) {
		t.Error("Key Risk Areas: INSTALL-TIME EXECUTION missing clickable link for 'evil-pkg'")
	}

	// Verify links use the same anchor pattern as package detail sections
	if !strings.Contains(output, `id="pkg-evil-pkg"`) {
		t.Error("Package detail section missing matching id='pkg-evil-pkg'")
	}
	if !strings.Contains(output, `id="pkg-shady-lib"`) {
		t.Error("Package detail section missing matching id='pkg-shady-lib'")
	}

	// Verify the risk-area-examples div has anchor tags (not plain text)
	// The old behavior was: <div class="risk-area-examples">Affected: evil-pkg, @shady/lib</div>
	// The new behavior should have <a> tags inside
	if strings.Contains(output, `risk-area-examples">Affected: evil-pkg,`) {
		t.Error("Key Risk Areas still using plain text for package names instead of anchor links")
	}
}

// Test: HTML Executive Summary narrative provides balanced risk overview
// Justification: Users need a factual, non-alarmist summary of supply chain
//
//	risk across all scanned packages for executive stakeholders
//
// Source: User requirements for balanced, professional report tone
// Methodology: Generate HTML report and verify narrative contains package counts,
//
//	risk posture, and key risk areas without alarmist language
//
// Result: Executive Summary section contains factual summary with measured tone
func TestHTMLExecutiveNarrative(t *testing.T) {
	results := []models.AnalysisResult{
		{
			Dependency: models.Dependency{
				Name:      "event-stream",
				Version:   "3.3.6",
				Ecosystem: models.EcosystemNPM,
			},
			RiskLevel: "HIGH",
			Findings: []models.Finding{
				{
					Severity:    "HIGH",
					Category:    "Ownership Changes",
					Description: "Recent ownership transfer to unknown maintainer",
					SourceURL:   "https://arxiv.org/abs/2005.09535",
				},
			},
			SupplyChainScore: &models.SupplyChainScore{TotalScore: 14, RiskLevel: "HIGH"},
		},
		{
			Dependency: models.Dependency{
				Name:      "@types/node",
				Version:   "20.0.0",
				Ecosystem: models.EcosystemNPM,
			},
			RiskLevel: "MEDIUM",
			Findings: []models.Finding{
				{
					Severity:    "MEDIUM",
					Category:    "Publisher Control",
					Description: "Single maintainer account",
				},
			},
			SupplyChainScore: &models.SupplyChainScore{TotalScore: 8, RiskLevel: "MEDIUM"},
		},
		{
			Dependency: models.Dependency{
				Name:      "safe-pkg",
				Version:   "1.0.0",
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

	// Verify Executive Summary section exists
	if !strings.Contains(output, "Executive Summary") {
		t.Error("HTML output missing Executive Summary heading")
	}

	// Verify narrative mentions package count and risk posture
	if !strings.Contains(output, "scanned 3 packages") {
		t.Error("Narrative missing package count")
	}
	if !strings.Contains(output, "2 of 3 packages show elevated supply chain risk") {
		t.Error("Narrative missing risk posture")
	}
	if !strings.Contains(output, "1 high, 1 medium") {
		t.Error("Narrative missing risk breakdown")
	}

	// Verify no alarmist language
	alarmist := []string{"CRITICAL DANGER", "immediate attention required", "URGENT"}
	for _, phrase := range alarmist {
		if strings.Contains(output, phrase) {
			t.Errorf("Narrative contains alarmist language: %q", phrase)
		}
	}

	// Verify exec-narrative CSS class is present
	if !strings.Contains(output, "exec-narrative") {
		t.Error("HTML output missing exec-narrative CSS class")
	}

	// Verify old Top Priority Findings section is NOT present
	if strings.Contains(output, "Top Priority Findings") {
		t.Error("HTML output should not contain old Top Priority Findings section")
	}
	if strings.Contains(output, "top-finding") {
		t.Error("HTML output should not contain old top-finding CSS classes")
	}

	// Verify package detail sections still have navigable IDs
	if !strings.Contains(output, `id="pkg-event-stream"`) {
		t.Error("Package detail section missing id='pkg-event-stream'")
	}
	if !strings.Contains(output, `id="pkg-types-node"`) {
		t.Error("Package detail section missing id='pkg-types-node'")
	}
}

// Test: Packages sorted by risk score descending, findings by severity descending
// Justification: Highest-risk packages should appear first in all report formats
//
//	so that users can immediately triage the most dangerous dependencies.
//	Within each package, the most severe findings should come first.
//
// Source: "Backstabber's Knife Collection" (Ohm et al., 2020) — rapid
//
//	identification of risky packages is critical for incident response
//
// Methodology: Create packages with known scores in mixed order, generate each
//
//	report format, verify output order matches risk score descending
//
// Result: All formats show highest-risk packages first, highest-severity findings first
func TestSortedResultsByRiskScore(t *testing.T) {
	results := []models.AnalysisResult{
		{
			Dependency: models.Dependency{Name: "low-pkg", Version: "1.0.0", Ecosystem: models.EcosystemNPM},
			RiskLevel:  "LOW",
			Findings: []models.Finding{
				{Severity: "LOW", Description: "Well maintained"},
			},
			SupplyChainScore: &models.SupplyChainScore{TotalScore: 3, RiskLevel: "LOW"},
		},
		{
			Dependency: models.Dependency{Name: "high-pkg", Version: "2.0.0", Ecosystem: models.EcosystemNPM},
			RiskLevel:  "HIGH",
			Findings: []models.Finding{
				{Severity: "LOW", Description: "Minor issue"},
				{Severity: "CRITICAL", Description: "Critical compromise vector"},
				{Severity: "MEDIUM", Description: "Moderate concern"},
				{Severity: "HIGH", Description: "Significant risk factor"},
			},
			SupplyChainScore: &models.SupplyChainScore{TotalScore: 15, RiskLevel: "HIGH"},
		},
		{
			Dependency: models.Dependency{Name: "medium-pkg", Version: "3.0.0", Ecosystem: models.EcosystemNPM},
			RiskLevel:  "MEDIUM",
			Findings: []models.Finding{
				{Severity: "MEDIUM", Description: "Missing provenance"},
			},
			SupplyChainScore: &models.SupplyChainScore{TotalScore: 9, RiskLevel: "MEDIUM"},
		},
	}

	t.Run("sortedResults orders by score descending", func(t *testing.T) {
		reporter := NewReporter(Config{})
		reporter.AddResults(results)

		sorted := reporter.sortedResults()

		if len(sorted) != 3 {
			t.Fatalf("Expected 3 results, got %d", len(sorted))
		}
		if sorted[0].Dependency.Name != "high-pkg" {
			t.Errorf("Expected first package to be 'high-pkg' (score 15), got %s", sorted[0].Dependency.Name)
		}
		if sorted[1].Dependency.Name != "medium-pkg" {
			t.Errorf("Expected second package to be 'medium-pkg' (score 9), got %s", sorted[1].Dependency.Name)
		}
		if sorted[2].Dependency.Name != "low-pkg" {
			t.Errorf("Expected third package to be 'low-pkg' (score 3), got %s", sorted[2].Dependency.Name)
		}
	})

	t.Run("sortedResults sorts findings by severity descending", func(t *testing.T) {
		reporter := NewReporter(Config{})
		reporter.AddResults(results)

		sorted := reporter.sortedResults()

		// high-pkg has 4 findings in mixed order; should be CRITICAL > HIGH > MEDIUM > LOW
		highPkg := sorted[0]
		if highPkg.Dependency.Name != "high-pkg" {
			t.Fatalf("Expected high-pkg first, got %s", highPkg.Dependency.Name)
		}
		expectedSeverities := []string{"CRITICAL", "HIGH", "MEDIUM", "LOW"}
		for i, finding := range highPkg.Findings {
			if finding.Severity != expectedSeverities[i] {
				t.Errorf("Finding %d: expected severity %s, got %s", i, expectedSeverities[i], finding.Severity)
			}
		}
	})

	t.Run("sortedResults does not mutate original", func(t *testing.T) {
		reporter := NewReporter(Config{})
		reporter.AddResults(results)

		_ = reporter.sortedResults()

		// Original order should be preserved
		if reporter.results[0].Dependency.Name != "low-pkg" {
			t.Error("sortedResults mutated original results slice")
		}
		// Original finding order should be preserved
		if reporter.results[1].Findings[0].Severity != "LOW" {
			t.Error("sortedResults mutated original findings slice")
		}
	})

	t.Run("Text format shows highest risk first", func(t *testing.T) {
		buf := &bytes.Buffer{}
		reporter := NewReporter(Config{Format: FormatText, Verbose: false, Writer: buf})
		reporter.stats.StartTime = time.Now().Add(-2 * time.Second)
		reporter.stats.EndTime = time.Now()
		reporter.AddResults(results)

		if err := reporter.Generate(); err != nil {
			t.Fatalf("Generate() failed: %v", err)
		}

		output := buf.String()
		highIdx := strings.Index(output, "high-pkg@2.0.0")
		medIdx := strings.Index(output, "medium-pkg@3.0.0")
		lowIdx := strings.Index(output, "low-pkg@1.0.0")

		if highIdx == -1 || medIdx == -1 || lowIdx == -1 {
			t.Fatal("Output missing one or more package names")
		}
		if highIdx > medIdx {
			t.Error("Text: high-pkg should appear before medium-pkg")
		}
		if medIdx > lowIdx {
			t.Error("Text: medium-pkg should appear before low-pkg")
		}
	})

	t.Run("Markdown format shows highest risk first", func(t *testing.T) {
		buf := &bytes.Buffer{}
		reporter := NewReporter(Config{Format: FormatMarkdown, Verbose: false, Writer: buf})
		reporter.stats.StartTime = time.Now().Add(-2 * time.Second)
		reporter.stats.EndTime = time.Now()
		reporter.AddResults(results)

		if err := reporter.Generate(); err != nil {
			t.Fatalf("Generate() failed: %v", err)
		}

		output := buf.String()
		// Find in the "Detailed Findings" section
		detailedIdx := strings.Index(output, "## Detailed Findings")
		if detailedIdx == -1 {
			t.Fatal("Markdown output missing '## Detailed Findings' section")
		}
		detailed := output[detailedIdx:]

		highIdx := strings.Index(detailed, "high-pkg@2.0.0")
		medIdx := strings.Index(detailed, "medium-pkg@3.0.0")
		lowIdx := strings.Index(detailed, "low-pkg@1.0.0")

		if highIdx == -1 || medIdx == -1 || lowIdx == -1 {
			t.Fatal("Markdown detailed section missing one or more package names")
		}
		if highIdx > medIdx {
			t.Error("Markdown: high-pkg should appear before medium-pkg in detailed findings")
		}
		if medIdx > lowIdx {
			t.Error("Markdown: medium-pkg should appear before low-pkg in detailed findings")
		}
	})

	t.Run("HTML format shows highest risk first", func(t *testing.T) {
		buf := &bytes.Buffer{}
		reporter := NewReporter(Config{Format: FormatHTML, Verbose: false, Writer: buf})
		reporter.stats.StartTime = time.Now().Add(-2 * time.Second)
		reporter.stats.EndTime = time.Now()
		reporter.AddResults(results)

		if err := reporter.Generate(); err != nil {
			t.Fatalf("Generate() failed: %v", err)
		}

		output := buf.String()
		// Look at "Package Details" section
		detailsIdx := strings.Index(output, "Package Details")
		if detailsIdx == -1 {
			t.Fatal("HTML output missing 'Package Details' section")
		}
		details := output[detailsIdx:]

		highIdx := strings.Index(details, "high-pkg@2.0.0")
		medIdx := strings.Index(details, "medium-pkg@3.0.0")
		lowIdx := strings.Index(details, "low-pkg@1.0.0")

		if highIdx == -1 || medIdx == -1 || lowIdx == -1 {
			t.Fatal("HTML details section missing one or more package names")
		}
		if highIdx > medIdx {
			t.Error("HTML: high-pkg should appear before medium-pkg")
		}
		if medIdx > lowIdx {
			t.Error("HTML: medium-pkg should appear before low-pkg")
		}
	})

	t.Run("JSON format shows highest risk first", func(t *testing.T) {
		buf := &bytes.Buffer{}
		reporter := NewReporter(Config{Format: FormatJSON, Verbose: false, Writer: buf})
		reporter.stats.StartTime = time.Now().Add(-2 * time.Second)
		reporter.stats.EndTime = time.Now()
		reporter.AddResults(results)

		if err := reporter.Generate(); err != nil {
			t.Fatalf("Generate() failed: %v", err)
		}

		output := buf.String()
		highIdx := strings.Index(output, `"high-pkg"`)
		medIdx := strings.Index(output, `"medium-pkg"`)
		lowIdx := strings.Index(output, `"low-pkg"`)

		if highIdx == -1 || medIdx == -1 || lowIdx == -1 {
			t.Fatal("JSON output missing one or more package names")
		}
		if highIdx > medIdx {
			t.Error("JSON: high-pkg should appear before medium-pkg in results")
		}
		if medIdx > lowIdx {
			t.Error("JSON: medium-pkg should appear before low-pkg in results")
		}
	})

	t.Run("HTML format sorts findings by severity within package", func(t *testing.T) {
		buf := &bytes.Buffer{}
		reporter := NewReporter(Config{Format: FormatHTML, Verbose: true, Writer: buf})
		reporter.stats.StartTime = time.Now().Add(-2 * time.Second)
		reporter.stats.EndTime = time.Now()
		reporter.AddResults(results)

		if err := reporter.Generate(); err != nil {
			t.Fatalf("Generate() failed: %v", err)
		}

		output := buf.String()
		// Within high-pkg's findings, CRITICAL should appear before LOW
		criticalIdx := strings.Index(output, "Critical compromise vector")
		lowFindingIdx := strings.Index(output, "Minor issue")

		if criticalIdx == -1 || lowFindingIdx == -1 {
			t.Fatal("HTML output missing expected finding descriptions")
		}
		if criticalIdx > lowFindingIdx {
			t.Error("HTML: CRITICAL finding should appear before LOW finding within a package")
		}
	})
}

// Test: Score gradient produces smooth color transitions across the 0-20 range
// Justification: A smooth gradient from green to red enables faster visual triage
//
//	of supply chain risk — users can instantly gauge relative risk at a
//	glance rather than mapping discrete buckets mentally.
//
// Source: "Backstabber's Knife Collection" (Ohm et al., 2020) — rapid
//
//	identification of risky packages is critical for incident response
//
// Methodology: Verify gradient interpolation at boundary values and midpoints,
//
//	check ANSI truecolor and CSS output formats
//
// Result: Score 0 is green, score 20 is red, intermediates smoothly interpolate
func TestScoreGradientRGB(t *testing.T) {
	tests := []struct {
		score      int
		wantR      int
		wantG      int
		wantB      int
		desc       string
	}{
		{0, 82, 183, 136, "score 0 should be forest green"},
		{5, 132, 204, 22, "score 5 should be lime/yellow-green"},
		{10, 245, 158, 11, "score 10 should be amber"},
		{15, 249, 115, 22, "score 15 should be orange"},
		{20, 239, 68, 68, "score 20 should be red"},
	}

	for _, tt := range tests {
		r, g, b := scoreGradientRGB(tt.score)
		if r != tt.wantR || g != tt.wantG || b != tt.wantB {
			t.Errorf("scoreGradientRGB(%d): got (%d,%d,%d), want (%d,%d,%d) — %s",
				tt.score, r, g, b, tt.wantR, tt.wantG, tt.wantB, tt.desc)
		}
	}
}

// Test: Gradient interpolates smoothly between adjacent stops
// Justification: Intermediate scores (e.g. 3, 7, 12) must produce colors
//
//	between adjacent gradient stops, not jump between buckets
//
// Source: Visual triage requirement for supply chain risk reports
// Methodology: Verify midpoint between two stops has intermediate RGB values
// Result: Score 2-3 produces values between stop 0 and stop 5
func TestScoreGradientInterpolation(t *testing.T) {
	// Score 2 should be between green (score 0) and lime (score 5)
	r, g, _ := scoreGradientRGB(2)
	if r <= 82 || r >= 132 {
		t.Errorf("scoreGradientRGB(2): R=%d should be between 82 and 132", r)
	}
	if g <= 183 || g >= 204 {
		t.Errorf("scoreGradientRGB(2): G=%d should be between 183 and 204", g)
	}

	// Score 12 should be between amber (score 10) and orange (score 15)
	r, _, _ = scoreGradientRGB(12)
	if r < 245 || r > 249 {
		t.Errorf("scoreGradientRGB(12): R=%d should be between 245 and 249", r)
	}
}

// Test: Gradient clamps at boundaries
// Justification: Scores outside the 0-20 range must not cause out-of-bounds
//
//	errors or produce unexpected colors
//
// Source: Defensive testing for edge cases in risk scoring
// Methodology: Test scores below 0 and above 20
// Result: Negative scores match score 0, scores >20 match score 20
func TestScoreGradientBoundaries(t *testing.T) {
	r0, g0, b0 := scoreGradientRGB(0)
	rNeg, gNeg, bNeg := scoreGradientRGB(-5)
	if r0 != rNeg || g0 != gNeg || b0 != bNeg {
		t.Errorf("scoreGradientRGB(-5) should equal scoreGradientRGB(0)")
	}

	r20, g20, b20 := scoreGradientRGB(20)
	rHigh, gHigh, bHigh := scoreGradientRGB(25)
	if r20 != rHigh || g20 != gHigh || b20 != bHigh {
		t.Errorf("scoreGradientRGB(25) should equal scoreGradientRGB(20)")
	}
}

// Test: scoreColor returns truecolor ANSI escape codes
// Justification: Terminal output must use 24-bit color for smooth gradient
//
//	display when rendering risk scores
//
// Source: ANSI truecolor specification (ISO 8613-6)
// Methodology: Verify scoreColor returns \033[38;2;R;G;Bm format
// Result: Output matches expected ANSI truecolor escape format
func TestScoreColorANSI(t *testing.T) {
	color := scoreColor(0)
	expected := "\033[38;2;82;183;136m"
	if color != expected {
		t.Errorf("scoreColor(0) = %q, want %q", color, expected)
	}

	color = scoreColor(20)
	expected = "\033[38;2;239;68;68m"
	if color != expected {
		t.Errorf("scoreColor(20) = %q, want %q", color, expected)
	}
}

// Test: scoreColorCSS returns valid CSS rgb() values
// Justification: HTML reports must use inline CSS colors for gradient score
//
//	display to accurately reflect risk levels
//
// Source: CSS Color Level 4 specification (W3C)
// Methodology: Verify scoreColorCSS returns rgb(R,G,B) format
// Result: Output matches expected CSS color format
func TestScoreColorCSS(t *testing.T) {
	css := scoreColorCSS(0)
	expected := "rgb(82,183,136)"
	if css != expected {
		t.Errorf("scoreColorCSS(0) = %q, want %q", css, expected)
	}

	css = scoreColorCSS(20)
	expected = "rgb(239,68,68)"
	if css != expected {
		t.Errorf("scoreColorCSS(20) = %q, want %q", css, expected)
	}

	css = scoreColorCSS(10)
	expected = "rgb(245,158,11)"
	if css != expected {
		t.Errorf("scoreColorCSS(10) = %q, want %q", css, expected)
	}
}

// Test: HTML report uses gradient colors for package score displays
// Justification: Score numbers in the HTML report must use gradient colors
//
//	to enable visual risk triage at a glance
//
// Source: "Backstabber's Knife Collection" (Ohm et al., 2020) — rapid
//
//	identification of risky packages is critical for incident response
//
// Methodology: Generate HTML report and verify inline style attributes use
//
//	the gradient color values on score elements
//
// Result: Package scores have inline color styles matching the gradient
func TestHTMLReportUsesGradientColors(t *testing.T) {
	results := []models.AnalysisResult{
		{
			Dependency: models.Dependency{
				Name:      "risky-pkg",
				Version:   "1.0.0",
				Ecosystem: models.EcosystemNPM,
			},
			RiskLevel: "HIGH",
			SupplyChainScore: &models.SupplyChainScore{
				TotalScore: 16,
				RiskLevel:  "HIGH",
			},
		},
		{
			Dependency: models.Dependency{
				Name:      "safe-pkg",
				Version:   "2.0.0",
				Ecosystem: models.EcosystemNPM,
			},
			RiskLevel: "LOW",
			SupplyChainScore: &models.SupplyChainScore{
				TotalScore: 3,
				RiskLevel:  "LOW",
			},
		},
	}

	buf := &bytes.Buffer{}
	reporter := NewReporter(Config{
		Format: FormatHTML,
		Writer: buf,
	})
	reporter.stats.StartTime = time.Now().Add(-2 * time.Second)
	reporter.stats.EndTime = time.Now()
	reporter.AddResults(results)

	err := reporter.Generate()
	if err != nil {
		t.Fatalf("Generate() failed: %v", err)
	}

	output := buf.String()

	// High-score package should have inline gradient color on its score
	highColor := scoreColorCSS(16)
	if !strings.Contains(output, fmt.Sprintf("style=\"color:%s\"", highColor)) {
		t.Errorf("HTML output missing gradient color %s for score 16", highColor)
	}

	// Low-score package should have inline gradient color on its score
	lowColor := scoreColorCSS(3)
	if !strings.Contains(output, fmt.Sprintf("style=\"color:%s\"", lowColor)) {
		t.Errorf("HTML output missing gradient color %s for score 3", lowColor)
	}

	// The two colors should be different (gradient, not flat)
	if highColor == lowColor {
		t.Error("Score 16 and score 3 should have different gradient colors")
	}
}

// Test: Category score cards in HTML report include tooltip descriptions
// Justification: Users need to understand what each supply chain risk category
//
//	assesses to interpret scores correctly and prioritize remediation
//
// Source: SLSA specification (https://slsa.dev/spec/v1.0/),
//
//	OSSF Scorecard methodology (https://github.com/ossf/scorecard)
//
// Methodology: Generate HTML report with category scores and verify each
//
//	category card includes a data-tooltip attribute with descriptive text
//
// Result: All 10 category cards have tooltips explaining their supply chain risk relevance
func TestHTMLCategoryTooltips(t *testing.T) {
	results := []models.AnalysisResult{
		{
			Dependency: models.Dependency{
				Name:      "test-pkg",
				Version:   "1.0.0",
				Ecosystem: models.EcosystemNPM,
			},
			RiskLevel: "MEDIUM",
			SupplyChainScore: &models.SupplyChainScore{
				TotalScore: 8,
				RiskLevel:  "MEDIUM",
				CategoryScores: models.CategoryScores{
					PublisherControl: models.CategoryScore{Score: 2, RiskPoints: 2, Verified: true},
					OwnershipChanges: models.CategoryScore{Score: 0, RiskPoints: 0, Verified: true},
					ReleaseAnomalies: models.CategoryScore{Score: 1, RiskPoints: 1, Verified: true},
					InstallExecution: models.CategoryScore{Score: 0, RiskPoints: 0, Verified: true},
					DependencySprawl: models.CategoryScore{Score: 1, RiskPoints: 1, Verified: true},
					Provenance:       models.CategoryScore{Score: 2, RiskPoints: 2, Verified: true},
					Health:           models.CategoryScore{Score: 0, RiskPoints: 0, Verified: true},
					Governance:       models.CategoryScore{Score: 1, RiskPoints: 1, Verified: true},
					ReleaseSecurity:  models.CategoryScore{Score: 1, RiskPoints: 1, Verified: true},
					PackageMaturity:  models.CategoryScore{Score: 0, RiskPoints: 0, Verified: true},
				},
			},
		},
	}

	buf := &bytes.Buffer{}
	reporter := NewReporter(Config{
		Format: FormatHTML,
		Writer: buf,
	})
	reporter.stats.StartTime = time.Now().Add(-1 * time.Second)
	reporter.stats.EndTime = time.Now()
	reporter.AddResults(results)

	err := reporter.Generate()
	if err != nil {
		t.Fatalf("Generate() failed: %v", err)
	}

	output := buf.String()

	// Every category should have a data-tooltip attribute with its description
	for name, tooltip := range categoryTooltips {
		if !strings.Contains(output, fmt.Sprintf("data-tooltip=\"%s\"", tooltip)) {
			t.Errorf("HTML output missing tooltip for category %q", name)
		}
	}

	// Verify tooltip CSS is present
	if !strings.Contains(output, "attr(data-tooltip)") {
		t.Error("HTML output missing tooltip CSS (attr(data-tooltip) rule)")
	}
}
