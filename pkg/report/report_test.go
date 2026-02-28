package report

import (
	"bytes"
	"encoding/json"
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

		if !strings.Contains(output, "EXECUTIVE SUMMARY") {
			t.Error("Output missing 'EXECUTIVE SUMMARY' section")
		}
		if !strings.Contains(output, "Top Priority Findings:") {
			t.Error("Output missing 'Top Priority Findings' section")
		}
		if !strings.Contains(output, "express@4.17.1") {
			t.Error("Output missing specific package 'express@4.17.1'")
		}
		if !strings.Contains(output, "Evidence:") {
			t.Error("Output missing evidence details")
		}
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

		if !strings.Contains(output, "<h3>Top Priority Findings</h3>") {
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
//                structured output on stdout.
// Source: Supply chain analysis UX requirement
// Methodology: Configure reporter with separate Writer and ProgressWriter
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
		if !strings.Contains(progressBuf.String(), "lodash") {
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
//                AI analysis which can be slow.
// Source: User report of missing progress bar with --ai --format html
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
//                corrupting piped or redirected structured output
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

// Test: JSON output has well-structured, typed results instead of interface{}
// Justification: JSON consumers need predictable schema with typed fields for
//                package results, not raw internal structs dumped as interface{}.
//                Structured output enables reliable tool integration.
// Source: Report readability requirements - logical nesting, proper types
// Methodology: Parse JSON output and verify key fields exist with correct types
// Result: Each package result has name, version, ecosystem, risk_level fields
func TestJSONOutputHasTypedResults(t *testing.T) {
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
			SupplyChainScore: &models.SupplyChainScore{
				TotalScore: 10,
				RiskLevel:  "HIGH",
			},
		},
	}

	buf := &bytes.Buffer{}
	reporter := NewReporter(Config{
		Format:  FormatJSON,
		Writer:  buf,
	})
	reporter.stats.StartTime = time.Now().Add(-2 * time.Second)
	reporter.stats.EndTime = time.Now()
	reporter.AddResults(results)

	if err := reporter.Generate(); err != nil {
		t.Fatalf("Generate() failed: %v", err)
	}

	// Parse JSON
	var report map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("Invalid JSON output: %v", err)
	}

	// Verify results is an array with typed fields
	resultsArr, ok := report["results"].([]interface{})
	if !ok {
		t.Fatal("results should be an array")
	}
	if len(resultsArr) != 1 {
		t.Fatalf("Expected 1 result, got %d", len(resultsArr))
	}

	pkg, ok := resultsArr[0].(map[string]interface{})
	if !ok {
		t.Fatal("result should be an object")
	}

	// Check typed fields exist
	if pkg["name"] != "express" {
		t.Errorf("Expected name 'express', got %v", pkg["name"])
	}
	if pkg["version"] != "4.17.1" {
		t.Errorf("Expected version '4.17.1', got %v", pkg["version"])
	}
	if pkg["risk_level"] != "HIGH" {
		t.Errorf("Expected risk_level 'HIGH', got %v", pkg["risk_level"])
	}

	// Verify supply_chain_score is a number, not nested object
	if pkg["supply_chain_score"] != float64(10) {
		t.Errorf("Expected supply_chain_score 10, got %v", pkg["supply_chain_score"])
	}
}

// Test: Structured risk areas replace ANSI-embedded strings
// Justification: Risk areas should be structured data that each formatter can
//                render appropriately, not strings with embedded ANSI codes that
//                need stripping in non-text formats. This prevents ANSI leaks.
// Source: Report readability requirements - clean non-text output
// Methodology: Generate risk areas and verify they contain structured fields
// Result: RiskArea structs have Tag, Severity, Count, Summary fields
func TestRiskAreasAreStructured(t *testing.T) {
	results := []models.AnalysisResult{
		{
			Dependency:          models.Dependency{Name: "bad-pkg", Version: "1.0.0"},
			RiskLevel:           "HIGH",
			SourceCodeAvailable: false,
			Metadata:            models.PackageMetadata{HasInstallScripts: true},
		},
	}

	reporter := NewReporter(Config{})
	reporter.AddResults(results)

	areas := reporter.generateRiskAreas()

	if len(areas) == 0 {
		t.Fatal("Expected at least one risk area")
	}

	// Verify structured data
	for _, area := range areas {
		if area.Tag == "" {
			t.Error("RiskArea.Tag should not be empty")
		}
		if area.Severity == "" {
			t.Error("RiskArea.Severity should not be empty")
		}
		if area.Summary == "" {
			t.Error("RiskArea.Summary should not be empty")
		}
		// Verify no ANSI codes leaked into structured data
		if strings.Contains(area.Tag, "\033[") {
			t.Error("RiskArea.Tag should not contain ANSI codes")
		}
		if strings.Contains(area.Summary, "\033[") {
			t.Error("RiskArea.Summary should not contain ANSI codes")
		}
	}
}

// Test: Text output is concise - no walls of text
// Justification: The previous report format had multi-line explanations for each
//                risk area and verbose headers. The rewrite aims for scannable output.
// Source: Report readability requirements - keep it concise
// Methodology: Generate text report and check it doesn't exceed line count thresholds
// Result: Non-verbose text report is compact (under threshold line count)
func TestTextOutputIsConcise(t *testing.T) {
	results := []models.AnalysisResult{
		{
			Dependency: models.Dependency{Name: "pkg-a", Version: "1.0.0", Ecosystem: models.EcosystemNPM},
			RiskLevel:  "HIGH",
			Findings:   []models.Finding{{Severity: "HIGH", Description: "Issue A"}},
		},
		{
			Dependency: models.Dependency{Name: "pkg-b", Version: "2.0.0", Ecosystem: models.EcosystemNPM},
			RiskLevel:  "LOW",
			Findings:   []models.Finding{{Severity: "LOW", Description: "Issue B"}},
		},
	}

	buf := &bytes.Buffer{}
	reporter := NewReporter(Config{
		Format:  FormatText,
		Verbose: false,
		Writer:  buf,
	})
	reporter.stats.StartTime = time.Now().Add(-3 * time.Second)
	reporter.stats.EndTime = time.Now()
	reporter.SetScanPath("/test/path")
	reporter.SetManifestCount(1)
	reporter.AddResults(results)

	if err := reporter.Generate(); err != nil {
		t.Fatalf("Generate() failed: %v", err)
	}

	lines := strings.Split(buf.String(), "\n")
	// Non-verbose summary should be compact - less than 35 lines for 2 packages
	if len(lines) > 35 {
		t.Errorf("Non-verbose text output too long: %d lines (expected < 35)", len(lines))
	}
}

// Test: Risk score displayed prominently per package in verbose mode
// Justification: Users need to see the risk score at a glance next to each package
// Source: Report readability requirements - show risk score prominently
// Methodology: Generate verbose text and verify score appears on the package header line
// Result: Package line includes score like "10/22" near the package name
func TestRiskScoreProminentInVerbose(t *testing.T) {
	results := []models.AnalysisResult{
		{
			Dependency: models.Dependency{Name: "risky-pkg", Version: "1.0.0", Ecosystem: models.EcosystemNPM},
			RiskLevel:  "HIGH",
			Findings:   []models.Finding{{Severity: "HIGH", Description: "Bad stuff"}},
			SupplyChainScore: &models.SupplyChainScore{
				TotalScore: 14,
				RiskLevel:  "HIGH",
			},
		},
	}

	buf := &bytes.Buffer{}
	reporter := NewReporter(Config{
		Format:  FormatText,
		Verbose: true,
		Writer:  buf,
	})
	reporter.stats.StartTime = time.Now().Add(-2 * time.Second)
	reporter.stats.EndTime = time.Now()
	reporter.AddResults(results)

	if err := reporter.Generate(); err != nil {
		t.Fatalf("Generate() failed: %v", err)
	}

	output := buf.String()

	// Score should appear near the package name
	if !strings.Contains(output, "14/22") {
		t.Error("Output should contain score '14/22' prominently")
	}
	// Risk level should appear on the same line area as the package
	if !strings.Contains(output, "risky-pkg@1.0.0") {
		t.Error("Output should contain package name with version")
	}
}
