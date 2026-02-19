package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/metalstormbass/snyft/pkg/models"
)

// Test: Known attacks database contains all documented supply chain attacks
// Justification: Missing attacks means gaps in pattern matching against real-world threats
// Source: Backstabber's Knife Collection (Ohm et al., 2020)
// Methodology: Verify database entries against documented attack names and fields
// Result: All expected attacks present with required fields populated
func TestKnownAttacksDatabase(t *testing.T) {
	t.Run("database contains expected attacks", func(t *testing.T) {
		expectedAttacks := []string{
			"event-stream (2018)",
			"ua-parser-js (2021)",
			"coa (2021)",
			"node-ipc (2022)",
			"eslint-scope (2018)",
		}

		if len(KnownAttacks) != len(expectedAttacks) {
			t.Errorf("expected %d attacks, got %d", len(expectedAttacks), len(KnownAttacks))
		}

		for _, expected := range expectedAttacks {
			found := false
			for _, attack := range KnownAttacks {
				if attack.Name == expected {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("expected attack %s not found in database", expected)
			}
		}
	})

	t.Run("all attacks have required fields", func(t *testing.T) {
		for _, attack := range KnownAttacks {
			if attack.Name == "" {
				t.Error("attack missing name")
			}
			if attack.Date == "" {
				t.Errorf("attack %s missing date", attack.Name)
			}
			if attack.Ecosystem == "" {
				t.Errorf("attack %s missing ecosystem", attack.Name)
			}
			if attack.Description == "" {
				t.Errorf("attack %s missing description", attack.Name)
			}
			if attack.AttackVector == "" {
				t.Errorf("attack %s missing attack vector", attack.Name)
			}
			if len(attack.Indicators) == 0 {
				t.Errorf("attack %s has no indicators", attack.Name)
			}
			if attack.AcademicSource == "" {
				t.Errorf("attack %s missing academic source", attack.Name)
			}
		}
	})

	t.Run("academic citations are present", func(t *testing.T) {
		for _, attack := range KnownAttacks {
			if attack.AcademicSource == "" {
				t.Errorf("attack %s missing academic citation", attack.Name)
			}
			validCitationMarkers := []string{"http://", "https://", "Ohm", "NDSS", "SLSA"}
			hasValidCitation := false
			for _, marker := range validCitationMarkers {
				if strings.Contains(attack.AcademicSource, marker) {
					hasValidCitation = true
					break
				}
			}
			if !hasValidCitation {
				t.Errorf("attack %s has suspicious academic source: %s", attack.Name, attack.AcademicSource)
			}
		}
	})

	t.Run("all attacks have impact descriptions", func(t *testing.T) {
		for _, attack := range KnownAttacks {
			if attack.ImpactDescription == "" {
				t.Errorf("attack %s missing impact description", attack.Name)
			}
		}
	})
}

// Test: GetKnownAttack retrieves attacks by exact name match
// Justification: Accurate retrieval is needed to build comparison prompts
// Source: Database lookup correctness
// Methodology: Retrieve existing and non-existent attacks, verify results
// Result: Existing attacks return correctly; missing attacks return nil, false
func TestGetKnownAttack(t *testing.T) {
	t.Run("retrieve existing attack", func(t *testing.T) {
		attack, found := GetKnownAttack("event-stream (2018)")
		if !found {
			t.Fatal("expected to find event-stream attack")
		}
		if attack.Name != "event-stream (2018)" {
			t.Errorf("expected name 'event-stream (2018)', got %s", attack.Name)
		}
		if attack.Ecosystem != "npm" {
			t.Errorf("expected ecosystem 'npm', got %s", attack.Ecosystem)
		}
	})

	t.Run("retrieve each known attack", func(t *testing.T) {
		for _, expected := range KnownAttacks {
			attack, found := GetKnownAttack(expected.Name)
			if !found {
				t.Errorf("expected to find attack %s", expected.Name)
				continue
			}
			if attack.Name != expected.Name {
				t.Errorf("name mismatch: expected %s, got %s", expected.Name, attack.Name)
			}
		}
	})

	t.Run("non-existent attack", func(t *testing.T) {
		_, found := GetKnownAttack("fake-attack")
		if found {
			t.Error("expected not to find fake attack")
		}
	})

	t.Run("empty name returns not found", func(t *testing.T) {
		_, found := GetKnownAttack("")
		if found {
			t.Error("expected not to find attack with empty name")
		}
	})
}

// Test: ListKnownAttacks filters correctly by ecosystem
// Justification: Ecosystem filtering ensures only relevant attacks are compared
// Source: Attack database filtering logic
// Methodology: Filter by npm, pypi, empty, and non-existent ecosystems
// Result: npm returns all npm attacks; empty returns all; unknown returns none
func TestListKnownAttacks(t *testing.T) {
	t.Run("list all attacks", func(t *testing.T) {
		attacks := ListKnownAttacks("")
		if len(attacks) != len(KnownAttacks) {
			t.Errorf("expected %d attacks, got %d", len(KnownAttacks), len(attacks))
		}
	})

	t.Run("filter by ecosystem", func(t *testing.T) {
		npmAttacks := ListKnownAttacks("npm")
		if len(npmAttacks) == 0 {
			t.Error("expected at least one npm attack")
		}
		for _, attack := range npmAttacks {
			if attack.Ecosystem != "npm" && attack.Ecosystem != "universal" {
				t.Errorf("expected npm or universal ecosystem, got %s", attack.Ecosystem)
			}
		}
	})

	t.Run("filter by non-existent ecosystem", func(t *testing.T) {
		attacks := ListKnownAttacks("rubygems")
		if len(attacks) != 0 {
			t.Error("expected no attacks for rubygems ecosystem")
		}
	})

	t.Run("all current attacks are npm ecosystem", func(t *testing.T) {
		npmAttacks := ListKnownAttacks("npm")
		if len(npmAttacks) != len(KnownAttacks) {
			t.Errorf("expected all %d attacks to be npm, got %d", len(KnownAttacks), len(npmAttacks))
		}
	})
}

// Test: buildPackageProfile generates structured profiles for attack comparison
// Justification: Profile quality directly affects AI comparison accuracy
// Source: Supply chain profiling methodology
// Methodology: Build profiles with complete, minimal, and nil SupplyChainScore data
// Result: Profiles contain all relevant data; nil SupplyChainScore handled gracefully
func TestBuildPackageProfile(t *testing.T) {
	t.Run("complete profile", func(t *testing.T) {
		result := models.AnalysisResult{
			RiskLevel: "HIGH",
			RiskScore: 85,
			RiskFactors: []string{
				"Single maintainer",
				"No 2FA",
			},
			SourceCodeAvailable: true,
			Metadata: models.PackageMetadata{
				Maintainers:         []string{"maintainer1"},
				HasInstallScripts:   true,
				HasCI:               false,
				HasSLSAAttestation:  false,
				HasBranchProtection: false,
			},
			Findings: []models.Finding{
				{
					Severity:    "HIGH",
					Category:    "Publisher Control",
					Description: "Single maintainer detected",
				},
			},
			SupplyChainScore: &models.SupplyChainScore{
				TotalScore: 12,
				RiskLevel:  "HIGH",
				CategoryScores: models.CategoryScores{
					PublisherControl: models.CategoryScore{
						RiskPoints:  2,
						Description: "Single maintainer, no 2FA",
					},
					OwnershipChanges: models.CategoryScore{
						RiskPoints:  0,
						Description: "No recent ownership changes",
					},
					ReleaseAnomalies: models.CategoryScore{
						RiskPoints:  1,
						Description: "Some irregular release patterns",
					},
					InstallExecution: models.CategoryScore{
						RiskPoints:  2,
						Description: "Has install scripts",
					},
				},
			},
		}

		profile := buildPackageProfile("test-package", models.EcosystemNPM, result)

		expectedContent := []string{
			"test-package", "npm", "HIGH",
			"Single maintainer", "No 2FA",
			"Publisher Control", "Ownership Changes",
			"Maintainers: 1", "Has Install Scripts: true",
		}
		for _, expected := range expectedContent {
			if !strings.Contains(profile, expected) {
				t.Errorf("profile missing expected content: %q", expected)
			}
		}
	})

	t.Run("minimal profile without supply chain score", func(t *testing.T) {
		result := models.AnalysisResult{
			RiskLevel:           "LOW",
			RiskScore:           10,
			SourceCodeAvailable: true,
			Metadata: models.PackageMetadata{
				Maintainers: []string{"m1", "m2", "m3"},
			},
		}

		profile := buildPackageProfile("minimal-pkg", models.EcosystemPyPI, result)

		if profile == "" {
			t.Error("expected non-empty profile")
		}
		for _, expected := range []string{"minimal-pkg", "pypi", "LOW"} {
			if !strings.Contains(profile, expected) {
				t.Errorf("profile missing: %q", expected)
			}
		}
		if strings.Contains(profile, "Supply Chain Score") {
			t.Error("profile should not contain Supply Chain Score when SupplyChainScore is nil")
		}
	})

	t.Run("profile with no findings or risk factors", func(t *testing.T) {
		result := models.AnalysisResult{
			RiskLevel:           "LOW",
			RiskScore:           5,
			SourceCodeAvailable: true,
			Metadata: models.PackageMetadata{
				Maintainers: []string{"m1", "m2"},
				HasCI:       true,
			},
		}

		profile := buildPackageProfile("clean-pkg", models.EcosystemNPM, result)

		if !strings.Contains(profile, "clean-pkg") {
			t.Error("profile missing package name")
		}
		if !strings.Contains(profile, "Maintainers: 2") {
			t.Error("profile missing maintainer count")
		}
		if strings.Contains(profile, "Identified Risk Factors") {
			t.Error("profile should not contain risk factors section when none exist")
		}
	})

	t.Run("profile includes Sigstore provenance", func(t *testing.T) {
		result := models.AnalysisResult{
			RiskLevel:           "LOW",
			RiskScore:           3,
			SourceCodeAvailable: true,
			Metadata: models.PackageMetadata{
				Maintainers:          []string{"m1", "m2"},
				HasSigstoreSignature: true,
				HasSLSAAttestation:   false,
			},
		}

		profile := buildPackageProfile("sigstore-pkg", models.EcosystemNPM, result)

		if !strings.Contains(profile, "Has Provenance: true") {
			t.Error("profile should show provenance as true when Sigstore signature exists")
		}
	})

	t.Run("profile filters finding severity", func(t *testing.T) {
		result := models.AnalysisResult{
			RiskLevel: "MEDIUM",
			RiskScore: 50,
			Metadata: models.PackageMetadata{
				Maintainers: []string{"m1"},
			},
			Findings: []models.Finding{
				{Severity: "CRITICAL", Category: "Install Execution", Description: "Obfuscated postinstall script"},
				{Severity: "HIGH", Category: "Publisher Control", Description: "Single maintainer"},
				{Severity: "MEDIUM", Category: "Health", Description: "Low test coverage"},
				{Severity: "LOW", Category: "Governance", Description: "No SECURITY.md"},
			},
		}

		profile := buildPackageProfile("mixed-findings", models.EcosystemNPM, result)

		if !strings.Contains(profile, "Obfuscated postinstall script") {
			t.Error("profile should include CRITICAL findings")
		}
		if !strings.Contains(profile, "Single maintainer") {
			t.Error("profile should include HIGH findings")
		}
		if strings.Contains(profile, "Low test coverage") {
			t.Error("profile should NOT include MEDIUM findings")
		}
		if strings.Contains(profile, "No SECURITY.md") {
			t.Error("profile should NOT include LOW findings")
		}
	})
}

// Test: buildBatchedAttackPrompt includes all attacks and required structure
// Justification: The batched prompt must include all attacks for comprehensive matching
// Source: Batched attack pattern matching design
// Methodology: Build prompt with multiple attacks and verify structure
// Result: Prompt includes all attack details, package profile, and JSON response format
func TestBuildBatchedAttackPrompt(t *testing.T) {
	attacks := []HistoricalAttack{
		{
			Name:           "test-attack-1",
			Date:           "2024-01",
			AttackVector:   "Account Takeover",
			Description:    "First test attack",
			Indicators:     []string{"indicator1"},
			AcademicSource: "Test Source 1",
		},
		{
			Name:           "test-attack-2",
			Date:           "2024-02",
			AttackVector:   "Install Script",
			Description:    "Second test attack",
			Indicators:     []string{"indicator2", "indicator3"},
			AcademicSource: "Test Source 2",
		},
	}

	profile := "Test package profile\nRisk: HIGH"

	prompt := buildBatchedAttackPrompt(profile, attacks, 0.7)

	expectedElements := []string{
		"test-attack-1",
		"test-attack-2",
		"Account Takeover",
		"Install Script",
		"indicator1",
		"indicator2",
		"Test package profile",
		"similarity_score",
		"confidence",
		"JSON",
		"Attack 1:",
		"Attack 2:",
		"0.7",
	}

	for _, elem := range expectedElements {
		if !strings.Contains(prompt, elem) {
			t.Errorf("prompt missing expected element: %s", elem)
		}
	}
}

// makeAnthropicMessageResponse builds a valid Anthropic API JSON response with the given text content.
func makeAnthropicMessageResponse(textContent string) string {
	return fmt.Sprintf(`{
		"id": "msg_test_123",
		"type": "message",
		"role": "assistant",
		"model": "claude-sonnet-4-5-20250929",
		"content": [{"type": "text", "text": %s}],
		"stop_reason": "end_turn",
		"usage": {"input_tokens": 100, "output_tokens": 50}
	}`, textContent)
}

// Test: MatchAgainstKnownAttacks with batched API call
// Justification: Core matching logic must use a single batched API call,
//
//	filter by ecosystem and threshold, and return properly structured matches
//
// Source: Backstabber's Knife Collection (Ohm et al., 2020) - attack pattern matching
// Methodology: Mock the Claude API to return controlled batched similarity scores;
//
//	verify ecosystem filtering, threshold filtering, single API call, and match structure
//
// Result: Only npm attacks matched; single API call made; matches above threshold returned
func TestMatchAgainstKnownAttacks(t *testing.T) {
	t.Run("high-risk package matches attacks above threshold", func(t *testing.T) {
		callCount := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			callCount++
			// Return batched response with 2 matches above threshold
			batchResp := batchAttackMatchResponse{
				Matches: []struct {
					AttackName         string   `json:"attack_name"`
					SimilarityScore    float64  `json:"similarity_score"`
					Confidence         float64  `json:"confidence"`
					MatchingIndicators []string `json:"matching_indicators"`
					DifferingFactors   []string `json:"differing_factors,omitempty"`
					Explanation        string   `json:"explanation"`
					Severity           string   `json:"severity"`
				}{
					{
						AttackName:         "ua-parser-js (2021)",
						SimilarityScore:    0.85,
						Confidence:         0.9,
						MatchingIndicators: []string{"Single maintainer", "Install scripts"},
						Explanation:        "High similarity to account takeover pattern",
						Severity:           "HIGH",
					},
					{
						AttackName:         "eslint-scope (2018)",
						SimilarityScore:    0.75,
						Confidence:         0.8,
						MatchingIndicators: []string{"Single maintainer"},
						Explanation:        "Moderate similarity",
						Severity:           "MEDIUM",
					},
				},
			}
			respJSON, _ := json.Marshal(batchResp)
			apiResp := makeAnthropicMessageResponse(fmt.Sprintf("%q", string(respJSON)))
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprint(w, apiResp)
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

		result := models.AnalysisResult{
			RiskLevel: "HIGH",
			RiskScore: 90,
			RiskFactors: []string{
				"Single maintainer with full control",
			},
			SourceCodeAvailable: true,
			Metadata: models.PackageMetadata{
				Maintainers:       []string{"single-maintainer"},
				HasInstallScripts: true,
			},
			SupplyChainScore: &models.SupplyChainScore{
				TotalScore: 14,
				RiskLevel:  "HIGH",
				CategoryScores: models.CategoryScores{
					PublisherControl: models.CategoryScore{
						RiskPoints:  2,
						Description: "Single maintainer, no 2FA",
					},
					InstallExecution: models.CategoryScore{
						RiskPoints:  2,
						Description: "Malicious install scripts",
					},
				},
			},
		}

		req := AttackMatchRequest{
			PackageName:    "suspicious-package",
			Ecosystem:      models.EcosystemNPM,
			AnalysisResult: result,
			Threshold:      0.7,
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		matches, err := MatchAgainstKnownAttacks(ctx, client, req)
		if err != nil {
			t.Fatalf("failed to match attacks: %v", err)
		}

		// Should make exactly 1 batched API call (not 5 individual calls)
		if callCount != 1 {
			t.Errorf("expected 1 batched API call, got %d", callCount)
		}
		if len(matches) != 2 {
			t.Errorf("expected 2 matches above threshold, got %d", len(matches))
		}

		for _, match := range matches {
			if match.PatternName == "" {
				t.Error("match missing pattern name")
			}
			if match.Confidence < 0 || match.Confidence > 1 {
				t.Errorf("invalid confidence: %f", match.Confidence)
			}
			if len(match.Evidence) == 0 {
				t.Error("match missing evidence")
			}
			if match.AcademicSource == "" {
				t.Error("match missing academic source")
			}
		}
	})

	t.Run("low similarity scores filtered by threshold", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Return all matches below threshold
			batchResp := `{"matches":[{"attack_name":"event-stream (2018)","similarity_score":0.3,"confidence":0.8,"matching_indicators":[],"explanation":"Low similarity","severity":"LOW"}]}`
			apiResp := makeAnthropicMessageResponse(fmt.Sprintf("%q", batchResp))
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprint(w, apiResp)
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

		req := AttackMatchRequest{
			PackageName: "safe-package",
			Ecosystem:   models.EcosystemNPM,
			AnalysisResult: models.AnalysisResult{
				RiskLevel:           "LOW",
				RiskScore:           10,
				SourceCodeAvailable: true,
				Metadata: models.PackageMetadata{
					Maintainers: []string{"m1", "m2", "m3"},
				},
			},
			Threshold: 0.7,
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		matches, err := MatchAgainstKnownAttacks(ctx, client, req)
		if err != nil {
			t.Fatalf("failed to match attacks: %v", err)
		}

		if len(matches) != 0 {
			t.Errorf("expected 0 matches below threshold, got %d", len(matches))
		}
	})

	t.Run("pypi ecosystem skips npm-only attacks", func(t *testing.T) {
		callCount := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			callCount++
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprint(w, `{"matches":[]}`)
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

		req := AttackMatchRequest{
			PackageName: "suspicious-pypi-package",
			Ecosystem:   models.EcosystemPyPI,
			AnalysisResult: models.AnalysisResult{
				RiskLevel:           "HIGH",
				RiskScore:           90,
				SourceCodeAvailable: true,
				Metadata: models.PackageMetadata{
					Maintainers: []string{"single-maintainer"},
				},
			},
			Threshold: 0.5,
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		matches, err := MatchAgainstKnownAttacks(ctx, client, req)
		if err != nil {
			t.Fatalf("failed to match attacks: %v", err)
		}

		// All known attacks are npm ecosystem, so pypi should skip all
		if callCount != 0 {
			t.Errorf("expected 0 API calls for pypi (all attacks are npm), got %d", callCount)
		}
		if len(matches) != 0 {
			t.Errorf("expected 0 matches for pypi ecosystem, got %d", len(matches))
		}
	})

	t.Run("API errors return error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = fmt.Fprint(w, `{"type":"error","error":{"type":"invalid_request_error","message":"test error"}}`)
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

		req := AttackMatchRequest{
			PackageName: "test-package",
			Ecosystem:   models.EcosystemNPM,
			AnalysisResult: models.AnalysisResult{
				RiskLevel: "HIGH",
				Metadata:  models.PackageMetadata{Maintainers: []string{"m1"}},
			},
			Threshold: 0.5,
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		_, err = MatchAgainstKnownAttacks(ctx, client, req)
		if err == nil {
			t.Fatal("expected error when API fails")
		}
	})

	t.Run("empty matches response returns nil", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			apiResp := makeAnthropicMessageResponse(`"{\"matches\":[]}"`)
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprint(w, apiResp)
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

		req := AttackMatchRequest{
			PackageName: "clean-package",
			Ecosystem:   models.EcosystemNPM,
			AnalysisResult: models.AnalysisResult{
				RiskLevel: "LOW",
				Metadata:  models.PackageMetadata{Maintainers: []string{"m1"}},
			},
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		matches, err := MatchAgainstKnownAttacks(ctx, client, req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(matches) != 0 {
			t.Errorf("expected 0 matches, got %d", len(matches))
		}
	})
}
