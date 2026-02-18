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
		// All known attacks in the database are npm; filtering by npm should return all
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
		// Should NOT contain supply chain score section
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
		// With no risk factors or findings, those sections should be absent
		if strings.Contains(profile, "Identified Risk Factors") {
			t.Error("profile should not contain risk factors section when none exist")
		}
	})

	// Test: Profile built from real-world package characteristics (mike-libraries/javascript)
	// Justification: Profiles must handle real package metadata structures correctly
	// Source: mike-libraries/javascript/package.json - real npm packages
	// Methodology: Build profiles for packages resembling express (popular, well-maintained)
	//              and stripe (cross-ecosystem) to verify realistic profile generation
	// Result: Profiles contain all expected fields for realistic package data
	t.Run("realistic profile for popular npm package", func(t *testing.T) {
		// Simulate a well-maintained popular package like express from mike-libraries
		result := models.AnalysisResult{
			RiskLevel:           "LOW",
			RiskScore:           8,
			SourceCodeAvailable: true,
			Metadata: models.PackageMetadata{
				Maintainers:         []string{"dougwilson", "wesleytodd", "blakeembrey"},
				HasInstallScripts:   false,
				HasCI:               true,
				HasSLSAAttestation:  false,
				HasBranchProtection: true,
			},
			SupplyChainScore: &models.SupplyChainScore{
				TotalScore: 3,
				RiskLevel:  "LOW",
				CategoryScores: models.CategoryScores{
					PublisherControl: models.CategoryScore{
						RiskPoints:  0,
						Description: "Multiple maintainers with good practices",
					},
					InstallExecution: models.CategoryScore{
						RiskPoints:  0,
						Description: "No install scripts",
					},
				},
			},
		}

		profile := buildPackageProfile("express", models.EcosystemNPM, result)

		if !strings.Contains(profile, "express") {
			t.Error("profile missing package name")
		}
		if !strings.Contains(profile, "Maintainers: 3") {
			t.Error("profile missing correct maintainer count")
		}
		if !strings.Contains(profile, "Has Install Scripts: false") {
			t.Error("profile missing install scripts status")
		}
	})
}

// Test: buildAttackComparisonPrompt includes all required elements for AI comparison
// Justification: Missing prompt elements degrade AI comparison quality
// Source: Prompt engineering for structured AI output
// Methodology: Build prompt and verify all structural elements present
// Result: Prompt includes attack details, package profile, and JSON response format
func TestBuildAttackComparisonPrompt(t *testing.T) {
	attack := HistoricalAttack{
		Name:              "test-attack",
		Date:              "2024-01",
		Ecosystem:         "npm",
		Description:       "Test attack description",
		AttackVector:      "Account Takeover",
		Indicators:        []string{"indicator1", "indicator2"},
		ImpactDescription: "Test impact",
		AcademicSource:    "Test Source",
	}

	profile := "Test package profile\nRisk: HIGH"

	prompt := buildAttackComparisonPrompt(profile, attack)

	expectedElements := []string{
		"test-attack",
		"Account Takeover",
		"indicator1",
		"indicator2",
		"Test package profile",
		"similarity_score",
		"confidence",
		"JSON",
		"Test impact",
		"Test Source",
	}

	for _, elem := range expectedElements {
		if !strings.Contains(prompt, elem) {
			t.Errorf("prompt missing expected element: %s", elem)
		}
	}
}

// Test: generateMitigationAdvice provides contextual advice for each attack vector type
// Justification: Correct mitigation advice helps users respond to identified risks
// Source: SLSA Framework and OSSF Scorecard mitigation recommendations
// Methodology: Test each attack vector type and severity level
// Result: Advice contains vector-specific and severity-specific recommendations
func TestGenerateMitigationAdvice(t *testing.T) {
	t.Run("account takeover advice", func(t *testing.T) {
		attack := HistoricalAttack{
			Name:         "test-attack",
			AttackVector: "Account Takeover",
		}
		response := AttackMatchResponse{
			Severity: "HIGH",
		}

		advice := generateMitigationAdvice(attack, response)

		for _, expected := range []string{"2FA", "maintainer", "Immediate Actions", "production"} {
			if !strings.Contains(advice, expected) {
				t.Errorf("advice missing expected content: %s", expected)
			}
		}
	})

	t.Run("malicious dependency advice", func(t *testing.T) {
		attack := HistoricalAttack{
			Name:         "test-attack",
			AttackVector: "Malicious Dependency Injection",
		}
		response := AttackMatchResponse{
			Severity: "MEDIUM",
		}

		advice := generateMitigationAdvice(attack, response)

		for _, expected := range []string{"dependencies", "lock files", "transitive"} {
			if !strings.Contains(advice, expected) {
				t.Errorf("advice missing expected content: %s", expected)
			}
		}
	})

	t.Run("install script advice", func(t *testing.T) {
		attack := HistoricalAttack{
			Name:         "test-attack",
			AttackVector: "Malicious Install Script",
		}
		response := AttackMatchResponse{
			Severity: "LOW",
		}

		advice := generateMitigationAdvice(attack, response)

		for _, expected := range []string{"install scripts", "postinstall", "--ignore-scripts"} {
			if !strings.Contains(advice, expected) {
				t.Errorf("advice missing expected content: %s", expected)
			}
		}
	})

	t.Run("unknown attack vector still produces advice header", func(t *testing.T) {
		attack := HistoricalAttack{
			Name:         "novel-attack",
			AttackVector: "Zero-Day Supply Chain Exploit",
		}
		response := AttackMatchResponse{
			Severity: "LOW",
		}

		advice := generateMitigationAdvice(attack, response)

		// Should still contain the header referencing the attack name
		if !strings.Contains(advice, "novel-attack") {
			t.Error("advice missing attack name reference")
		}
		// LOW severity should NOT trigger immediate actions section
		if strings.Contains(advice, "Immediate Actions") {
			t.Error("LOW severity should not include immediate actions")
		}
	})

	t.Run("combined attack vector matches account takeover", func(t *testing.T) {
		// event-stream uses "Account Takeover + Malicious Dependency Injection"
		attack := HistoricalAttack{
			Name:         "event-stream (2018)",
			AttackVector: "Account Takeover + Malicious Dependency Injection",
		}
		response := AttackMatchResponse{
			Severity: "HIGH",
		}

		advice := generateMitigationAdvice(attack, response)

		// The switch uses strings.Contains, so combined vector should match Account Takeover
		if !strings.Contains(advice, "2FA") {
			t.Error("combined vector should match Account Takeover advice")
		}
	})

	t.Run("CRITICAL severity triggers immediate actions", func(t *testing.T) {
		attack := HistoricalAttack{
			Name:         "test-attack",
			AttackVector: "Account Takeover",
		}
		response := AttackMatchResponse{
			Severity: "CRITICAL",
		}

		advice := generateMitigationAdvice(attack, response)

		if !strings.Contains(advice, "Immediate Actions") {
			t.Error("CRITICAL severity should include immediate actions")
		}
	})
}

// mockAnthropicServer creates an httptest server that mimics the Anthropic Messages API.
// It returns the server and a function to set the next response JSON body.
func mockAnthropicServer(t *testing.T, responseJSON string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if !strings.HasSuffix(r.URL.Path, "/messages") {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, responseJSON)
	}))
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

// Test: callClaudeForComparison correctly parses JSON responses from the API
// Justification: Response parsing failures silently skip valid attack matches
// Source: Anthropic API response format documentation
// Methodology: Mock the API with known JSON responses and verify parsing
// Result: Valid JSON parsed correctly; markdown-wrapped JSON parsed; invalid JSON returns error
func TestCallClaudeForComparison(t *testing.T) {
	t.Run("parses valid JSON response", func(t *testing.T) {
		attackResp := AttackMatchResponse{
			AttackName:         "ua-parser-js (2021)",
			SimilarityScore:    0.85,
			Confidence:         0.9,
			MatchingIndicators: []string{"Single maintainer", "Malicious install scripts"},
			DifferingFactors:   []string{"No credential harvesting detected"},
			Explanation:        "High similarity to account takeover pattern",
			Severity:           "HIGH",
		}
		respJSON, _ := json.Marshal(attackResp)
		apiResp := makeAnthropicMessageResponse(string(json.RawMessage(fmt.Sprintf("%q", string(respJSON)))))

		server := mockAnthropicServer(t, apiResp)
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

		result, err := callClaudeForComparison(context.Background(), client, "test prompt")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if result.AttackName != "ua-parser-js (2021)" {
			t.Errorf("expected attack name 'ua-parser-js (2021)', got %s", result.AttackName)
		}
		if result.SimilarityScore != 0.85 {
			t.Errorf("expected similarity 0.85, got %f", result.SimilarityScore)
		}
		if result.Severity != "HIGH" {
			t.Errorf("expected severity HIGH, got %s", result.Severity)
		}
		if len(result.MatchingIndicators) != 2 {
			t.Errorf("expected 2 matching indicators, got %d", len(result.MatchingIndicators))
		}
	})

	t.Run("parses markdown-wrapped JSON response", func(t *testing.T) {
		// Some LLM responses wrap JSON in markdown code blocks
		innerJSON := `{"attack_name":"coa (2021)","similarity_score":0.6,"confidence":0.7,"matching_indicators":["compromised credentials"],"explanation":"Moderate similarity","severity":"MEDIUM"}`
		wrappedJSON := "```json\n" + innerJSON + "\n```"
		apiResp := makeAnthropicMessageResponse(fmt.Sprintf("%q", wrappedJSON))

		server := mockAnthropicServer(t, apiResp)
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

		result, err := callClaudeForComparison(context.Background(), client, "test prompt")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if result.AttackName != "coa (2021)" {
			t.Errorf("expected attack name 'coa (2021)', got %s", result.AttackName)
		}
		if result.SimilarityScore != 0.6 {
			t.Errorf("expected similarity 0.6, got %f", result.SimilarityScore)
		}
	})

	t.Run("returns error for invalid JSON response", func(t *testing.T) {
		apiResp := makeAnthropicMessageResponse(`"this is not valid JSON for AttackMatchResponse"`)

		server := mockAnthropicServer(t, apiResp)
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

		_, err = callClaudeForComparison(context.Background(), client, "test prompt")
		if err == nil {
			t.Fatal("expected error for invalid JSON response")
		}
		if !strings.Contains(err.Error(), "failed to parse") {
			t.Errorf("expected parse error, got: %v", err)
		}
	})

	t.Run("returns error for empty response content", func(t *testing.T) {
		apiResp := `{
			"id": "msg_test_123",
			"type": "message",
			"role": "assistant",
			"model": "claude-sonnet-4-5-20250929",
			"content": [],
			"stop_reason": "end_turn",
			"usage": {"input_tokens": 100, "output_tokens": 0}
		}`

		server := mockAnthropicServer(t, apiResp)
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

		_, err = callClaudeForComparison(context.Background(), client, "test prompt")
		if err == nil {
			t.Fatal("expected error for empty response content")
		}
	})
}

// Test: callClaudeForComparison handles response with no text content blocks
// Justification: The API may return content blocks of type "image" or other types
//                that don't contain text; the parser must detect this and return
//                a clear error rather than silently producing an empty result
// Source: Anthropic API content block types specification
// Methodology: Mock the API to return a message with a non-text content block;
//              verify the function returns an appropriate error
// Result: Returns "no text content" error when all content blocks are non-text
func TestCallClaudeForComparison_NoTextContent(t *testing.T) {
	// Response has a content block but it's not of type "text"
	apiResp := `{
		"id": "msg_test_nontext",
		"type": "message",
		"role": "assistant",
		"model": "claude-sonnet-4-5-20250929",
		"content": [{"type": "tool_use", "id": "tool_1", "name": "test", "input": {}}],
		"stop_reason": "tool_use",
		"usage": {"input_tokens": 100, "output_tokens": 50}
	}`

	server := mockAnthropicServer(t, apiResp)
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

	_, err = callClaudeForComparison(context.Background(), client, "test prompt")
	if err == nil {
		t.Fatal("expected error for response with no text content")
	}
	if !strings.Contains(err.Error(), "no text content") {
		t.Errorf("expected 'no text content' error, got: %v", err)
	}
}

// Test: buildPackageProfile includes Sigstore signature in provenance field
// Justification: Packages with Sigstore signatures have verified provenance;
//                this must be reflected in the profile for accurate attack matching
// Source: Sigstore - https://www.sigstore.dev/ - keyless signing and transparency
// Methodology: Build profile with HasSigstoreSignature=true, HasSLSAAttestation=false;
//              verify "Has Provenance: true" appears in output
// Result: Profile correctly shows provenance as true when Sigstore signature exists
func TestBuildPackageProfile_SigstoreProvenance(t *testing.T) {
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
}

// Test: buildPackageProfile includes only HIGH/CRITICAL findings, not MEDIUM/LOW
// Justification: Attack comparison profiles should focus on high-severity findings
//                to avoid noise in similarity assessment; including low-severity
//                findings would dilute the signal
// Source: OSSF Scorecard severity classification
// Methodology: Build profile with findings of all severities; verify only
//              HIGH and CRITICAL findings appear in output
// Result: HIGH and CRITICAL findings present; MEDIUM and LOW findings absent
func TestBuildPackageProfile_FindingSeverityFilter(t *testing.T) {
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
}

// Test: MatchAgainstKnownAttacks correctly filters by ecosystem and returns matches
// Justification: Core matching logic must filter irrelevant attacks and return
//                properly structured matches above the threshold
// Source: Backstabber's Knife Collection (Ohm et al., 2020) - attack pattern matching
// Methodology: Mock the Claude API to return controlled similarity scores; verify
//              that ecosystem filtering, threshold filtering, and match structure work
// Result: Only npm attacks matched for npm packages; matches above threshold returned;
//         match fields populated from both API response and attack database
func TestMatchAgainstKnownAttacks(t *testing.T) {
	t.Run("high-risk package matches attacks above threshold", func(t *testing.T) {
		// Mock server that always returns a high similarity score
		callCount := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			callCount++
			respJSON := `{"attack_name":"test","similarity_score":0.85,"confidence":0.9,"matching_indicators":["Single maintainer","Install scripts"],"explanation":"High similarity","severity":"HIGH"}`
			apiResp := makeAnthropicMessageResponse(fmt.Sprintf("%q", respJSON))
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, apiResp)
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
				"No 2FA enforcement",
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

		// All 5 npm attacks should be called and match (similarity 0.85 > threshold 0.7)
		if callCount != 5 {
			t.Errorf("expected 5 API calls (one per npm attack), got %d", callCount)
		}
		if len(matches) != 5 {
			t.Errorf("expected 5 matches above threshold, got %d", len(matches))
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
			if match.MitigationAdvice == "" {
				t.Error("match missing mitigation advice")
			}
		}
	})

	t.Run("low similarity scores filtered by threshold", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			respJSON := `{"attack_name":"test","similarity_score":0.3,"confidence":0.8,"matching_indicators":[],"explanation":"Low similarity","severity":"LOW"}`
			apiResp := makeAnthropicMessageResponse(fmt.Sprintf("%q", respJSON))
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, apiResp)
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
			RiskLevel:           "LOW",
			RiskScore:           10,
			SourceCodeAvailable: true,
			Metadata: models.PackageMetadata{
				Maintainers: []string{"m1", "m2", "m3"},
			},
		}

		req := AttackMatchRequest{
			PackageName:    "safe-package",
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

		// Similarity 0.3 < threshold 0.7, so no matches
		if len(matches) != 0 {
			t.Errorf("expected 0 matches below threshold, got %d", len(matches))
		}
	})

	t.Run("pypi ecosystem skips npm-only attacks", func(t *testing.T) {
		callCount := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			callCount++
			respJSON := `{"attack_name":"test","similarity_score":0.9,"confidence":0.9,"matching_indicators":["test"],"explanation":"test","severity":"HIGH"}`
			apiResp := makeAnthropicMessageResponse(fmt.Sprintf("%q", respJSON))
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, apiResp)
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
			RiskLevel:           "HIGH",
			RiskScore:           90,
			SourceCodeAvailable: true,
			Metadata: models.PackageMetadata{
				Maintainers: []string{"single-maintainer"},
			},
		}

		req := AttackMatchRequest{
			PackageName:    "suspicious-pypi-package",
			Ecosystem:      models.EcosystemPyPI,
			AnalysisResult: result,
			Threshold:      0.5,
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		matches, err := MatchAgainstKnownAttacks(ctx, client, req)
		if err != nil {
			t.Fatalf("failed to match attacks: %v", err)
		}

		// All known attacks are npm ecosystem, so pypi should skip all of them
		if callCount != 0 {
			t.Errorf("expected 0 API calls for pypi (all attacks are npm), got %d", callCount)
		}
		if len(matches) != 0 {
			t.Errorf("expected 0 matches for pypi ecosystem, got %d", len(matches))
		}
	})

	t.Run("default threshold applied when zero", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Score 0.65 is below default threshold 0.7 but above 0.5
			respJSON := `{"attack_name":"test","similarity_score":0.65,"confidence":0.7,"matching_indicators":["test"],"explanation":"test","severity":"MEDIUM"}`
			apiResp := makeAnthropicMessageResponse(fmt.Sprintf("%q", respJSON))
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, apiResp)
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
			PackageName: "test-package",
			Ecosystem:   models.EcosystemNPM,
			AnalysisResult: models.AnalysisResult{
				RiskLevel: "MEDIUM",
				Metadata:  models.PackageMetadata{Maintainers: []string{"m1"}},
			},
			Threshold: 0, // Should default to 0.7
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		matches, err := MatchAgainstKnownAttacks(ctx, client, req)
		if err != nil {
			t.Fatalf("failed to match attacks: %v", err)
		}

		// 0.65 < default threshold 0.7, so no matches
		if len(matches) != 0 {
			t.Errorf("expected 0 matches with default threshold 0.7, got %d", len(matches))
		}
	})

	t.Run("API errors are handled gracefully", func(t *testing.T) {
		// Use 400 (not 500) to avoid SDK-level retries that slow the test.
		// The client's own retry logic treats 400 as non-retryable too.
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"type":"error","error":{"type":"invalid_request_error","message":"test error"}}`)
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

		// Should not return an error - errors for individual attacks are skipped
		matches, err := MatchAgainstKnownAttacks(ctx, client, req)
		if err != nil {
			t.Fatalf("expected graceful handling, got error: %v", err)
		}

		// All API calls fail, so no matches
		if len(matches) != 0 {
			t.Errorf("expected 0 matches when API fails, got %d", len(matches))
		}
	})
}
