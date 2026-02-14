package ai

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/metalstormbass/snyft/pkg/models"
)

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
			// Verify citation contains either a paper title or URL
			if !containsAny(attack.AcademicSource, []string{"http://", "https://", "Ohm", "NDSS", "SLSA"}) {
				t.Errorf("attack %s has suspicious academic source: %s", attack.Name, attack.AcademicSource)
			}
		}
	})
}

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

	t.Run("non-existent attack", func(t *testing.T) {
		_, found := GetKnownAttack("fake-attack")
		if found {
			t.Error("expected not to find fake attack")
		}
	})
}

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
}

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

		// Verify profile contains key information
		if !containsAny(profile, []string{"test-package", "npm", "HIGH", "Single maintainer"}) {
			t.Error("profile missing expected content")
		}
	})

	t.Run("minimal profile", func(t *testing.T) {
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
		if !containsAny(profile, []string{"minimal-pkg", "pypi", "LOW"}) {
			t.Error("profile missing basic information")
		}
	})
}

func TestBuildAttackComparisonPrompt(t *testing.T) {
	attack := HistoricalAttack{
		Name:         "test-attack",
		Date:         "2024-01",
		Ecosystem:    "npm",
		Description:  "Test attack description",
		AttackVector: "Account Takeover",
		Indicators:   []string{"indicator1", "indicator2"},
		AcademicSource: "Test Source",
	}

	profile := "Test package profile\nRisk: HIGH"

	prompt := buildAttackComparisonPrompt(profile, attack)

	// Verify prompt structure
	expectedElements := []string{
		"test-attack",
		"Account Takeover",
		"indicator1",
		"indicator2",
		"Test package profile",
		"similarity_score",
		"confidence",
		"JSON",
	}

	for _, elem := range expectedElements {
		if !containsAny(prompt, []string{elem}) {
			t.Errorf("prompt missing expected element: %s", elem)
		}
	}
}

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

		expectedAdvice := []string{
			"2FA",
			"maintainer",
			"Immediate Actions",
			"production",
		}

		for _, expected := range expectedAdvice {
			if !containsAny(advice, []string{expected}) {
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

		expectedAdvice := []string{
			"dependencies",
			"lock files",
			"transitive",
		}

		for _, expected := range expectedAdvice {
			if !containsAny(advice, []string{expected}) {
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

		expectedAdvice := []string{
			"install scripts",
			"postinstall",
			"--ignore-scripts",
		}

		for _, expected := range expectedAdvice {
			if !containsAny(advice, []string{expected}) {
				t.Errorf("advice missing expected content: %s", expected)
			}
		}
	})
}

// Integration test - requires CLAUDE_API_KEY environment variable
func TestMatchAgainstKnownAttacks_Integration(t *testing.T) {
	// Skip if no API key
	apiKey := os.Getenv("CLAUDE_API_KEY")
	if apiKey == "" {
		apiKey = os.Getenv("ANTHROPIC_API_KEY")
	}
	if apiKey == "" {
		t.Skip("Skipping integration test: CLAUDE_API_KEY not set")
	}

	// Create client
	cfg := DefaultConfig()
	cfg.APIKey = apiKey
	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	defer client.Close()

	t.Run("high-risk package with account takeover indicators", func(t *testing.T) {
		// Simulate a package that looks like ua-parser-js attack
		result := models.AnalysisResult{
			RiskLevel: "HIGH",
			RiskScore: 90,
			RiskFactors: []string{
				"Single maintainer with full control",
				"No 2FA enforcement",
				"Malicious install scripts detected",
			},
			SourceCodeAvailable: true,
			Metadata: models.PackageMetadata{
				Maintainers:       []string{"single-maintainer"},
				HasInstallScripts: true,
				HasCI:             false,
				PublishedAt:       time.Now().Add(-30 * 24 * time.Hour), // Recent
			},
			Findings: []models.Finding{
				{
					Severity:    "CRITICAL",
					Category:    "Install Execution",
					Description: "Suspicious postinstall script with network requests",
				},
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
			Threshold:      0.5, // Lower threshold for testing
		}

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		matches, err := MatchAgainstKnownAttacks(ctx, client, req)
		if err != nil {
			t.Fatalf("failed to match attacks: %v", err)
		}

		// Should find at least one match given the high-risk indicators
		if len(matches) == 0 {
			t.Log("Warning: expected at least one attack pattern match for high-risk package")
		}

		// Verify match structure
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

			t.Logf("Found match: %s (confidence: %.2f, severity: %s)",
				match.PatternName, match.Confidence, match.Severity)
		}
	})

	t.Run("low-risk package should have minimal matches", func(t *testing.T) {
		result := models.AnalysisResult{
			RiskLevel:           "LOW",
			RiskScore:           15,
			RiskFactors:         []string{},
			SourceCodeAvailable: true,
			Metadata: models.PackageMetadata{
				Maintainers:         []string{"m1", "m2", "m3"},
				HasInstallScripts:   false,
				HasCI:               true,
				HasSLSAAttestation:  true,
				HasBranchProtection: true,
			},
			SupplyChainScore: &models.SupplyChainScore{
				TotalScore: 3,
				RiskLevel:  "LOW",
			},
		}

		req := AttackMatchRequest{
			PackageName:    "safe-package",
			Ecosystem:      models.EcosystemNPM,
			AnalysisResult: result,
			Threshold:      0.7,
		}

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		matches, err := MatchAgainstKnownAttacks(ctx, client, req)
		if err != nil {
			t.Fatalf("failed to match attacks: %v", err)
		}

		// Low-risk package should have few or no matches above threshold
		if len(matches) > 2 {
			t.Errorf("expected few matches for low-risk package, got %d", len(matches))
		}

		t.Logf("Low-risk package matched %d patterns", len(matches))
	})
}

// Helper function to check if a string contains any of the given substrings
func containsAny(s string, substrings []string) bool {
	for _, substr := range substrings {
		if containsSubstring(s, substr) {
			return true
		}
	}
	return false
}

func containsSubstring(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || findSubstring(s, substr))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
