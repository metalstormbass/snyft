// +build integration

// This file contains integration tests that make REAL API calls to Claude.
// These tests are disabled by default and only run when the "integration" build tag is set.
//
// To run these tests:
//   export CLAUDE_API_KEY=your-api-key
//   go test ./pkg/ai/... -tags=integration -v
//
// NOTE: These tests make real API calls and will incur costs.
// For CI/CD and regular testing, use the mocked integration tests in integration_mocked_test.go

package ai

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/metalstormbass/snyft/pkg/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Note: Semantic analyzer integration tests removed after PR #59 reverted semantic code analysis
// as it was deemed out of scope for supply chain risk assessment.

// Test: Attack pattern matching integration
// Justification: Validates attack pattern matching with real Claude API
// Source: Historical attack pattern database
// Methodology: Match high-risk package against known attack patterns
// Result: Should return pattern matches with similarity scores
func TestAttackMatcher_Integration_RealAPI(t *testing.T) {
	apiKey := os.Getenv("CLAUDE_API_KEY")
	if apiKey == "" {
		apiKey = os.Getenv("ANTHROPIC_API_KEY")
	}
	if apiKey == "" {
		t.Skip("Skipping integration test: CLAUDE_API_KEY not set")
	}

	cfg := DefaultConfig()
	cfg.APIKey = apiKey
	client, err := NewClient(cfg)
	require.NoError(t, err)
	defer client.Close()

	// Create high-risk analysis result
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
		},
	}

	req := AttackMatchRequest{
		PackageName:    "suspicious-test-package",
		Ecosystem:      models.EcosystemNPM,
		AnalysisResult: result,
		Threshold:      0.4, // Lower threshold for testing
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	matches, err := MatchAgainstKnownAttacks(ctx, client, req)
	require.NoError(t, err, "Should successfully match attack patterns")

	// Validate matches
	if len(matches) > 0 {
		for _, match := range matches {
			assert.NotEmpty(t, match.PatternName, "Match should have pattern name")
			assert.True(t, match.Confidence >= 0 && match.Confidence <= 1, "Confidence should be 0-1")
			assert.NotEmpty(t, match.Severity, "Match should have severity")
			assert.NotEmpty(t, match.Description, "Match should have description")
			assert.NotEmpty(t, match.AcademicSource, "Match should have academic source")

			t.Logf("Pattern match: %s (confidence: %.2f)",
				match.PatternName, match.Confidence)
		}
	} else {
		t.Log("No attack pattern matches found (threshold may be too high)")
	}
}

// Test: Executive explanation generation integration
// Justification: Validates executive explanation with real Claude API
// Source: Stakeholder communication requirements
// Methodology: Generate explanation for high-risk package
// Result: Should return structured explanation with all sections
func TestExplainer_Integration_RealAPI(t *testing.T) {
	apiKey := os.Getenv("CLAUDE_API_KEY")
	if apiKey == "" {
		apiKey = os.Getenv("ANTHROPIC_API_KEY")
	}
	if apiKey == "" {
		t.Skip("Skipping integration test: CLAUDE_API_KEY not set")
	}

	cfg := DefaultConfig()
	cfg.APIKey = apiKey
	client, err := NewClient(cfg)
	require.NoError(t, err)
	defer client.Close()

	config := &ExplainerConfig{
		Client:         client,
		TargetAudience: "executive",
		IncludeAttacks: true,
		MaxTokens:      1500,
		Temperature:    0.5,
	}

	explainer := NewExplainer(config)

	result := models.AnalysisResult{
		RiskLevel: "HIGH",
		RiskScore: 85,
		RiskFactors: []string{
			"Single maintainer (account takeover risk)",
			"Dangerous install scripts detected",
			"No SLSA attestation or Sigstore signature",
		},
		Findings: []models.Finding{
			{
				Severity:    "HIGH",
				Category:    "Publisher Control",
				Description: "Single maintainer - single point of compromise",
				Evidence:    "Only 1 maintainer found in npm registry",
			},
		},
		SupplyChainScore: &models.SupplyChainScore{
			TotalScore: 14,
			RiskLevel:  "HIGH",
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	explainerResult, err := explainer.ExplainRisk(ctx, "suspicious-package", models.EcosystemNPM, result)
	require.NoError(t, err, "Should successfully generate executive explanation")

	// Validate explanation structure
	require.NotNil(t, explainerResult.Explanation, "Should have explanation")
	assert.NotEmpty(t, explainerResult.Explanation.Summary, "Should have summary")
	assert.NotEmpty(t, explainerResult.Explanation.RecommendedAction, "Should have recommendation")
	assert.True(t, explainerResult.Explanation.Confidence > 0, "Should have confidence > 0")

	t.Logf("Summary: %s", explainerResult.Explanation.Summary)
	t.Logf("Recommendation: %s", explainerResult.Explanation.RecommendedAction)
	t.Logf("Confidence: %.2f", explainerResult.Explanation.Confidence)
}
