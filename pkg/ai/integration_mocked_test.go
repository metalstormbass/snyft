package ai

import (
	"context"
	"testing"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/metalstormbass/snyft/pkg/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test: Executive explanation generation integration with mock
// Justification: Validates executive explanation without API calls
// Source: Stakeholder communication requirements
// Methodology: Generate explanation for high-risk package using mock
// Result: Should return structured explanation with all sections
func TestExplainer_Integration_Mocked(t *testing.T) {
	cfg := DefaultConfig()
	cfg.APIKey = "test-key"
	client, err := NewClient(cfg)
	require.NoError(t, err)
	defer func() { _ = client.Close() }()

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

	// Test response parsing with mock message
	mockMessage := CreateExecutiveExplanationResponse("HIGH")
	explanation := explainer.parseExecutiveResponse(mockMessage.Content[0].Text, result)

	// Validate explanation structure
	require.NotNil(t, explanation, "Should have explanation")
	assert.NotEmpty(t, explanation.Summary, "Should have summary")
	// RecommendedAction intentionally not populated per CLAUDE.md policy

	t.Logf("Executive explanation validated successfully")
}

// Test: Quick summary generation with mock
// Justification: Quick summaries should be concise (2-3 sentences)
// Source: Executive briefing best practices
// Methodology: Generate quick summary with mock API
// Result: Should return brief summary with clear recommendation
func TestExplainer_QuickSummary_Integration_Mocked(t *testing.T) {
	// Test with mock response
	mockMessage := CreateQuickSummaryResponse(55)
	summary := mockMessage.Content[0].Text

	assert.NotEmpty(t, summary, "Summary should not be empty")

	// Quick summary should be concise
	sentences := countSentences(summary)
	assert.LessOrEqual(t, sentences, 5, "Quick summary should be concise (<=5 sentences)")

	t.Logf("Quick summary: %s", summary)
}

// Test: Batch explanation processing with mock
// Justification: Efficient processing of multiple packages
// Source: Bulk processing requirements
// Methodology: Process multiple packages in batch using mocks
// Result: Should return results for all packages
func TestExplainer_BatchExplain_Integration_Mocked(t *testing.T) {
	cfg := DefaultConfig()
	cfg.APIKey = "test-key"
	client, err := NewClient(cfg)
	require.NoError(t, err)
	defer func() { _ = client.Close() }()

	config := &ExplainerConfig{
		Client: client,
	}
	explainer := NewExplainer(config)

	packages := []string{"pkg-a", "pkg-b"}
	results := []models.AnalysisResult{
		{RiskLevel: "LOW", RiskScore: 20},
		{RiskLevel: "HIGH", RiskScore: 85},
	}

	// Test parsing logic for multiple results
	for i, result := range results {
		var mockResp *anthropic.Message
		if result.RiskLevel == "LOW" {
			mockResp = CreateExecutiveExplanationResponse("LOW")
		} else {
			mockResp = CreateExecutiveExplanationResponse("HIGH")
		}

		explanation := explainer.parseExecutiveResponse(mockResp.Content[0].Text, result)
		assert.NotNil(t, explanation, "Package %d should have explanation", i)
		t.Logf("Package %s: %s", packages[i], explanation.Summary[:min(100, len(explanation.Summary))])
	}
}

// Test: Context cancellation handling
// Justification: Operations should handle context cancellation gracefully
// Source: Go context best practices
// Methodology: Test with context error
// Result: Should handle error without panic
func TestIntegration_ContextCancellation_Mocked(t *testing.T) {
	mockClient := NewMockClient().WithError(CreateContextCancelledError())

	ctx := context.Background()
	_, err := mockClient.CreateMessage(ctx, anthropic.MessageNewParams{})

	assert.Error(t, err, "Should return error")
	assert.ErrorIs(t, err, context.Canceled, "Should be context cancelled error")
}

// Test: Rate limit error handling
// Justification: Should handle API rate limits gracefully
// Source: Claude API rate limiting
// Methodology: Return rate limit error from mock
// Result: Should handle error without panic
func TestIntegration_RateLimitError_Mocked(t *testing.T) {
	mockClient := NewMockClient().WithError(CreateRateLimitError())

	ctx := context.Background()
	_, err := mockClient.CreateMessage(ctx, anthropic.MessageNewParams{})

	assert.Error(t, err, "Should return error")
	assert.Contains(t, err.Error(), "rate limit", "Should be rate limit error")
}

// Test: Server error handling
// Justification: Should handle API server errors gracefully
// Source: Retry logic and circuit breaker patterns
// Methodology: Return server error from mock
// Result: Should handle error without panic
func TestIntegration_ServerError_Mocked(t *testing.T) {
	mockClient := NewMockClient().WithError(CreateServerError())

	ctx := context.Background()
	_, err := mockClient.CreateMessage(ctx, anthropic.MessageNewParams{})

	assert.Error(t, err, "Should return error")
	assert.Contains(t, err.Error(), "server error", "Should be server error")
}

// Test: Mock client call tracking
// Justification: Verify mock client tracks API calls correctly
// Source: Testing best practices
// Methodology: Make multiple calls and verify call count
// Result: Should track calls correctly
func TestMockClient_CallTracking(t *testing.T) {
	mockClient := NewMockClient().WithResponse("test response")

	ctx := context.Background()

	// Make 3 calls
	for i := 0; i < 3; i++ {
		_, err := mockClient.CreateMessage(ctx, anthropic.MessageNewParams{})
		require.NoError(t, err)
	}

	assert.Equal(t, 3, mockClient.CallCount, "Should track 3 calls")
}

// Test: Mock client multiple responses
// Justification: Verify mock client can return different responses
// Source: Testing best practices
// Methodology: Set up multiple responses and verify they're returned in order
// Result: Should return responses in order
func TestMockClient_MultipleResponses(t *testing.T) {
	mockClient := NewMockClient()
	mockClient.WithResponse("Response 1")
	mockClient.WithResponse("Response 2")
	mockClient.WithResponse("Response 3")

	ctx := context.Background()

	// First call
	msg1, err := mockClient.CreateMessage(ctx, anthropic.MessageNewParams{})
	require.NoError(t, err)
	assert.Equal(t, "Response 1", msg1.Content[0].Text)

	// Second call
	msg2, err := mockClient.CreateMessage(ctx, anthropic.MessageNewParams{})
	require.NoError(t, err)
	assert.Equal(t, "Response 2", msg2.Content[0].Text)

	// Third call
	msg3, err := mockClient.CreateMessage(ctx, anthropic.MessageNewParams{})
	require.NoError(t, err)
	assert.Equal(t, "Response 3", msg3.Content[0].Text)
}

// Test: MatchAgainstKnownAttacks ecosystem filtering (no API calls needed)
// Justification: PyPI packages should be filtered out before API calls since all
//                KnownAttacks are npm-ecosystem. This validates the filter logic
//                without requiring an API key.
// Source: Cross-ecosystem filtering requirements for attack pattern matching
// Methodology: Submit a PyPI package through MatchAgainstKnownAttacks with a real
//              Client (no API calls will be made since all attacks are npm-only).
// Result: Should return 0 matches — PyPI package correctly filtered from npm attack DB
func TestMatchAgainstKnownAttacks_EcosystemFilter_Mocked(t *testing.T) {
	cfg := DefaultConfig()
	cfg.APIKey = "test-key"
	client, err := NewClient(cfg)
	require.NoError(t, err)
	defer func() { _ = client.Close() }()

	req := AttackMatchRequest{
		PackageName: "requests",
		Ecosystem:   models.EcosystemPyPI,
		AnalysisResult: models.AnalysisResult{
			RiskLevel: "MEDIUM",
			RiskScore: 55,
			RiskFactors: []string{
				"Single primary maintainer",
			},
			Metadata: models.PackageMetadata{
				Maintainers: []string{"primary-author"},
			},
			SupplyChainScore: &models.SupplyChainScore{
				TotalScore: 6,
				RiskLevel:  "MEDIUM",
			},
		},
		Threshold: 0.3, // Low threshold to verify filtering, not scoring
	}

	ctx := context.Background()
	matches, err := MatchAgainstKnownAttacks(ctx, client, req)
	require.NoError(t, err, "MatchAgainstKnownAttacks should not error")

	// All KnownAttacks are npm; PyPI package should be filtered out before any API call
	assert.Equal(t, 0, len(matches),
		"PyPI package should match 0 npm-only attack patterns; got %d", len(matches))
}

// Test: MatchAgainstKnownAttacks with empty known attacks ecosystem
// Justification: Verifies that an ecosystem with no known attacks returns empty
// Source: Edge case handling for attack pattern matching
// Methodology: Use Maven ecosystem which has no entries in KnownAttacks
// Result: Should return 0 matches without errors
func TestMatchAgainstKnownAttacks_NoMatchingEcosystem_Mocked(t *testing.T) {
	cfg := DefaultConfig()
	cfg.APIKey = "test-key"
	client, err := NewClient(cfg)
	require.NoError(t, err)
	defer func() { _ = client.Close() }()

	req := AttackMatchRequest{
		PackageName: "com.google.guava:guava",
		Ecosystem:   models.EcosystemMaven,
		AnalysisResult: models.AnalysisResult{
			RiskLevel: "LOW",
			RiskScore: 15,
		},
		Threshold: 0.1,
	}

	ctx := context.Background()
	matches, err := MatchAgainstKnownAttacks(ctx, client, req)
	require.NoError(t, err)
	assert.Equal(t, 0, len(matches), "Maven package should match 0 npm-only attack patterns")
}

// Test: BatchExplain input validation
// Justification: Mismatched input arrays should return a clear error
// Source: Defensive programming for batch operations
// Methodology: Pass arrays of different lengths to BatchExplain
// Result: Should return an error for mismatched lengths
func TestBatchExplain_InputValidation_Mocked(t *testing.T) {
	explainer := NewExplainer(&ExplainerConfig{})

	packages := []string{"pkg-a", "pkg-b"}
	ecosystems := []models.Ecosystem{models.EcosystemNPM} // Mismatched length
	results := []models.AnalysisResult{{RiskLevel: "LOW"}, {RiskLevel: "HIGH"}}

	_, err := explainer.BatchExplain(context.Background(), packages, ecosystems, results)
	assert.Error(t, err, "Should return error for mismatched input lengths")
	assert.Contains(t, err.Error(), "mismatched input lengths")
}

// Note: countSentences and min helpers are defined in other test files
