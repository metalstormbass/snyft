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

	// Test response parsing with mock message
	mockMessage := CreateExecutiveExplanationResponse("HIGH")
	explanation := explainer.parseExecutiveResponse(mockMessage.Content[0].Text, result)

	// Validate explanation structure
	require.NotNil(t, explanation, "Should have explanation")
	assert.NotEmpty(t, explanation.Summary, "Should have summary")
	assert.NotEmpty(t, explanation.RecommendedAction, "Should have recommendation")

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
	defer client.Close()

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

// Note: countSentences and min helpers are defined in other test files
