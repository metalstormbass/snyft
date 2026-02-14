package ai

import (
	"context"
	"testing"
	"time"

	"github.com/metalstormbass/snyft/pkg/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test: Client creation with invalid configurations
// Justification: Robust error handling prevents runtime failures
// Methodology: Test various invalid configuration scenarios
// Result: Should return descriptive errors for each invalid config
func TestClient_ErrorHandling_InvalidConfig(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		wantErr bool
		errMsg  string
	}{
		{
			name:    "nil config",
			config:  nil,
			wantErr: true,
			errMsg:  "config",
		},
		{
			name: "empty API key",
			config: &Config{
				APIKey:  "",
				BaseURL: "https://api.anthropic.com",
			},
			wantErr: true,
			errMsg:  "API key",
		},
		{
			name: "invalid base URL",
			config: &Config{
				APIKey:  "test-key",
				BaseURL: "",
			},
			wantErr: true,
			errMsg:  "base URL",
		},
		{
			name: "negative timeout",
			config: &Config{
				APIKey:  "test-key",
				BaseURL: "https://api.anthropic.com",
				Timeout: -5 * time.Second,
			},
			wantErr: true,
			errMsg:  "timeout",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var err error
			if tt.config == nil {
				// Test nil config directly in NewClient
				defer func() {
					if r := recover(); r != nil {
						t.Logf("Expected panic for nil config: %v", r)
					}
				}()
				_, err = NewClient(nil)
			} else {
				err = tt.config.Validate()
			}

			if tt.wantErr {
				assert.Error(t, err, "Should return error for: "+tt.name)
				if err != nil && tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg, "Error should mention: "+tt.errMsg)
				}
			} else {
				assert.NoError(t, err, "Should not return error for: "+tt.name)
			}
		})
	}
}

// Test: Context cancellation during operations
// Justification: Operations should respect context cancellation when blocked
// Methodology: Exhaust rate limiter then cancel context
// Result: Should return context error when waiting
func TestClient_ErrorHandling_ContextCancellation(t *testing.T) {
	cfg := DefaultConfig()
	cfg.APIKey = "test-key"
	cfg.RateLimit = 1 // Only 1 request per minute

	client, err := NewClient(cfg)
	require.NoError(t, err)
	defer client.Close()

	// Test rate limiter respects context cancellation when blocked
	t.Run("rate limiter context cancel when blocked", func(t *testing.T) {
		ctx := context.Background()

		// Exhaust the rate limiter
		err := client.rateLimiter.Wait(ctx)
		assert.NoError(t, err, "First request should succeed")

		// Now try with cancelled context (should fail immediately since no tokens)
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		err = client.rateLimiter.Wait(ctx)
		assert.Error(t, err, "Should return error when context cancelled and no tokens available")
	})

	// Test timeout context when blocked
	t.Run("timeout context when blocked", func(t *testing.T) {
		// Create a new client with very limited rate
		cfg2 := DefaultConfig()
		cfg2.APIKey = "test-key"
		cfg2.RateLimit = 1
		client2, err := NewClient(cfg2)
		require.NoError(t, err)
		defer client2.Close()

		ctx := context.Background()

		// Exhaust the rate limiter
		_ = client2.rateLimiter.Wait(ctx)

		// Try with very short timeout (should fail)
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
		defer cancel()

		time.Sleep(5 * time.Millisecond) // Ensure timeout occurs

		err = client2.rateLimiter.Wait(ctx)
		assert.Error(t, err, "Should return error when context times out")
	})
}

// Note: Semantic analyzer tests removed after PR #59 reverted semantic code analysis
// as it was deemed out of scope for supply chain risk assessment.

// Test: Explainer error handling
// Justification: Explainer should handle missing or invalid data gracefully
// Methodology: Test with incomplete analysis results
// Result: Should generate explanations with available data or return error
func TestExplainer_ErrorHandling(t *testing.T) {
	// Note: Removed "nil analysis result" subtest as it requires real API call
	// and would fail without a valid client

	explainer := NewExplainer(&ExplainerConfig{})

	t.Run("missing supply chain score", func(t *testing.T) {
		result := models.AnalysisResult{
			RiskLevel:        "HIGH",
			RiskScore:        85,
			SupplyChainScore: nil, // Missing
		}

		style := explainer.determineExplanationStyle(result.RiskLevel)
		assert.NotEmpty(t, style, "Should determine style even without supply chain score")
	})

	t.Run("empty risk factors", func(t *testing.T) {
		result := models.AnalysisResult{
			RiskLevel:   "LOW",
			RiskScore:   10,
			RiskFactors: []string{}, // Empty
		}

		prompt := explainer.buildExecutivePrompt("test-pkg", models.EcosystemNPM, result, "brief")
		assert.NotNil(t, prompt, "Should build prompt even with empty risk factors")
	})
}

// Test: Attack matcher error handling
// Justification: Attack matching should handle edge cases gracefully
// Methodology: Test with invalid or incomplete data
// Result: Should return empty matches or error without crashing
func TestAttackMatcher_ErrorHandling(t *testing.T) {
	t.Run("empty package profile", func(t *testing.T) {
		result := models.AnalysisResult{}
		profile := buildPackageProfile("", models.EcosystemNPM, result)
		assert.NotEmpty(t, profile, "Should build profile even with empty data")
	})

	t.Run("invalid attack pattern", func(t *testing.T) {
		_, found := GetKnownAttack("non-existent-attack")
		assert.False(t, found, "Should return false for non-existent attack")
	})

	t.Run("list attacks with invalid ecosystem", func(t *testing.T) {
		attacks := ListKnownAttacks("invalid-ecosystem")
		assert.Empty(t, attacks, "Should return empty list for invalid ecosystem")
	})

	t.Run("generate mitigation for unknown vector", func(t *testing.T) {
		attack := HistoricalAttack{
			Name:         "test-attack",
			AttackVector: "Unknown Vector Type",
		}
		response := AttackMatchResponse{
			Severity: "HIGH",
		}

		advice := generateMitigationAdvice(attack, response)
		assert.NotEmpty(t, advice, "Should generate advice even for unknown vector")
		assert.Contains(t, advice, "Immediate Actions", "Should include action items")
	})
}

// Note: Cache error handling tests removed after PR #59 reverted semantic code analysis

// Test: Prompt building with edge cases
// Justification: Prompts must handle missing or unusual data
// Methodology: Build prompts with incomplete data
// Result: Should create valid prompts with available data
func TestPrompts_ErrorHandling(t *testing.T) {
	t.Run("semantic analysis with minimal metadata", func(t *testing.T) {
		metadata := models.PackageMetadata{} // All fields default/empty
		findings := []models.Finding{}        // Empty findings

		prompt := NewSemanticAnalysisPrompt("test-pkg", models.EcosystemNPM, metadata, findings)
		assert.NotNil(t, prompt, "Should create prompt with minimal data")

		system, user := prompt.Render()
		assert.NotEmpty(t, system, "Should have system prompt")
		assert.NotEmpty(t, user, "Should have user prompt")
	})

	t.Run("executive explanation with missing scores", func(t *testing.T) {
		result := models.AnalysisResult{
			RiskLevel:        "MEDIUM",
			SupplyChainScore: nil, // Missing
		}

		prompt := NewExecutiveExplanationPrompt("test-pkg", models.EcosystemPyPI, result, "executive")
		assert.NotNil(t, prompt, "Should create prompt without supply chain score")
	})

	t.Run("code pattern analysis with empty script", func(t *testing.T) {
		prompt := NewCodePatternAnalysisPrompt("postinstall", "")
		assert.NotNil(t, prompt, "Should create prompt with empty script")

		_, user := prompt.Render()
		assert.NotEmpty(t, user, "Should have user prompt")
	})
}

// Test: Confidence calculation edge cases
// Justification: Confidence should be bounded and handle extreme inputs
// Methodology: Test with extreme values and edge cases
// Result: Confidence should always be 0.0-1.0
func TestConfidence_EdgeCases(t *testing.T) {
	explainer := NewExplainer(&ExplainerConfig{})

	// Note: Semantic analyzer confidence tests removed after PR #59

	t.Run("explainer confidence bounds", func(t *testing.T) {
		// Test with empty result
		emptyResult := models.AnalysisResult{}
		conf1 := explainer.calculateConfidence(emptyResult)
		assert.GreaterOrEqual(t, conf1, 0.0, "Confidence should be >= 0")
		assert.LessOrEqual(t, conf1, 1.0, "Confidence should be <= 1")

		// Test with complete result
		completeResult := models.AnalysisResult{
			Findings: make([]models.Finding, 10),
			Metadata: models.PackageMetadata{
				RepoStars:            10000,
				RepoForks:            1000,
				Maintainers:          []string{"a", "b", "c"},
				HasSLSAAttestation:   true,
				HasSigstoreSignature: true,
			},
			SupplyChainScore: &models.SupplyChainScore{TotalScore: 5},
		}
		conf2 := explainer.calculateConfidence(completeResult)
		assert.GreaterOrEqual(t, conf2, 0.0, "Confidence should be >= 0")
		assert.LessOrEqual(t, conf2, 1.0, "Confidence should be <= 1")
	})
}

// Test: Concurrent operations
// Justification: Client should be safe for concurrent use
// Methodology: Run multiple operations concurrently
// Result: Should handle concurrent requests without data races
func TestClient_Concurrency(t *testing.T) {
	cfg := DefaultConfig()
	cfg.APIKey = "test-key"
	client, err := NewClient(cfg)
	require.NoError(t, err)
	defer client.Close()

	t.Run("concurrent rate limiter access", func(t *testing.T) {
		done := make(chan bool, 10)
		ctx := context.Background()

		for i := 0; i < 10; i++ {
			go func() {
				_ = client.rateLimiter.Wait(ctx)
				done <- true
			}()
		}

		// Wait for all goroutines
		for i := 0; i < 10; i++ {
			<-done
		}
	})

	t.Run("concurrent GetStats calls", func(t *testing.T) {
		done := make(chan bool, 10)

		for i := 0; i < 10; i++ {
			go func() {
				_ = client.GetStats()
				done <- true
			}()
		}

		for i := 0; i < 10; i++ {
			<-done
		}
	})
}
