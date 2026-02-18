package ai

import (
	"context"
	"strings"
	"testing"

	"github.com/metalstormbass/snyft/pkg/models"
)

// Test: HIGH risk package prompt and style integration
// Justification: High-risk packages (e.g., single maintainer + install scripts)
//                require urgent, actionable communication to stakeholders
// Source: Communication best practices for security findings
// Methodology: Verify the full prompt-building pipeline for HIGH risk produces
//              urgent tone with attack pattern context and BLOCK/REVIEW guidance
// Result: Should generate urgent style with attack references and blocking recommendation
func TestExplainer_HighRiskPackage(t *testing.T) {
	config := &ExplainerConfig{
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
			"Recent ownership transfer",
		},
		Findings: []models.Finding{
			{
				Severity:    "HIGH",
				Category:    "Publisher Control",
				Description: "Single maintainer - single point of compromise",
				Evidence:    "Only 1 maintainer found in npm registry",
			},
			{
				Severity:    "HIGH",
				Category:    "Install Execution",
				Description: "Install script makes network requests",
				Evidence:    "postinstall script contains curl command",
			},
		},
		SupplyChainScore: &models.SupplyChainScore{
			TotalScore: 14,
			RiskLevel:  "HIGH",
		},
	}

	// Verify style selection
	style := explainer.determineExplanationStyle(result.RiskLevel)
	if style != "urgent" {
		t.Errorf("Expected style 'urgent' for HIGH risk, got '%s'", style)
	}

	// Verify prompt building with attack context
	prompt := explainer.buildExecutivePrompt("suspicious-package", models.EcosystemNPM, result, style)
	if prompt == nil {
		t.Fatal("Expected prompt, got nil")
	}
	if !contains(prompt.UserPrompt, "URGENT") {
		t.Error("Expected prompt to contain 'URGENT' for HIGH risk style")
	}

	// Attack patterns for both maintainer and install script should be included
	if !contains(prompt.UserPrompt, "eslint-scope") {
		t.Error("Expected prompt to reference eslint-scope for single maintainer finding")
	}
	if !contains(prompt.UserPrompt, "event-stream") {
		t.Error("Expected prompt to reference event-stream for install script finding")
	}

	// Recommendation guidance should suggest BLOCK
	guidance := explainer.getRecommendationGuidance(result.RiskLevel)
	if !contains(guidance, "BLOCK") {
		t.Error("Expected HIGH risk guidance to contain 'BLOCK'")
	}
}

// Test: Executive explanation for MEDIUM risk package
// Justification: Medium risk packages require balanced analysis for informed decision-making
// Source: Risk communication frameworks
// Methodology: Create MEDIUM risk result, verify balanced tone
// Result: Should generate balanced explanation with REVIEW recommendation
func TestExplainer_MediumRiskPackage(t *testing.T) {
	config := &ExplainerConfig{
		TargetAudience: "technical",
		IncludeAttacks: false,
		MaxTokens:      1500,
		Temperature:    0.5,
	}

	explainer := NewExplainer(config)

	result := models.AnalysisResult{
		RiskLevel: "MEDIUM",
		RiskScore: 55,
		RiskFactors: []string{
			"No branch protection on default branch",
			"Low bus factor (2 contributors)",
		},
		Findings: []models.Finding{
			{
				Severity:    "MEDIUM",
				Category:    "Health",
				Description: "Low bus factor - concentrated development",
				Evidence:    "Top contributor accounts for 80% of commits",
			},
		},
		SupplyChainScore: &models.SupplyChainScore{
			TotalScore: 8,
			RiskLevel:  "MEDIUM",
		},
		Metadata: models.PackageMetadata{
			Maintainers: []string{"alice", "bob"},
			RepoStars:   150,
		},
	}

	// Verify style determination
	style := explainer.determineExplanationStyle(result.RiskLevel)
	if style != "balanced" {
		t.Errorf("Expected style 'balanced', got '%s'", style)
	}

	// Verify prompt building
	prompt := explainer.buildExecutivePrompt("test-package", models.EcosystemPyPI, result, style)
	if prompt == nil {
		t.Fatal("Expected prompt, got nil")
	}
	if !contains(prompt.UserPrompt, "BALANCED") {
		t.Error("Expected prompt to contain 'BALANCED'")
	}
}

// Test: Executive explanation for LOW risk package
// Justification: Low risk packages should provide concise, reassuring assessment
// Source: Security communication best practices
// Methodology: Create LOW risk result, verify brief tone
// Result: Should generate brief explanation with ALLOW recommendation
func TestExplainer_LowRiskPackage(t *testing.T) {
	explainer := NewExplainer(&ExplainerConfig{
		TargetAudience: "general",
		IncludeAttacks: false,
	})

	result := models.AnalysisResult{
		RiskLevel: "LOW",
		RiskScore: 20,
		RiskFactors: []string{
			"Package uses CI-based publishing",
			"Has SLSA Level 3 attestation",
			"Multiple maintainers with 2FA",
		},
		SupplyChainScore: &models.SupplyChainScore{
			TotalScore: 2,
			RiskLevel:  "LOW",
		},
		Metadata: models.PackageMetadata{
			Maintainers:         []string{"alice", "bob", "charlie"},
			HasSLSAAttestation:  true,
			HasBranchProtection: true,
			RepoStars:           5000,
		},
	}

	style := explainer.determineExplanationStyle(result.RiskLevel)
	if style != "brief" {
		t.Errorf("Expected style 'brief', got '%s'", style)
	}

	guidance := explainer.getRecommendationGuidance(result.RiskLevel)
	if !contains(guidance, "ALLOW") {
		t.Error("Expected guidance to contain 'ALLOW'")
	}
}

// Test: Attack pattern context inclusion
// Justification: Real-world attack examples help stakeholders understand risk relevance
// Source: Effective risk communication requires concrete examples
// Methodology: Enable attack context, verify relevant patterns are included
// Result: Should include attack references when IncludeAttacks=true
func TestExplainer_AttackPatternContext(t *testing.T) {
	explainer := NewExplainer(&ExplainerConfig{
		IncludeAttacks: true,
	})

	// Result with install script issue (should trigger event-stream reference)
	result := models.AnalysisResult{
		RiskLevel: "HIGH",
		Findings: []models.Finding{
			{
				Description: "Package has dangerous install script",
				Category:    "Install Execution",
			},
		},
	}

	context := explainer.getAttackPatternContext(result)
	if !contains(context, "event-stream") {
		t.Error("Expected context to contain 'event-stream'")
	}
	if !contains(context, "Install Script Attacks") {
		t.Error("Expected context to contain 'Install Script Attacks'")
	}

	// Result with single maintainer (should trigger account takeover reference)
	result2 := models.AnalysisResult{
		RiskLevel: "HIGH",
		Findings: []models.Finding{
			{
				Description: "Single maintainer detected",
				Category:    "Publisher Control",
			},
		},
	}

	context2 := explainer.getAttackPatternContext(result2)
	if !contains(context2, "Account Takeover") {
		t.Error("Expected context to contain 'Account Takeover'")
	}
	if !contains(context2, "eslint-scope") {
		t.Error("Expected context to contain 'eslint-scope'")
	}
}

// Test: Attack pattern context exclusion when disabled
// Justification: Some audiences prefer technical-only analysis without attack comparisons
// Source: Audience-appropriate communication
// Methodology: Disable attack context, verify generic guidance
// Result: Should not include specific attack references when IncludeAttacks=false
func TestExplainer_AttackPatternContext_Disabled(t *testing.T) {
	explainer := NewExplainer(&ExplainerConfig{
		IncludeAttacks: false,
	})

	result := models.AnalysisResult{
		RiskLevel: "HIGH",
		Findings: []models.Finding{
			{
				Description: "Single maintainer detected",
			},
		},
	}

	context := explainer.getAttackPatternContext(result)
	if contains(context, "eslint-scope") {
		t.Error("Expected context to not contain 'eslint-scope' when attacks disabled")
	}
	if !contains(context, "Do not include") {
		t.Error("Expected generic guidance when attacks disabled")
	}
}

// Test: Confidence score calculation
// Justification: Confidence helps stakeholders understand certainty of assessment
// Source: Risk assessment best practices require confidence indicators
// Methodology: Test with varying data availability
// Result: Confidence should decrease with missing data, increase with rich data
func TestExplainer_ConfidenceCalculation(t *testing.T) {
	explainer := NewExplainer(&ExplainerConfig{})

	tests := []struct {
		name               string
		result             models.AnalysisResult
		expectedConfidence float64
		tolerance          float64
	}{
		{
			name: "High confidence - complete data",
			result: models.AnalysisResult{
				Findings: []models.Finding{{}, {}, {}, {}},
				SupplyChainScore: &models.SupplyChainScore{
					TotalScore: 5,
				},
				Metadata: models.PackageMetadata{
					RepoStars:            1000,
					RepoForks:            50,
					Maintainers:          []string{"alice", "bob"},
					HasSLSAAttestation:   true,
					HasSigstoreSignature: true,
				},
			},
			expectedConfidence: 1.0,
			tolerance:          0.05,
		},
		{
			name: "Medium confidence - some missing data",
			result: models.AnalysisResult{
				Findings: []models.Finding{{}},
				Metadata: models.PackageMetadata{
					RepoStars:   100,
					Maintainers: []string{"alice"},
				},
			},
			expectedConfidence: 0.75,
			tolerance:          0.1,
		},
		{
			name: "Low confidence - minimal data",
			result: models.AnalysisResult{
				Metadata: models.PackageMetadata{
					RepoStars: 0,
					RepoForks: 0,
				},
			},
			expectedConfidence: 0.5,
			tolerance:          0.15,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			confidence := explainer.calculateConfidence(tt.result)
			if confidence < tt.expectedConfidence-tt.tolerance || confidence > tt.expectedConfidence+tt.tolerance {
				t.Errorf("Expected confidence %.2f±%.2f, got %.2f", tt.expectedConfidence, tt.tolerance, confidence)
			}
		})
	}
}

// Test: Response parsing from structured text
// Justification: AI responses may vary in format - parser must be robust
// Source: Defensive programming for AI outputs
// Methodology: Test parsing of different response formats
// Result: Should extract key fields from various response structures
func TestExplainer_ParseExecutiveResponse(t *testing.T) {
	explainer := NewExplainer(&ExplainerConfig{})

	tests := []struct {
		name     string
		response string
		validate func(t *testing.T, explanation *models.ExecutiveExplanation)
	}{
		{
			name: "Structured markdown response",
			response: `# Executive Summary

This package exhibits high supply chain risk due to single maintainer control.

## Key Risks

- Single point of failure for account takeover
- No multi-factor authentication enforcement
- Local publishing without CI verification

## Business Impact

If compromised, this package could expose customer credentials and violate SOC2 compliance.

## Recommendation

BLOCK: Do not use until maintainer count increases and 2FA is enforced.`,
			validate: func(t *testing.T, explanation *models.ExecutiveExplanation) {
				if !contains(explanation.Summary, "high supply chain risk") {
					t.Error("Expected summary to contain 'high supply chain risk'")
				}
				if len(explanation.KeyRisks) < 2 {
					t.Errorf("Expected at least 2 key risks, got %d", len(explanation.KeyRisks))
				}
				if !contains(explanation.BusinessImpact, "SOC2") {
					t.Error("Expected business impact to contain 'SOC2'")
				}
				if !contains(explanation.RecommendedAction, "BLOCK") {
					t.Error("Expected recommendation to contain 'BLOCK'")
				}
			},
		},
		{
			name: "Plain text response",
			response: `This package demonstrates good security practices with SLSA Level 3 attestation and multiple maintainers. No immediate concerns identified. Recommendation: ALLOW with standard monitoring.`,
			validate: func(t *testing.T, explanation *models.ExecutiveExplanation) {
				if !contains(explanation.Summary, "good security practices") {
					t.Error("Expected summary to contain 'good security practices'")
				}
				if explanation.Summary == "" {
					t.Error("Expected non-empty summary")
				}
			},
		},
		{
			name: "Bullet point risks",
			response: `Executive Summary:
Package shows moderate risk requiring review.

Key Risks:
* Low bus factor
* No branch protection
* Unverified provenance

Recommendation: REVIEW before production deployment.`,
			validate: func(t *testing.T, explanation *models.ExecutiveExplanation) {
				if len(explanation.KeyRisks) < 2 {
					t.Errorf("Expected at least 2 key risks, got %d", len(explanation.KeyRisks))
				}
				if !contains(explanation.RecommendedAction, "REVIEW") {
					t.Error("Expected recommendation to contain 'REVIEW'")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := models.AnalysisResult{
				RiskLevel: "MEDIUM",
				RiskScore: 50,
			}

			explanation := explainer.parseExecutiveResponse(tt.response, result)
			if explanation == nil {
				t.Fatal("Expected explanation, got nil")
			}
			tt.validate(t, explanation)

			// All explanations should have confidence
			if explanation.Confidence <= 0.0 {
				t.Errorf("Expected confidence > 0.0, got %.2f", explanation.Confidence)
			}
		})
	}
}

// Test: Style guidance generation
// Justification: Different risk levels require different communication approaches
// Source: Crisis communication and risk assessment literature
// Methodology: Verify style guidance matches risk level appropriately
// Result: HIGH=urgent, MEDIUM=balanced, LOW=brief
func TestExplainer_StyleGuidance(t *testing.T) {
	explainer := NewExplainer(&ExplainerConfig{})

	tests := []struct {
		style         string
		riskLevel     string
		shouldContain []string
	}{
		{
			style:         "urgent",
			riskLevel:     "HIGH",
			shouldContain: []string{"URGENT", "critical", "immediate action"},
		},
		{
			style:         "balanced",
			riskLevel:     "MEDIUM",
			shouldContain: []string{"BALANCED", "REVIEW", "objectively"},
		},
		{
			style:         "brief",
			riskLevel:     "LOW",
			shouldContain: []string{"BRIEF", "concise", "ALLOW"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.style, func(t *testing.T) {
			guidance := explainer.getStyleGuidance(tt.style, tt.riskLevel)
			if guidance == "" {
				t.Error("Expected non-empty guidance")
			}

			for _, expectedText := range tt.shouldContain {
				if !contains(guidance, expectedText) {
					t.Errorf("Style guidance for %s should contain '%s'", tt.style, expectedText)
				}
			}
		})
	}
}

// Test: Target audience customization
// Justification: Different stakeholders need different detail levels
// Source: Audience analysis for technical communication
// Methodology: Verify prompts adapt to target audience
// Result: Should tailor language to audience type
func TestExplainer_TargetAudience(t *testing.T) {
	audiences := []string{"executive", "technical", "compliance", "general"}

	result := models.AnalysisResult{
		RiskLevel: "MEDIUM",
		RiskScore: 50,
		Metadata: models.PackageMetadata{
			Maintainers: []string{"alice"},
		},
	}

	for _, audience := range audiences {
		t.Run(audience, func(t *testing.T) {
			config := &ExplainerConfig{
				TargetAudience: audience,
			}
			explainer := NewExplainer(config)

			prompt := explainer.buildExecutivePrompt("test-pkg", models.EcosystemNPM, result, "balanced")
			if !contains(prompt.UserPrompt, audience) {
				t.Errorf("Prompt should reference target audience: %s", audience)
			}
		})
	}
}

// Test: BatchExplain input validation
// Justification: Mismatched input lengths must be caught before API calls
// Source: Defensive programming for batch operations
// Methodology: Pass mismatched slice lengths and verify error
// Result: Should return clear error for mismatched inputs
func TestExplainer_BatchExplain_MismatchedInputs(t *testing.T) {
	explainer := NewExplainer(&ExplainerConfig{})

	packages := []string{"pkg-a", "pkg-b"}
	ecosystems := []models.Ecosystem{models.EcosystemNPM} // Wrong length
	results := []models.AnalysisResult{{}, {}}

	_, err := explainer.BatchExplain(context.Background(), packages, ecosystems, results)
	if err == nil {
		t.Fatal("Expected error for mismatched input lengths")
	}
	if !contains(err.Error(), "mismatched") {
		t.Errorf("Expected error to mention 'mismatched', got: %v", err)
	}
}

// Test: Default configuration values
// Justification: Sensible defaults prevent configuration errors
// Source: API design best practices
// Methodology: Create explainer without full config
// Result: Should set reasonable defaults
func TestExplainer_DefaultConfig(t *testing.T) {
	config := &ExplainerConfig{
		Client: nil,
		// No other fields set
	}

	explainer := NewExplainer(config)

	if explainer.config.MaxTokens != 1500 {
		t.Errorf("Expected default max tokens 1500, got %d", explainer.config.MaxTokens)
	}
	if explainer.config.Temperature != 0.5 {
		t.Errorf("Expected default temperature 0.5, got %.2f", explainer.config.Temperature)
	}
	if explainer.config.TargetAudience != "general" {
		t.Errorf("Expected default audience 'general', got '%s'", explainer.config.TargetAudience)
	}
}

// Test: Attack pattern context for ownership transfer findings
// Justification: Ownership transfer is a top attack vector (event-stream 2018)
// Source: "Backstabber's Knife Collection" (Ohm et al., 2020)
// Methodology: Create finding with ownership-related description, verify context
// Result: Should include ownership transfer attack references
func TestExplainer_AttackPatternContext_OwnershipTransfer(t *testing.T) {
	explainer := NewExplainer(&ExplainerConfig{
		IncludeAttacks: true,
	})

	result := models.AnalysisResult{
		RiskLevel: "HIGH",
		Findings: []models.Finding{
			{
				Description: "Recent ownership transfer detected",
				Category:    "Ownership Changes",
			},
		},
	}

	ctx := explainer.getAttackPatternContext(result)
	if !contains(ctx, "Ownership Transfer") {
		t.Error("Expected context to reference 'Ownership Transfer' for transfer findings")
	}
}

// Test: Attack pattern context for dormant package reactivation
// Justification: Dormant packages suddenly releasing is a well-documented attack vector
// Source: "Towards Measuring Supply Chain Attacks" (NDSS 2020)
// Methodology: Create finding with dormant-related description, verify context
// Result: Should include dormant reactivation references
func TestExplainer_AttackPatternContext_DormantReactivation(t *testing.T) {
	explainer := NewExplainer(&ExplainerConfig{
		IncludeAttacks: true,
	})

	result := models.AnalysisResult{
		RiskLevel: "HIGH",
		Findings: []models.Finding{
			{
				Description: "Dormant package suddenly reactivated after 2 years",
				Category:    "Release Anomalies",
			},
		},
	}

	ctx := explainer.getAttackPatternContext(result)
	if !contains(ctx, "Dormant Package Reactivation") {
		t.Error("Expected context to reference 'Dormant Package Reactivation'")
	}
}

// Test: Attack pattern context for provenance issues
// Justification: Missing provenance is a key indicator of build chain compromise
// Source: SLSA Framework - Build integrity requirements
// Methodology: Create finding with provenance-related description, verify context
// Result: Should include build chain compromise references
func TestExplainer_AttackPatternContext_Provenance(t *testing.T) {
	explainer := NewExplainer(&ExplainerConfig{
		IncludeAttacks: true,
	})

	result := models.AnalysisResult{
		RiskLevel: "MEDIUM",
		Findings: []models.Finding{
			{
				Description: "No provenance attestation found",
				Category:    "Provenance",
			},
		},
	}

	ctx := explainer.getAttackPatternContext(result)
	if !contains(ctx, "Build Chain Compromise") {
		t.Error("Expected context to reference 'Build Chain Compromise' for provenance findings")
	}
	if !contains(ctx, "SolarWinds") {
		t.Error("Expected context to reference 'SolarWinds' as a build chain attack example")
	}
}

// Test: Attack pattern context with no matching findings
// Justification: When no findings match known patterns, should provide generic guidance
// Source: Risk communication best practices
// Methodology: Create findings that don't match any known attack pattern keywords
// Result: Should return generic guidance for including attack comparisons
func TestExplainer_AttackPatternContext_NoMatchingFindings(t *testing.T) {
	explainer := NewExplainer(&ExplainerConfig{
		IncludeAttacks: true,
	})

	result := models.AnalysisResult{
		RiskLevel: "MEDIUM",
		Findings: []models.Finding{
			{
				Description: "Low bus factor detected",
				Category:    "Health",
			},
		},
	}

	ctx := explainer.getAttackPatternContext(result)
	if !contains(ctx, "attack pattern comparisons") {
		t.Error("Expected generic attack pattern guidance when no specific patterns match")
	}
}

// Test: Style and recommendation for CRITICAL risk level
// Justification: CRITICAL should be treated identically to HIGH for style/recommendation
// Source: Risk level classification design
// Methodology: Verify CRITICAL maps to urgent style and BLOCK recommendation
// Result: CRITICAL should produce same output as HIGH
func TestExplainer_CriticalRiskLevel(t *testing.T) {
	explainer := NewExplainer(&ExplainerConfig{})

	style := explainer.determineExplanationStyle("CRITICAL")
	if style != "urgent" {
		t.Errorf("Expected style 'urgent' for CRITICAL, got '%s'", style)
	}

	guidance := explainer.getRecommendationGuidance("CRITICAL")
	if !contains(guidance, "BLOCK") {
		t.Error("Expected CRITICAL guidance to contain 'BLOCK'")
	}
}

// Test: Style and recommendation for unknown risk level
// Justification: Unknown risk levels should default to balanced analysis
// Source: Defensive programming for risk classification
// Methodology: Pass an unrecognized risk level, verify defaults
// Result: Should default to balanced style with ALLOW recommendation
func TestExplainer_UnknownRiskLevel(t *testing.T) {
	explainer := NewExplainer(&ExplainerConfig{})

	style := explainer.determineExplanationStyle("UNKNOWN")
	if style != "balanced" {
		t.Errorf("Expected style 'balanced' for unknown risk, got '%s'", style)
	}

	guidance := explainer.getRecommendationGuidance("UNKNOWN")
	if !contains(guidance, "ALLOW") {
		t.Error("Expected unknown risk guidance to default to 'ALLOW'")
	}
}

// Test: parseExecutiveResponse with JSON input
// Justification: AI may return JSON-formatted responses; parser must handle both
// Source: Defensive programming for AI outputs
// Methodology: Pass valid JSON executive explanation, verify parsed fields
// Result: Should correctly parse JSON into ExecutiveExplanation struct
func TestExplainer_ParseExecutiveResponse_JSON(t *testing.T) {
	explainer := NewExplainer(&ExplainerConfig{})

	jsonResponse := `{"summary":"Package is high risk.","key_risks":["Single maintainer","No provenance"],"business_impact":"Could affect production","recommended_action":"BLOCK","technical_details":"Uses local publishing"}`

	result := models.AnalysisResult{
		RiskLevel: "HIGH",
		RiskScore: 80,
	}

	explanation := explainer.parseExecutiveResponse(jsonResponse, result)
	if explanation == nil {
		t.Fatal("Expected explanation, got nil")
	}
	if explanation.Summary != "Package is high risk." {
		t.Errorf("Expected JSON summary to be parsed, got: %s", explanation.Summary)
	}
}

// Helper functions

func contains(s, substr string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(substr))
}

func countSentences(text string) int {
	count := 0
	for _, ch := range text {
		if ch == '.' || ch == '!' || ch == '?' {
			count++
		}
	}
	return count
}
