package ai

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/anthropics/anthropic-sdk-go"
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

	// Risk assessment guidance should indicate HIGH RISK
	guidance := explainer.getRiskAssessmentGuidance(result.RiskLevel)
	if !contains(guidance, "HIGH RISK") {
		t.Error("Expected HIGH risk guidance to contain 'HIGH RISK'")
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

	guidance := explainer.getRiskAssessmentGuidance(result.RiskLevel)
	if !contains(guidance, "LOW RISK") {
		t.Error("Expected guidance to contain 'LOW RISK'")
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
				// RecommendedAction intentionally not populated per CLAUDE.md policy
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
				// RecommendedAction intentionally not populated per CLAUDE.md policy
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
			shouldContain: []string{"URGENT", "critical", "risk level"},
		},
		{
			style:         "balanced",
			riskLevel:     "MEDIUM",
			shouldContain: []string{"BALANCED", "risk factors", "objectively"},
		},
		{
			style:         "brief",
			riskLevel:     "LOW",
			shouldContain: []string{"BRIEF", "concise", "risk signals"},
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

	guidance := explainer.getRiskAssessmentGuidance("CRITICAL")
	if !contains(guidance, "HIGH RISK") {
		t.Error("Expected CRITICAL guidance to contain 'HIGH RISK'")
	}
}

// Test: Style and risk assessment for unknown risk level
// Justification: Unknown risk levels should default to balanced analysis
// Source: Defensive programming for risk classification
// Methodology: Pass an unrecognized risk level, verify defaults
// Result: Should default to balanced style with LOW RISK assessment
func TestExplainer_UnknownRiskLevel(t *testing.T) {
	explainer := NewExplainer(&ExplainerConfig{})

	style := explainer.determineExplanationStyle("UNKNOWN")
	if style != "balanced" {
		t.Errorf("Expected style 'balanced' for unknown risk, got '%s'", style)
	}

	guidance := explainer.getRiskAssessmentGuidance("UNKNOWN")
	if !contains(guidance, "LOW RISK") {
		t.Error("Expected unknown risk guidance to default to 'LOW RISK'")
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

// Test: ExplainRisk generates a full executive explanation via mocked API
// Justification: ExplainRisk is the core entry point for executive explanations;
//                must correctly build prompts, call the API, and parse responses
// Source: Stakeholder communication requirements for supply chain risk
// Methodology: Mock the Claude API to return a structured response, verify the
//              ExplainerResult contains parsed explanation with all expected fields
// Result: Should return ExplainerResult with non-empty explanation, token count, model
func TestExplainer_ExplainRisk_Mocked(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		responseText := `## Executive Summary

This package shows moderate supply chain risk due to limited maintainer diversity.

## Key Risks

- Low bus factor increases account takeover risk
- No branch protection on default branch

## Business Impact

If compromised, could affect downstream applications relying on this package.

## Recommendation

REVIEW before production deployment. Verify maintainer practices.

## Technical Details

Top contributor accounts for 80% of commits.`
		fmt.Fprintf(w, `{
			"id": "msg_explain_123",
			"type": "message",
			"role": "assistant",
			"model": "claude-sonnet-4-5-20250929",
			"content": [{"type": "text", "text": %q}],
			"stop_reason": "end_turn",
			"usage": {"input_tokens": 500, "output_tokens": 200}
		}`, responseText)
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

	explainer := NewExplainer(&ExplainerConfig{
		Client:         client,
		TargetAudience: "executive",
		IncludeAttacks: true,
		MaxTokens:      1500,
		Temperature:    0.5,
	})

	result := models.AnalysisResult{
		RiskLevel: "MEDIUM",
		RiskScore: 55,
		RiskFactors: []string{
			"Low bus factor",
			"No branch protection",
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
			RepoForks:   20,
		},
	}

	ctx := context.Background()
	explainerResult, err := explainer.ExplainRisk(ctx, "test-package", models.EcosystemNPM, result)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if explainerResult == nil {
		t.Fatal("expected non-nil result")
	}
	if explainerResult.Error != nil {
		t.Fatalf("unexpected error in result: %v", explainerResult.Error)
	}
	if explainerResult.Explanation == nil {
		t.Fatal("expected non-nil explanation")
	}
	if explainerResult.Explanation.Summary == "" {
		t.Error("expected non-empty summary")
	}
	if explainerResult.RawResponse == "" {
		t.Error("expected non-empty raw response")
	}
	if explainerResult.TokensUsed <= 0 {
		t.Error("expected positive token count")
	}
	if explainerResult.ModelVersion == "" {
		t.Error("expected non-empty model version")
	}
	if explainerResult.Explanation.GeneratedAt.IsZero() {
		t.Error("expected non-zero generated timestamp")
	}
	if explainerResult.Explanation.Confidence <= 0 {
		t.Error("expected positive confidence")
	}
}

// Test: ExplainRisk returns error on API failure
// Justification: API failures must be propagated as errors, not silently swallowed
// Source: Error handling best practices for AI-powered analysis
// Methodology: Mock API returns 400 error, verify error propagation
// Result: Should return error and ExplainerResult with Error field set
func TestExplainer_ExplainRisk_APIError(t *testing.T) {
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

	explainer := NewExplainer(&ExplainerConfig{
		Client: client,
	})

	result := models.AnalysisResult{
		RiskLevel: "MEDIUM",
		RiskScore: 50,
	}

	explainerResult, err := explainer.ExplainRisk(context.Background(), "fail-pkg", models.EcosystemNPM, result)
	if err == nil {
		t.Fatal("expected error from API failure")
	}

	// The second return value is the raw API error; the wrapped error is in ExplainerResult.Error
	if explainerResult == nil {
		t.Fatal("expected non-nil ExplainerResult even on error")
	}
	if explainerResult.Error == nil {
		t.Error("expected ExplainerResult.Error to be set")
	} else if !strings.Contains(explainerResult.Error.Error(), "failed to generate executive explanation") {
		t.Errorf("expected wrapped explanation error, got: %v", explainerResult.Error)
	}
}

// Test: ExplainRisk correctly parses JSON response from API
// Justification: When AI returns structured JSON instead of markdown, the parser
//                should correctly deserialize all fields
// Source: Anthropic API response format flexibility
// Methodology: Mock API returns a JSON-formatted executive explanation
// Result: All JSON fields should be correctly parsed into ExecutiveExplanation
func TestExplainer_ExplainRisk_JSONResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		jsonResp := `{"summary":"High risk package.","key_risks":["Single maintainer","No provenance"],"business_impact":"Potential data breach","recommended_action":"BLOCK","technical_details":"Local publishing detected"}`
		fmt.Fprintf(w, `{
			"id": "msg_json_123",
			"type": "message",
			"role": "assistant",
			"model": "claude-sonnet-4-5-20250929",
			"content": [{"type": "text", "text": %q}],
			"stop_reason": "end_turn",
			"usage": {"input_tokens": 300, "output_tokens": 100}
		}`, jsonResp)
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

	explainer := NewExplainer(&ExplainerConfig{
		Client: client,
	})

	result := models.AnalysisResult{
		RiskLevel: "HIGH",
		RiskScore: 85,
	}

	explainerResult, err := explainer.ExplainRisk(context.Background(), "json-pkg", models.EcosystemNPM, result)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if explainerResult.Explanation.Summary != "High risk package." {
		t.Errorf("expected parsed JSON summary, got: %s", explainerResult.Explanation.Summary)
	}
	if len(explainerResult.Explanation.KeyRisks) != 2 {
		t.Errorf("expected 2 key risks from JSON, got %d", len(explainerResult.Explanation.KeyRisks))
	}
	if explainerResult.Explanation.RecommendedAction != "BLOCK" {
		t.Errorf("expected 'BLOCK' recommendation, got: %s", explainerResult.Explanation.RecommendedAction)
	}
}

// Test: extractTextContent correctly extracts text from Anthropic message blocks
// Justification: Response parsing must handle single and multiple content blocks
// Source: Anthropic API message response format
// Methodology: Use httptest to produce properly deserialized messages, then extract text
// Result: Should concatenate text from all text-type content blocks
func TestExplainer_ExtractTextContent(t *testing.T) {
	explainer := NewExplainer(&ExplainerConfig{})

	// Helper: create a real API message via httptest to get proper SDK deserialization
	makeMessage := func(t *testing.T, textContent string) *anthropic.Message {
		t.Helper()
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{
				"id": "msg_extract",
				"type": "message",
				"role": "assistant",
				"model": "claude-sonnet-4-5-20250929",
				"content": [{"type": "text", "text": %q}],
				"stop_reason": "end_turn",
				"usage": {"input_tokens": 10, "output_tokens": 5}
			}`, textContent)
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

		msg, err := client.CreateMessage(context.Background(), anthropic.MessageNewParams{
			Model:     anthropic.Model("claude-sonnet-4-5-20250929"),
			MaxTokens: 100,
			Messages:  []anthropic.MessageParam{anthropic.NewUserMessage(anthropic.NewTextBlock("test"))},
		})
		if err != nil {
			t.Fatalf("failed to get message: %v", err)
		}
		return msg
	}

	t.Run("single text block", func(t *testing.T) {
		msg := makeMessage(t, "Hello, world!")
		text := explainer.extractTextContent(msg)
		if text != "Hello, world!" {
			t.Errorf("expected 'Hello, world!', got %q", text)
		}
	})

	t.Run("extracts non-empty content", func(t *testing.T) {
		msg := makeMessage(t, "This is a risk assessment summary.")
		text := explainer.extractTextContent(msg)
		if text == "" {
			t.Error("expected non-empty extracted text")
		}
		if text != "This is a risk assessment summary." {
			t.Errorf("unexpected text: %q", text)
		}
	})

	t.Run("empty content returns empty string", func(t *testing.T) {
		msg := &anthropic.Message{
			Content: []anthropic.ContentBlockUnion{},
		}
		text := explainer.extractTextContent(msg)
		if text != "" {
			t.Errorf("expected empty string, got %q", text)
		}
	})
}

// Test: GenerateQuickSummary produces concise summary via mocked API
// Justification: Quick summaries must be concise (2-3 sentences) and include
//                a clear BLOCK/REVIEW/ALLOW recommendation
// Source: Executive briefing best practices
// Methodology: Mock API to return concise summary, verify it's returned correctly
// Result: Should return non-empty summary string
func TestExplainer_GenerateQuickSummary_Mocked(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{
			"id": "msg_quick_123",
			"type": "message",
			"role": "assistant",
			"model": "claude-haiku-4-5-20251001",
			"content": [{"type": "text", "text": "Moderate risk. Limited maintainer diversity increases account takeover risk. Recommendation: REVIEW before production deployment."}],
			"stop_reason": "end_turn",
			"usage": {"input_tokens": 100, "output_tokens": 30}
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

	explainer := NewExplainer(&ExplainerConfig{
		Client: client,
	})

	result := models.AnalysisResult{
		RiskLevel: "MEDIUM",
		RiskScore: 55,
	}

	summary, err := explainer.GenerateQuickSummary(context.Background(), "test-pkg", result)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if summary == "" {
		t.Error("expected non-empty summary")
	}
	if !strings.Contains(summary, "REVIEW") {
		t.Error("expected summary to contain recommendation")
	}

	// Quick summary should be concise
	sentences := countSentences(summary)
	if sentences > 5 {
		t.Errorf("expected concise summary (<=5 sentences), got %d", sentences)
	}
}

// Test: GenerateQuickSummary returns error on API failure
// Justification: API errors must be clearly surfaced to callers
// Source: Error handling best practices
// Methodology: Mock API returns error, verify error propagation
// Result: Should return empty string and error
func TestExplainer_GenerateQuickSummary_APIError(t *testing.T) {
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

	explainer := NewExplainer(&ExplainerConfig{
		Client: client,
	})

	result := models.AnalysisResult{
		RiskLevel: "HIGH",
		RiskScore: 80,
	}

	_, err = explainer.GenerateQuickSummary(context.Background(), "fail-pkg", result)
	if err == nil {
		t.Fatal("expected error from API failure")
	}
	if !strings.Contains(err.Error(), "failed to generate quick summary") {
		t.Errorf("expected quick summary error, got: %v", err)
	}
}

// Test: BatchExplain processes multiple packages and handles mixed success/failure
// Justification: Batch processing must continue on individual failures and record
//                errors per-package without failing the entire batch
// Source: Bulk processing requirements for dependency graph analysis
// Methodology: Mock API that alternates success/failure, verify mixed results
// Result: Should return results for all packages, with errors on failed ones
func TestExplainer_BatchExplain_MixedResults(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if callCount%2 == 0 {
			// Even calls fail
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"type":"error","error":{"type":"invalid_request_error","message":"test"}}`)
			return
		}
		// Odd calls succeed
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{
			"id": "msg_batch",
			"type": "message",
			"role": "assistant",
			"model": "claude-sonnet-4-5-20250929",
			"content": [{"type": "text", "text": "Low risk package. Good practices. Recommendation: ALLOW."}],
			"stop_reason": "end_turn",
			"usage": {"input_tokens": 200, "output_tokens": 50}
		}`)
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

	explainer := NewExplainer(&ExplainerConfig{
		Client: client,
	})

	packages := []string{"pkg-a", "pkg-b", "pkg-c"}
	ecosystems := []models.Ecosystem{models.EcosystemNPM, models.EcosystemPyPI, models.EcosystemNPM}
	results := []models.AnalysisResult{
		{RiskLevel: "LOW", RiskScore: 10},
		{RiskLevel: "MEDIUM", RiskScore: 50},
		{RiskLevel: "LOW", RiskScore: 15},
	}

	explainerResults, err := explainer.BatchExplain(context.Background(), packages, ecosystems, results)
	if err != nil {
		t.Fatalf("unexpected batch error: %v", err)
	}

	if len(explainerResults) != 3 {
		t.Fatalf("expected 3 results, got %d", len(explainerResults))
	}

	// First package (odd call) should succeed
	if explainerResults[0].Error != nil {
		t.Errorf("expected first package to succeed, got error: %v", explainerResults[0].Error)
	}

	// Second package (even call) should fail
	if explainerResults[1].Error == nil {
		t.Error("expected second package to have error")
	}

	// Third package (odd call) should succeed
	if explainerResults[2].Error != nil {
		t.Errorf("expected third package to succeed, got error: %v", explainerResults[2].Error)
	}
}

// Test: BatchExplain with all successful results
// Justification: Happy path must return all results with valid explanations
// Source: Batch processing requirements
// Methodology: Mock API returns success for all calls
// Result: All results should have valid explanations and no errors
func TestExplainer_BatchExplain_AllSuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{
			"id": "msg_batch_ok",
			"type": "message",
			"role": "assistant",
			"model": "claude-sonnet-4-5-20250929",
			"content": [{"type": "text", "text": "Package shows good security practices. Recommendation: ALLOW."}],
			"stop_reason": "end_turn",
			"usage": {"input_tokens": 200, "output_tokens": 50}
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

	explainer := NewExplainer(&ExplainerConfig{
		Client: client,
	})

	packages := []string{"pkg-a", "pkg-b"}
	ecosystems := []models.Ecosystem{models.EcosystemNPM, models.EcosystemPyPI}
	results := []models.AnalysisResult{
		{RiskLevel: "LOW", RiskScore: 10, Metadata: models.PackageMetadata{Maintainers: []string{"a", "b"}, RepoStars: 100}},
		{RiskLevel: "LOW", RiskScore: 15, Metadata: models.PackageMetadata{Maintainers: []string{"x"}, RepoStars: 50}},
	}

	explainerResults, err := explainer.BatchExplain(context.Background(), packages, ecosystems, results)
	if err != nil {
		t.Fatalf("unexpected batch error: %v", err)
	}

	for i, r := range explainerResults {
		if r.Error != nil {
			t.Errorf("package %d: unexpected error: %v", i, r.Error)
		}
		if r.Explanation == nil {
			t.Errorf("package %d: expected non-nil explanation", i)
		}
		if r.RawResponse == "" {
			t.Errorf("package %d: expected non-empty raw response", i)
		}
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
