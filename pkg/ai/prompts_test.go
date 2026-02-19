package ai

import (
	"strings"
	"testing"

	"github.com/metalstormbass/snyft/pkg/models"
)

// TestPromptTemplateRender tests the basic rendering of prompt templates
func TestPromptTemplateRender(t *testing.T) {
	template := &PromptTemplate{
		SystemPrompt: "You are a test assistant.",
		UserPrompt:   "Hello {{name}}, your age is {{age}}.",
		Parameters: map[string]string{
			"name": "Alice",
			"age":  "30",
		},
	}

	system, user := template.Render()

	if system != "You are a test assistant." {
		t.Errorf("Expected system prompt to be unchanged, got: %s", system)
	}

	expected := "Hello Alice, your age is 30."
	if user != expected {
		t.Errorf("Expected user prompt: %s, got: %s", expected, user)
	}
}

// TestAttackPatternMatchingPrompt tests the creation of attack pattern matching prompts
func TestAttackPatternMatchingPrompt(t *testing.T) {
	analysisResult := models.AnalysisResult{
		Dependency: models.Dependency{
			Name:      "suspicious-package",
			Version:   "1.0.0",
			Ecosystem: models.EcosystemNPM,
		},
		RiskLevel: "HIGH",
		RiskScore: 85,
		RiskFactors: []string{
			"Single maintainer",
			"No source code verification",
			"Suspicious install scripts",
		},
		Findings: []models.Finding{
			{
				Severity:    "HIGH",
				Category:    "Account Takeover Risk",
				Description: "Single maintainer with no 2FA",
			},
		},
		SupplyChainScore: &models.SupplyChainScore{
			TotalScore: 15,
			RiskLevel:  "HIGH",
			CategoryScores: models.CategoryScores{
				PublisherControl: models.CategoryScore{RiskPoints: 2},
				OwnershipChanges: models.CategoryScore{RiskPoints: 1},
				ReleaseAnomalies: models.CategoryScore{RiskPoints: 2},
				InstallExecution: models.CategoryScore{RiskPoints: 2},
				DependencySprawl: models.CategoryScore{RiskPoints: 1},
				Provenance:       models.CategoryScore{RiskPoints: 2},
				Health:           models.CategoryScore{RiskPoints: 2},
				Governance:       models.CategoryScore{RiskPoints: 2},
				ReleaseSecurity:  models.CategoryScore{RiskPoints: 1},
			},
		},
	}

	prompt := NewAttackPatternMatchingPrompt("suspicious-package", models.EcosystemNPM, analysisResult)

	// Test that system prompt includes attack patterns
	if !strings.Contains(prompt.SystemPrompt, "Typosquatting") {
		t.Error("System prompt should mention Typosquatting pattern")
	}
	if !strings.Contains(prompt.SystemPrompt, "Account Takeover") {
		t.Error("System prompt should mention Account Takeover pattern")
	}
	if !strings.Contains(prompt.SystemPrompt, "Malicious Install Script") {
		t.Error("System prompt should mention Malicious Install Script pattern")
	}
	if !strings.Contains(prompt.SystemPrompt, "event-stream") {
		t.Error("System prompt should reference historical attack examples")
	}

	_, user := prompt.Render()

	// Test that user prompt includes package details
	if !strings.Contains(user, "suspicious-package") {
		t.Error("User prompt should include package name")
	}
	if !strings.Contains(user, "HIGH") {
		t.Error("User prompt should include risk level")
	}

	// Test that user prompt includes supply chain score
	if !strings.Contains(user, "15/18") {
		t.Error("User prompt should include supply chain score")
	}

	// Test temperature for pattern matching
	if prompt.Temperature != 0.4 {
		t.Errorf("Expected temperature 0.4 for pattern matching, got: %f", prompt.Temperature)
	}
}

// TestExecutiveExplanationPrompt tests the creation of executive explanation prompts
func TestExecutiveExplanationPrompt(t *testing.T) {
	analysisResult := models.AnalysisResult{
		Dependency: models.Dependency{
			Name:      "test-package",
			Version:   "2.0.0",
			Ecosystem: models.EcosystemPyPI,
		},
		RiskLevel: "MEDIUM",
		RiskScore: 55,
		RiskFactors: []string{
			"No CI/CD detected",
			"Single maintainer",
		},
		Findings: []models.Finding{
			{
				Severity:    "HIGH",
				Category:    "No Provenance",
				Description: "Package lacks cryptographic signatures",
			},
			{
				Severity:    "MEDIUM",
				Category:    "Low Community Engagement",
				Description: "Package has minimal stars and forks",
			},
		},
		SupplyChainScore: &models.SupplyChainScore{
			TotalScore: 10,
			RiskLevel:  "MEDIUM",
			CategoryScores: models.CategoryScores{
				PublisherControl: models.CategoryScore{
					RiskPoints:  2,
					Description: "Single maintainer with personal account",
				},
				Provenance: models.CategoryScore{
					RiskPoints:  2,
					Description: "No provenance evidence",
				},
				Health: models.CategoryScore{
					RiskPoints:  1,
					Description: "Moderate health indicators",
				},
			},
		},
	}

	prompt := NewExecutiveExplanationPrompt("test-package", models.EcosystemPyPI, analysisResult, "Engineering Manager")

	// Test system prompt includes stakeholder communication principles
	if !strings.Contains(strings.ToLower(prompt.SystemPrompt), "business impact") {
		t.Error("System prompt should mention business impact")
	}
	if !strings.Contains(prompt.SystemPrompt, "stakeholder") {
		t.Error("System prompt should mention stakeholders")
	}
	if !strings.Contains(strings.ToLower(prompt.SystemPrompt), "actionable") {
		t.Error("System prompt should emphasize actionable recommendations")
	}

	_, user := prompt.Render()

	// Test that user prompt includes target audience
	if !strings.Contains(user, "Engineering Manager") {
		t.Error("User prompt should include target audience")
	}

	// Test that user prompt requests business impact
	if !strings.Contains(strings.ToLower(user), "business impact") {
		t.Error("User prompt should request business impact section")
	}

	// Test that user prompt requests risk context
	if !strings.Contains(strings.ToLower(user), "risk") {
		t.Error("User prompt should reference risk assessment")
	}

	// Test temperature for executive explanations (should be higher for creativity)
	if prompt.Temperature != 0.7 {
		t.Errorf("Expected temperature 0.7 for executive explanations, got: %f", prompt.Temperature)
	}

	// Test max tokens (should be higher for comprehensive explanations)
	if prompt.MaxTokens != 3000 {
		t.Errorf("Expected max tokens 3000, got: %d", prompt.MaxTokens)
	}
}

// TestPackageComparisonPrompt tests the creation of package comparison prompts
func TestPackageComparisonPrompt(t *testing.T) {
	packages := []string{"package-a", "package-b", "package-c"}
	ecosystems := []models.Ecosystem{models.EcosystemNPM, models.EcosystemNPM, models.EcosystemPyPI}

	analysisResults := []models.AnalysisResult{
		{
			RiskLevel:   "LOW",
			RiskScore:   20,
			RiskFactors: []string{"Well maintained"},
			Findings:    []models.Finding{},
			Metadata: models.PackageMetadata{
				RepoStars:           1000,
				HasCI:               true,
				HasSLSAAttestation:  true,
				HasSigstoreSignature: false,
			},
			SupplyChainScore: &models.SupplyChainScore{
				TotalScore: 3,
				RiskLevel:  "LOW",
			},
		},
		{
			RiskLevel:   "HIGH",
			RiskScore:   85,
			RiskFactors: []string{"Single maintainer", "No CI"},
			Findings: []models.Finding{
				{Severity: "HIGH", Category: "Risk"},
			},
			Metadata: models.PackageMetadata{
				RepoStars: 10,
				HasCI:     false,
			},
			SupplyChainScore: &models.SupplyChainScore{
				TotalScore: 14,
				RiskLevel:  "HIGH",
			},
		},
		{
			RiskLevel:   "MEDIUM",
			RiskScore:   50,
			RiskFactors: []string{"No provenance"},
			Findings:    []models.Finding{},
			Metadata: models.PackageMetadata{
				RepoStars: 500,
				HasCI:     true,
			},
			SupplyChainScore: &models.SupplyChainScore{
				TotalScore: 8,
				RiskLevel:  "MEDIUM",
			},
		},
	}

	prompt := NewPackageComparisonPrompt(packages, ecosystems, analysisResults)

	_, user := prompt.Render()

	// Test that user prompt includes all package names
	for _, pkg := range packages {
		if !strings.Contains(user, pkg) {
			t.Errorf("User prompt should include package: %s", pkg)
		}
	}

	// Test that user prompt includes risk levels
	if !strings.Contains(user, "LOW") || !strings.Contains(user, "HIGH") || !strings.Contains(user, "MEDIUM") {
		t.Error("User prompt should include all risk levels")
	}

	// Test that user prompt requests relative ranking
	if !strings.Contains(user, "Relative Risk Ranking") {
		t.Error("User prompt should request relative risk ranking")
	}

	// Test that user prompt requests risk assessment
	if !strings.Contains(user, "Risk Assessment") {
		t.Error("User prompt should request risk assessment")
	}
}

// TestGetPromptDescription tests the prompt description function
func TestGetPromptDescription(t *testing.T) {
	testCases := []struct {
		promptType  PromptType
		shouldContain string
	}{
		{PromptTypeAttackPatternMatch, "attack patterns"},
		{PromptTypeExecutiveExplanation, "stakeholder"},
		{PromptTypePackageComparison, "multiple packages"},
		{PromptTypeCustom, "Custom"},
	}

	for _, tc := range testCases {
		desc := GetPromptDescription(tc.promptType)
		if !strings.Contains(desc, tc.shouldContain) {
			t.Errorf("Description for %s should contain '%s', got: %s", tc.promptType, tc.shouldContain, desc)
		}
	}
}

// TestNewCustomPrompt tests the creation of custom prompts
func TestNewCustomPrompt(t *testing.T) {
	systemPrompt := "You are a custom assistant."
	userPrompt := "Hello {{name}}!"
	params := map[string]string{"name": "World"}
	temperature := 0.5
	maxTokens := 1000

	prompt := NewCustomPrompt(systemPrompt, userPrompt, params, temperature, maxTokens)

	if prompt.SystemPrompt != systemPrompt {
		t.Error("Custom prompt should preserve system prompt")
	}

	if prompt.Temperature != temperature {
		t.Errorf("Expected temperature %f, got: %f", temperature, prompt.Temperature)
	}

	if prompt.MaxTokens != maxTokens {
		t.Errorf("Expected max tokens %d, got: %d", maxTokens, prompt.MaxTokens)
	}

	_, user := prompt.Render()
	if user != "Hello World!" {
		t.Errorf("Expected rendered user prompt 'Hello World!', got: %s", user)
	}
}

// TestCountHighSeverityFindings tests the helper function
func TestCountHighSeverityFindings(t *testing.T) {
	findings := []models.Finding{
		{Severity: "HIGH", Category: "Test1"},
		{Severity: "CRITICAL", Category: "Test2"},
		{Severity: "MEDIUM", Category: "Test3"},
		{Severity: "LOW", Category: "Test4"},
		{Severity: "HIGH", Category: "Test5"},
	}

	count := countHighSeverityFindings(findings)
	if count != 3 {
		t.Errorf("Expected 3 high severity findings, got: %d", count)
	}
}

// TestPromptSystemMessages tests that all system prompts contain key concepts
func TestPromptSystemMessages(t *testing.T) {
	testCases := []struct {
		name          string
		systemPrompt  string
		mustContain   []string
		mustNotContain []string
	}{
		{
			name:         "SemanticAnalysis",
			systemPrompt: SemanticAnalysisSystemPrompt,
			mustContain: []string{
				"supply chain",
				"compromise likelihood",
				"Backstabber's Knife Collection",
				"SLSA",
				"OSSF Scorecard",
				"maintainer",
			},
			mustNotContain: []string{
				// Should explicitly say we DON'T do CVE tracking
			},
		},
		{
			name:         "AttackPatternComparison",
			systemPrompt: AttackPatternComparisonSystemPrompt,
			mustContain: []string{
				"attack pattern",
				"Typosquatting",
				"Account Takeover",
				"event-stream",
				"crossenv",
				"Historical Examples",
			},
			mustNotContain: []string{},
		},
		{
			name:         "ExecutiveExplanation",
			systemPrompt: ExecutiveExplanationSystemPrompt,
			mustContain: []string{
				"stakeholder",
				"Business Impact",
				"Risk-Focused",
				"Executive Summary",
				"Risk Context",
			},
			mustNotContain: []string{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			for _, keyword := range tc.mustContain {
				if !strings.Contains(tc.systemPrompt, keyword) {
					t.Errorf("%s system prompt should contain: %s", tc.name, keyword)
				}
			}

			for _, keyword := range tc.mustNotContain {
				if strings.Contains(tc.systemPrompt, keyword) {
					t.Errorf("%s system prompt should NOT contain: %s", tc.name, keyword)
				}
			}
		})
	}
}

// TestAcademicReferences tests that prompts reference academic sources
func TestAcademicReferences(t *testing.T) {
	// Test SemanticAnalysisSystemPrompt references
	semanticRefs := []string{
		"Backstabber's Knife Collection",
		"Ohm et al.",
		"2020",
		"SLSA",
		"OSSF",
		"arxiv.org",
	}

	for _, ref := range semanticRefs {
		if !strings.Contains(SemanticAnalysisSystemPrompt, ref) {
			t.Errorf("SemanticAnalysisSystemPrompt should reference: %s", ref)
		}
	}

	// Test AttackPatternComparisonSystemPrompt references (has different required refs)
	attackPatternRefs := []string{
		"Backstabber's Knife Collection",
		"Ohm et al.",
		"2020",
		"SLSA",
	}

	for _, ref := range attackPatternRefs {
		if !strings.Contains(AttackPatternComparisonSystemPrompt, ref) {
			t.Errorf("AttackPatternComparisonSystemPrompt should reference: %s", ref)
		}
	}
}

// TestPromptParameterization tests that all templates properly parameterize
func TestPromptParameterization(t *testing.T) {
	// Test that templates don't leave unreplaced placeholders after rendering
	analysisResult := models.AnalysisResult{
		Dependency: models.Dependency{
			Name:      "test-pkg",
			Version:   "1.0.0",
			Ecosystem: models.EcosystemNPM,
		},
		RiskLevel:   "MEDIUM",
		RiskScore:   50,
		RiskFactors: []string{"test factor"},
		Findings: []models.Finding{
			{Severity: "HIGH", Category: "Test", Description: "Test finding"},
		},
	}

	prompt := NewAttackPatternMatchingPrompt("test-pkg", models.EcosystemNPM, analysisResult)
	_, user := prompt.Render()

	// Should not contain any unreplaced {{placeholders}}
	if strings.Contains(user, "{{") || strings.Contains(user, "}}") {
		t.Error("Rendered prompt contains unreplaced placeholders")
	}
}
