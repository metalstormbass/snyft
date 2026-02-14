package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/metalstormbass/snyft/pkg/models"
)

// ExplainerConfig configures the executive explanation generator
type ExplainerConfig struct {
	Client          *Client
	TargetAudience  string  // "executive", "technical", "compliance", "general"
	IncludeAttacks  bool    // Include real-world attack comparisons
	MaxTokens       int     // Max tokens for response (default: 1500)
	Temperature     float64 // Temperature for response generation (default: 0.5)
}

// Explainer generates business-friendly explanations of technical security findings
type Explainer struct {
	config *ExplainerConfig
}

// NewExplainer creates a new executive explanation generator
func NewExplainer(config *ExplainerConfig) *Explainer {
	// Set defaults
	if config.MaxTokens == 0 {
		config.MaxTokens = 1500
	}
	if config.Temperature == 0 {
		config.Temperature = 0.5
	}
	if config.TargetAudience == "" {
		config.TargetAudience = "general"
	}

	return &Explainer{
		config: config,
	}
}

// ExplainerResult contains the generated explanation with metadata
type ExplainerResult struct {
	Explanation  *models.ExecutiveExplanation
	RawResponse  string
	TokensUsed   int
	ModelVersion string
	Error        error
}

// ExplainRisk generates an executive-friendly explanation of an analysis result
func (e *Explainer) ExplainRisk(ctx context.Context, packageName string, ecosystem models.Ecosystem, result models.AnalysisResult) (*ExplainerResult, error) {
	// Determine the explanation style based on risk level
	style := e.determineExplanationStyle(result.RiskLevel)

	// Build the prompt for executive explanation
	prompt := e.buildExecutivePrompt(packageName, ecosystem, result, style)

	// Call Claude API
	systemPrompt, userPrompt := prompt.Render()

	params := anthropic.MessageNewParams{
		Model:       anthropic.ModelClaudeSonnet4_5,
		MaxTokens:   int64(e.config.MaxTokens),
		Temperature: anthropic.Float(e.config.Temperature),
		System: []anthropic.TextBlockParam{
			{Text: systemPrompt},
		},
		Messages: []anthropic.MessageParam{
			anthropic.NewUserMessage(anthropic.NewTextBlock(userPrompt)),
		},
	}

	msg, err := e.config.Client.CreateMessage(ctx, params)
	if err != nil {
		return &ExplainerResult{
			Error: fmt.Errorf("failed to generate executive explanation: %w", err),
		}, err
	}

	// Extract text content from response
	rawResponse := e.extractTextContent(msg)

	// Parse the response into ExecutiveExplanation
	explanation := e.parseExecutiveResponse(rawResponse, result)

	// Add generation timestamp
	explanation.GeneratedAt = time.Now()

	return &ExplainerResult{
		Explanation:  explanation,
		RawResponse:  rawResponse,
		TokensUsed:   int(msg.Usage.InputTokens + msg.Usage.OutputTokens),
		ModelVersion: string(msg.Model),
		Error:        nil,
	}, nil
}

// determineExplanationStyle determines the style based on risk level
func (e *Explainer) determineExplanationStyle(riskLevel string) string {
	switch strings.ToUpper(riskLevel) {
	case "HIGH", "CRITICAL":
		return "urgent"
	case "MEDIUM":
		return "balanced"
	case "LOW":
		return "brief"
	default:
		return "balanced"
	}
}

// buildExecutivePrompt creates a customized prompt based on risk level and audience
func (e *Explainer) buildExecutivePrompt(packageName string, ecosystem models.Ecosystem, result models.AnalysisResult, style string) *PromptTemplate {
	// Start with the base executive explanation prompt
	basePrompt := NewExecutiveExplanationPrompt(packageName, ecosystem, result, e.config.TargetAudience)

	// Customize based on style
	styleGuidance := e.getStyleGuidance(style, result.RiskLevel)
	recommendationGuidance := e.getRecommendationGuidance(result.RiskLevel)

	// Inject style-specific instructions
	enhancedUserPrompt := fmt.Sprintf(`%s

## Style Instructions

%s

## Recommendation Guidance

%s

## Attack Pattern Context

%s`,
		basePrompt.UserPrompt,
		styleGuidance,
		recommendationGuidance,
		e.getAttackPatternContext(result))

	basePrompt.UserPrompt = enhancedUserPrompt
	basePrompt.Temperature = e.config.Temperature
	basePrompt.MaxTokens = e.config.MaxTokens

	return basePrompt
}

// getStyleGuidance returns style-specific instructions
func (e *Explainer) getStyleGuidance(style, riskLevel string) string {
	switch style {
	case "urgent":
		return `**URGENT TONE REQUIRED**

This is a HIGH RISK package. Your explanation should:
- Lead with the most critical risk immediately
- Use clear, action-oriented language
- Emphasize time sensitivity if applicable
- Be direct and unambiguous about the risk
- Keep summary to 2-3 sentences maximum
- Include a clear, specific recommendation (BLOCK/REVIEW with conditions)

Example opening: "This package exhibits [critical risk factor] which significantly increases the likelihood of supply chain compromise. [Specific evidence]. Immediate action is recommended."`

	case "brief":
		return `**BRIEF, REASSURING TONE**

This is a LOW RISK package. Your explanation should:
- Be concise (2-3 sentences total for summary)
- Acknowledge that some minor concerns exist but don't warrant alarm
- Focus on best practices and continuous monitoring
- Use measured, balanced language
- Recommendation should be ALLOW (with optional monitoring suggestions)

Example opening: "This package demonstrates generally good supply chain security practices with minor areas for improvement. [Brief summary of findings]. No immediate action required."`

	case "balanced":
		return `**BALANCED, ANALYTICAL TONE**

This is a MEDIUM RISK package. Your explanation should:
- Present risks objectively without alarm or dismissiveness
- Provide clear context for each risk factor
- Balance concerns with mitigating factors
- Be thorough but concise (3-4 sentences for summary)
- Recommendation should be REVIEW (with specific conditions to check)

Example opening: "This package exhibits several supply chain risk factors that warrant review before deployment. [Key findings]. A more detailed security review is recommended."`
	default:
		return `**BALANCED, ANALYTICAL TONE**

This is a MEDIUM RISK package. Your explanation should:
- Present risks objectively without alarm or dismissiveness
- Provide clear context for each risk factor
- Balance concerns with mitigating factors
- Be thorough but concise (3-4 sentences for summary)
- Recommendation should be REVIEW (with specific conditions to check)

Example opening: "This package exhibits several supply chain risk factors that warrant review before deployment. [Key findings]. A more detailed security review is recommended."`
	}
}

// getRecommendationGuidance returns recommendation-specific instructions
func (e *Explainer) getRecommendationGuidance(riskLevel string) string {
	switch strings.ToUpper(riskLevel) {
	case "HIGH", "CRITICAL":
		return `Your recommendation should be one of:
- **BLOCK**: Do not use this package until critical risks are addressed. Use when there are multiple HIGH severity findings or patterns matching known attacks.
- **REVIEW WITH CAUTION**: Use only if absolutely necessary, with specific security measures in place (isolation, monitoring, etc.).

Include specific conditions that would need to be met before considering this package safe.`

	case "MEDIUM":
		return `Your recommendation should be:
- **REVIEW**: Conduct a security review before deployment. Specify what aspects to review (maintainer verification, install script audit, dependency tree analysis, etc.).
- **ALLOW WITH MONITORING**: May be acceptable for non-critical systems with appropriate monitoring.

Include specific review criteria and monitoring recommendations.`

	case "LOW":
		return `Your recommendation should be:
- **ALLOW**: Package is acceptable for use.
- **MONITOR**: Continue standard monitoring practices.

You may include optional suggestions for ongoing best practices but emphasize that no immediate action is required.`
	default:
		return `Your recommendation should be:
- **ALLOW**: Package is acceptable for use.
- **MONITOR**: Continue standard monitoring practices.

You may include optional suggestions for ongoing best practices but emphasize that no immediate action is required.`
	}
}

// getAttackPatternContext builds context about relevant attack patterns
func (e *Explainer) getAttackPatternContext(result models.AnalysisResult) string {
	if !e.config.IncludeAttacks {
		return "Do not include specific attack pattern comparisons unless they are highly relevant."
	}

	// Build context based on findings
	contexts := []string{}

	// Check for patterns that match known attacks
	for _, finding := range result.Findings {
		switch {
		case strings.Contains(strings.ToLower(finding.Description), "single maintainer"):
			contexts = append(contexts, "**Account Takeover Risk**: Reference the eslint-scope (2018) and ua-parser-js (2021) attacks where single-maintainer packages were compromised via account takeover.")

		case strings.Contains(strings.ToLower(finding.Description), "install script"):
			contexts = append(contexts, "**Install Script Attacks**: Reference the event-stream (2018) and flatmap-stream attacks where malicious code was executed during package installation.")

		case strings.Contains(strings.ToLower(finding.Description), "ownership") || strings.Contains(strings.ToLower(finding.Description), "transfer"):
			contexts = append(contexts, "**Ownership Transfer Attacks**: Reference pattern of abandoned package takeovers where attackers gain control and inject malicious code.")

		case strings.Contains(strings.ToLower(finding.Description), "provenance") || strings.Contains(strings.ToLower(finding.Description), "attestation"):
			contexts = append(contexts, "**Build Chain Compromise**: Reference SolarWinds (2020) and CodeCov (2021) where build infrastructure was compromised.")

		case strings.Contains(strings.ToLower(finding.Description), "dormant") || strings.Contains(strings.ToLower(finding.Description), "reactivat"):
			contexts = append(contexts, "**Dormant Package Reactivation**: Common pattern where long-abandoned packages suddenly release malicious versions.")
		}
	}

	if len(contexts) == 0 {
		return "Include attack pattern comparisons only if they provide valuable context for the identified risks."
	}

	return fmt.Sprintf("When discussing risks, you may reference these relevant attack patterns:\n\n%s\n\nOnly include if they help clarify the risk - don't force comparisons.", strings.Join(contexts, "\n\n"))
}

// extractTextContent extracts text content from Claude API response
func (e *Explainer) extractTextContent(msg *anthropic.Message) string {
	var textContent strings.Builder

	for _, block := range msg.Content {
		// ContentBlockUnion provides AsText() to safely cast to TextBlock
		if block.Type == "text" {
			textBlock := block.AsText()
			textContent.WriteString(textBlock.Text)
		}
	}

	return textContent.String()
}

// parseExecutiveResponse parses the AI response into an ExecutiveExplanation struct
func (e *Explainer) parseExecutiveResponse(response string, result models.AnalysisResult) *models.ExecutiveExplanation {
	// Try to parse structured response
	// The AI may return JSON or structured markdown

	explanation := &models.ExecutiveExplanation{
		Confidence: e.calculateConfidence(result),
	}

	// Attempt to parse as JSON first
	if err := json.Unmarshal([]byte(response), explanation); err == nil {
		return explanation
	}

	// Parse as structured text
	lines := strings.Split(response, "\n")

	var currentSection string
	var summaryLines []string
	var keyRisks []string
	var businessImpactLines []string
	var recommendationLines []string
	var technicalLines []string

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Skip empty lines
		if line == "" {
			continue
		}

		// Detect sections
		lower := strings.ToLower(line)
		if strings.Contains(lower, "executive summary") || strings.Contains(lower, "summary:") {
			currentSection = "summary"
			continue
		} else if strings.Contains(lower, "key risk") || strings.Contains(lower, "top concern") {
			currentSection = "risks"
			continue
		} else if strings.Contains(lower, "business impact") {
			currentSection = "impact"
			continue
		} else if strings.Contains(lower, "recommend") {
			currentSection = "recommendation"
			// Check if there's content after the "Recommendation:" label on the same line
			if idx := strings.Index(lower, "recommend"); idx >= 0 {
				// Find the colon after "recommend"
				colonIdx := strings.Index(line[idx:], ":")
				if colonIdx >= 0 {
					// Extract content after the colon
					content := strings.TrimSpace(line[idx+colonIdx+1:])
					if content != "" {
						recommendationLines = append(recommendationLines, content)
					}
				}
			}
			continue
		} else if strings.Contains(lower, "technical") {
			currentSection = "technical"
			continue
		}

		// Accumulate content by section
		switch currentSection {
		case "summary":
			// Skip markdown headers
			if !strings.HasPrefix(line, "#") && !strings.HasPrefix(line, "**") {
				summaryLines = append(summaryLines, line)
			}
		case "risks":
			// Extract bullet points
			if strings.HasPrefix(line, "-") || strings.HasPrefix(line, "*") || strings.HasPrefix(line, "•") {
				risk := strings.TrimPrefix(line, "-")
				risk = strings.TrimPrefix(risk, "*")
				risk = strings.TrimPrefix(risk, "•")
				risk = strings.TrimSpace(risk)
				if risk != "" {
					keyRisks = append(keyRisks, risk)
				}
			} else if len(line) > 0 && !strings.HasPrefix(line, "#") {
				// Numbered risks or plain text
				keyRisks = append(keyRisks, line)
			}
		case "impact":
			if !strings.HasPrefix(line, "#") {
				businessImpactLines = append(businessImpactLines, line)
			}
		case "recommendation":
			if !strings.HasPrefix(line, "#") {
				recommendationLines = append(recommendationLines, line)
			}
		case "technical":
			if !strings.HasPrefix(line, "#") {
				technicalLines = append(technicalLines, line)
			}
		default:
			// If no section detected yet, assume it's summary
			if currentSection == "" && !strings.HasPrefix(line, "#") {
				summaryLines = append(summaryLines, line)
			}
		}
	}

	// Assemble the explanation
	explanation.Summary = strings.Join(summaryLines, " ")
	explanation.KeyRisks = keyRisks
	explanation.BusinessImpact = strings.Join(businessImpactLines, " ")
	explanation.RecommendedAction = strings.Join(recommendationLines, " ")
	explanation.TechnicalDetails = strings.Join(technicalLines, " ")

	// Fallback: if we couldn't parse structured content, use the whole response as summary
	if explanation.Summary == "" {
		explanation.Summary = response
	}

	return explanation
}

// calculateConfidence calculates confidence score based on data availability
func (e *Explainer) calculateConfidence(result models.AnalysisResult) float64 {
	confidence := 1.0

	// Reduce confidence if we're missing key data
	if result.Metadata.RepoStars == 0 && result.Metadata.RepoForks == 0 {
		confidence -= 0.1 // No repository metrics
	}

	if len(result.Metadata.Maintainers) == 0 {
		confidence -= 0.1 // No maintainer information
	}

	if result.SupplyChainScore == nil {
		confidence -= 0.15 // Missing supply chain score
	}

	if len(result.Findings) == 0 {
		confidence -= 0.1 // No findings (unusual)
	}

	// Increase confidence if we have rich data
	if result.SupplyChainScore != nil && len(result.Findings) > 3 {
		confidence += 0.1
	}

	if result.Metadata.HasSLSAAttestation || result.Metadata.HasSigstoreSignature {
		confidence += 0.05 // Strong provenance data
	}

	// Clamp to 0.0-1.0
	if confidence < 0.0 {
		confidence = 0.0
	}
	if confidence > 1.0 {
		confidence = 1.0
	}

	return confidence
}

// GenerateQuickSummary generates a concise 2-3 sentence summary with recommendation
func (e *Explainer) GenerateQuickSummary(ctx context.Context, packageName string, result models.AnalysisResult) (string, error) {
	// Build a minimal prompt focused on brevity
	quickPrompt := fmt.Sprintf(`Package: %s
Risk Level: %s
Risk Score: %d/100

Generate a 2-3 sentence executive summary with a clear recommendation (BLOCK/REVIEW/ALLOW).

Focus on:
1. Overall risk level and top concern
2. Key evidence
3. Recommended action

Be concise and actionable. Format: [Risk assessment]. [Key evidence]. [Recommendation: BLOCK/REVIEW/ALLOW].`,
		packageName,
		result.RiskLevel,
		result.RiskScore,
	)

	params := anthropic.MessageNewParams{
		Model:       anthropic.ModelClaudeHaiku4_5, // Use Haiku for speed
		MaxTokens:   int64(300),
		Temperature: anthropic.Float(0.3), // Low temperature for concise, focused output
		System: []anthropic.TextBlockParam{
			{Text: "You are a security analyst providing concise risk assessments. Be direct and actionable."},
		},
		Messages: []anthropic.MessageParam{
			anthropic.NewUserMessage(anthropic.NewTextBlock(quickPrompt)),
		},
	}

	msg, err := e.config.Client.CreateMessage(ctx, params)
	if err != nil {
		return "", fmt.Errorf("failed to generate quick summary: %w", err)
	}

	return e.extractTextContent(msg), nil
}

// BatchExplain generates executive explanations for multiple packages
func (e *Explainer) BatchExplain(ctx context.Context, packages []string, ecosystems []models.Ecosystem, results []models.AnalysisResult) ([]*ExplainerResult, error) {
	if len(packages) != len(ecosystems) || len(packages) != len(results) {
		return nil, fmt.Errorf("mismatched input lengths: packages=%d, ecosystems=%d, results=%d", len(packages), len(ecosystems), len(results))
	}

	explainerResults := make([]*ExplainerResult, len(packages))

	// Process each package
	for i := range packages {
		result, err := e.ExplainRisk(ctx, packages[i], ecosystems[i], results[i])
		if err != nil {
			// Continue processing others, but record the error
			explainerResults[i] = &ExplainerResult{
				Error: err,
			}
			continue
		}
		explainerResults[i] = result
	}

	return explainerResults, nil
}
