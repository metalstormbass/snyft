package analyzer

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/metalstormbass/snyft/pkg/ai"
	"github.com/metalstormbass/snyft/pkg/models"
)

// enrichWithAIAnalysis enhances the analysis result with AI-powered analysis.
// This method is opt-in and only runs if the Claude API client is configured.
//
// The AI analysis flow makes 3 focused API calls per package (down from 16+):
//
//  1. Deep Analysis (Sonnet) - Single holistic call examining ALL data to find:
//     - Compound risk patterns (cross-signal combinations)
//     - Behavioral anomalies in maintainer/process
//     - Contextual insights rules cannot detect
//
//  2. Attack Pattern Matching (Sonnet) - Single batched call comparing against
//     all relevant known supply chain attacks at once.
//
//  3. Executive Summary (Sonnet) - Stakeholder-friendly explanation.
//
// All failures are graceful - AI analysis never blocks or fails the main scan.
func (a *Analyzer) enrichWithAIAnalysis(result *models.AnalysisResult) {
	if a.claudeClient == nil || !a.aiEnabled {
		return
	}

	aiResult := &models.AIAnalysisResult{
		Timestamp:         time.Now(),
		ModelVersion:      "claude-sonnet-4.5",
		OverallConfidence: 0.0,
		AttackPatterns:    []models.AttackPatternMatch{},
	}

	// Use the configured AI timeout, falling back to 120s
	timeout := a.aiTimeout
	if timeout <= 0 {
		timeout = 120 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Step 1: Deep analysis — holistic cross-cutting analysis replacing 10 per-category calls.
	// This is the primary value-add: finding compound risk patterns and behavioral anomalies
	// that rule-based scoring cannot detect.
	checkAnalyzer := ai.NewCheckAnalyzer(a.claudeClient)
	deepResult := checkAnalyzer.AnalyzeDeep(ctx, result.Dependency.Name, result.Dependency.Ecosystem, result)
	if deepResult != nil {
		aiResult.DeepAnalysis = deepResult
	} else {
		aiResult.AnalysisNotes += "Deep analysis returned no findings; "
	}

	// Step 2: Batched attack pattern matching (single API call for all relevant attacks)
	attackPatterns, err := a.runAttackPatternMatching(ctx, result)
	if err != nil {
		aiResult.AnalysisNotes += fmt.Sprintf("Attack pattern matching failed: %v; ", err)
	} else if attackPatterns != nil {
		aiResult.AttackPatterns = attackPatterns
	}

	// Step 3: Generate executive explanation
	execSummary, err := a.generateExecutiveExplanation(ctx, result)
	if err != nil {
		aiResult.AnalysisNotes += fmt.Sprintf("Executive explanation generation failed: %v; ", err)
	} else if execSummary != nil {
		aiResult.ExecutiveSummary = execSummary
	}

	// Calculate overall confidence
	confidenceCount := 0
	confidenceSum := 0.0

	if aiResult.DeepAnalysis != nil && aiResult.DeepAnalysis.Confidence > 0 {
		confidenceCount++
		confidenceSum += aiResult.DeepAnalysis.Confidence
	}

	if len(aiResult.AttackPatterns) > 0 {
		confidenceCount++
		patternConfSum := 0.0
		for _, ap := range aiResult.AttackPatterns {
			patternConfSum += ap.Confidence
		}
		confidenceSum += patternConfSum / float64(len(aiResult.AttackPatterns))
	}

	if aiResult.ExecutiveSummary != nil && aiResult.ExecutiveSummary.Confidence > 0 {
		confidenceCount++
		confidenceSum += aiResult.ExecutiveSummary.Confidence
	}

	if confidenceCount > 0 {
		aiResult.OverallConfidence = confidenceSum / float64(confidenceCount)
	}

	// Attach AI analysis result if we have any findings
	if aiResult.DeepAnalysis != nil || len(aiResult.AttackPatterns) > 0 || aiResult.ExecutiveSummary != nil || aiResult.AnalysisNotes != "" {
		result.AIAnalysis = aiResult
	}
}

// runAttackPatternMatching compares package behavior to documented supply chain attack patterns
// using a single batched API call for all relevant attacks.
func (a *Analyzer) runAttackPatternMatching(ctx context.Context, result *models.AnalysisResult) ([]models.AttackPatternMatch, error) {
	req := ai.AttackMatchRequest{
		PackageName:    result.Dependency.Name,
		Ecosystem:      result.Dependency.Ecosystem,
		AnalysisResult: *result,
	}

	matches, err := ai.MatchAgainstKnownAttacks(ctx, a.claudeClient, req)
	if err != nil {
		return nil, fmt.Errorf("attack pattern matching failed: %w", err)
	}

	return matches, nil
}

// generateExecutiveExplanation creates a stakeholder-friendly summary of the risk assessment
func (a *Analyzer) generateExecutiveExplanation(ctx context.Context, result *models.AnalysisResult) (*models.ExecutiveExplanation, error) {
	prompt := ai.NewExecutiveExplanationPrompt(
		result.Dependency.Name,
		result.Dependency.Ecosystem,
		*result,
		"technical stakeholders (developers, security engineers)",
	)

	systemPrompt, userPrompt := prompt.Render()

	params := anthropic.MessageNewParams{
		Model:       anthropic.ModelClaudeSonnet4_5,
		MaxTokens:   int64(prompt.MaxTokens),
		Temperature: anthropic.Float(float64(prompt.Temperature)),
		System: []anthropic.TextBlockParam{
			{
				Text: systemPrompt,
				Type: "text",
			},
		},
		Messages: []anthropic.MessageParam{
			anthropic.NewUserMessage(anthropic.NewTextBlock(userPrompt)),
		},
	}

	message, err := a.claudeClient.CreateMessage(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("failed to call Claude API: %w", err)
	}

	execExplanation := a.parseExecutiveExplanationResponse(message)

	return execExplanation, nil
}

// parseExecutiveExplanationResponse extracts structured executive explanation from Claude's response
func (a *Analyzer) parseExecutiveExplanationResponse(message *anthropic.Message) *models.ExecutiveExplanation {
	if len(message.Content) == 0 {
		return nil
	}

	var responseText string
	for _, block := range message.Content {
		if block.Type == "text" {
			responseText += block.Text
		}
	}

	explanation := &models.ExecutiveExplanation{
		Summary:           a.extractSection(responseText, "Executive Summary", "Business Impact"),
		BusinessImpact:    a.extractSection(responseText, "Business Impact", "Technical Explanation"),
		RecommendedAction: a.extractSection(responseText, "Recommendations", "Additional Context"),
		TechnicalDetails:  a.extractSection(responseText, "Technical Explanation", "Risk Assessment"),
		Confidence:        0.8,
		GeneratedAt:       time.Now(),
	}

	explanation.KeyRisks = a.extractKeyRisks(responseText)

	return explanation
}

// extractSection extracts text between two section headers
func (a *Analyzer) extractSection(text, startMarker, endMarker string) string {
	startIdx := strings.Index(text, startMarker)
	if startIdx == -1 {
		return ""
	}

	startIdx += len(startMarker)

	endIdx := strings.Index(text[startIdx:], endMarker)
	if endIdx == -1 {
		if len(text[startIdx:]) > 500 {
			return strings.TrimSpace(text[startIdx : startIdx+500])
		}
		return strings.TrimSpace(text[startIdx:])
	}

	section := text[startIdx : startIdx+endIdx]
	return strings.TrimSpace(section)
}

// extractKeyRisks extracts key risk points from the response text
func (a *Analyzer) extractKeyRisks(text string) []string {
	risks := []string{}

	lines := strings.Split(text, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "- ") || strings.HasPrefix(line, "* ") {
			risk := strings.TrimPrefix(line, "- ")
			risk = strings.TrimPrefix(risk, "* ")
			risks = append(risks, risk)
		} else if len(line) > 2 && line[0] >= '1' && line[0] <= '9' && line[1] == '.' {
			risk := strings.TrimSpace(line[2:])
			risks = append(risks, risk)
		}
	}

	if len(risks) > 5 {
		risks = risks[:5]
	}

	return risks
}
