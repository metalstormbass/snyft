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

// enrichWithAIAnalysis enhances the analysis result with AI-powered semantic analysis.
// This method is opt-in and only runs if the Claude API client is configured.
//
// Methodology:
//  1. Per-Category Analysis - Runs AI analysis for each of the 10 scoring categories,
//     providing deeper contextual analysis beyond the rule-based checks. Results are
//     stored as CategoryScore.AIInsight on each category score.
//  2. Attack Pattern Matching - Compares observed behaviors to documented supply chain
//     attack patterns (event-stream, ua-parser-js, coa, node-ipc, eslint-scope, etc.)
//  3. Executive Summary - Generates a stakeholder-friendly explanation of the overall
//     risk assessment.
//
// The per-category analysis runs all 10 categories in parallel using Claude Haiku for
// speed and cost efficiency. The attack matching and executive summary use Claude Sonnet
// for higher quality cross-cutting analysis.
//
// Justification: AI analysis provides contextual understanding of risk patterns that
// static rules may miss - semantic interpretation of install scripts, contextual
// assessment of ownership patterns, intelligent interpretation of anomalies.
//
// All failures are graceful - AI analysis never blocks or fails the main scan.
func (a *Analyzer) enrichWithAIAnalysis(result *models.AnalysisResult) {
	// Check if AI analysis is enabled (client initialized and not explicitly disabled)
	if a.claudeClient == nil || !a.aiEnabled {
		return
	}

	// Initialize AI analysis result
	aiResult := &models.AIAnalysisResult{
		Timestamp:         time.Now(),
		ModelVersion:      "claude-sonnet-4.5",
		OverallConfidence: 0.0,
		AttackPatterns:    []models.AttackPatternMatch{},
	}

	// Extended timeout for AI operations: 10 parallel category analyses + attack matching + exec summary
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	// Step 1: Run per-category AI analysis in parallel.
	// This augments each CategoryScore with an AIInsight containing deeper contextual analysis.
	// Results are written directly into result.SupplyChainScore.CategoryScores.*.AIInsight.
	// Failures are graceful - a failed category analysis leaves AIInsight as nil.
	checkAnalyzer := ai.NewCheckAnalyzer(a.claudeClient)
	checkAnalyzer.AnalyzeAllCategories(ctx, result.Dependency.Name, result.Dependency.Ecosystem, result)

	// Step 2: Run attack pattern matching (cross-cutting analysis)
	attackPatterns, err := a.runAttackPatternMatching(ctx, result)
	if err != nil {
		// Log error but continue - don't fail the scan
		aiResult.AnalysisNotes += fmt.Sprintf("Attack pattern matching failed: %v; ", err)
	} else if attackPatterns != nil {
		aiResult.AttackPatterns = attackPatterns
	}

	// Step 3: Generate executive explanation (cross-cutting summary)
	execSummary, err := a.generateExecutiveExplanation(ctx, result)
	if err != nil {
		// Log error but continue
		aiResult.AnalysisNotes += fmt.Sprintf("Executive explanation generation failed: %v; ", err)
	} else if execSummary != nil {
		aiResult.ExecutiveSummary = execSummary
	}

	// Calculate overall confidence based on successful cross-cutting analyses
	confidenceCount := 0
	confidenceSum := 0.0

	if len(aiResult.AttackPatterns) > 0 {
		confidenceCount++
		// Average confidence from attack patterns
		for _, ap := range aiResult.AttackPatterns {
			confidenceSum += ap.Confidence
		}
		confidenceSum /= float64(len(aiResult.AttackPatterns))
	}

	if aiResult.ExecutiveSummary != nil && aiResult.ExecutiveSummary.Confidence > 0 {
		confidenceCount++
		confidenceSum += aiResult.ExecutiveSummary.Confidence
	}

	if confidenceCount > 0 {
		aiResult.OverallConfidence = confidenceSum / float64(confidenceCount)
	}

	// Attach AI analysis result if we have cross-cutting findings.
	// Note: per-category insights are stored on CategoryScore.AIInsight directly,
	// not on AIAnalysisResult - they belong with their respective category scores.
	if len(aiResult.AttackPatterns) > 0 || aiResult.ExecutiveSummary != nil || aiResult.AnalysisNotes != "" {
		result.AIAnalysis = aiResult
	}
}

// runAttackPatternMatching compares package behavior to documented supply chain attack patterns
// using the canonical ai.MatchAgainstKnownAttacks implementation that compares against a
// structured database of historical attacks with proper JSON parsing.
// Returns nil on error or if no patterns match.
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
// Returns nil on error
func (a *Analyzer) generateExecutiveExplanation(ctx context.Context, result *models.AnalysisResult) (*models.ExecutiveExplanation, error) {
	// Generate executive explanation prompt
	// Target audience: technical stakeholders (developers, security engineers)
	prompt := ai.NewExecutiveExplanationPrompt(
		result.Dependency.Name,
		result.Dependency.Ecosystem,
		*result,
		"technical stakeholders (developers, security engineers)",
	)

	systemPrompt, userPrompt := prompt.Render()

	// Create message parameters
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

	// Call Claude API
	message, err := a.claudeClient.CreateMessage(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("failed to call Claude API: %w", err)
	}

	// Parse response to extract executive explanation
	execExplanation := a.parseExecutiveExplanationResponse(message)

	return execExplanation, nil
}

// parseExecutiveExplanationResponse extracts structured executive explanation from Claude's response
func (a *Analyzer) parseExecutiveExplanationResponse(message *anthropic.Message) *models.ExecutiveExplanation {
	if len(message.Content) == 0 {
		return nil
	}

	// Extract text content
	var responseText string
	for _, block := range message.Content {
		if block.Type == "text" {
			responseText += block.Text
		}
	}

	// Parse the response to extract structured sections
	// This is a simplified parser
	explanation := &models.ExecutiveExplanation{
		Summary:           a.extractSection(responseText, "Executive Summary", "Business Impact"),
		BusinessImpact:    a.extractSection(responseText, "Business Impact", "Technical Explanation"),
		RecommendedAction: a.extractSection(responseText, "Recommendations", "Additional Context"),
		TechnicalDetails:  a.extractSection(responseText, "Technical Explanation", "Risk Assessment"),
		Confidence:        0.8, // Default confidence
		GeneratedAt:       time.Now(),
	}

	// Extract key risks (look for bullet points or numbered lists)
	explanation.KeyRisks = a.extractKeyRisks(responseText)

	return explanation
}

// extractSection extracts text between two section headers
func (a *Analyzer) extractSection(text, startMarker, endMarker string) string {
	startIdx := strings.Index(text, startMarker)
	if startIdx == -1 {
		return ""
	}

	// Start after the marker
	startIdx += len(startMarker)

	// Find the end marker
	endIdx := strings.Index(text[startIdx:], endMarker)
	if endIdx == -1 {
		// If no end marker, take the rest or limit to 500 chars
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

	// Look for lines starting with bullet points or numbers
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

	// Limit to top 5 risks
	if len(risks) > 5 {
		risks = risks[:5]
	}

	return risks
}

