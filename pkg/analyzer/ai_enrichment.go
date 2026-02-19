package analyzer

import (
	"context"
	"encoding/json"
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
// The AI analysis flow makes 3 focused API calls per package, each with its own
// independent timeout so a slow call doesn't starve subsequent calls:
//
//  1. Deep Analysis (Sonnet) - Single holistic call examining ALL data to find:
//     - Compound risk patterns (cross-signal combinations)
//     - Behavioral anomalies in maintainer/process
//     - Contextual insights rules cannot detect
//
//  2. Attack Pattern Matching (Sonnet) - Single batched call comparing against
//     all relevant known supply chain attacks at once.
//
//  3. Unified Summary (Sonnet) - Synthesizes ALL findings (rule-based + deep analysis
//     + attack patterns) into a single coherent assessment with optional score adjustment.
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

	// Resolve per-call timeout: prefer explicit config, fallback to 45s
	perCallTimeout := a.aiPerCallTimeout
	if perCallTimeout <= 0 {
		perCallTimeout = 45 * time.Second
	}

	// Step 1: Deep analysis — holistic cross-cutting analysis.
	// Each step gets its own independent timeout so a slow call doesn't starve the next.
	deepCtx, deepCancel := context.WithTimeout(context.Background(), perCallTimeout)
	defer deepCancel()

	checkAnalyzer := ai.NewCheckAnalyzer(a.claudeClient)
	deepResult := checkAnalyzer.AnalyzeDeep(deepCtx, result.Dependency.Name, result.Dependency.Ecosystem, result)
	if deepResult != nil {
		aiResult.DeepAnalysis = deepResult
	} else {
		aiResult.AnalysisNotes += "Deep analysis returned no findings; "
	}

	// Step 2: Batched attack pattern matching (independent timeout)
	attackCtx, attackCancel := context.WithTimeout(context.Background(), perCallTimeout)
	defer attackCancel()

	attackPatterns, err := a.runAttackPatternMatching(attackCtx, result)
	if err != nil {
		aiResult.AnalysisNotes += fmt.Sprintf("Attack pattern matching failed: %v; ", err)
	} else if attackPatterns != nil {
		aiResult.AttackPatterns = attackPatterns
	}

	// Step 3: Unified summary — sees ALL prior findings and can adjust score
	summaryCtx, summaryCancel := context.WithTimeout(context.Background(), perCallTimeout)
	defer summaryCancel()

	unifiedSummary := a.generateUnifiedSummary(summaryCtx, result, aiResult.DeepAnalysis, aiResult.AttackPatterns)
	if unifiedSummary != nil {
		aiResult.UnifiedSummary = unifiedSummary

		// Populate backward-compatible ExecutiveSummary from unified summary
		aiResult.ExecutiveSummary = &models.ExecutiveExplanation{
			Summary:          unifiedSummary.Summary,
			KeyRisks:         unifiedSummary.KeyRisks,
			BusinessImpact:   unifiedSummary.BusinessImpact,
			TechnicalDetails: unifiedSummary.TechnicalDetails,
			Confidence:       unifiedSummary.Confidence,
			GeneratedAt:      unifiedSummary.GeneratedAt,
		}

		// Apply AI score adjustment if confidence is high enough
		a.applyAIScoreAdjustment(result, unifiedSummary)
	} else {
		aiResult.AnalysisNotes += "Unified summary generation failed; "
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

	if aiResult.UnifiedSummary != nil && aiResult.UnifiedSummary.Confidence > 0 {
		confidenceCount++
		confidenceSum += aiResult.UnifiedSummary.Confidence
	}

	if confidenceCount > 0 {
		aiResult.OverallConfidence = confidenceSum / float64(confidenceCount)
	}

	// Attach AI analysis result if we have any findings
	if aiResult.DeepAnalysis != nil || len(aiResult.AttackPatterns) > 0 || aiResult.UnifiedSummary != nil || aiResult.AnalysisNotes != "" {
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

// unifiedSummaryResponse is the JSON structure expected from Claude for the unified review
type unifiedSummaryResponse struct {
	Summary          string   `json:"summary"`
	KeyRisks         []string `json:"key_risks"`
	BusinessImpact   string   `json:"business_impact"`
	TechnicalDetails string   `json:"technical_details"`
	Confidence       float64  `json:"confidence"`
	ScoreAdjustment  int      `json:"score_adjustment"`
	AdjustmentReason string   `json:"adjustment_reason"`
}

// generateUnifiedSummary creates a unified review that sees ALL prior findings
// (rule-based scores + deep analysis + attack patterns) and produces a single
// coherent assessment with an optional score adjustment (-2 to +2).
func (a *Analyzer) generateUnifiedSummary(ctx context.Context, result *models.AnalysisResult, deepAnalysis *models.DeepAnalysisResult, attackPatterns []models.AttackPatternMatch) *models.UnifiedAISummary {
	prompt := ai.NewUnifiedReviewPrompt(result, deepAnalysis, attackPatterns)
	systemPrompt, userPrompt := prompt.Render()

	params := anthropic.MessageNewParams{
		Model:     anthropic.ModelClaudeSonnet4_5,
		MaxTokens: int64(prompt.MaxTokens),
		System: []anthropic.TextBlockParam{
			{Text: systemPrompt},
		},
		Messages: []anthropic.MessageParam{
			anthropic.NewUserMessage(anthropic.NewTextBlock(userPrompt)),
		},
		Temperature: anthropic.Float(prompt.Temperature),
	}

	message, err := a.claudeClient.CreateMessage(ctx, params)
	if err != nil {
		return nil
	}

	// Extract text content
	var responseText string
	for _, block := range message.Content {
		if block.Type == "text" {
			responseText += block.Text
		}
	}

	if responseText == "" {
		return nil
	}

	// Clean potential markdown wrapping
	responseText = strings.TrimSpace(responseText)
	responseText = strings.TrimPrefix(responseText, "```json")
	responseText = strings.TrimPrefix(responseText, "```")
	responseText = strings.TrimSuffix(responseText, "```")
	responseText = strings.TrimSpace(responseText)

	var resp unifiedSummaryResponse
	if err := json.Unmarshal([]byte(responseText), &resp); err != nil {
		return nil
	}

	// Clamp score adjustment to [-2, +2]
	adj := resp.ScoreAdjustment
	if adj < -2 {
		adj = -2
	}
	if adj > 2 {
		adj = 2
	}

	return &models.UnifiedAISummary{
		Summary:          resp.Summary,
		KeyRisks:         resp.KeyRisks,
		BusinessImpact:   resp.BusinessImpact,
		TechnicalDetails: resp.TechnicalDetails,
		Confidence:       resp.Confidence,
		ScoreAdjustment:  adj,
		AdjustmentReason: resp.AdjustmentReason,
		GeneratedAt:      time.Now(),
	}
}

// applyAIScoreAdjustment modifies the supply chain score based on AI analysis.
// Only applies if confidence >= 0.7 and adjustment is non-zero.
// Updates TotalScore (clamped to 0-22), re-derives RiskLevel, and updates legacy RiskScore.
func (a *Analyzer) applyAIScoreAdjustment(result *models.AnalysisResult, summary *models.UnifiedAISummary) {
	if result.SupplyChainScore == nil || summary == nil {
		return
	}

	if summary.ScoreAdjustment == 0 || summary.Confidence < 0.7 {
		return
	}

	adj := summary.ScoreAdjustment
	result.SupplyChainScore.AIAdjustment = adj
	result.SupplyChainScore.AIAdjustmentReason = summary.AdjustmentReason

	// Apply adjustment to total score
	newTotal := result.SupplyChainScore.TotalScore + adj
	if newTotal < 0 {
		newTotal = 0
	}
	if newTotal > 22 {
		newTotal = 22
	}
	result.SupplyChainScore.TotalScore = newTotal

	// Re-derive risk level from adjusted score
	if newTotal >= 14 {
		result.SupplyChainScore.RiskLevel = "HIGH"
	} else if newTotal >= 10 {
		result.SupplyChainScore.RiskLevel = "MEDIUM"
	} else {
		result.SupplyChainScore.RiskLevel = "LOW"
	}

	// Update legacy fields
	result.RiskLevel = result.SupplyChainScore.RiskLevel
	result.RiskScore = result.SupplyChainScore.TotalScore * 100 / 22
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
