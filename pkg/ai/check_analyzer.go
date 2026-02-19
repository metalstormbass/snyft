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

// deepAnalysisSystemPrompt focuses on what rules CANNOT do: cross-cutting pattern
// recognition, behavioral anomaly detection, and compound risk identification.
// The AI receives ALL data at once to find holistic insights the per-category
// rule-based engine misses by design.
const deepAnalysisSystemPrompt = `You are a supply chain security analyst reviewing the results of an automated scan.

## Your Role

You receive the COMPLETE analysis of a package — all 11 category scores, all metadata, all findings. The rule-based engine has already scored each category individually. Your job is to:

1. **Identify compound patterns from ACTUAL findings**: When multiple rule-based findings occur together, note whether they form a known attack pattern
   - Example: IF single maintainer AND 2+ years dormant AND sudden release were ALL actually found, note this matches the account takeover pattern from Ohm et al. (2020)
   - ONLY cite patterns where ALL contributing signals were actually detected — never infer missing data

2. **Note factual observations about the data**:
   - Summarize what was actually found, not what might happen
   - If data is missing or unavailable, say so — do not treat missing data as a risk signal

3. **Provide contextual interpretation of actual findings**:
   - Example: "This package has 1M weekly downloads and a single maintainer" — factual observation from data
   - Example: "No CI was detected despite 50+ contributors" — factual observation about data inconsistency

## Critical Rules

- ONLY reference data that is actually present in the findings below
- NEVER speculate about risks not supported by the data (no "could", "might", "potentially")
- If a data point was not checked or is unavailable, say "not assessed" — do NOT assume worst case
- Do NOT infer intent — only describe what the data shows
- Do NOT simply restate or paraphrase the rule-based findings
- Do NOT track CVEs or known vulnerabilities
- Do NOT recommend fixes or best practices

## Output Format

Respond ONLY with valid JSON. No markdown, no code blocks, no text outside the JSON object.

{
  "risk_assessment": "1-3 sentence factual summary of what the scan found",
  "compound_risks": [
    {
      "pattern": "human-readable pattern name",
      "risk_level": "HIGH|MEDIUM|LOW",
      "contributing": ["signal 1 (actually found)", "signal 2 (actually found)"],
      "explanation": "why these co-occurring findings match a documented pattern"
    }
  ],
  "behavior_findings": ["factual observation about the data"],
  "missed_by_rules": ["cross-cutting factual observation rules scored separately"],
  "confidence": 0.0
}

IMPORTANT:
- If you find NO compound patterns beyond what rules already caught, return empty arrays. Do NOT fabricate findings.
- Every entry in compound_risks MUST reference only signals that were actually detected in the data.
- confidence should reflect data completeness: 0.9 if metadata is comprehensive, 0.5 if many fields are missing.`

// deepAnalysisResponse is the JSON structure expected from Claude for deep analysis
type deepAnalysisResponse struct {
	RiskAssessment   string `json:"risk_assessment"`
	CompoundRisks    []struct {
		Pattern      string   `json:"pattern"`
		RiskLevel    string   `json:"risk_level"`
		Contributing []string `json:"contributing"`
		Explanation  string   `json:"explanation"`
	} `json:"compound_risks"`
	BehaviorFindings []string `json:"behavior_findings"`
	MissedByRules    []string `json:"missed_by_rules"`
	Confidence       float64  `json:"confidence"`
}

// CheckAnalyzer performs AI-powered deep analysis to augment rule-based scoring.
// Instead of re-analyzing each category individually, it performs a single holistic
// analysis that identifies cross-cutting patterns and behavioral anomalies.
type CheckAnalyzer struct {
	client *Client
}

// NewCheckAnalyzer creates a new check analyzer
func NewCheckAnalyzer(client *Client) *CheckAnalyzer {
	return &CheckAnalyzer{client: client}
}

// AnalyzeDeep performs a single consolidated AI analysis that examines ALL signals
// together to find cross-cutting risk patterns and behavioral anomalies that
// per-category rule-based scoring cannot detect.
//
// This replaces the previous AnalyzeAllCategories approach (10 separate per-category
// API calls) with a single call that provides genuinely new insights.
//
// Returns nil on error (graceful degradation).
func (ca *CheckAnalyzer) AnalyzeDeep(ctx context.Context, packageName string, ecosystem models.Ecosystem, result *models.AnalysisResult) *models.DeepAnalysisResult {
	if result.SupplyChainScore == nil {
		return nil
	}

	// Build the complete context: all categories, all metadata, all findings
	fullContext := ca.buildFullContext(packageName, ecosystem, result)

	userPrompt := fmt.Sprintf(`Review the following complete scan results and identify any cross-cutting patterns from the ACTUAL findings.

%s

Based ONLY on the data above:
1. COMPOUND patterns: Do any of the actual findings co-occur in ways that match documented supply chain attack patterns?
2. DATA observations: What factual observations can be made from the combination of findings?
3. CROSS-CUTTING insights: Do any findings from different categories interact meaningfully?

If the rule-based findings already captured everything relevant, return empty arrays. Do NOT invent findings not supported by the data above.

Respond ONLY with valid JSON (no markdown, no code blocks).`, fullContext)

	params := anthropic.MessageNewParams{
		Model:     anthropic.ModelClaudeSonnet4_5,
		MaxTokens: 1500,
		System: []anthropic.TextBlockParam{
			{Text: deepAnalysisSystemPrompt},
		},
		Messages: []anthropic.MessageParam{
			anthropic.NewUserMessage(anthropic.NewTextBlock(userPrompt)),
		},
		Temperature: anthropic.Float(0.3),
	}

	msg, err := ca.client.CreateMessage(ctx, params)
	if err != nil {
		return nil
	}

	// Extract text content
	var responseText string
	for _, block := range msg.Content {
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

	var resp deepAnalysisResponse
	if err := json.Unmarshal([]byte(responseText), &resp); err != nil {
		return nil
	}

	// Convert to model types
	compoundRisks := make([]models.CompoundRisk, 0, len(resp.CompoundRisks))
	for _, cr := range resp.CompoundRisks {
		compoundRisks = append(compoundRisks, models.CompoundRisk{
			Pattern:      cr.Pattern,
			RiskLevel:    cr.RiskLevel,
			Contributing: cr.Contributing,
			Explanation:  cr.Explanation,
		})
	}

	return &models.DeepAnalysisResult{
		RiskAssessment:   resp.RiskAssessment,
		CompoundRisks:    compoundRisks,
		BehaviorFindings: resp.BehaviorFindings,
		MissedByRules:    resp.MissedByRules,
		Confidence:       resp.Confidence,
	}
}

// AnalyzeAllCategories is kept for backward compatibility but now delegates to AnalyzeDeep.
// The deep analysis result is stored on AIAnalysisResult.DeepAnalysis rather than on
// individual CategoryScore.AIInsight fields.
func (ca *CheckAnalyzer) AnalyzeAllCategories(ctx context.Context, packageName string, ecosystem models.Ecosystem, result *models.AnalysisResult) {
	// No-op: deep analysis is called directly from ai_enrichment.go now
}

// buildFullContext creates a comprehensive context dump of ALL data for the package,
// giving the AI everything it needs for holistic cross-cutting analysis.
func (ca *CheckAnalyzer) buildFullContext(packageName string, ecosystem models.Ecosystem, result *models.AnalysisResult) string {
	var sb strings.Builder

	// Package identity
	sb.WriteString(fmt.Sprintf("## Package: %s (ecosystem: %s)\n\n", packageName, ecosystem))

	// Rule-based scores overview
	if result.SupplyChainScore != nil {
		cs := result.SupplyChainScore.CategoryScores
		sb.WriteString(fmt.Sprintf("## Rule-Based Scores (Total: %d/22, Risk Level: %s)\n\n",
			result.SupplyChainScore.TotalScore, result.SupplyChainScore.RiskLevel))

		categories := []struct {
			name  string
			score models.CategoryScore
		}{
			{"Publisher Control", cs.PublisherControl},
			{"Ownership Changes", cs.OwnershipChanges},
			{"Release Anomalies", cs.ReleaseAnomalies},
			{"Install Execution", cs.InstallExecution},
			{"Dependency Sprawl", cs.DependencySprawl},
			{"Provenance", cs.Provenance},
			{"Health", cs.Health},
			{"Governance", cs.Governance},
			{"Release Security", cs.ReleaseSecurity},
			{"Package Maturity", cs.PackageMaturity},
			{"CI Pipeline Security", cs.CIPipelineSecurity},
		}

		for _, cat := range categories {
			sb.WriteString(fmt.Sprintf("- %s: %d/2 risk points — %s\n", cat.name, cat.score.RiskPoints, cat.score.Description))
			if cat.score.Evidence != "" {
				sb.WriteString(fmt.Sprintf("  Evidence: %s\n", cat.score.Evidence))
			}
		}
		sb.WriteString("\n")
	}

	// Risk factors
	if len(result.RiskFactors) > 0 {
		sb.WriteString("## Identified Risk Factors\n\n")
		for _, rf := range result.RiskFactors {
			sb.WriteString(fmt.Sprintf("- %s\n", rf))
		}
		sb.WriteString("\n")
	}

	// High-severity findings
	highFindings := 0
	for _, f := range result.Findings {
		if f.Severity == "HIGH" || f.Severity == "CRITICAL" {
			highFindings++
		}
	}
	if highFindings > 0 {
		sb.WriteString("## High-Severity Findings\n\n")
		for _, f := range result.Findings {
			if f.Severity == "HIGH" || f.Severity == "CRITICAL" {
				sb.WriteString(fmt.Sprintf("- [%s] %s: %s\n", f.Severity, f.Category, f.Description))
				if f.Evidence != "" {
					sb.WriteString(fmt.Sprintf("  Evidence: %s\n", f.Evidence))
				}
			}
		}
		sb.WriteString("\n")
	}

	// Metadata context — the raw signals for behavioral analysis
	m := result.Metadata
	sb.WriteString("## Package Metadata (Raw Signals)\n\n")

	// Maintainer info
	sb.WriteString(fmt.Sprintf("Maintainer count: %d\n", len(m.Maintainers)))
	if len(m.Maintainers) > 0 {
		sb.WriteString(fmt.Sprintf("Maintainers: %s\n", strings.Join(m.Maintainers, ", ")))
	}

	// Popularity (attack target value)
	if m.DownloadCount > 0 {
		sb.WriteString(fmt.Sprintf("Downloads: %d\n", m.DownloadCount))
	}
	if m.RepoStars > 0 {
		sb.WriteString(fmt.Sprintf("Stars: %d, Forks: %d, Open Issues: %d\n", m.RepoStars, m.RepoForks, m.RepoOpenIssues))
	}

	// Timeline
	if !m.PublishedAt.IsZero() {
		age := time.Since(m.PublishedAt)
		sb.WriteString(fmt.Sprintf("First published: %s (%.0f days ago)\n", m.PublishedAt.Format("2006-01-02"), age.Hours()/24))
	}
	if !m.RepoCreatedAt.IsZero() {
		sb.WriteString(fmt.Sprintf("Repository created: %s\n", m.RepoCreatedAt.Format("2006-01-02")))
	}
	if !m.RepoLastCommit.IsZero() {
		staleness := time.Since(m.RepoLastCommit)
		sb.WriteString(fmt.Sprintf("Last commit: %s (%.0f days ago)\n", m.RepoLastCommit.Format("2006-01-02"), staleness.Hours()/24))
	}
	if m.LatestVersion != "" {
		sb.WriteString(fmt.Sprintf("Latest version: %s\n", m.LatestVersion))
	}

	// Development health
	if m.BusFactor > 0 {
		sb.WriteString(fmt.Sprintf("Bus factor: %d\n", m.BusFactor))
	}
	if m.TopContributorPct > 0 {
		sb.WriteString(fmt.Sprintf("Top contributor: %.0f%% of commits\n", m.TopContributorPct))
	}
	sb.WriteString(fmt.Sprintf("Code review rate: %.0f%%\n", m.CodeReviewRate))
	sb.WriteString(fmt.Sprintf("Branch protection: %v\n", m.HasBranchProtection))
	sb.WriteString(fmt.Sprintf("Required reviewers: %d\n", m.RequiredReviewers))

	// Build infrastructure
	sb.WriteString(fmt.Sprintf("Has CI: %v\n", m.HasCI))
	if len(m.CISystems) > 0 {
		sb.WriteString(fmt.Sprintf("CI systems: %s\n", strings.Join(m.CISystems, ", ")))
	}
	sb.WriteString(fmt.Sprintf("Has self-hosted runners: %v\n", m.HasSelfHosted))
	sb.WriteString(fmt.Sprintf("Automated release process: %v\n", m.HasReleaseProcess))

	// Provenance
	sb.WriteString(fmt.Sprintf("Signed releases: %v\n", m.SignedReleases))
	sb.WriteString(fmt.Sprintf("SLSA attestation: %v\n", m.HasSLSAAttestation))
	sb.WriteString(fmt.Sprintf("Sigstore signature: %v\n", m.HasSigstoreSignature))
	if ecosystem == models.EcosystemNPM {
		sb.WriteString(fmt.Sprintf("npm provenance: %v\n", m.HasNPMProvenance))
	}

	// Source verification
	sb.WriteString(fmt.Sprintf("Source code available: %v\n", result.SourceCodeAvailable))
	if result.SourceVerification != nil {
		sb.WriteString(fmt.Sprintf("Matching git tag: %v\n", result.SourceVerification.HasMatchingGitTag))
		sb.WriteString(fmt.Sprintf("Source package: %v\n", result.SourceVerification.HasSourcePackage))
	}

	// Install scripts
	sb.WriteString(fmt.Sprintf("Has install scripts: %v\n", m.HasInstallScripts))
	if len(m.InstallScripts) > 0 {
		sb.WriteString("Install script contents:\n")
		for scriptType, content := range m.InstallScripts {
			sb.WriteString(fmt.Sprintf("  [%s]: %s\n", scriptType, content))
		}
	}

	// Repository status
	sb.WriteString(fmt.Sprintf("Repository archived: %v\n", m.RepoArchived))

	// OSSF Score
	if m.OSSFScore > 0 {
		sb.WriteString(fmt.Sprintf("OSSF Scorecard: %.1f/10\n", m.OSSFScore))
	}

	// Dependency metrics
	if m.DependencyMetrics != nil {
		sb.WriteString(fmt.Sprintf("Direct dependencies: %d\n", m.DependencyMetrics.DirectCount))
		sb.WriteString(fmt.Sprintf("Transitive dependencies: %d\n", m.DependencyMetrics.TransitiveCount))
	}

	// Libraries.io enrichment data (blast radius indicators)
	if m.DependentsCount > 0 || m.DependentReposCount > 0 {
		sb.WriteString("\n## Blast Radius (Libraries.io)\n\n")
		sb.WriteString(fmt.Sprintf("Dependents (packages): %d\n", m.DependentsCount))
		sb.WriteString(fmt.Sprintf("Dependent repos: %d\n", m.DependentReposCount))
		if m.ContributionsCount > 0 {
			sb.WriteString(fmt.Sprintf("Contributions: %d\n", m.ContributionsCount))
		}
	}

	return sb.String()
}
