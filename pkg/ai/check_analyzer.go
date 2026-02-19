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
const deepAnalysisSystemPrompt = `You are a supply chain security analyst performing deep behavioral analysis.

## Your Role

You receive the COMPLETE analysis of a package — all 10 category scores, all metadata, all findings. The rule-based engine has already scored each category individually. Your job is to find what the rules MISSED:

1. **Compound risk patterns**: Combinations of weak signals that together indicate HIGH risk
   - Example: single maintainer + 2 years dormant + sudden release + no CI = classic account takeover pattern
   - Example: ownership transfer + new install scripts + removed tests = potential malicious acquisition

2. **Behavioral anomalies in maintainer/process**:
   - Does the maintainer behavior pattern look consistent with legitimate development?
   - Are there signs of account compromise, social engineering, or hostile takeover?
   - Does the release pattern match normal software development cadence?

3. **Insights rules cannot detect**:
   - Contextual interpretation (e.g., "a 10-year-old package with 1M downloads and 1 maintainer is a bigger takeover target than a new package with 1 maintainer")
   - Ecosystem-specific norms (e.g., "no CI is unusual for packages with >1M downloads in npm")
   - Temporal correlations (e.g., "ownership changed 2 weeks before a major release")

## What You DO NOT Do

- Do NOT simply restate or paraphrase the rule-based findings
- Do NOT track CVEs or known vulnerabilities
- Do NOT recommend fixes or best practices
- Do NOT analyze code quality

## Academic Foundation

- "Backstabber's Knife Collection" (Ohm et al., 2020) — 90% of supply chain attacks target maintainer accounts
- "Small World with High Risks" (Zimmermann et al., 2019) — dependency network compromise propagation
- SLSA Framework — build integrity requirements
- OSSF Scorecard — automated security health metrics

## Output Format

Respond ONLY with valid JSON. No markdown, no code blocks, no text outside the JSON object.

{
  "risk_assessment": "1-3 sentence holistic assessment of this package's compromise likelihood",
  "compound_risks": [
    {
      "pattern": "human-readable pattern name",
      "risk_level": "HIGH|MEDIUM|LOW",
      "contributing": ["signal 1", "signal 2", "signal 3"],
      "explanation": "why this combination is concerning"
    }
  ],
  "behavior_findings": ["behavioral anomaly 1", "behavioral anomaly 2"],
  "missed_by_rules": ["insight 1 that rules cannot detect", "insight 2"],
  "confidence": 0.0
}

IMPORTANT:
- If you find NO compound risks or anomalies beyond what rules already caught, say so honestly with an empty array. Do NOT fabricate findings.
- Only report genuine cross-cutting patterns. Quality over quantity.
- confidence should reflect data quality: 0.9 if you have rich metadata, 0.5 if data is sparse.`

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

	userPrompt := fmt.Sprintf(`Perform deep behavioral analysis of this package's supply chain risk profile. All rule-based scoring is already complete — your job is to find what the rules MISSED.

%s

Identify:
1. COMPOUND risk patterns: combinations of signals that together indicate higher risk than any single signal
2. BEHAVIORAL anomalies: patterns in maintainer or process behavior that are inconsistent with legitimate development
3. CONTEXTUAL insights: things that require holistic judgment rather than individual category scoring

If there are no genuine compound risks beyond what the rules already found, say so. Do NOT fabricate findings.

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
		sb.WriteString(fmt.Sprintf("## Rule-Based Scores (Total: %d/20, Risk Level: %s)\n\n",
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

	return sb.String()
}
