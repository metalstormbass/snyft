package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/metalstormbass/snyft/pkg/models"
)

// checkAnalyzerSystemPrompt provides the foundational context for per-category AI analysis.
// The AI augments rule-based scoring with deeper contextual analysis - it does NOT replace it.
const checkAnalyzerSystemPrompt = `You are a supply chain security expert augmenting rule-based risk scoring with deeper contextual analysis.

## Your Role

You receive a rule-based risk score for a specific supply chain security category and the raw data that produced it. Your job is to:

1. **Validate or challenge** the rule-based assessment with additional context
2. **Identify patterns** the rules may have missed or underweighted
3. **Add context** about whether signals are typical or anomalous for this type of package
4. **Amplify or mitigate** risk based on correlated signals
5. **Provide a specific recommendation** for this exact category

## What You Assess

Supply chain compromise risk factors only:
- Maintainer account security and control concentration
- Suspicious behavioral patterns (dormancy, reactivation, anomalous activity)
- Build and release integrity weaknesses
- Community health and governance gaps
- Install-time code execution risks
- Dependency attack surface

## What You DO NOT Do

❌ Track known CVEs or security advisories
❌ Scan for code vulnerabilities (SQL injection, XSS, etc.)
❌ Analyze code quality or correctness
❌ Reference CVE databases

## Academic Foundation

Your analysis is grounded in:
- "Backstabber's Knife Collection" (Ohm et al., 2020) - OSS supply chain attack patterns
- "Small World with High Risks" (Zimmermann et al., 2019) - npm dependency network analysis
- SLSA Framework - Build integrity and provenance
- OSSF Scorecard - Automated security health metrics

## Output Format

Respond ONLY with valid JSON. No markdown, no code blocks, no text outside the JSON object.

{
  "ai_risk_level": "HIGH|MEDIUM|LOW",
  "confidence": 0.0,
  "findings": ["specific finding 1", "specific finding 2"],
  "context": "contextual analysis explaining amplifying or mitigating factors",
  "recommendation": "specific actionable recommendation for this category"
}`

// categoryAIResponse is the JSON structure expected from Claude for per-category analysis
type categoryAIResponse struct {
	AIRiskLevel    string   `json:"ai_risk_level"`
	Confidence     float64  `json:"confidence"`
	Findings       []string `json:"findings"`
	Context        string   `json:"context"`
	Recommendation string   `json:"recommendation"`
}

// CheckAnalyzer performs AI-powered per-category deeper analysis to augment rule-based scoring.
// Each of the 10 supply chain scoring categories gets its own contextual AI analysis.
type CheckAnalyzer struct {
	client *Client
}

// NewCheckAnalyzer creates a new per-category check analyzer
func NewCheckAnalyzer(client *Client) *CheckAnalyzer {
	return &CheckAnalyzer{client: client}
}

// AnalyzeAllCategories runs AI analysis for all 10 scoring categories in parallel.
// Results are written directly into the CategoryScore.AIInsight fields on the result.
// All failures are graceful - AI analysis never blocks or fails the main scan.
//
// Categories analyzed:
//  1. Publisher Control - maintainer account takeover risk
//  2. Ownership Changes - suspicious transfer patterns
//  3. Release Anomalies - dormancy/reactivation patterns
//  4. Install Execution - semantic analysis of install scripts
//  5. Dependency Sprawl - attack surface assessment
//  6. Provenance - build integrity gaps
//  7. Health - community health and concentration risk
//  8. Governance - accountability and maintenance patterns
//  9. Release Security - CI/CD integrity assessment
//  10. Package Maturity - lifecycle risk assessment
func (ca *CheckAnalyzer) AnalyzeAllCategories(ctx context.Context, packageName string, ecosystem models.Ecosystem, result *models.AnalysisResult) {
	if result.SupplyChainScore == nil {
		return
	}

	cs := &result.SupplyChainScore.CategoryScores

	type task struct {
		name    string
		context string
		score   models.CategoryScore
		set     func(*models.CategoryAIInsight)
	}

	tasks := []task{
		{
			name:    "Publisher Control",
			context: ca.buildPublisherControlContext(packageName, ecosystem, result),
			score:   cs.PublisherControl,
			set:     func(i *models.CategoryAIInsight) { cs.PublisherControl.AIInsight = i },
		},
		{
			name:    "Ownership Changes",
			context: ca.buildOwnershipChangesContext(packageName, ecosystem, result),
			score:   cs.OwnershipChanges,
			set:     func(i *models.CategoryAIInsight) { cs.OwnershipChanges.AIInsight = i },
		},
		{
			name:    "Release Anomalies",
			context: ca.buildReleaseAnomaliesContext(packageName, ecosystem, result),
			score:   cs.ReleaseAnomalies,
			set:     func(i *models.CategoryAIInsight) { cs.ReleaseAnomalies.AIInsight = i },
		},
		{
			name:    "Install Execution",
			context: ca.buildInstallExecutionContext(packageName, ecosystem, result),
			score:   cs.InstallExecution,
			set:     func(i *models.CategoryAIInsight) { cs.InstallExecution.AIInsight = i },
		},
		{
			name:    "Dependency Sprawl",
			context: ca.buildDependencySprawlContext(packageName, ecosystem, result),
			score:   cs.DependencySprawl,
			set:     func(i *models.CategoryAIInsight) { cs.DependencySprawl.AIInsight = i },
		},
		{
			name:    "Provenance",
			context: ca.buildProvenanceContext(packageName, ecosystem, result),
			score:   cs.Provenance,
			set:     func(i *models.CategoryAIInsight) { cs.Provenance.AIInsight = i },
		},
		{
			name:    "Health",
			context: ca.buildHealthContext(packageName, ecosystem, result),
			score:   cs.Health,
			set:     func(i *models.CategoryAIInsight) { cs.Health.AIInsight = i },
		},
		{
			name:    "Governance",
			context: ca.buildGovernanceContext(packageName, ecosystem, result),
			score:   cs.Governance,
			set:     func(i *models.CategoryAIInsight) { cs.Governance.AIInsight = i },
		},
		{
			name:    "Release Security",
			context: ca.buildReleaseSecurityContext(packageName, ecosystem, result),
			score:   cs.ReleaseSecurity,
			set:     func(i *models.CategoryAIInsight) { cs.ReleaseSecurity.AIInsight = i },
		},
		{
			name:    "Package Maturity",
			context: ca.buildPackageMaturityContext(packageName, ecosystem, result),
			score:   cs.PackageMaturity,
			set:     func(i *models.CategoryAIInsight) { cs.PackageMaturity.AIInsight = i },
		},
	}

	var wg sync.WaitGroup
	var mu sync.Mutex

	for _, t := range tasks {
		wg.Add(1)
		go func(t task) {
			defer wg.Done()
			insight, err := ca.analyzeSingleCategory(ctx, t.name, t.score, t.context)
			if err != nil {
				// Graceful degradation - a failed AI analysis does not affect rule-based scores
				return
			}
			mu.Lock()
			t.set(insight)
			mu.Unlock()
		}(t)
	}

	wg.Wait()
}

// analyzeSingleCategory calls Claude to analyze a single scoring category.
// It receives the rule-based score and category-specific context, and returns
// a CategoryAIInsight with deeper analysis.
//
// Uses Haiku for speed and cost efficiency - these are focused JSON responses
// with well-structured input, not requiring the full Sonnet capability.
func (ca *CheckAnalyzer) analyzeSingleCategory(ctx context.Context, categoryName string, score models.CategoryScore, categoryContext string) (*models.CategoryAIInsight, error) {
	userPrompt := fmt.Sprintf(`Analyze the following supply chain security category for deeper risk insights that augment the rule-based scoring.

Category: %s
Rule-based Risk Points: %d/2 (0=low risk, 2=high risk)
Rule-based Description: %s
Rule-based Evidence: %s
Data Verified: %v

Package-Specific Context:
%s

Identify:
1. Patterns the rule-based check may have missed or underweighted
2. Contextual factors that amplify or mitigate the measured risk
3. Whether the risk signals are typical or anomalous for this type of package
4. A specific, actionable recommendation for this category

Respond ONLY with valid JSON (no markdown, no code blocks):
{
  "ai_risk_level": "HIGH|MEDIUM|LOW",
  "confidence": 0.0,
  "findings": ["specific finding 1", "specific finding 2"],
  "context": "contextual analysis of amplifying/mitigating factors",
  "recommendation": "specific actionable recommendation for this category"
}`,
		categoryName,
		score.RiskPoints,
		score.Description,
		score.Evidence,
		score.Verified,
		categoryContext,
	)

	params := anthropic.MessageNewParams{
		Model:     anthropic.ModelClaudeHaiku4_5,
		MaxTokens: 600,
		System: []anthropic.TextBlockParam{
			{Text: checkAnalyzerSystemPrompt},
		},
		Messages: []anthropic.MessageParam{
			anthropic.NewUserMessage(anthropic.NewTextBlock(userPrompt)),
		},
		Temperature: anthropic.Float(0.2),
	}

	msg, err := ca.client.CreateMessage(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("API call failed for category %s: %w", categoryName, err)
	}

	// Extract text content from response
	var responseText string
	for _, block := range msg.Content {
		if block.Type == "text" {
			responseText += block.Text
		}
	}

	if responseText == "" {
		return nil, fmt.Errorf("empty response from API for category %s", categoryName)
	}

	// Clean potential markdown wrapping
	responseText = strings.TrimSpace(responseText)
	responseText = strings.TrimPrefix(responseText, "```json")
	responseText = strings.TrimPrefix(responseText, "```")
	responseText = strings.TrimSuffix(responseText, "```")
	responseText = strings.TrimSpace(responseText)

	var resp categoryAIResponse
	if err := json.Unmarshal([]byte(responseText), &resp); err != nil {
		return nil, fmt.Errorf("failed to parse AI response for category %s: %w", categoryName, err)
	}

	return &models.CategoryAIInsight{
		AIRiskLevel:    resp.AIRiskLevel,
		Confidence:     resp.Confidence,
		Findings:       resp.Findings,
		Context:        resp.Context,
		Recommendation: resp.Recommendation,
	}, nil
}

// ============================================================================
// CATEGORY CONTEXT BUILDERS
// Each function builds the most relevant metadata context for that category,
// so the AI receives the richest possible input for its analysis.
// ============================================================================

// buildPublisherControlContext builds context for Publisher Control analysis.
//
// Focus: maintainer account takeover risk - single point of compromise,
// account age, email domain stability, package concentration, signing practices.
//
// Source: Ohm et al. (2020) - 90% of supply chain attacks target maintainer accounts
func (ca *CheckAnalyzer) buildPublisherControlContext(packageName string, ecosystem models.Ecosystem, result *models.AnalysisResult) string {
	m := result.Metadata
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("Package: %s (ecosystem: %s)\n", packageName, ecosystem))
	sb.WriteString(fmt.Sprintf("Maintainer count: %d\n", len(m.Maintainers)))
	if len(m.Maintainers) > 0 {
		sb.WriteString(fmt.Sprintf("Maintainers: %s\n", strings.Join(m.Maintainers, ", ")))
	}

	// Download count indicates attack value - compromising a popular package has higher impact
	if m.DownloadCount > 0 {
		sb.WriteString(fmt.Sprintf("Download count: %d (indicates attack target value)\n", m.DownloadCount))
	}

	// Repository owner type (personal vs org) affects security controls available
	if m.RepoOwner != "" {
		sb.WriteString(fmt.Sprintf("Repository owner: %s\n", m.RepoOwner))
	}

	// Signing practices - absence means no artifact integrity verification
	sb.WriteString(fmt.Sprintf("Signed releases: %v\n", m.SignedReleases))
	sb.WriteString(fmt.Sprintf("Has SLSA attestation: %v\n", m.HasSLSAAttestation))
	sb.WriteString(fmt.Sprintf("Has Sigstore signature: %v\n", m.HasSigstoreSignature))
	if ecosystem == models.EcosystemNPM {
		sb.WriteString(fmt.Sprintf("Has npm provenance: %v\n", m.HasNPMProvenance))
	}
	if ecosystem == models.EcosystemPyPI {
		sb.WriteString(fmt.Sprintf("Has PyPI signatures: %v\n", m.HasPyPISignatures))
	}

	// Repository creation date - newer repos may indicate account hijack or transfer
	if !m.RepoCreatedAt.IsZero() {
		age := time.Since(m.RepoCreatedAt)
		sb.WriteString(fmt.Sprintf("Repository created: %s (%.0f days ago)\n", m.RepoCreatedAt.Format("2006-01-02"), age.Hours()/24))
	}

	// OSSFScore gives overall health signal
	if m.OSSFScore > 0 {
		sb.WriteString(fmt.Sprintf("OSSF Scorecard score: %.1f/10\n", m.OSSFScore))
	}

	return sb.String()
}

// buildOwnershipChangesContext builds context for Ownership Changes analysis.
//
// Focus: suspicious transfer patterns - timing anomalies between repo creation
// and package publishing, maintainer turnover, abandoned package takeover risk.
//
// Source: Ohm et al. (2020) - ownership transfer as attack vector
func (ca *CheckAnalyzer) buildOwnershipChangesContext(packageName string, ecosystem models.Ecosystem, result *models.AnalysisResult) string {
	m := result.Metadata
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("Package: %s (ecosystem: %s)\n", packageName, ecosystem))
	sb.WriteString(fmt.Sprintf("Current maintainers: %d (%s)\n", len(m.Maintainers), strings.Join(m.Maintainers, ", ")))

	// Timing comparison: repo creation vs package first publish
	// Significant gap suggests package predates current repository (possible transfer)
	if !m.PublishedAt.IsZero() {
		sb.WriteString(fmt.Sprintf("Package first published: %s\n", m.PublishedAt.Format("2006-01-02")))
	}
	if !m.RepoCreatedAt.IsZero() {
		sb.WriteString(fmt.Sprintf("Repository created: %s\n", m.RepoCreatedAt.Format("2006-01-02")))
		if !m.PublishedAt.IsZero() {
			gap := m.RepoCreatedAt.Sub(m.PublishedAt)
			if gap > 30*24*time.Hour {
				sb.WriteString(fmt.Sprintf("Repository created %.0f days AFTER package first published (possible transfer indicator)\n", gap.Hours()/24))
			} else if gap < -30*24*time.Hour {
				sb.WriteString(fmt.Sprintf("Repository created %.0f days BEFORE package first published (normal development pattern)\n", -gap.Hours()/24))
			}
		}
	}

	// Commit activity patterns - sudden author changes indicate potential takeover
	if m.BusFactor > 0 {
		sb.WriteString(fmt.Sprintf("Current bus factor: %d contributor(s) responsible for majority of commits\n", m.BusFactor))
	}
	if m.TopContributorPct > 0 {
		sb.WriteString(fmt.Sprintf("Top contributor: %.0f%% of all commits\n", m.TopContributorPct))
	}
	if len(m.CommitDistribution) > 0 {
		sb.WriteString(fmt.Sprintf("Distinct commit authors: %d\n", len(m.CommitDistribution)))
	}

	// Source code availability - missing source is a major red flag for takeover
	sb.WriteString(fmt.Sprintf("Source code available: %v\n", result.SourceCodeAvailable))
	if !m.RepoLastCommit.IsZero() {
		sb.WriteString(fmt.Sprintf("Last commit: %s\n", m.RepoLastCommit.Format("2006-01-02")))
	}

	return sb.String()
}

// buildReleaseAnomaliesContext builds context for Release Anomalies analysis.
//
// Focus: dormancy/reactivation patterns - the classic "abandoned package takeover"
// attack vector where an attacker gains control and releases malicious versions
// after a long period of inactivity.
//
// Source: Ohm et al. (2020) - dormant package reactivation as attack pattern
func (ca *CheckAnalyzer) buildReleaseAnomaliesContext(packageName string, ecosystem models.Ecosystem, result *models.AnalysisResult) string {
	m := result.Metadata
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("Package: %s (ecosystem: %s)\n", packageName, ecosystem))

	// Release timing context
	if !m.PublishedAt.IsZero() {
		age := time.Since(m.PublishedAt)
		sb.WriteString(fmt.Sprintf("First published: %s (%.0f days ago)\n", m.PublishedAt.Format("2006-01-02"), age.Hours()/24))
	}
	if !m.RepoLastCommit.IsZero() {
		staleness := time.Since(m.RepoLastCommit)
		sb.WriteString(fmt.Sprintf("Last commit: %s (%.0f days ago)\n", m.RepoLastCommit.Format("2006-01-02"), staleness.Hours()/24))
	}
	if m.LatestVersion != "" {
		sb.WriteString(fmt.Sprintf("Latest version: %s\n", m.LatestVersion))
	}

	// Repository activity indicators
	if m.RepoStars > 0 {
		sb.WriteString(fmt.Sprintf("Stars: %d, Forks: %d (community interest level)\n", m.RepoStars, m.RepoForks))
	}
	if m.RepoOpenIssues > 0 {
		sb.WriteString(fmt.Sprintf("Open issues: %d\n", m.RepoOpenIssues))
	}

	// Bus factor change signals - new single contributor after previously distributed = suspicious
	if m.BusFactor > 0 {
		sb.WriteString(fmt.Sprintf("Current bus factor: %d\n", m.BusFactor))
	}
	if m.TopContributorPct > 0 {
		sb.WriteString(fmt.Sprintf("Top contributor: %.0f%% of commits\n", m.TopContributorPct))
	}

	// Download count helps contextualize why this package would be a target
	if m.DownloadCount > 0 {
		sb.WriteString(fmt.Sprintf("Download count: %d (attack target value)\n", m.DownloadCount))
	}

	return sb.String()
}

// buildInstallExecutionContext builds context for Install Execution analysis.
//
// Focus: semantic analysis of install scripts - what do the scripts actually do?
// Rule-based checks use regex for dangerous patterns, but AI can understand
// the full semantics and intent of the code.
//
// Source: Ohm et al. (2020) - install-time execution as primary attack vector
// Examples: event-stream (2018), ua-parser-js (2021), coa (2021)
func (ca *CheckAnalyzer) buildInstallExecutionContext(packageName string, ecosystem models.Ecosystem, result *models.AnalysisResult) string {
	m := result.Metadata
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("Package: %s (ecosystem: %s)\n", packageName, ecosystem))
	sb.WriteString(fmt.Sprintf("Has install scripts: %v\n", m.HasInstallScripts))

	// Include actual script content for semantic analysis
	// This is where AI adds the most value over rule-based pattern matching
	if len(m.InstallScripts) > 0 {
		sb.WriteString(fmt.Sprintf("Install script count: %d\n", len(m.InstallScripts)))
		sb.WriteString("Script contents:\n")
		for scriptType, scriptContent := range m.InstallScripts {
			sb.WriteString(fmt.Sprintf("  [%s]: %s\n", scriptType, scriptContent))
		}
	}

	// Include already-detected dangerous patterns for context
	if m.InstallScriptAnalysis != nil {
		sb.WriteString(fmt.Sprintf("\nRule-based analysis detected dangerous patterns: %v\n", m.InstallScriptAnalysis.HasDangerousPatterns))
		sb.WriteString(fmt.Sprintf("Rule-based risk level: %s\n", m.InstallScriptAnalysis.RiskLevel))
		if len(m.InstallScriptAnalysis.DangerousPatterns) > 0 {
			sb.WriteString("Dangerous patterns detected:\n")
			for _, p := range m.InstallScriptAnalysis.DangerousPatterns {
				sb.WriteString(fmt.Sprintf("  - [%s] %s: %s\n", p.Severity, p.Pattern, p.Description))
				if p.Match != "" {
					sb.WriteString(fmt.Sprintf("    Match: %s\n", p.Match))
				}
			}
		}
	}

	// Additional context about the package's legitimacy signals
	sb.WriteString(fmt.Sprintf("\nSource code available: %v\n", result.SourceCodeAvailable))
	sb.WriteString(fmt.Sprintf("Has CI: %v\n", m.HasCI))
	if m.DownloadCount > 0 {
		sb.WriteString(fmt.Sprintf("Download count: %d\n", m.DownloadCount))
	}

	return sb.String()
}

// buildDependencySprawlContext builds context for Dependency Sprawl analysis.
//
// Focus: attack surface assessment - each dependency is a potential attack vector.
// High transitive dependency counts create exponential attack surface.
//
// Source: Zimmermann et al. (2019) - "Small World with High Risks"
// Each direct dependency multiplies the attack surface transitively.
func (ca *CheckAnalyzer) buildDependencySprawlContext(packageName string, ecosystem models.Ecosystem, result *models.AnalysisResult) string {
	m := result.Metadata
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("Package: %s (ecosystem: %s)\n", packageName, ecosystem))

	if m.DependencyMetrics != nil {
		dm := m.DependencyMetrics
		sb.WriteString(fmt.Sprintf("Direct dependencies: %d\n", dm.DirectCount))
		sb.WriteString(fmt.Sprintf("Transitive dependencies: %d\n", dm.TransitiveCount))
		if dm.MaxDepth > 0 {
			sb.WriteString(fmt.Sprintf("Maximum dependency depth: %d\n", dm.MaxDepth))
		}
		sb.WriteString(fmt.Sprintf("Dependency count verified from lock file: %v\n", dm.Verified))
	}

	// Context about what type of package this is helps assess whether sprawl is expected
	// A testing framework is expected to have more deps than a simple utility
	if m.License != "" {
		sb.WriteString(fmt.Sprintf("License: %s\n", m.License))
	}
	if m.DownloadCount > 0 {
		sb.WriteString(fmt.Sprintf("Download count: %d (popularity indicates attack surface value)\n", m.DownloadCount))
	}

	// OSSF dependency update check (if available)
	if score, ok := m.OSSFChecks["Dependency-Update-Tool"]; ok {
		sb.WriteString(fmt.Sprintf("OSSF Dependency-Update-Tool score: %d/10\n", score))
	}
	if score, ok := m.OSSFChecks["Pinned-Dependencies"]; ok {
		sb.WriteString(fmt.Sprintf("OSSF Pinned-Dependencies score: %d/10\n", score))
	}

	return sb.String()
}

// buildProvenanceContext builds context for Provenance analysis.
//
// Focus: build integrity gaps - can we verify the published artifact matches
// the source code? Missing provenance means we cannot detect build chain compromise.
//
// Source: SLSA Framework - Build Integrity Requirements
// SolarWinds (2020) and CodeCov (2021) showed build chain compromise impact.
func (ca *CheckAnalyzer) buildProvenanceContext(packageName string, ecosystem models.Ecosystem, result *models.AnalysisResult) string {
	m := result.Metadata
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("Package: %s (ecosystem: %s)\n", packageName, ecosystem))

	// SLSA attestation details
	sb.WriteString(fmt.Sprintf("Has SLSA attestation: %v\n", m.HasSLSAAttestation))
	if m.SLSALevel != "" {
		sb.WriteString(fmt.Sprintf("SLSA level: %s\n", m.SLSALevel))
	}

	// Signing mechanisms
	sb.WriteString(fmt.Sprintf("Has Sigstore signature: %v\n", m.HasSigstoreSignature))
	if ecosystem == models.EcosystemNPM {
		sb.WriteString(fmt.Sprintf("Has npm provenance attestation: %v\n", m.HasNPMProvenance))
	}
	if ecosystem == models.EcosystemPyPI {
		sb.WriteString(fmt.Sprintf("Has PyPI cryptographic signatures: %v\n", m.HasPyPISignatures))
	}
	sb.WriteString(fmt.Sprintf("Has signed GitHub releases: %v\n", m.SignedReleases))
	sb.WriteString(fmt.Sprintf("Reproducible build configured: %v\n", m.ReproducibleBuild))
	if m.ProvenanceDetails != "" {
		sb.WriteString(fmt.Sprintf("Provenance details: %s\n", m.ProvenanceDetails))
	}

	// Build system context
	if len(m.CISystems) > 0 {
		sb.WriteString(fmt.Sprintf("CI systems: %s\n", strings.Join(m.CISystems, ", ")))
	}
	sb.WriteString(fmt.Sprintf("Has automated release process: %v\n", m.HasReleaseProcess))

	// Source code availability as a prerequisite for provenance
	sb.WriteString(fmt.Sprintf("Source code available: %v\n", result.SourceCodeAvailable))
	if result.SourceVerification != nil {
		sb.WriteString(fmt.Sprintf("Has matching git tag: %v\n", result.SourceVerification.HasMatchingGitTag))
		sb.WriteString(fmt.Sprintf("Has source package: %v\n", result.SourceVerification.HasSourcePackage))
	}

	// OSSF Signed-Releases score
	if score, ok := m.OSSFChecks["Signed-Releases"]; ok {
		sb.WriteString(fmt.Sprintf("OSSF Signed-Releases score: %d/10\n", score))
	}

	return sb.String()
}

// buildHealthContext builds context for Health analysis.
//
// Focus: community health and concentration risk - a package controlled by
// a single contributor is far more vulnerable to account takeover or
// malicious insider action than one with distributed development.
//
// Source: Ohm et al. (2020) - single maintainer as primary attack target
// node-ipc (2022) demonstrated insider threat from solo maintainer
func (ca *CheckAnalyzer) buildHealthContext(packageName string, ecosystem models.Ecosystem, result *models.AnalysisResult) string {
	m := result.Metadata
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("Package: %s (ecosystem: %s)\n", packageName, ecosystem))

	// Bus factor - key concentration risk indicator
	sb.WriteString(fmt.Sprintf("Bus factor: %d (contributors needed for 50%% of commits)\n", m.BusFactor))
	if m.TopContributorPct > 0 {
		sb.WriteString(fmt.Sprintf("Top contributor concentration: %.0f%% of all commits\n", m.TopContributorPct))
	}
	if len(m.CommitDistribution) > 0 {
		sb.WriteString(fmt.Sprintf("Total distinct commit authors: %d\n", len(m.CommitDistribution)))
	}
	sb.WriteString(fmt.Sprintf("Maintainer count: %d\n", len(m.Maintainers)))

	// Code review - key oversight mechanism
	sb.WriteString(fmt.Sprintf("Code review rate: %.0f%% of PRs reviewed\n", m.CodeReviewRate))
	sb.WriteString(fmt.Sprintf("Branch protection enabled: %v\n", m.HasBranchProtection))
	sb.WriteString(fmt.Sprintf("Required reviewers: %d\n", m.RequiredReviewers))

	// CI quality - automated quality gates
	sb.WriteString(fmt.Sprintf("CI quality score: %d/10\n", m.CIQualityScore))
	sb.WriteString(fmt.Sprintf("CI includes tests: %v\n", m.CIHasTests))
	if len(m.CISystems) > 0 {
		sb.WriteString(fmt.Sprintf("CI systems: %s\n", strings.Join(m.CISystems, ", ")))
	}

	// Repository activity signals
	if m.RepoStars > 0 {
		sb.WriteString(fmt.Sprintf("Stars: %d, Forks: %d, Open issues: %d\n", m.RepoStars, m.RepoForks, m.RepoOpenIssues))
	}
	if !m.RepoLastCommit.IsZero() {
		staleness := time.Since(m.RepoLastCommit)
		sb.WriteString(fmt.Sprintf("Last commit: %s (%.0f days ago)\n", m.RepoLastCommit.Format("2006-01-02"), staleness.Hours()/24))
	}

	// OSSF health-related checks
	if score, ok := m.OSSFChecks["Code-Review"]; ok {
		sb.WriteString(fmt.Sprintf("OSSF Code-Review score: %d/10\n", score))
	}
	if score, ok := m.OSSFChecks["Branch-Protection"]; ok {
		sb.WriteString(fmt.Sprintf("OSSF Branch-Protection score: %d/10\n", score))
	}

	return sb.String()
}

// buildGovernanceContext builds context for Governance analysis.
//
// Focus: accountability and maintenance patterns - well-governed projects
// have security policies, contribution guides, and are responsive to issues.
// Abandoned or ungoverned packages are easier targets for takeover.
//
// Source: OSSF Scorecard - Governance and maintenance metrics
func (ca *CheckAnalyzer) buildGovernanceContext(packageName string, ecosystem models.Ecosystem, result *models.AnalysisResult) string {
	m := result.Metadata
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("Package: %s (ecosystem: %s)\n", packageName, ecosystem))

	// Repository state - archived means permanently unmaintained
	sb.WriteString(fmt.Sprintf("Repository archived: %v\n", m.RepoArchived))

	// Activity signals
	if !m.RepoLastCommit.IsZero() {
		staleness := time.Since(m.RepoLastCommit)
		sb.WriteString(fmt.Sprintf("Last commit: %s (%.0f days ago)\n", m.RepoLastCommit.Format("2006-01-02"), staleness.Hours()/24))
	}
	if !m.RepoUpdatedAt.IsZero() {
		staleness := time.Since(m.RepoUpdatedAt)
		sb.WriteString(fmt.Sprintf("Repository last updated: %.0f days ago\n", staleness.Hours()/24))
	}
	if m.RepoOpenIssues > 0 {
		sb.WriteString(fmt.Sprintf("Open issues: %d (responsiveness indicator)\n", m.RepoOpenIssues))
	}

	// License as a governance signal - no license indicates less formal project
	if m.License != "" {
		sb.WriteString(fmt.Sprintf("License: %s\n", m.License))
	} else {
		sb.WriteString("License: none (informal project)\n")
	}

	// Maintainer context
	sb.WriteString(fmt.Sprintf("Maintainer count: %d\n", len(m.Maintainers)))
	if m.RepoOwner != "" {
		sb.WriteString(fmt.Sprintf("Repository owner: %s\n", m.RepoOwner))
	}

	// OSSF governance-related checks
	if score, ok := m.OSSFChecks["Security-Policy"]; ok {
		sb.WriteString(fmt.Sprintf("OSSF Security-Policy score: %d/10\n", score))
	}
	if score, ok := m.OSSFChecks["Maintained"]; ok {
		sb.WriteString(fmt.Sprintf("OSSF Maintained score: %d/10\n", score))
	}
	if m.OSSFScore > 0 {
		sb.WriteString(fmt.Sprintf("Overall OSSF score: %.1f/10\n", m.OSSFScore))
	}

	return sb.String()
}

// buildReleaseSecurityContext builds context for Release Security analysis.
//
// Focus: CI/CD integrity - releases published directly from a developer machine
// (rather than automated CI) are far more susceptible to build chain compromise.
// Self-hosted runners provide uncontrolled build environments.
//
// Source: SLSA Build Level Requirements
// SolarWinds (2020) demonstrated the impact of compromised build infrastructure
func (ca *CheckAnalyzer) buildReleaseSecurityContext(packageName string, ecosystem models.Ecosystem, result *models.AnalysisResult) string {
	m := result.Metadata
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("Package: %s (ecosystem: %s)\n", packageName, ecosystem))

	// Build system details - structured data if available
	if len(m.BuildSystems) > 0 {
		sb.WriteString("Build systems detected:\n")
		for _, bs := range m.BuildSystems {
			sb.WriteString(fmt.Sprintf("  - %s (hosted by: %s, self-hosted: %v)\n", bs.Platform, bs.HostedBy, bs.IsSelfHosted))
			if bs.RunnerDetails != "" {
				sb.WriteString(fmt.Sprintf("    Runner: %s\n", bs.RunnerDetails))
			}
			if bs.ConfigFile != "" {
				sb.WriteString(fmt.Sprintf("    Config: %s\n", bs.ConfigFile))
			}
		}
	} else if len(m.CISystems) > 0 {
		sb.WriteString(fmt.Sprintf("CI systems: %s\n", strings.Join(m.CISystems, ", ")))
	} else {
		sb.WriteString("CI systems: none detected (possible manual publishing)\n")
	}

	sb.WriteString(fmt.Sprintf("Has self-hosted runners: %v (uncontrolled build environment)\n", m.HasSelfHosted))
	sb.WriteString(fmt.Sprintf("Has automated release process: %v\n", m.HasReleaseProcess))

	// Release controls
	sb.WriteString(fmt.Sprintf("Branch protection enabled: %v\n", m.HasBranchProtection))
	sb.WriteString(fmt.Sprintf("Required reviewers: %d\n", m.RequiredReviewers))
	sb.WriteString(fmt.Sprintf("Signed releases: %v\n", m.SignedReleases))
	sb.WriteString(fmt.Sprintf("Has SLSA attestation: %v\n", m.HasSLSAAttestation))

	// Source code traceability
	sb.WriteString(fmt.Sprintf("Source code available: %v\n", result.SourceCodeAvailable))
	if result.SourceVerification != nil {
		sb.WriteString(fmt.Sprintf("Has matching git tag for release: %v\n", result.SourceVerification.HasMatchingGitTag))
	}

	// OSSF release security checks
	if score, ok := m.OSSFChecks["CI-Tests"]; ok {
		sb.WriteString(fmt.Sprintf("OSSF CI-Tests score: %d/10\n", score))
	}
	if score, ok := m.OSSFChecks["Branch-Protection"]; ok {
		sb.WriteString(fmt.Sprintf("OSSF Branch-Protection score: %d/10\n", score))
	}

	return sb.String()
}

// buildPackageMaturityContext builds context for Package Maturity analysis.
//
// Focus: lifecycle risk - very new packages are unvetted; abandoned packages
// are vulnerable to takeover. Irregular release cadence indicates governance issues.
//
// Source: Ohm et al. (2020) - maturity as a proxy for security vetting
// Zimmermann et al. (2019) - new packages have higher compromise risk
func (ca *CheckAnalyzer) buildPackageMaturityContext(packageName string, ecosystem models.Ecosystem, result *models.AnalysisResult) string {
	m := result.Metadata
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("Package: %s (ecosystem: %s)\n", packageName, ecosystem))

	// Package age - too new = unvetted; too old without activity = abandoned
	if !m.PublishedAt.IsZero() {
		age := time.Since(m.PublishedAt)
		sb.WriteString(fmt.Sprintf("First published: %s (%.0f days / %.1f years ago)\n",
			m.PublishedAt.Format("2006-01-02"), age.Hours()/24, age.Hours()/(24*365)))
	}

	// Staleness - when was the last development activity?
	if !m.RepoLastCommit.IsZero() {
		staleness := time.Since(m.RepoLastCommit)
		sb.WriteString(fmt.Sprintf("Last commit: %s (%.0f days ago)\n", m.RepoLastCommit.Format("2006-01-02"), staleness.Hours()/24))
	}
	if !m.RepoUpdatedAt.IsZero() {
		staleness := time.Since(m.RepoUpdatedAt)
		sb.WriteString(fmt.Sprintf("Repository last updated: %.0f days ago\n", staleness.Hours()/24))
	}

	// Version progression - indicates maturity trajectory
	if m.LatestVersion != "" {
		sb.WriteString(fmt.Sprintf("Latest version: %s\n", m.LatestVersion))
	}

	// Community engagement as maturity proxy
	if m.RepoStars > 0 {
		sb.WriteString(fmt.Sprintf("Stars: %d, Forks: %d\n", m.RepoStars, m.RepoForks))
	}
	if m.DownloadCount > 0 {
		sb.WriteString(fmt.Sprintf("Download count: %d\n", m.DownloadCount))
	}
	if m.RepoOpenIssues > 0 {
		sb.WriteString(fmt.Sprintf("Open issues: %d\n", m.RepoOpenIssues))
	}

	// Repository archived status - permanent maintenance end
	sb.WriteString(fmt.Sprintf("Repository archived: %v\n", m.RepoArchived))

	// Maintainer continuity
	sb.WriteString(fmt.Sprintf("Maintainer count: %d\n", len(m.Maintainers)))
	if m.BusFactor > 0 {
		sb.WriteString(fmt.Sprintf("Bus factor: %d\n", m.BusFactor))
	}

	// OSSF maintained check
	if score, ok := m.OSSFChecks["Maintained"]; ok {
		sb.WriteString(fmt.Sprintf("OSSF Maintained score: %d/10\n", score))
	}

	return sb.String()
}
