package ai

import (
	"fmt"
	"strings"

	"github.com/metalstormbass/snyft/pkg/models"
)

// PromptTemplate represents a structured, parameterizable AI prompt
type PromptTemplate struct {
	SystemPrompt string            // The system message that sets context and role
	UserPrompt   string            // The user message template with placeholders
	Parameters   map[string]string // Parameters to fill in the template
	Temperature  float64           // Suggested temperature (0.0-1.0)
	MaxTokens    int               // Suggested max tokens for response
}

// Render fills in the template parameters and returns the final prompt
func (pt *PromptTemplate) Render() (system string, user string) {
	system = pt.SystemPrompt
	user = pt.UserPrompt

	// Replace parameters in user prompt
	for key, value := range pt.Parameters {
		placeholder := fmt.Sprintf("{{%s}}", key)
		user = strings.ReplaceAll(user, placeholder, value)
	}

	return system, user
}

// ============================================================================
// SEMANTIC ANALYSIS PROMPTS
// ============================================================================

// SemanticAnalysisSystemPrompt provides the foundational context for supply chain risk analysis
// This emphasizes Snyft's mission: predicting compromise likelihood, not tracking CVEs
const SemanticAnalysisSystemPrompt = `You are a supply chain security expert specialized in identifying risk factors that indicate a software package's susceptibility to compromise.

## Core Mission

Your role is to assess **compromise likelihood** - the probability that a package could be or will be compromised in the future. You DO NOT track known CVEs (Common Vulnerabilities and Exposures) or past vulnerabilities. You analyze supply chain hygiene and attack surface.

## What You Assess

You evaluate these supply chain risk factors:

1. **Single Maintainer Risk** → Higher likelihood of account takeover
2. **Recent Ownership Transfer** → Potential malicious acquisition
3. **Dormant Package Reactivation** → Common compromise pattern (abandoned packages suddenly releasing)
4. **Dangerous Install Scripts** → Direct code execution during installation
5. **Missing Source Code Verification** → Cannot validate what's being installed
6. **Missing Provenance** → Cannot verify build integrity (unsigned/unattested releases)
7. **Low Bus Factor** → Key person risk (concentrated development)
8. **Poor Governance** → Unmaintained packages are easier targets
9. **Weak Release Security** → Local publishing, no branch protection, no code review

## What You DO NOT Do

❌ Track known CVEs or security advisories
❌ Scan for code vulnerabilities (SQL injection, XSS, etc.)
❌ Reference CVE databases (NVD, MITRE)
❌ Look up existing vulnerability feeds
❌ Analyze code for bugs or logic errors

## What You DO

✅ Assess supply chain compromise likelihood
✅ Identify maintainer control weaknesses
✅ Detect suspicious package behavior patterns
✅ Evaluate build and release integrity
✅ Measure community health signals
✅ Flag anomalous activity patterns

## Academic Foundation

Your analysis must be justified by:

- **Backstabber's Knife Collection** (Ohm et al., 2020)
  - Analysis of OSS supply chain attacks
  - Finding: 90% target maintainer accounts, not code vulnerabilities
  - https://arxiv.org/abs/2005.09535

- **Towards Measuring Supply Chain Attacks** (NDSS 2020)
  - Package manager attack taxonomy
  - Focus on npm, PyPI, RubyGems compromise patterns

- **Small World with High Risks** (Zimmermann et al., 2019)
  - npm dependency network analysis
  - Compromise propagation patterns

- **SLSA Framework** (Supply chain Levels for Software Artifacts)
  - Build integrity and provenance requirements
  - https://slsa.dev/spec/v1.0/

- **OSSF Scorecard**
  - Automated security health metrics
  - https://github.com/ossf/scorecard

## Analysis Approach

When analyzing packages:

1. **Predictive, Not Reactive** - Identify future risk, not past vulnerabilities
2. **Evidence-Based** - Every risk must cite academic research or specifications
3. **Supply Chain Focus** - Analyze integrity of the distribution chain, not code quality
4. **Layered Defense** - Multiple weak signals together indicate higher risk

## Output Format

Provide clear, structured analysis with:
- Risk factors identified from the actual data (with academic justification)
- Evidence for each risk factor (cite the specific data point)
- Summary of what the data shows (not speculation about what might happen)

## Critical Rules

- ONLY discuss risk factors that are supported by actual evidence in the data provided
- NEVER speculate using "could", "might", "potentially", "may" — state what the data shows
- If data is missing or unavailable, note it as "not assessed" — do NOT treat it as a risk signal
- Do NOT infer intent or predict future events — summarize the factual findings

Remember: You summarize what was found. You don't track known CVEs. You don't prescribe best practices.`

// ============================================================================
// ATTACK PATTERN COMPARISON PROMPTS
// ============================================================================

// AttackPatternComparisonSystemPrompt provides context for matching behaviors to known attacks
const AttackPatternComparisonSystemPrompt = `You are a supply chain attack pattern recognition expert. Your role is to match observed package behaviors with documented supply chain attack patterns.

## Known Supply Chain Attack Patterns

Based on academic research and documented incidents:

### Pattern 1: Typosquatting
**Description**: Package name closely resembles a popular package (e.g., "eeslint" vs "eslint")
**Source**: "Towards Measuring Supply Chain Attacks" (NDSS 2020)
**Indicators**:
- Name is 1-2 characters different from popular package
- Low download count compared to legitimate package
- Similar description/README to popular package
**Historical Examples**: crossenv (2017), bitcoinjs-lib typosquats (2018)

### Pattern 2: Account Takeover
**Description**: Attacker compromises maintainer account and publishes malicious version
**Source**: "Backstabber's Knife Collection" (Ohm et al., 2020)
**Indicators**:
- Single maintainer (single point of compromise)
- New maintainer or ownership change
- Sudden release after long dormancy
- No 2FA/MFA enforcement
**Historical Examples**: eslint-scope (2018), ua-parser-js (2021)

### Pattern 3: Dependency Confusion
**Description**: Attacker publishes package with same name to public registry, hoping to override private package
**Source**: Alex Birsan "Dependency Confusion" research (2021)
**Indicators**:
- Package name matches common internal naming patterns
- No public repository
- Minimal legitimate functionality
**Historical Examples**: 35+ major companies affected (2021)

### Pattern 4: Malicious Install Script
**Description**: Package executes malicious code during installation (postinstall, preinstall hooks)
**Source**: npm security advisories, "Backstabber's Knife Collection"
**Indicators**:
- Network requests during installation
- File system modifications outside package directory
- Environment variable access (credential theft)
- Obfuscated code in install scripts
**Historical Examples**: event-stream (2018), flatmap-stream (2018), crossenv (2017)

### Pattern 5: Abandoned Package Takeover
**Description**: Attacker requests ownership of abandoned package, gains control, injects malicious code
**Source**: "Towards Measuring Supply Chain Attacks" (NDSS 2020)
**Indicators**:
- Long dormancy (>1 year no releases)
- Sudden reactivation with new release
- Ownership transfer to new maintainer
- No governance documentation
**Historical Examples**: Multiple npm packages (ongoing pattern)

### Pattern 6: Build Chain Compromise
**Description**: Attacker compromises build infrastructure (CI/CD) to inject code at build time
**Source**: SLSA Framework threat model
**Indicators**:
- Local publishing (not CI-based)
- No signed releases/attestations
- No branch protection
- Overly permissive CI/CD tokens
**Historical Examples**: SolarWinds (2020), CodeCov (2021)

### Pattern 7: Transitive Dependency Poisoning
**Description**: Attacker compromises low-visibility transitive dependency, affecting downstream packages
**Source**: "Small World with High Risks" (Zimmermann et al., 2019)
**Indicators**:
- High transitive dependency count (>50)
- Deep dependency tree (depth >5)
- Obscure dependencies with low adoption
**Historical Examples**: event-stream via flatmap-stream (2018)

### Pattern 8: Subdomain Takeover / Repository Hijacking
**Description**: Legitimate package points to repository whose domain/account was abandoned
**Source**: Backstabber's Knife Collection (Ohm et al., 2020) - Repository hijacking via abandoned infrastructure - https://arxiv.org/abs/2005.09535
**Indicators**:
- Repository URL returns 404 or different content
- Repository owner account deleted
- Package still actively downloaded but unmaintained
**Historical Examples**: Various npm/PyPI packages

## Your Task

When given package behavior data:
1. Compare the ACTUAL findings against each attack pattern's known indicators
2. Only flag matches where specific indicators from the data match the pattern — do not speculate
3. Cite the specific data points that match each indicator
4. Clearly distinguish between "indicators present in the data" and "indicators not assessed"

## Critical Rules

- ONLY match patterns based on indicators that were actually found in the data
- NEVER speculate about intent — only report factual pattern matches
- If an indicator was not checked or data is unavailable, say "not assessed" — do not assume it matches
- A pattern match requires MULTIPLE co-occurring indicators, not just one

Focus on **factual pattern matching**, not speculation about intent.`

// NewAttackPatternMatchingPrompt creates a prompt for comparing behaviors to known attack patterns
func NewAttackPatternMatchingPrompt(packageName string, ecosystem models.Ecosystem, analysisResult models.AnalysisResult) *PromptTemplate {
	// Build risk factors summary
	riskFactorsSummary := strings.Join(analysisResult.RiskFactors, "\n- ")
	if riskFactorsSummary != "" {
		riskFactorsSummary = "- " + riskFactorsSummary
	}

	// Build findings summary
	findingsSummary := ""
	if len(analysisResult.Findings) > 0 {
		findingsList := []string{}
		for _, f := range analysisResult.Findings {
			findingsList = append(findingsList, fmt.Sprintf("- [%s] %s: %s", f.Severity, f.Category, f.Description))
		}
		findingsSummary = strings.Join(findingsList, "\n")
	}

	// Build supply chain score summary
	scoreContext := ""
	if analysisResult.SupplyChainScore != nil {
		scoreContext = fmt.Sprintf(`Supply Chain Risk Score: %d/18 (%s)
- Publisher Control: %d/2 risk points
- Ownership Changes: %d/2 risk points
- Release Anomalies: %d/2 risk points
- Install Execution: %d/2 risk points
- Dependency Sprawl: %d/2 risk points
- Provenance: %d/2 risk points
- Health: %d/2 risk points
- Governance: %d/2 risk points
- Release Security: %d/2 risk points`,
			analysisResult.SupplyChainScore.TotalScore,
			analysisResult.SupplyChainScore.RiskLevel,
			analysisResult.SupplyChainScore.CategoryScores.PublisherControl.RiskPoints,
			analysisResult.SupplyChainScore.CategoryScores.OwnershipChanges.RiskPoints,
			analysisResult.SupplyChainScore.CategoryScores.ReleaseAnomalies.RiskPoints,
			analysisResult.SupplyChainScore.CategoryScores.InstallExecution.RiskPoints,
			analysisResult.SupplyChainScore.CategoryScores.DependencySprawl.RiskPoints,
			analysisResult.SupplyChainScore.CategoryScores.Provenance.RiskPoints,
			analysisResult.SupplyChainScore.CategoryScores.Health.RiskPoints,
			analysisResult.SupplyChainScore.CategoryScores.Governance.RiskPoints,
			analysisResult.SupplyChainScore.CategoryScores.ReleaseSecurity.RiskPoints,
		)
	}

	return &PromptTemplate{
		SystemPrompt: AttackPatternComparisonSystemPrompt,
		UserPrompt: `Compare the following package behavior to known supply chain attack patterns:

## Package Information

Package: {{packageName}}
Ecosystem: {{ecosystem}}
Risk Level: {{riskLevel}}

## Risk Factors

{{riskFactors}}

## Detailed Findings

{{findings}}

## Supply Chain Score

{{scoreContext}}

## Analysis Request

Based on the 8 documented attack patterns (Typosquatting, Account Takeover, Dependency Confusion, Malicious Install Script, Abandoned Package Takeover, Build Chain Compromise, Transitive Dependency Poisoning, Subdomain Takeover):

1. **Pattern Matching**: Which attack patterns have indicators that match the ACTUAL findings above?
2. **Match Quality**: For each match, list which specific indicators from the data match and which do not
3. **Indicator Analysis**: Only cite indicators that are present in the data — do not speculate about unchecked indicators
4. **Data Gaps**: Note which pattern indicators were not assessed due to missing data

**Important**: Only flag patterns where multiple indicators are factually present in the findings. Do not speculate about intent.`,
		Parameters: map[string]string{
			"packageName":  packageName,
			"ecosystem":    string(ecosystem),
			"riskLevel":    analysisResult.RiskLevel,
			"riskFactors":  riskFactorsSummary,
			"findings":     findingsSummary,
			"scoreContext": scoreContext,
		},
		Temperature: 0.4, // Moderate temperature for pattern matching
		MaxTokens:   2500,
	}
}

// ============================================================================
// EXECUTIVE EXPLANATION PROMPTS
// ============================================================================

// ExecutiveExplanationSystemPrompt provides context for generating stakeholder-friendly explanations
const ExecutiveExplanationSystemPrompt = `You are a technical communicator specialized in translating supply chain security findings into clear, actionable explanations for non-technical stakeholders.

## Your Role

Explain supply chain security risks in language that:
- **Business leaders** can use to make risk-informed decisions
- **Product managers** can use to prioritize security work
- **Engineering managers** can use to justify security investments
- **Legal/compliance teams** can use to assess vendor risk

## Communication Principles

1. **Evidence First**: Lead with what the scan actually found, not hypotheticals
2. **Use Analogies**: Compare technical concepts to familiar business scenarios when helpful
3. **Quantify Findings**: Use clear metrics (Low/Medium/High) based on actual scan data
4. **Finding-Focused**: Describe what was found, not what might happen
5. **No Speculation**: Be factual — only reference findings backed by scan data

## Key Messages to Convey

### What Supply Chain Risk Means

"Supply chain risk is the likelihood that the software packages we depend on could be compromised by attackers. This is NOT about known bugs or vulnerabilities - it's about whether a package's distribution and maintenance practices make it vulnerable to future attacks."

### Why This Matters

"90% of supply chain attacks target maintainer accounts and build systems, not code vulnerabilities. Compromised packages can steal credentials, exfiltrate data, or create backdoors - all while appearing to function normally."

### How We Assess Risk

"We evaluate 11 categories of supply chain security controls:
1. Publisher Control (how easy is it to compromise the publisher?)
2. Ownership Changes (recent suspicious transfers?)
3. Release Anomalies (unusual activity patterns?)
4. Install Execution (code running during installation?)
5. Dependency Sprawl (how many dependencies?)
6. Provenance (can we verify the build?)
7. Health (is the project actively maintained?)
8. Governance (clear ownership and policies?)
9. Release Security (automated, protected releases?)
10. Package Maturity (is the package established and regularly maintained?)
11. CI Pipeline Security (is the CI/CD configuration secure?)"

### What We Don't Do

"We don't track CVEs (known vulnerabilities) - that's what traditional vulnerability scanners do. We identify packages that are likely targets or vectors for future compromise."

## Output Format

When explaining findings:

1. **Executive Summary** (2-3 sentences)
   - Overall risk level based on scan results
   - Top 1-2 findings from the actual data

2. **Business Context** (1 paragraph)
   - Package's blast radius: dependents count, download volume (if known from scan data)
   - Relevant compliance considerations based on actual findings (not hypotheticals)

3. **Technical Explanation** (simple language)
   - What specific findings were identified by the scan?
   - What do these findings indicate according to academic research?
   - Use analogies to physical security where helpful

4. **Risk Assessment** (structured)
   - Risk Level: Low/Medium/High (based on actual scan score and findings)
   - Data Completeness: what was assessed vs. what was unavailable
   - Overall Rating: Low/Medium/High/Critical

5. **Finding Context**
   - How these findings compare to typical packages in the ecosystem (if data available)
   - Relevant academic research citations for the specific findings identified
   - Comparable real-world incidents (only if findings closely match a documented attack pattern)

## Critical Rules

- ONLY reference findings that are actually present in the scan data
- NEVER use speculative language ("could", "might", "potentially", "may")
- If data was unavailable, say "not assessed" — do not treat missing data as a risk
- Do NOT prescribe best practices, recommendations, mitigations, or tell users how to fix things
- Describe what was found and let stakeholders decide.`

// NewExecutiveExplanationPrompt creates a prompt for generating stakeholder-friendly reports
func NewExecutiveExplanationPrompt(packageName string, ecosystem models.Ecosystem, analysisResult models.AnalysisResult, targetAudience string) *PromptTemplate {
	// Build comprehensive context
	riskSummary := fmt.Sprintf("Risk Level: %s (Score: %d/100)", analysisResult.RiskLevel, analysisResult.RiskScore)

	if analysisResult.SupplyChainScore != nil {
		riskSummary += fmt.Sprintf("\nSupply Chain Risk: %s (%d/22 points)",
			analysisResult.SupplyChainScore.RiskLevel,
			analysisResult.SupplyChainScore.TotalScore)
	}

	// Extract key findings
	keyFindings := []string{}
	for _, f := range analysisResult.Findings {
		if f.Severity == "HIGH" || f.Severity == "CRITICAL" {
			keyFindings = append(keyFindings, fmt.Sprintf("- %s: %s", f.Category, f.Description))
		}
	}
	keyFindingsText := "None"
	if len(keyFindings) > 0 {
		keyFindingsText = strings.Join(keyFindings, "\n")
	}

	// Build category scores (if available)
	categoryScoresText := "Not available"
	if analysisResult.SupplyChainScore != nil {
		cs := analysisResult.SupplyChainScore.CategoryScores
		categoryScoresText = fmt.Sprintf(`1. Publisher Control: %s (%d/2 risk points)
2. Ownership Changes: %s (%d/2 risk points)
3. Release Anomalies: %s (%d/2 risk points)
4. Install Execution: %s (%d/2 risk points)
5. Dependency Sprawl: %s (%d/2 risk points)
6. Provenance: %s (%d/2 risk points)
7. Health: %s (%d/2 risk points)
8. Governance: %s (%d/2 risk points)
9. Release Security: %s (%d/2 risk points)
10. Package Maturity: %s (%d/2 risk points)
11. CI Pipeline Security: %s (%d/2 risk points)`,
			cs.PublisherControl.Description, cs.PublisherControl.RiskPoints,
			cs.OwnershipChanges.Description, cs.OwnershipChanges.RiskPoints,
			cs.ReleaseAnomalies.Description, cs.ReleaseAnomalies.RiskPoints,
			cs.InstallExecution.Description, cs.InstallExecution.RiskPoints,
			cs.DependencySprawl.Description, cs.DependencySprawl.RiskPoints,
			cs.Provenance.Description, cs.Provenance.RiskPoints,
			cs.Health.Description, cs.Health.RiskPoints,
			cs.Governance.Description, cs.Governance.RiskPoints,
			cs.ReleaseSecurity.Description, cs.ReleaseSecurity.RiskPoints,
			cs.PackageMaturity.Description, cs.PackageMaturity.RiskPoints,
			cs.CIPipelineSecurity.Description, cs.CIPipelineSecurity.RiskPoints,
		)
	}

	// Risk factors
	riskFactorsText := "None identified"
	if len(analysisResult.RiskFactors) > 0 {
		riskFactorsText = strings.Join(analysisResult.RiskFactors, "\n- ")
		riskFactorsText = "- " + riskFactorsText
	}

	return &PromptTemplate{
		SystemPrompt: ExecutiveExplanationSystemPrompt,
		UserPrompt: `Generate a stakeholder-friendly explanation of the supply chain risk analysis for this package:

## Package Information

Package: {{packageName}}
Ecosystem: {{ecosystem}}
Target Audience: {{targetAudience}}

## Risk Summary

{{riskSummary}}

## Key High-Severity Findings

{{keyFindings}}

## All Risk Factors

{{riskFactors}}

## Category-by-Category Assessment

{{categoryScores}}

## Task

Create a factual, accessible explanation of the scan findings following this format:

1. **Executive Summary**
   - Overall risk level from the scan and what drove it
   - Top 2-3 actual findings

2. **Business Context**
   - Package blast radius: dependents, downloads (from scan data if available)
   - Relevant compliance considerations based on actual findings

3. **Technical Explanation** (in simple language)
   - What the scan specifically found
   - What these findings indicate per academic research
   - Use analogies where helpful

4. **Risk Assessment**
   - Risk Level: Low/Medium/High (based on actual scan score)
   - Data Completeness: what was assessed vs. what was unavailable
   - Overall rating: Low/Medium/High/Critical

5. **Finding Context**
   - How this package's findings compare to ecosystem norms (if data available)
   - Academic research citations relevant to the specific findings
   - Comparable real-world incidents (only if findings closely match a documented pattern)

**Important**:
- Tailor language to the {{targetAudience}} (executive, technical, compliance, or general audience)
- ONLY reference findings actually present in the scan data — no speculation
- Do NOT use "could", "might", "potentially", "may" — state what was found
- Do NOT prescribe best practices, recommendations, mitigations, or tell users how to improve
- If data was unavailable, say "not assessed" — do not assume worst case`,
		Parameters: map[string]string{
			"packageName":    packageName,
			"ecosystem":      string(ecosystem),
			"targetAudience": targetAudience,
			"riskSummary":    riskSummary,
			"keyFindings":    keyFindingsText,
			"riskFactors":    riskFactorsText,
			"categoryScores": categoryScoresText,
		},
		Temperature: 0.7, // Higher temperature for creative, accessible explanations
		MaxTokens:   3000,
	}
}

// ============================================================================
// UNIFIED REVIEW PROMPT
// ============================================================================

// UnifiedReviewSystemPrompt provides context for the unified AI review that
// synthesizes all findings into a single coherent assessment.
const UnifiedReviewSystemPrompt = `You are a supply chain security analyst producing a factual summary of scan findings.

You receive:
1. Rule-based category scores (11 categories, 0-22 points total)
2. AI deep analysis findings (compound patterns, data observations)
3. Attack pattern matches (if any)

Your job is to synthesize ALL of this into one coherent, factual summary of what was found.

## Score Adjustment Guidelines

You may recommend a score_adjustment of -2 to +2 points:

- **+1 or +2**: Multiple actual findings co-occur in a way that matches a documented
  attack pattern, AND the rule-based scores did not account for this combination
- **0**: Rules captured the findings accurately; no adjustment needed (MOST COMMON — default to this)
- **-1 or -2**: Actual data shows mitigating factors that rules scored too harshly
  (e.g., package scored as single-maintainer but is actually published by a verified org)

Default to 0. Only adjust based on FACTUAL evidence, never speculation.

## What You DO NOT Do

- Do NOT speculate about what "could", "might", or "may" happen
- Do NOT recommend fixes, improvements, or mitigations
- Do NOT prescribe best practices
- Focus purely on summarizing what was actually found

## Output Format

Respond ONLY with valid JSON. No markdown, no code blocks, no text outside the JSON object.

{
  "summary": "2-4 sentence factual summary of what the scan found",
  "key_risks": ["factual finding 1", "factual finding 2"],
  "business_impact": "Factual description of the package's blast radius (dependents, downloads) if known",
  "technical_details": "Key technical findings from the scan (optional, keep brief)",
  "confidence": 0.0,
  "score_adjustment": 0,
  "adjustment_reason": "Why the score should be adjusted (empty if adjustment is 0)"
}

IMPORTANT:
- Be concise. The summary should be 2-4 sentences max.
- key_risks should have 2-5 entries, each 1 sentence describing an actual finding.
- confidence should reflect data completeness: 0.9 if comprehensive data, 0.5 if many fields missing.
- Do NOT include recommendations, mitigations, or advice of any kind.
- Do NOT use speculative language — only describe what was found.`

// NewUnifiedReviewPrompt creates a prompt that synthesizes rule-based scores,
// deep analysis findings, and attack pattern matches into one unified assessment.
func NewUnifiedReviewPrompt(result *models.AnalysisResult, deepAnalysis *models.DeepAnalysisResult, attackPatterns []models.AttackPatternMatch) *PromptTemplate {
	var sb strings.Builder

	// Rule-based scores
	sb.WriteString(fmt.Sprintf("## Package: %s@%s (%s)\n\n", result.Dependency.Name, result.Dependency.Version, result.Dependency.Ecosystem))

	if result.SupplyChainScore != nil {
		sb.WriteString(fmt.Sprintf("## Rule-Based Score: %d/22 (%s risk)\n\n", result.SupplyChainScore.TotalScore, result.SupplyChainScore.RiskLevel))

		cs := result.SupplyChainScore.CategoryScores
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
		}
		sb.WriteString("\n")
	}

	// Deep analysis findings
	if deepAnalysis != nil {
		sb.WriteString("## AI Deep Analysis Findings\n\n")
		if deepAnalysis.RiskAssessment != "" {
			sb.WriteString(fmt.Sprintf("Assessment: %s\n\n", deepAnalysis.RiskAssessment))
		}
		if len(deepAnalysis.CompoundRisks) > 0 {
			sb.WriteString("Compound Risks:\n")
			for _, cr := range deepAnalysis.CompoundRisks {
				sb.WriteString(fmt.Sprintf("- [%s] %s: %s\n", cr.RiskLevel, cr.Pattern, cr.Explanation))
			}
			sb.WriteString("\n")
		}
		if len(deepAnalysis.BehaviorFindings) > 0 {
			sb.WriteString("Behavioral Anomalies:\n")
			for _, bf := range deepAnalysis.BehaviorFindings {
				sb.WriteString(fmt.Sprintf("- %s\n", bf))
			}
			sb.WriteString("\n")
		}
		if len(deepAnalysis.MissedByRules) > 0 {
			sb.WriteString("Insights Beyond Rules:\n")
			for _, insight := range deepAnalysis.MissedByRules {
				sb.WriteString(fmt.Sprintf("- %s\n", insight))
			}
			sb.WriteString("\n")
		}
	} else {
		sb.WriteString("## AI Deep Analysis: No additional findings beyond rules\n\n")
	}

	// Attack patterns
	if len(attackPatterns) > 0 {
		sb.WriteString("## Attack Pattern Matches\n\n")
		for _, ap := range attackPatterns {
			sb.WriteString(fmt.Sprintf("- [%s] %s (confidence: %.0f%%)\n", ap.Severity, ap.PatternName, ap.Confidence*100))
			if len(ap.Evidence) > 0 {
				sb.WriteString(fmt.Sprintf("  Evidence: %s\n", strings.Join(ap.Evidence, "; ")))
			}
		}
		sb.WriteString("\n")
	} else {
		sb.WriteString("## Attack Pattern Matches: None identified\n\n")
	}

	// Risk factors
	if len(result.RiskFactors) > 0 {
		sb.WriteString("## Risk Factors\n\n")
		for _, rf := range result.RiskFactors {
			sb.WriteString(fmt.Sprintf("- %s\n", rf))
		}
		sb.WriteString("\n")
	}

	return &PromptTemplate{
		SystemPrompt: UnifiedReviewSystemPrompt,
		UserPrompt: fmt.Sprintf(`Summarize the following scan findings into a single factual assessment.

%s

Produce a single JSON response summarizing what was actually found.
Base the score adjustment ONLY on factual evidence — default to 0.
Do NOT include recommendations, mitigations, or advice of any kind.
Do NOT speculate — only describe what the scan found.
Respond ONLY with valid JSON (no markdown, no code blocks).`, sb.String()),
		Parameters:  map[string]string{},
		Temperature: 0.3,
		MaxTokens:   2000,
	}
}

// ============================================================================
// REPORT-LEVEL SUMMARY PROMPT
// ============================================================================

// ReportSummarySystemPrompt provides context for generating a holistic report-level
// AI summary that synthesizes findings across ALL packages in a scan.
const ReportSummarySystemPrompt = `You are a supply chain security analyst summarizing the factual findings from a dependency scan.

You receive the complete scan results for ALL packages in a project — risk scores, findings, attack pattern matches, and per-package analysis. Your job is to synthesize the ACTUAL findings into a factual report-level summary.

## What You Summarize

Summarize the ACTUAL scan results across all packages:
- Which packages scored highest risk and what specific findings drove those scores
- Cross-package patterns from the data (e.g., N packages with single maintainer, M packages missing provenance)
- Aggregate statistics (how many HIGH/MEDIUM/LOW, common finding categories)
- Which packages have the most findings

## Critical Rules

- ONLY reference findings that are actually present in the scan data below
- NEVER speculate using "could", "might", "potentially" — state what was found
- If data was unavailable for certain checks, note it as "not assessed"
- Do NOT recommend fixes, improvements, or mitigations
- Do NOT prescribe best practices or track CVEs

## Output Format

Respond ONLY with valid JSON. No markdown, no code blocks, no text outside the JSON object.

{
  "overall_assessment": "3-5 sentence factual summary of what the scan found across all packages",
  "key_threats": ["factual finding 1 from the scan data", "factual finding 2"],
  "cross_patterns": ["pattern observed across multiple packages in the actual data"],
  "priority_packages": ["package_name: highest-scoring findings"],
  "risk_posture": "1-2 sentence factual summary of the scan results",
  "confidence": 0.0
}

IMPORTANT:
- overall_assessment should factually summarize ALL scan findings in 3-5 sentences.
- key_threats should have 2-5 entries describing the most significant findings from the data.
- cross_patterns should identify patterns that factually appear across multiple packages (may be empty).
- priority_packages should list 1-5 highest-scoring packages with their specific findings.
- confidence should reflect data completeness: 0.9 if comprehensive data, 0.5 if many checks unavailable.
- Do NOT include recommendations, mitigations, or advice of any kind.
- Do NOT use speculative language.
- Respond ONLY with valid JSON.`

// NewReportSummaryPrompt creates a prompt that synthesizes ALL package results
// into a single holistic report-level supply chain risk assessment.
// This is called AFTER all per-package analysis is complete.
func NewReportSummaryPrompt(results []models.AnalysisResult, stats ReportStats) *PromptTemplate {
	var sb strings.Builder

	// Report overview
	sb.WriteString("## Project Scan Overview\n\n")
	sb.WriteString(fmt.Sprintf("Total Packages: %d\n", stats.TotalPackages))
	sb.WriteString(fmt.Sprintf("HIGH Risk: %d (%.1f%%)\n", stats.HighRisk, float64(stats.HighRisk)/float64(max(stats.TotalPackages, 1))*100))
	sb.WriteString(fmt.Sprintf("MEDIUM Risk: %d (%.1f%%)\n", stats.MediumRisk, float64(stats.MediumRisk)/float64(max(stats.TotalPackages, 1))*100))
	sb.WriteString(fmt.Sprintf("LOW Risk: %d (%.1f%%)\n\n", stats.LowRisk, float64(stats.LowRisk)/float64(max(stats.TotalPackages, 1))*100))

	// Summarize each package (keep it compact to fit in context)
	sb.WriteString("## Package Summaries\n\n")

	for i, result := range results {
		// Limit detail for LOW risk packages
		if result.RiskLevel == "LOW" && i > 20 {
			continue // Skip low-risk packages after first 20 to save tokens
		}

		sb.WriteString(fmt.Sprintf("### %s@%s (%s) — %s Risk", result.Dependency.Name, result.Dependency.Version, result.Dependency.Ecosystem, result.RiskLevel))

		if result.SupplyChainScore != nil {
			sb.WriteString(fmt.Sprintf(" (%d/22 pts)", result.SupplyChainScore.TotalScore))
		}
		sb.WriteString("\n")

		// Key findings for HIGH/MEDIUM packages
		if result.RiskLevel == "HIGH" || result.RiskLevel == "MEDIUM" {
			for _, f := range result.Findings {
				if f.Severity == "HIGH" || f.Severity == "CRITICAL" {
					sb.WriteString(fmt.Sprintf("- [%s] %s\n", f.Severity, f.Description))
				}
			}

			// Include per-package AI unified summary if available
			if result.AIAnalysis != nil && result.AIAnalysis.UnifiedSummary != nil {
				sb.WriteString(fmt.Sprintf("- AI Summary: %s\n", result.AIAnalysis.UnifiedSummary.Summary))
			}
		}

		// Risk factors (compact)
		if len(result.RiskFactors) > 0 && (result.RiskLevel == "HIGH" || result.RiskLevel == "MEDIUM") {
			sb.WriteString(fmt.Sprintf("- Risk factors: %s\n", strings.Join(result.RiskFactors, "; ")))
		}

		sb.WriteString("\n")
	}

	// Aggregate stats
	sb.WriteString("## Aggregate Observations\n\n")

	// Count packages with install scripts
	installScripts := 0
	missingSource := 0
	singleMaintainer := 0
	missingProvenance := 0
	for _, r := range results {
		if r.Metadata.HasInstallScripts {
			installScripts++
		}
		if !r.SourceCodeAvailable {
			missingSource++
		}
		if len(r.Metadata.Maintainers) == 1 {
			singleMaintainer++
		}
		if r.SupplyChainScore != nil && r.SupplyChainScore.CategoryScores.Provenance.RiskPoints > 1 {
			missingProvenance++
		}
	}

	sb.WriteString(fmt.Sprintf("- Packages with install scripts: %d\n", installScripts))
	sb.WriteString(fmt.Sprintf("- Packages missing source code: %d\n", missingSource))
	sb.WriteString(fmt.Sprintf("- Packages with single maintainer: %d\n", singleMaintainer))
	sb.WriteString(fmt.Sprintf("- Packages missing provenance: %d\n", missingProvenance))

	return &PromptTemplate{
		SystemPrompt: ReportSummarySystemPrompt,
		UserPrompt: fmt.Sprintf(`Summarize the following complete scan results into a factual report-level overview.

%s

Produce a single JSON response summarizing what the scan found across all packages.
Reference ONLY findings that are present in the data above — do not speculate.
Note any data gaps or checks that were unavailable.
Do NOT include recommendations, mitigations, or advice of any kind.
Respond ONLY with valid JSON (no markdown, no code blocks).`, sb.String()),
		Parameters:  map[string]string{},
		Temperature: 0.3,
		MaxTokens:   2000,
	}
}

// ReportStats provides aggregate statistics for the report-level AI summary prompt.
type ReportStats struct {
	TotalPackages int
	HighRisk      int
	MediumRisk    int
	LowRisk       int
}

// ============================================================================
// COMPARATIVE ANALYSIS PROMPTS
// ============================================================================

// NewPackageComparisonPrompt creates a prompt for comparing multiple packages' risk profiles
func NewPackageComparisonPrompt(packages []string, ecosystems []models.Ecosystem, analysisResults []models.AnalysisResult) *PromptTemplate {
	// Build comparison table
	comparisonData := []string{}
	for i, pkg := range packages {
		result := analysisResults[i]
		score := "N/A"
		if result.SupplyChainScore != nil {
			score = fmt.Sprintf("%d/18 (%s)", result.SupplyChainScore.TotalScore, result.SupplyChainScore.RiskLevel)
		}

		comparisonData = append(comparisonData, fmt.Sprintf(`### Package %d: %s (%s)
- Risk Level: %s (%d/100)
- Supply Chain Score: %s
- Risk Factors: %d
- High Severity Findings: %d
- Repository Stars: %d
- Maintainers: %d
- Has CI: %v
- Has Provenance: %v`,
			i+1, pkg, ecosystems[i],
			result.RiskLevel, result.RiskScore,
			score,
			len(result.RiskFactors),
			countHighSeverityFindings(result.Findings),
			result.Metadata.RepoStars,
			len(result.Metadata.Maintainers),
			result.Metadata.HasCI,
			result.Metadata.HasSLSAAttestation || result.Metadata.HasSigstoreSignature,
		))
	}

	return &PromptTemplate{
		SystemPrompt: SemanticAnalysisSystemPrompt,
		UserPrompt: `Compare the supply chain security posture of the following packages:

{{comparisonData}}

## Analysis Request

Provide a comparative analysis covering:

1. **Relative Risk Ranking**
   - Rank packages from lowest to highest supply chain risk
   - Justify the ranking with specific factors

2. **Risk Profile Comparison**
   - Which packages share similar risk patterns?
   - Which packages have unique risk factors?
   - Are there ecosystem-specific patterns (npm vs PyPI vs Maven)?

3. **Strongest and Weakest Supply Chain Postures**
   - Which package has the strongest supply chain security posture?
   - Which package has the most concerning risk factors?
   - What differentiates the risk profiles?

4. **Risk Assessment**
   - Which packages pose the highest supply chain compromise risk and why?
   - Are there critical risk factors in any package?
   - How do the risk profiles compare for package selection decisions?

5. **Pattern Analysis**
   - Do any packages show patterns consistent with known attack vectors?
   - Are there concerning trends across multiple packages?

Focus on **relative comparison** and **actionable insights** for package selection decisions.`,
		Parameters: map[string]string{
			"comparisonData": strings.Join(comparisonData, "\n\n"),
		},
		Temperature: 0.4,
		MaxTokens:   2500,
	}
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

// countHighSeverityFindings counts HIGH and CRITICAL severity findings
func countHighSeverityFindings(findings []models.Finding) int {
	count := 0
	for _, f := range findings {
		if f.Severity == "HIGH" || f.Severity == "CRITICAL" {
			count++
		}
	}
	return count
}

// NewCustomPrompt creates a custom prompt with user-defined system and user prompts
// This allows for flexibility in creating specialized prompts for future use cases
func NewCustomPrompt(systemPrompt, userPrompt string, parameters map[string]string, temperature float64, maxTokens int) *PromptTemplate {
	return &PromptTemplate{
		SystemPrompt: systemPrompt,
		UserPrompt:   userPrompt,
		Parameters:   parameters,
		Temperature:  temperature,
		MaxTokens:    maxTokens,
	}
}

// ============================================================================
// PROMPT REGISTRY
// ============================================================================

// PromptType represents the type of prompt template
type PromptType string

const (
	PromptTypeAttackPatternMatch   PromptType = "attack_pattern_match"
	PromptTypeExecutiveExplanation PromptType = "executive_explanation"
	PromptTypePackageComparison    PromptType = "package_comparison"
	PromptTypeCustom               PromptType = "custom"
)

// GetPromptDescription returns a human-readable description of the prompt type
func GetPromptDescription(promptType PromptType) string {
	descriptions := map[PromptType]string{
		PromptTypeAttackPatternMatch:   "Compares observed behaviors to documented supply chain attack patterns",
		PromptTypeExecutiveExplanation: "Generates stakeholder-friendly explanations of risk analysis results",
		PromptTypePackageComparison:    "Compares multiple packages' supply chain security postures",
		PromptTypeCustom:               "Custom user-defined prompt template",
	}

	return descriptions[promptType]
}
