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
- Risk factors identified (with academic justification)
- Evidence for each risk factor
- Likelihood assessment (not severity of impact)
- Recommendations for mitigation (if applicable)

Remember: You predict compromise likelihood. You don't track known CVEs.`

// NewSemanticAnalysisPrompt creates a prompt for semantic analysis of package behavior
// This is used to analyze package metadata, repository activity, and detect risk patterns
func NewSemanticAnalysisPrompt(packageName string, ecosystem models.Ecosystem, metadata models.PackageMetadata, findings []models.Finding) *PromptTemplate {
	// Build findings summary
	findingsSummary := ""
	if len(findings) > 0 {
		findingsList := []string{}
		for _, f := range findings {
			findingsList = append(findingsList, fmt.Sprintf("- [%s] %s: %s", f.Severity, f.Category, f.Description))
		}
		findingsSummary = strings.Join(findingsList, "\n")
	} else {
		findingsSummary = "No findings detected"
	}

	// Build metadata summary
	metadataSummary := fmt.Sprintf(`Package: %s
Ecosystem: %s
Maintainers: %d
Repository Stars: %d
Repository Forks: %d
Last Commit: %s
Has CI: %v
Has Install Scripts: %v
Has SLSA Attestation: %v
Has Sigstore Signature: %v
Bus Factor: %d
Code Review Rate: %.0f%%
Branch Protection: %v
Required Reviewers: %d`,
		packageName,
		ecosystem,
		len(metadata.Maintainers),
		metadata.RepoStars,
		metadata.RepoForks,
		metadata.RepoLastCommit.Format("2006-01-02"),
		metadata.HasCI,
		metadata.HasInstallScripts,
		metadata.HasSLSAAttestation,
		metadata.HasSigstoreSignature,
		metadata.BusFactor,
		metadata.CodeReviewRate,
		metadata.HasBranchProtection,
		metadata.RequiredReviewers,
	)

	return &PromptTemplate{
		SystemPrompt: SemanticAnalysisSystemPrompt,
		UserPrompt: `Analyze the following package for supply chain compromise risk:

## Package Metadata

{{metadata}}

## Detected Findings

{{findings}}

## Analysis Request

Based on the metadata and findings above, provide a semantic analysis of this package's supply chain risk:

1. **Risk Pattern Recognition**: What patterns suggest this package could be compromised?
2. **Maintainer Control Assessment**: How vulnerable is the maintainer control to account takeover?
3. **Release Integrity**: Can we trust the published artifacts match the source code?
4. **Community Health**: Is this package actively maintained with distributed development?
5. **Attack Surface**: What vectors could an attacker use to inject malicious code?

For each risk identified, cite the relevant academic research (Ohm et al. 2020, SLSA framework, OSSF Scorecard, etc.).

Focus on **compromise likelihood**, not code vulnerabilities or known CVEs.`,
		Parameters: map[string]string{
			"metadata": metadataSummary,
			"findings": findingsSummary,
		},
		Temperature: 0.3, // Lower temperature for analytical tasks
		MaxTokens:   2000,
	}
}

// NewCodePatternAnalysisPrompt creates a prompt for analyzing suspicious code patterns
// in install scripts (npm postinstall, Python setup.py, Java pom.xml)
func NewCodePatternAnalysisPrompt(scriptType string, scriptContent string) *PromptTemplate {
	return &PromptTemplate{
		SystemPrompt: SemanticAnalysisSystemPrompt,
		UserPrompt: `Analyze the following install-time script for supply chain risk patterns:

## Script Type: {{scriptType}}

## Script Content

` + "```" + `
{{scriptContent}}
` + "```" + `

## Analysis Request

Analyze this script for patterns that increase supply chain compromise risk:

1. **Network Access Patterns**: Does the script download code from external sources during installation?
   - Risk: Downloaded code bypasses package registry audits
   - Reference: "Backstabber's Knife Collection" - download-and-execute is a common attack pattern

2. **File System Operations**: Does the script modify files outside the package directory?
   - Risk: Global modifications can persist malicious code
   - Reference: SLSA Build Level 1 - builds should be hermetic

3. **Privilege Escalation**: Does the script attempt to gain elevated privileges (sudo, admin)?
   - Risk: Root access enables system-wide compromise
   - Reference: npm package "crossenv" attack (2017) used privilege escalation

4. **Obfuscation Techniques**: Is the code deliberately obfuscated or hard to audit?
   - Risk: Malicious actors hide intent through obfuscation
   - Reference: "event-stream" attack (2018) used obfuscated payload

5. **Environment Variable Access**: Does the script read sensitive environment variables?
   - Risk: Credential theft during installation
   - Reference: Multiple npm packages caught exfiltrating AWS credentials

6. **Child Process Spawning**: Does the script spawn subprocesses that could hide malicious behavior?
   - Risk: Process injection and sandbox escape
   - Reference: "flatmap-stream" attack used child processes

**Output Format:**

For each pattern found, provide:
- Pattern name (e.g., "Network Download", "File System Modification")
- Specific code snippet demonstrating the pattern
- Risk level (HIGH/MEDIUM/LOW)
- Academic justification (cite research or documented attacks)
- Why this increases compromise likelihood (not why it's a code vulnerability)

If no risky patterns are found, explain why the script appears benign.`,
		Parameters: map[string]string{
			"scriptType":     scriptType,
			"scriptContent": scriptContent,
		},
		Temperature: 0.2, // Very low temperature for code analysis
		MaxTokens:   1500,
	}
}

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
**Source**: Various security advisories
**Indicators**:
- Repository URL returns 404 or different content
- Repository owner account deleted
- Package still actively downloaded but unmaintained
**Historical Examples**: Various npm/PyPI packages

## Your Task

When given package behavior data:
1. Identify which attack patterns (if any) match the observed behavior
2. Explain the match quality (strong/moderate/weak match)
3. Cite the specific indicators present
4. Assess the likelihood this represents actual malicious intent vs. poor security practices
5. Provide mitigation recommendations

Focus on **pattern matching**, not on whether the package is definitively malicious.`

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

1. **Pattern Matching**: Which attack patterns (if any) match this package's behavior?
2. **Match Quality**: For each match, explain the strength (strong/moderate/weak) and why
3. **Indicator Analysis**: List the specific indicators present that match the pattern
4. **Intent Assessment**: Is this likely malicious intent or poor security practices?
5. **False Positive Risk**: What evidence would contradict the pattern match?

**Important**: This is pattern recognition, not a definitive judgment. Focus on likelihood and evidence quality.`,
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

1. **Business Impact First**: Lead with business consequences, not technical details
2. **Use Analogies**: Compare technical concepts to familiar business scenarios
3. **Quantify Risk**: Use clear metrics (Low/Medium/High) with justification
4. **Actionable Recommendations**: Always provide concrete next steps
5. **Avoid Fear-Mongering**: Be factual, not alarmist; explain likelihood not just severity

## Key Messages to Convey

### What Supply Chain Risk Means

"Supply chain risk is the likelihood that the software packages we depend on could be compromised by attackers. This is NOT about known bugs or vulnerabilities - it's about whether a package's distribution and maintenance practices make it vulnerable to future attacks."

### Why This Matters

"90% of supply chain attacks target maintainer accounts and build systems, not code vulnerabilities. Compromised packages can steal credentials, exfiltrate data, or create backdoors - all while appearing to function normally."

### How We Assess Risk

"We evaluate 10 categories of supply chain security controls:
1. Publisher Control (how easy is it to compromise the publisher?)
2. Ownership Changes (recent suspicious transfers?)
3. Release Anomalies (unusual activity patterns?)
4. Install Execution (code running during installation?)
5. Dependency Sprawl (how many dependencies?)
6. Provenance (can we verify the build?)
7. Health (is the project actively maintained?)
8. Governance (clear ownership and policies?)
9. Release Security (automated, protected releases?)
10. Package Maturity (is the package established and regularly maintained?)"

### What We Don't Do

"We don't track CVEs (known vulnerabilities) - that's what traditional vulnerability scanners do. We identify packages that are likely targets or vectors for future compromise."

## Output Format

When explaining risks:

1. **Executive Summary** (2-3 sentences)
   - Overall risk level
   - Top 1-2 concerns
   - Recommended action

2. **Business Impact** (1 paragraph)
   - What could happen if this package is compromised?
   - What business processes or data could be affected?
   - Reference relevant compliance frameworks (SOC2, ISO 27001, etc.)

3. **Technical Explanation** (simple language)
   - What specific risks were identified?
   - Why do these increase compromise likelihood?
   - Use analogies to physical security where helpful

4. **Risk Assessment** (structured)
   - Likelihood: Low/Medium/High (with justification)
   - Potential Impact: Low/Medium/High (with examples)
   - Overall Risk: Low/Medium/High/Critical

5. **Recommendations** (prioritized)
   - Immediate actions (if critical)
   - Short-term improvements (1-4 weeks)
   - Long-term strategy (ongoing)

6. **References** (optional)
   - Link to relevant academic research
   - Industry best practices (SLSA, OSSF Scorecard)
   - Comparable incidents (if applicable)

Remember: Clarity over completeness. Stakeholders need enough information to make decisions, not exhaustive technical details.`

// NewExecutiveExplanationPrompt creates a prompt for generating stakeholder-friendly reports
func NewExecutiveExplanationPrompt(packageName string, ecosystem models.Ecosystem, analysisResult models.AnalysisResult, targetAudience string) *PromptTemplate {
	// Build comprehensive context
	riskSummary := fmt.Sprintf("Risk Level: %s (Score: %d/100)", analysisResult.RiskLevel, analysisResult.RiskScore)

	if analysisResult.SupplyChainScore != nil {
		riskSummary += fmt.Sprintf("\nSupply Chain Risk: %s (%d/20 points)",
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
9. Release Security: %s (%d/2 risk points)`,
			cs.PublisherControl.Description, cs.PublisherControl.RiskPoints,
			cs.OwnershipChanges.Description, cs.OwnershipChanges.RiskPoints,
			cs.ReleaseAnomalies.Description, cs.ReleaseAnomalies.RiskPoints,
			cs.InstallExecution.Description, cs.InstallExecution.RiskPoints,
			cs.DependencySprawl.Description, cs.DependencySprawl.RiskPoints,
			cs.Provenance.Description, cs.Provenance.RiskPoints,
			cs.Health.Description, cs.Health.RiskPoints,
			cs.Governance.Description, cs.Governance.RiskPoints,
			cs.ReleaseSecurity.Description, cs.ReleaseSecurity.RiskPoints,
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

Create a comprehensive yet accessible explanation following the format:

1. **Executive Summary**
   - Overall risk level and why
   - Top concerns (max 2-3)
   - Recommended immediate action (if any)

2. **Business Impact**
   - What could happen if this package is compromised?
   - Which business processes or assets could be affected?
   - Relevant compliance considerations (if applicable)

3. **Technical Explanation** (in simple language)
   - Explain the key risks identified
   - Why these increase compromise likelihood
   - Use analogies where helpful

4. **Risk Assessment**
   - Likelihood of compromise: Low/Medium/High (with reasoning)
   - Potential business impact: Low/Medium/High (with examples)
   - Overall risk rating: Low/Medium/High/Critical

5. **Recommendations** (prioritized)
   - Immediate actions (if critical risk)
   - Short-term improvements (1-4 weeks)
   - Long-term strategy (ongoing)
   - Each recommendation should be specific and actionable

6. **Additional Context**
   - Brief reference to academic research or industry standards (SLSA, OSSF)
   - Comparable real-world incidents (if relevant)
   - Links to further reading

**Important**:
- Tailor language to the {{targetAudience}} (executive, technical, compliance, or general audience)
- Be factual, not alarmist
- Focus on likelihood and business impact, not just technical details
- Make recommendations concrete and actionable
- Remember: this is about future compromise risk, not current vulnerabilities`,
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

3. **Best and Worst Practices**
   - Which package demonstrates the best supply chain security practices?
   - Which package has the most concerning risk factors?
   - What specific practices should others adopt?

4. **Recommendations**
   - If choosing between these packages, which would you recommend and why?
   - What mitigations would reduce risk for higher-risk packages?
   - Are there deal-breaker risks in any package?

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
	PromptTypeSemanticAnalysis     PromptType = "semantic_analysis"
	PromptTypeCodePatternAnalysis  PromptType = "code_pattern_analysis"
	PromptTypeAttackPatternMatch   PromptType = "attack_pattern_match"
	PromptTypeExecutiveExplanation PromptType = "executive_explanation"
	PromptTypePackageComparison    PromptType = "package_comparison"
	PromptTypeCustom               PromptType = "custom"
)

// GetPromptDescription returns a human-readable description of the prompt type
func GetPromptDescription(promptType PromptType) string {
	descriptions := map[PromptType]string{
		PromptTypeSemanticAnalysis:     "Analyzes package metadata and behavior to identify supply chain risk patterns",
		PromptTypeCodePatternAnalysis:  "Examines install-time scripts for dangerous patterns and behaviors",
		PromptTypeAttackPatternMatch:   "Compares observed behaviors to documented supply chain attack patterns",
		PromptTypeExecutiveExplanation: "Generates stakeholder-friendly explanations of risk analysis results",
		PromptTypePackageComparison:    "Compares multiple packages' supply chain security postures",
		PromptTypeCustom:               "Custom user-defined prompt template",
	}

	return descriptions[promptType]
}
