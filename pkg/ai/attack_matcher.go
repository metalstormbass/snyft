package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/metalstormbass/snyft/pkg/models"
)

// HistoricalAttack represents a documented supply chain attack with structured data
type HistoricalAttack struct {
	Name              string   `json:"name"`
	Date              string   `json:"date"`
	Ecosystem         string   `json:"ecosystem"`
	Description       string   `json:"description"`
	AttackVector      string   `json:"attack_vector"`
	Indicators        []string `json:"indicators"`
	ImpactDescription string   `json:"impact_description"`
	AcademicSource    string   `json:"academic_source"`
	AdditionalRefs    []string `json:"additional_refs,omitempty"`
}

// KnownAttacks is a database of documented supply chain attacks
var KnownAttacks = []HistoricalAttack{
	{
		Name:         "event-stream (2018)",
		Date:         "2018-11",
		Ecosystem:    "npm",
		Description:  "Maintainer transferred ownership to malicious actor who injected cryptocurrency-stealing code via dependency (flatmap-stream)",
		AttackVector: "Account Takeover + Malicious Dependency Injection",
		Indicators: []string{
			"Ownership transfer to new maintainer",
			"Addition of suspicious dependency (flatmap-stream)",
			"Obfuscated code in dependency",
			"Dormant package suddenly active",
			"Malicious code targeting cryptocurrency wallets",
			"Single maintainer (no distributed control)",
		},
		ImpactDescription: "Injected code stole Bitcoin wallet credentials from applications using the package. Affected Copay wallet and thousands of downstream projects.",
		AcademicSource:    "Backstabber's Knife Collection (Ohm et al., 2020) - https://arxiv.org/abs/2005.09535",
		AdditionalRefs: []string{
			"NPM Security Advisory: https://blog.npmjs.org/post/180565383195/details-about-the-event-stream-incident",
			"Snyk Analysis: https://snyk.io/blog/malicious-code-found-in-npm-package-event-stream/",
		},
	},
	{
		Name:         "ua-parser-js (2021)",
		Date:         "2021-10",
		Ecosystem:    "npm",
		Description:  "Attacker compromised maintainer account and published malicious versions containing cryptocurrency miners and credential stealers",
		AttackVector: "Account Takeover",
		Indicators: []string{
			"Account compromise (credentials stolen)",
			"Unauthorized release published",
			"Malicious install scripts (preinstall/postinstall)",
			"Cryptocurrency mining code",
			"Credential harvesting payload",
			"Single maintainer vulnerability",
			"No 2FA on account",
		},
		ImpactDescription: "Published versions contained trojanized install scripts that downloaded and executed cryptocurrency miners and password stealers. Package has 8+ million weekly downloads.",
		AcademicSource:    "Towards Measuring Supply Chain Attacks on Package Managers (NDSS 2020) - Account takeover attack taxonomy",
		AdditionalRefs: []string{
			"GitHub Security Advisory: https://github.com/advisories/GHSA-pjwm-rvh2-c87w",
			"Sonatype Analysis: https://blog.sonatype.com/npm-libraries-infected-with-cryptocurrency-miner",
		},
	},
	{
		Name:         "coa (2021)",
		Date:         "2021-11",
		Ecosystem:    "npm",
		Description:  "Attacker gained access to maintainer account and published malicious version with credential-stealing payload",
		AttackVector: "Account Takeover",
		Indicators: []string{
			"Compromised maintainer credentials",
			"Malicious version published (2.0.3, 2.0.4)",
			"Obfuscated malicious code",
			"Environment variable exfiltration",
			"Network requests to attacker-controlled server",
			"Package with moderate popularity (6.6M weekly downloads)",
		},
		ImpactDescription: "Malicious code harvested environment variables (including credentials, tokens, API keys) and sent them to attacker-controlled server. Part of broader attack campaign.",
		AcademicSource:    "Backstabber's Knife Collection (Ohm et al., 2020) - Credential harvesting patterns",
		AdditionalRefs: []string{
			"NPM Security Advisory: https://github.com/advisories/GHSA-73qr-pfmq-6rp8",
			"Recorded Future Analysis: https://www.recordedfuture.com/npm-package-compromised",
		},
	},
	{
		Name:         "node-ipc (2022)",
		Date:         "2022-03",
		Ecosystem:    "npm",
		Description:  "Legitimate maintainer intentionally injected destructive payload (protestware) that deleted files on Russian and Belarusian IPs",
		AttackVector: "Intentional Sabotage by Maintainer (Protestware)",
		Indicators: []string{
			"Legitimate maintainer gone rogue",
			"Politically-motivated malicious code",
			"File system destruction payload",
			"Geolocation-based targeting",
			"Single maintainer with full control",
			"No code review or oversight",
			"Sudden behavior change in release",
		},
		ImpactDescription: "Package intentionally deleted files on systems with Russian or Belarusian IPs as political protest. Demonstrates risk of single maintainer with unchecked control. Affected Vue.js ecosystem.",
		AcademicSource:    "SLSA Framework threat model - Insider threats and single-maintainer risk",
		AdditionalRefs: []string{
			"Snyk Advisory: https://security.snyk.io/vuln/SNYK-JS-NODEIPC-2426370",
			"Liran Tal Analysis: https://blog.lirantal.com/the-node-ipc-protestware-controversy/",
		},
	},
	{
		Name:         "eslint-scope (2018)",
		Date:         "2018-07",
		Ecosystem:    "npm",
		Description:  "Attacker compromised maintainer's NPM credentials and published malicious version that stole NPM tokens from developer machines",
		AttackVector: "Account Takeover",
		Indicators: []string{
			"Compromised NPM account credentials",
			"Malicious version published (3.7.2)",
			"Credential theft via postinstall script",
			"Exfiltration of NPM authentication tokens",
			"Network request to attacker server",
			"Package used by millions of developers",
			"No account 2FA protection",
		},
		ImpactDescription: "Stole NPM credentials from developer machines, potentially allowing attacker to compromise additional packages. Quickly detected and removed, but highlighted credential theft risk during installation.",
		AcademicSource:    "Backstabber's Knife Collection (Ohm et al., 2020) - Credential harvesting during installation",
		AdditionalRefs: []string{
			"NPM Post-Mortem: https://eslint.org/blog/2018/07/postmortem-for-malicious-package-publishes/",
			"OSSF Case Study: https://github.com/ossf/wg-securing-critical-projects/blob/main/case-studies/eslint-scope.md",
		},
	},
}

// AttackMatchRequest contains the data needed to match against known attacks
type AttackMatchRequest struct {
	PackageName   string
	Ecosystem     models.Ecosystem
	AnalysisResult models.AnalysisResult
	Threshold     float64 // Minimum similarity score (default: 0.7)
}

// AttackMatchResponse contains the AI-generated similarity assessment
type AttackMatchResponse struct {
	AttackName       string   `json:"attack_name"`
	SimilarityScore  float64  `json:"similarity_score"`  // 0.0-1.0
	Confidence       float64  `json:"confidence"`        // 0.0-1.0
	MatchingIndicators []string `json:"matching_indicators"`
	DifferingFactors []string `json:"differing_factors,omitempty"`
	Explanation      string   `json:"explanation"`
	Severity         string   `json:"severity"`  // HIGH, MEDIUM, LOW
}

// MatchAgainstKnownAttacks compares a package against the database of known supply chain attacks
// Returns matches with similarity scores above the threshold (default: 0.7)
func MatchAgainstKnownAttacks(ctx context.Context, client *Client, req AttackMatchRequest) ([]models.AttackPatternMatch, error) {
	if req.Threshold == 0 {
		req.Threshold = 0.7
	}

	// Build package profile for comparison
	packageProfile := buildPackageProfile(req.PackageName, req.Ecosystem, req.AnalysisResult)

	// For each known attack, ask Claude to assess similarity
	var matches []models.AttackPatternMatch

	for _, attack := range KnownAttacks {
		// Skip attacks from different ecosystems (unless ecosystem-agnostic patterns)
		if attack.Ecosystem != string(req.Ecosystem) && attack.Ecosystem != "universal" {
			continue
		}

		// Build comparison prompt
		prompt := buildAttackComparisonPrompt(packageProfile, attack)

		// Call Claude API
		response, err := callClaudeForComparison(ctx, client, prompt)
		if err != nil {
			// Log error but continue with other attacks
			continue
		}

		// Parse response
		if response.SimilarityScore >= req.Threshold {
			match := models.AttackPatternMatch{
				PatternName:      attack.Name,
				Description:      attack.Description,
				Confidence:       response.Confidence,
				Severity:         response.Severity,
				Evidence:         response.MatchingIndicators,
				AcademicSource:   attack.AcademicSource,
				Indicators:       attack.Indicators,
				MitigationAdvice: generateMitigationAdvice(attack, *response),
			}
			matches = append(matches, match)
		}
	}

	return matches, nil
}

// buildPackageProfile creates a structured profile of the package for comparison
func buildPackageProfile(packageName string, ecosystem models.Ecosystem, result models.AnalysisResult) string {
	var profile strings.Builder

	profile.WriteString(fmt.Sprintf("Package: %s\n", packageName))
	profile.WriteString(fmt.Sprintf("Ecosystem: %s\n", ecosystem))
	profile.WriteString(fmt.Sprintf("Risk Level: %s (Score: %d/100)\n", result.RiskLevel, result.RiskScore))

	if result.SupplyChainScore != nil {
		profile.WriteString(fmt.Sprintf("\nSupply Chain Score: %d/18 (%s)\n",
			result.SupplyChainScore.TotalScore,
			result.SupplyChainScore.RiskLevel))

		cs := result.SupplyChainScore.CategoryScores
		profile.WriteString(fmt.Sprintf("- Publisher Control: %d/2 risk points - %s\n", cs.PublisherControl.RiskPoints, cs.PublisherControl.Description))
		profile.WriteString(fmt.Sprintf("- Ownership Changes: %d/2 risk points - %s\n", cs.OwnershipChanges.RiskPoints, cs.OwnershipChanges.Description))
		profile.WriteString(fmt.Sprintf("- Release Anomalies: %d/2 risk points - %s\n", cs.ReleaseAnomalies.RiskPoints, cs.ReleaseAnomalies.Description))
		profile.WriteString(fmt.Sprintf("- Install Execution: %d/2 risk points - %s\n", cs.InstallExecution.RiskPoints, cs.InstallExecution.Description))
	}

	profile.WriteString("\nKey Characteristics:\n")
	profile.WriteString(fmt.Sprintf("- Maintainers: %d\n", len(result.Metadata.Maintainers)))
	profile.WriteString(fmt.Sprintf("- Has Install Scripts: %v\n", result.Metadata.HasInstallScripts))
	profile.WriteString(fmt.Sprintf("- Source Code Available: %v\n", result.SourceCodeAvailable))
	profile.WriteString(fmt.Sprintf("- Has CI: %v\n", result.Metadata.HasCI))
	profile.WriteString(fmt.Sprintf("- Has Provenance: %v\n", result.Metadata.HasSLSAAttestation || result.Metadata.HasSigstoreSignature))
	profile.WriteString(fmt.Sprintf("- Branch Protection: %v\n", result.Metadata.HasBranchProtection))

	if len(result.RiskFactors) > 0 {
		profile.WriteString("\nIdentified Risk Factors:\n")
		for _, rf := range result.RiskFactors {
			profile.WriteString(fmt.Sprintf("- %s\n", rf))
		}
	}

	if len(result.Findings) > 0 {
		profile.WriteString("\nHigh-Severity Findings:\n")
		for _, f := range result.Findings {
			if f.Severity == "HIGH" || f.Severity == "CRITICAL" {
				profile.WriteString(fmt.Sprintf("- [%s] %s: %s\n", f.Severity, f.Category, f.Description))
			}
		}
	}

	return profile.String()
}

// buildAttackComparisonPrompt creates a prompt for comparing a package to a known attack
func buildAttackComparisonPrompt(packageProfile string, attack HistoricalAttack) string {
	var prompt strings.Builder

	prompt.WriteString("You are analyzing a software package to determine if it exhibits patterns similar to a documented supply chain attack.\n\n")

	prompt.WriteString("## Historical Attack Pattern\n\n")
	prompt.WriteString(fmt.Sprintf("**Attack Name:** %s\n", attack.Name))
	prompt.WriteString(fmt.Sprintf("**Date:** %s\n", attack.Date))
	prompt.WriteString(fmt.Sprintf("**Attack Vector:** %s\n", attack.AttackVector))
	prompt.WriteString(fmt.Sprintf("**Description:** %s\n\n", attack.Description))

	prompt.WriteString("**Known Indicators from Historical Attack:**\n")
	for _, indicator := range attack.Indicators {
		prompt.WriteString(fmt.Sprintf("- %s\n", indicator))
	}

	prompt.WriteString(fmt.Sprintf("\n**Impact:** %s\n", attack.ImpactDescription))
	prompt.WriteString(fmt.Sprintf("**Academic Source:** %s\n\n", attack.AcademicSource))

	prompt.WriteString("## Package Under Analysis\n\n")
	prompt.WriteString(packageProfile)

	prompt.WriteString("\n## Task\n\n")
	prompt.WriteString("Compare the package under analysis to this historical attack pattern and provide a structured assessment:\n\n")
	prompt.WriteString("1. **Similarity Score** (0.0-1.0): How similar is this package's profile to the historical attack?\n")
	prompt.WriteString("   - 0.0-0.3: Minimal similarity (different pattern)\n")
	prompt.WriteString("   - 0.3-0.5: Some shared characteristics (weak match)\n")
	prompt.WriteString("   - 0.5-0.7: Moderate similarity (notable overlap)\n")
	prompt.WriteString("   - 0.7-0.9: High similarity (strong pattern match)\n")
	prompt.WriteString("   - 0.9-1.0: Near-identical pattern (almost certain match)\n\n")

	prompt.WriteString("2. **Confidence** (0.0-1.0): How confident are you in this assessment based on available data?\n\n")

	prompt.WriteString("3. **Matching Indicators**: List which indicators from the historical attack are present\n\n")

	prompt.WriteString("4. **Differing Factors**: List factors that distinguish this package from the attack\n\n")

	prompt.WriteString("5. **Explanation**: Provide a clear explanation of the comparison\n\n")

	prompt.WriteString("6. **Severity**: Assess severity (HIGH/MEDIUM/LOW) if this pattern match suggests real risk\n\n")

	prompt.WriteString("Respond ONLY with valid JSON in this exact format (no markdown, no code blocks):\n")
	prompt.WriteString("{\n")
	prompt.WriteString("  \"attack_name\": \"attack name\",\n")
	prompt.WriteString("  \"similarity_score\": 0.0,\n")
	prompt.WriteString("  \"confidence\": 0.0,\n")
	prompt.WriteString("  \"matching_indicators\": [\"indicator 1\", \"indicator 2\"],\n")
	prompt.WriteString("  \"differing_factors\": [\"factor 1\", \"factor 2\"],\n")
	prompt.WriteString("  \"explanation\": \"detailed explanation\",\n")
	prompt.WriteString("  \"severity\": \"HIGH\"\n")
	prompt.WriteString("}\n")

	return prompt.String()
}

// callClaudeForComparison calls the Claude API to assess similarity between package and attack
func callClaudeForComparison(ctx context.Context, client *Client, prompt string) (*AttackMatchResponse, error) {
	params := anthropic.MessageNewParams{
		Model:       anthropic.Model("claude-sonnet-4-5-20250929"),
		MaxTokens:   2000,
		Messages: []anthropic.MessageParam{
			anthropic.NewUserMessage(anthropic.NewTextBlock(prompt)),
		},
		Temperature: anthropic.Float(0.3), // Low temperature for analytical consistency
	}

	msg, err := client.CreateMessage(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("failed to call Claude API: %w", err)
	}

	// Extract text from response
	if len(msg.Content) == 0 {
		return nil, fmt.Errorf("empty response from Claude API")
	}

	var responseText string
	for _, block := range msg.Content {
		if block.Type == "text" {
			responseText += block.Text
		}
	}

	if responseText == "" {
		return nil, fmt.Errorf("no text content in Claude API response")
	}

	// Parse JSON response
	var response AttackMatchResponse
	// Clean potential markdown code blocks
	responseText = strings.TrimSpace(responseText)
	responseText = strings.TrimPrefix(responseText, "```json")
	responseText = strings.TrimPrefix(responseText, "```")
	responseText = strings.TrimSuffix(responseText, "```")
	responseText = strings.TrimSpace(responseText)

	if err := json.Unmarshal([]byte(responseText), &response); err != nil {
		return nil, fmt.Errorf("failed to parse Claude API response: %w (response: %s)", err, responseText)
	}

	return &response, nil
}

// generateMitigationAdvice provides contextual mitigation advice based on the attack pattern match
func generateMitigationAdvice(attack HistoricalAttack, response AttackMatchResponse) string {
	var advice strings.Builder

	advice.WriteString(fmt.Sprintf("Based on similarity to the %s attack pattern:\n\n", attack.Name))

	// Generic advice based on attack vector
	switch {
	case strings.Contains(attack.AttackVector, "Account Takeover"):
		advice.WriteString("- Verify maintainer identity and account security (check for 2FA)\n")
		advice.WriteString("- Review recent ownership or maintainer changes\n")
		advice.WriteString("- Check for unexpected releases or version changes\n")
		advice.WriteString("- Consider using package version pinning\n")

	case strings.Contains(attack.AttackVector, "Malicious Dependency"):
		advice.WriteString("- Audit all dependencies, especially recent additions\n")
		advice.WriteString("- Use dependency lock files to prevent unexpected updates\n")
		advice.WriteString("- Scan dependencies for known malicious packages\n")
		advice.WriteString("- Review transitive dependencies carefully\n")

	case strings.Contains(attack.AttackVector, "Install Script"):
		advice.WriteString("- Inspect install scripts (postinstall, preinstall) for malicious behavior\n")
		advice.WriteString("- Consider using --ignore-scripts flag during installation\n")
		advice.WriteString("- Sandbox installation processes\n")
		advice.WriteString("- Monitor network activity during package installation\n")
	}

	// Severity-based advice
	if response.Severity == "HIGH" || response.Severity == "CRITICAL" {
		advice.WriteString("\n**Immediate Actions (High Severity):**\n")
		advice.WriteString("- DO NOT use this package in production until verified safe\n")
		advice.WriteString("- Conduct thorough security audit of package code\n")
		advice.WriteString("- Report findings to package registry security team\n")
		advice.WriteString("- Consider alternative packages with better security posture\n")
	}

	return advice.String()
}

// GetKnownAttack retrieves a specific attack by name from the database
func GetKnownAttack(name string) (*HistoricalAttack, bool) {
	for _, attack := range KnownAttacks {
		if attack.Name == name {
			return &attack, true
		}
	}
	return nil, false
}

// ListKnownAttacks returns all attacks, optionally filtered by ecosystem
func ListKnownAttacks(ecosystem string) []HistoricalAttack {
	if ecosystem == "" {
		return KnownAttacks
	}

	var filtered []HistoricalAttack
	for _, attack := range KnownAttacks {
		if attack.Ecosystem == ecosystem || attack.Ecosystem == "universal" {
			filtered = append(filtered, attack)
		}
	}
	return filtered
}
