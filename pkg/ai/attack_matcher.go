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
	PackageName    string
	Ecosystem      models.Ecosystem
	AnalysisResult models.AnalysisResult
	Threshold      float64 // Minimum similarity score (default: 0.7)
}

// batchAttackMatchResponse is the JSON structure for the batched attack matching response
type batchAttackMatchResponse struct {
	Matches []struct {
		AttackName         string   `json:"attack_name"`
		SimilarityScore    float64  `json:"similarity_score"`
		Confidence         float64  `json:"confidence"`
		MatchingIndicators []string `json:"matching_indicators"`
		DifferingFactors   []string `json:"differing_factors,omitempty"`
		Explanation        string   `json:"explanation"`
		Severity           string   `json:"severity"`
	} `json:"matches"`
}

// MatchAgainstKnownAttacks compares a package against ALL relevant known supply chain
// attacks in a single API call. This replaces the previous approach of making one API
// call per attack pattern, reducing API calls from N to 1.
//
// Returns matches with similarity scores above the threshold (default: 0.7).
func MatchAgainstKnownAttacks(ctx context.Context, client *Client, req AttackMatchRequest) ([]models.AttackPatternMatch, error) {
	if req.Threshold == 0 {
		req.Threshold = 0.7
	}

	// Filter relevant attacks by ecosystem
	var relevantAttacks []HistoricalAttack
	for _, attack := range KnownAttacks {
		if attack.Ecosystem == string(req.Ecosystem) || attack.Ecosystem == "universal" {
			relevantAttacks = append(relevantAttacks, attack)
		}
	}

	if len(relevantAttacks) == 0 {
		return nil, nil
	}

	// Build package profile
	packageProfile := buildPackageProfile(req.PackageName, req.Ecosystem, req.AnalysisResult)

	// Build batched comparison prompt
	prompt := buildBatchedAttackPrompt(packageProfile, relevantAttacks, req.Threshold)

	// Single API call for ALL attack comparisons
	params := anthropic.MessageNewParams{
		Model:     anthropic.Model("claude-sonnet-4-5-20250929"),
		MaxTokens: 2500,
		Messages: []anthropic.MessageParam{
			anthropic.NewUserMessage(anthropic.NewTextBlock(prompt)),
		},
		Temperature: anthropic.Float(0.3),
	}

	msg, err := client.CreateMessage(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("failed to call Claude API: %w", err)
	}

	// Extract text
	var responseText string
	for _, block := range msg.Content {
		if block.Type == "text" {
			responseText += block.Text
		}
	}

	if responseText == "" {
		return nil, fmt.Errorf("empty response from Claude API")
	}

	// Clean potential markdown wrapping
	responseText = strings.TrimSpace(responseText)
	responseText = strings.TrimPrefix(responseText, "```json")
	responseText = strings.TrimPrefix(responseText, "```")
	responseText = strings.TrimSuffix(responseText, "```")
	responseText = strings.TrimSpace(responseText)

	var resp batchAttackMatchResponse
	if err := json.Unmarshal([]byte(responseText), &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w (response: %s)", err, responseText)
	}

	// Convert to model types, filtering by threshold
	var matches []models.AttackPatternMatch
	for _, m := range resp.Matches {
		if m.SimilarityScore < req.Threshold {
			continue
		}

		// Find the matching attack for academic source
		var academicSource string
		var indicators []string
		for _, attack := range relevantAttacks {
			if attack.Name == m.AttackName {
				academicSource = attack.AcademicSource
				indicators = attack.Indicators
				break
			}
		}

		matches = append(matches, models.AttackPatternMatch{
			PatternName:    m.AttackName,
			Description:    m.Explanation,
			Confidence:     m.Confidence,
			Severity:       m.Severity,
			Evidence:       m.MatchingIndicators,
			AcademicSource: academicSource,
			Indicators:     indicators,
		})
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

// buildBatchedAttackPrompt creates a single prompt that compares a package against
// ALL relevant known attacks at once, instead of one-at-a-time.
func buildBatchedAttackPrompt(packageProfile string, attacks []HistoricalAttack, threshold float64) string {
	var prompt strings.Builder

	prompt.WriteString("You are analyzing a software package to determine if it exhibits patterns similar to documented supply chain attacks.\n\n")

	prompt.WriteString("## Package Under Analysis\n\n")
	prompt.WriteString(packageProfile)

	prompt.WriteString("\n## Known Attack Patterns to Compare Against\n\n")

	for i, attack := range attacks {
		prompt.WriteString(fmt.Sprintf("### Attack %d: %s\n", i+1, attack.Name))
		prompt.WriteString(fmt.Sprintf("**Date:** %s | **Vector:** %s\n", attack.Date, attack.AttackVector))
		prompt.WriteString(fmt.Sprintf("**Description:** %s\n", attack.Description))
		prompt.WriteString("**Indicators:**\n")
		for _, indicator := range attack.Indicators {
			prompt.WriteString(fmt.Sprintf("- %s\n", indicator))
		}
		prompt.WriteString(fmt.Sprintf("**Source:** %s\n\n", attack.AcademicSource))
	}

	prompt.WriteString("## Task\n\n")
	prompt.WriteString(fmt.Sprintf("Compare this package against ALL %d attack patterns above. For each pattern, assess the similarity.\n\n", len(attacks)))
	prompt.WriteString(fmt.Sprintf("Only include matches with similarity_score >= %.1f in the output.\n\n", threshold))
	prompt.WriteString("Scoring guide:\n")
	prompt.WriteString("- 0.0-0.3: Minimal similarity\n")
	prompt.WriteString("- 0.3-0.5: Some shared characteristics\n")
	prompt.WriteString("- 0.5-0.7: Moderate similarity\n")
	prompt.WriteString("- 0.7-0.9: High similarity (strong match)\n")
	prompt.WriteString("- 0.9-1.0: Near-identical pattern\n\n")

	prompt.WriteString("Respond ONLY with valid JSON (no markdown, no code blocks):\n")
	prompt.WriteString("{\n")
	prompt.WriteString("  \"matches\": [\n")
	prompt.WriteString("    {\n")
	prompt.WriteString("      \"attack_name\": \"exact attack name from list above\",\n")
	prompt.WriteString("      \"similarity_score\": 0.0,\n")
	prompt.WriteString("      \"confidence\": 0.0,\n")
	prompt.WriteString("      \"matching_indicators\": [\"indicator 1\"],\n")
	prompt.WriteString("      \"differing_factors\": [\"factor 1\"],\n")
	prompt.WriteString("      \"explanation\": \"why this pattern matches or doesn't\",\n")
	prompt.WriteString("      \"severity\": \"HIGH|MEDIUM|LOW\"\n")
	prompt.WriteString("    }\n")
	prompt.WriteString("  ]\n")
	prompt.WriteString("}\n\n")
	prompt.WriteString("If NO attacks have similarity >= the threshold, return {\"matches\": []}.\n")
	prompt.WriteString("Be conservative — only flag genuine pattern matches, not superficial overlaps.")

	return prompt.String()
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
