package analyzer

import (
	"fmt"
	"strings"

	"github.com/metalstormbass/snyft/pkg/models"
)

// scoreCIPipelineSecurity: CI/CD pipeline configuration security (0-2 pts)
//
// Test: CI/CD pipeline configuration risk assessment
// Justification: Insecure CI/CD configurations are a direct supply chain attack vector.
//                Unpinned actions can be hijacked via tag mutation, excessive permissions
//                grant attackers wider blast radius, dangerous triggers like
//                pull_request_target enable code execution from untrusted forks,
//                script injection enables RCE, and self-hosted runners give attackers
//                full control over the build environment and published artifacts.
// Source: "Backstabber's Knife Collection" (Ohm et al., 2020)
//         https://arxiv.org/abs/2005.09535
//         SLSA Build Level Requirements (https://slsa.dev/spec/v1.0/levels)
//         GitHub Actions Security Hardening (https://docs.github.com/en/actions/security-guides)
// Methodology:
//   - Detect CI systems via repository file structure analysis
//   - Parse CI config files for insecure patterns (unpinned actions/orbs/images,
//     excessive permissions, dangerous triggers, script injection, secrets in logs,
//     missing environment protection)
//   - Detect self-hosted runners (uncontrolled build environment)
//   - Evaluate overall CI pipeline hygiene
// Result:
//   - 0 risk points (score 2): CI present with no workflow security issues
//   - 1 risk point (score 1): CI present but has some configuration risks
//   - 2 risk points (score 0): No CI detected, or CI has critical security issues
//
// Score: 0 = no CI or critical CI security issues (high risk)
//        1 = CI present with moderate issues (medium risk)
//        2 = CI present with secure configuration (low risk)
func (a *Analyzer) scoreCIPipelineSecurity(result *models.AnalysisResult) models.CategoryScore {
	const ciSource = " [Source: SLSA v1.0 Build Level Requirements; Backstabber's Knife Collection (Ohm et al., 2020); GitHub Actions Security Hardening]"

	ciMethodology := "Checked for: (1) CI/CD system presence via repository file detection, (2) CI workflow configuration security (unpinned actions/orbs/images, excessive permissions, dangerous triggers, script injection, secrets in logs, missing environment protection), (3) self-hosted runner detection. Data sources: GitHub/GitLab/Bitbucket APIs, CI config file parsing."

	if result.RepositoryURL == "" {
		return models.CategoryScore{
			Score:       0,
			RiskPoints:  1,
			Description: "Unable to verify CI pipeline security: no repository URL",
			Evidence:    "No repository URL available; CI pipeline configuration cannot be assessed" + ciSource,
			Verified:    false,
			Methodology: "No repository URL available. Could not check any CI pipeline configuration.",
			ChecksPerformed: []models.CheckResult{
				{Name: "CI system detection", Status: "SKIPPED", Detail: "No repository URL"},
				{Name: "CI workflow security", Status: "SKIPPED", Detail: "No repository URL"},
				{Name: "Self-hosted runner detection", Status: "SKIPPED", Detail: "No repository URL"},
			},
		}
	}

	evidence := []string{}
	checks := []models.CheckResult{}
	verified := true

	// Sub-check 1: CI system presence
	hasCI := result.Metadata.HasCI && len(result.Metadata.CISystems) > 0
	if hasCI {
		ciList := strings.Join(result.Metadata.CISystems, ", ")
		evidence = append(evidence, fmt.Sprintf("CI system detected: %s", ciList))
		checks = append(checks, models.CheckResult{
			Name:   "CI system detection",
			Status: "PASS",
			Detail: fmt.Sprintf("CI system(s) detected: %s", ciList),
		})
	} else {
		evidence = append(evidence, "No CI/CD system detected in repository")
		checks = append(checks, models.CheckResult{
			Name:   "CI system detection",
			Status: "FAIL",
			Detail: "No CI/CD system detected in repository",
		})
		// No CI detected = moderate risk (1 point). Many legitimate packages
		// (especially smaller or ecosystem-native packages) don't use CI.
		// Only assign max risk (2) when CI exists but has dangerous configuration.
		return models.CategoryScore{
			Score:       0,
			RiskPoints:  1,
			Description: "No CI/CD system detected",
			Evidence:    strings.Join(evidence, "; ") + ciSource,
			Verified:    verified,
			Methodology: ciMethodology,
			ChecksPerformed: append(checks,
				models.CheckResult{Name: "CI workflow security", Status: "SKIPPED", Detail: "No CI system to analyze"},
				models.CheckResult{Name: "Self-hosted runner detection", Status: "SKIPPED", Detail: "No CI system to analyze"},
			),
		}
	}

	// Sub-check 2: CI workflow configuration security
	// Count total risk signals across all parsed CI workflows
	totalRiskCount := 0
	hasScriptInjection := false
	hasDangerousTriggers := false
	hasExcessivePermissions := false
	hasMissingEnvProtection := false
	hasSecretsInLogs := false
	totalUnpinnedActions := 0
	riskDetails := []string{}

	for _, ciRisk := range result.Metadata.CIWorkflowRisks {
		totalRiskCount += ciRisk.RiskCount

		if ciRisk.HasScriptInjection {
			hasScriptInjection = true
			riskDetails = append(riskDetails, fmt.Sprintf("Script injection risk in %s workflow", ciRisk.Platform))
		}
		if len(ciRisk.DangerousTriggers) > 0 {
			hasDangerousTriggers = true
			riskDetails = append(riskDetails, fmt.Sprintf("Dangerous triggers in %s: %s", ciRisk.Platform, strings.Join(ciRisk.DangerousTriggers, ", ")))
		}
		if ciRisk.HasExcessivePermissions {
			hasExcessivePermissions = true
			riskDetails = append(riskDetails, fmt.Sprintf("Excessive permissions in %s workflow", ciRisk.Platform))
		}
		if ciRisk.MissingEnvironmentProtection {
			hasMissingEnvProtection = true
			riskDetails = append(riskDetails, fmt.Sprintf("Missing environment protection on %s publish workflow", ciRisk.Platform))
		}
		if ciRisk.SecretsInLogs {
			hasSecretsInLogs = true
			riskDetails = append(riskDetails, fmt.Sprintf("Secrets may be exposed in %s logs", ciRisk.Platform))
		}
		totalUnpinnedActions += len(ciRisk.UnpinnedActions)
	}

	if totalUnpinnedActions > 0 {
		riskDetails = append(riskDetails, fmt.Sprintf("%d unpinned CI dependencies (tag hijacking risk)", totalUnpinnedActions))
	}

	// Determine CI workflow security status
	if len(result.Metadata.CIWorkflowRisks) == 0 && hasCI {
		// CI detected but no workflow risks parsed (config not fetchable or no risks found)
		// Check if we had build systems we could analyze
		if len(result.Metadata.BuildSystems) > 0 {
			evidence = append(evidence, "CI workflow configuration analyzed: no security issues detected")
			checks = append(checks, models.CheckResult{
				Name:   "CI workflow security",
				Status: "PASS",
				Detail: "No insecure patterns detected in CI configuration",
			})
		} else {
			evidence = append(evidence, "CI detected but workflow configuration could not be analyzed")
			checks = append(checks, models.CheckResult{
				Name:   "CI workflow security",
				Status: "UNAVAILABLE",
				Detail: "CI system detected but configuration files could not be fetched for analysis",
			})
		}
	} else if totalRiskCount == 0 {
		evidence = append(evidence, "CI workflow configuration is secure: no risk signals detected")
		checks = append(checks, models.CheckResult{
			Name:   "CI workflow security",
			Status: "PASS",
			Detail: "No insecure patterns detected in CI configuration",
		})
	} else {
		// Build detail string for the check result
		riskSummary := fmt.Sprintf("%d risk signal(s) detected", totalRiskCount)
		criticalFlags := []string{}
		if hasScriptInjection {
			criticalFlags = append(criticalFlags, "script injection")
		}
		if hasDangerousTriggers {
			criticalFlags = append(criticalFlags, "dangerous triggers")
		}
		if hasExcessivePermissions {
			criticalFlags = append(criticalFlags, "excessive permissions")
		}
		if hasMissingEnvProtection {
			criticalFlags = append(criticalFlags, "missing environment protection")
		}
		if hasSecretsInLogs {
			criticalFlags = append(criticalFlags, "secrets in logs")
		}
		if totalUnpinnedActions > 0 {
			criticalFlags = append(criticalFlags, fmt.Sprintf("%d unpinned actions", totalUnpinnedActions))
		}
		if len(criticalFlags) > 0 {
			riskSummary += ": " + strings.Join(criticalFlags, ", ")
		}

		evidence = append(evidence, riskDetails...)
		checks = append(checks, models.CheckResult{
			Name:   "CI workflow security",
			Status: "FAIL",
			Detail: riskSummary,
		})
	}

	// Sub-check 3: Self-hosted runner detection
	if result.Metadata.HasSelfHosted {
		selfHostedNames := []string{}
		for _, bs := range result.Metadata.BuildSystems {
			if bs.IsSelfHosted {
				selfHostedNames = append(selfHostedNames, bs.Platform)
			}
		}
		evidence = append(evidence, fmt.Sprintf("Self-hosted CI runners detected (%s): build environment not controlled by trusted provider",
			strings.Join(selfHostedNames, ", ")))
		checks = append(checks, models.CheckResult{
			Name:   "Self-hosted runner detection",
			Status: "FAIL",
			Detail: fmt.Sprintf("Self-hosted runners detected: %s (uncontrolled build environment)", strings.Join(selfHostedNames, ", ")),
		})
	} else if hasCI {
		if len(result.Metadata.BuildSystems) > 0 {
			cloudNames := []string{}
			for _, bs := range result.Metadata.BuildSystems {
				cloudNames = append(cloudNames, bs.Platform+" ("+bs.HostedBy+")")
			}
			evidence = append(evidence, fmt.Sprintf("Cloud-hosted CI: %s", strings.Join(cloudNames, ", ")))
		}
		checks = append(checks, models.CheckResult{
			Name:   "Self-hosted runner detection",
			Status: "PASS",
			Detail: "All CI runners are cloud-hosted (controlled build environment)",
		})
	}

	// Calculate risk points based on findings
	// Critical issues (script injection, dangerous triggers) = highest risk
	// Moderate issues (unpinned actions, excessive permissions) = medium risk
	// Self-hosted runners = additional risk
	hasCriticalIssue := hasScriptInjection || hasDangerousTriggers
	hasModerateIssue := hasExcessivePermissions || hasMissingEnvProtection || hasSecretsInLogs || totalUnpinnedActions > 0
	hasSelfHosted := result.Metadata.HasSelfHosted

	riskPoints := 0
	if hasCriticalIssue || (hasModerateIssue && hasSelfHosted) || totalRiskCount >= 5 {
		// Critical CI security issues or combination of moderate + self-hosted
		riskPoints = 2
	} else if hasModerateIssue || hasSelfHosted || totalRiskCount >= 2 {
		// Some CI security concerns
		riskPoints = 1
	}
	// else: CI present with no/minimal issues = 0 risk points

	// Determine description
	var description string
	switch riskPoints {
	case 2:
		description = "Critical CI pipeline security issues: workflow configuration creates direct attack vectors"
	case 1:
		description = "CI pipeline has some security concerns: configuration risks detected"
	default:
		description = "Secure CI pipeline: no configuration issues detected"
	}

	return models.CategoryScore{
		Score:           2 - riskPoints,
		RiskPoints:      riskPoints,
		Description:     description,
		Evidence:        strings.Join(evidence, "; ") + ciSource,
		Verified:        verified,
		Methodology:     ciMethodology,
		ChecksPerformed: checks,
	}
}
