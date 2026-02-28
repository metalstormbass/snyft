package analyzer

import (
	"fmt"
	"strings"

	"github.com/metalstormbass/snyft/pkg/models"
)

// scoreReleaseSecurity: CI publishing/branch protection/signed tags/PR reviews (0-2 pts)
//
// Test: Package release security controls
// Justification: Where attackers inject malicious payloads into the supply chain.
//                Local publishing from developer machines = single point of compromise.
//                No branch protection/reviews = direct path to inject malicious code.
//                GitHub Actions with excessive permissions = workflow compromise vector.
// Source: "Backstabber's Knife Collection" (Ohm et al., 2020)
//         https://arxiv.org/abs/2005.09535
//         "Towards Measuring Supply Chain Attacks on Package Managers" (NDSS 2020)
//         SLSA Build Level Requirements (https://slsa.dev/spec/v1.0/levels)
// Methodology:
//   - Check HasAutomatedReleases via CI/CD detection
//   - Query branch protection rules via GitHub/GitLab/Bitbucket APIs (with OSSF fallback)
//   - Verify signed releases via GetProvenanceInfo and CheckSignedReleases (with OSSF fallback)
//   - Check required PR reviews from branch protection or code review rate (with OSSF fallback)
//   - Analyze GitHub Actions workflow permissions for least privilege
// Result:
//   - 0 risk points (score 2): CI publishing + branch protection + signed tags + required reviews
//   - 1 risk point (score 1): Some controls present but gaps exist
//   - 2 risk points (score 0): Local publishing or no protections
//
// Score: 0 = local publishing/no protections (high risk)
//        1 = some controls but gaps (medium risk)
//        2 = CI publishing with full protections (low risk)
func (a *Analyzer) scoreReleaseSecurity(result *models.AnalysisResult) models.CategoryScore {
	// Source: SLSA v1.0 Build Level Requirements; Backstabber's Knife Collection (Ohm et al., 2020)

	relSecMethodology := "Checked for: (1) automated CI/CD release process, (2) branch protection on default branch, (3) cryptographically signed releases/tags, (4) required PR reviewers, (5) CI/CD workflow security (unpinned actions, excessive permissions, script injection, secrets in logs, missing environment protection), (6) self-hosted runner detection, (7) documented release process from contributing/release docs. Data sources: GitHub/GitLab/Bitbucket APIs with OSSF Scorecard fallback."

	if result.RepositoryURL == "" {
		return models.CategoryScore{
			Score:       1,
			RiskPoints:  1,
			Description: "No source repository URL found — unable to check for CI/CD automation, branch protection, signed releases, or review requirements. Release security is unknown.",
			Evidence:    "No repository URL available; further investigation recommended",
			Verified:    false,
			Methodology: "No repository URL available. Could not check any release security controls.",
			ChecksPerformed: []models.CheckResult{
				{Name: "CI/CD release process", Status: "SKIPPED", Detail: "No repository URL"},
				{Name: "Branch protection", Status: "SKIPPED", Detail: "No repository URL"},
				{Name: "Signed releases", Status: "SKIPPED", Detail: "No repository URL"},
				{Name: "Required PR reviews", Status: "SKIPPED", Detail: "No repository URL"},
			},
		}
	}

	points := 0
	evidence := []string{}
	relSecChecks := []models.CheckResult{}
	verified := true

	// Component 1: CI-based Publishing
	if result.Metadata.HasReleaseProcess {
		points++
		evidence = append(evidence, "Automated CI/CD release process detected")
		relSecChecks = append(relSecChecks, models.CheckResult{Name: "CI/CD release process", Status: "PASS", Detail: "Automated CI/CD release workflow detected"})
	} else {
		ossfPackaging := 0
		if result.Metadata.OSSFChecks != nil {
			if ps, ok := result.Metadata.OSSFChecks["Packaging"]; ok {
				ossfPackaging = ps
			}
		}
		if ossfPackaging >= 7 {
			points++
			evidence = append(evidence, fmt.Sprintf("OSSF Packaging: %d/10 (automated publishing)", ossfPackaging))
			relSecChecks = append(relSecChecks, models.CheckResult{Name: "CI/CD release process", Status: "PASS", Detail: fmt.Sprintf("OSSF Packaging score: %d/10 (>= 7 threshold)", ossfPackaging)})
		} else {
			evidence = append(evidence, "No automated release process (local publishing risk)")
			relSecChecks = append(relSecChecks, models.CheckResult{Name: "CI/CD release process", Status: "FAIL", Detail: "No automated release process detected; packages may be published from developer machines"})
		}
	}

	// Component 2: Branch Protection
	// The GitHub API requires admin access to read branch protection (returns 403/404
	// without it). When the API is denied, fall back to OSSF Scorecard data. If neither
	// source has data, report UNAVAILABLE rather than FAIL — "access denied" is not
	// evidence of missing protection.
	// Pattern: follows governance.go OSSF fallback (primary check → OSSF → UNAVAILABLE).
	if result.Metadata.HasBranchProtection {
		points++
		evidence = append(evidence, "Branch protection enabled on default branch")
		relSecChecks = append(relSecChecks, models.CheckResult{Name: "Branch protection", Status: "PASS", Detail: "Branch protection enabled on default branch"})
	} else {
		ossfBranchProt := 0
		if result.Metadata.OSSFChecks != nil {
			if bp, ok := result.Metadata.OSSFChecks["Branch-Protection"]; ok {
				ossfBranchProt = bp
			}
		}
		if ossfBranchProt >= 7 {
			points++
			evidence = append(evidence, fmt.Sprintf("OSSF Branch-Protection: %d/10", ossfBranchProt))
			relSecChecks = append(relSecChecks, models.CheckResult{Name: "Branch protection", Status: "PASS", Detail: fmt.Sprintf("OSSF Branch-Protection score: %d/10 (>= 7 threshold)", ossfBranchProt)})
		} else if ossfBranchProt > 0 {
			evidence = append(evidence, fmt.Sprintf("OSSF Branch-Protection: %d/10 (weak)", ossfBranchProt))
			relSecChecks = append(relSecChecks, models.CheckResult{Name: "Branch protection", Status: "FAIL", Detail: fmt.Sprintf("OSSF Branch-Protection score: %d/10 (< 7 threshold)", ossfBranchProt)})
		} else if result.Metadata.BranchProtectionDenied {
			// API returned 403/404 (admin access required) and OSSF has no data.
			// Cannot determine branch protection status — report as unavailable,
			// not as a failure, to avoid penalizing packages we simply can't check.
			evidence = append(evidence, "Branch protection status unavailable (API access denied, no OSSF data)")
			relSecChecks = append(relSecChecks, models.CheckResult{Name: "Branch protection", Status: "UNAVAILABLE", Detail: "GitHub API requires admin access to read branch protection; OSSF Scorecard has no data for this repository"})
		} else {
			evidence = append(evidence, "No branch protection detected")
			relSecChecks = append(relSecChecks, models.CheckResult{Name: "Branch protection", Status: "FAIL", Detail: "No branch protection detected via API or OSSF Scorecard"})
		}
	}

	// Component 3: Signed Releases/Tags
	if result.Metadata.SignedReleases {
		points++
		evidence = append(evidence, "Releases are cryptographically signed")
		relSecChecks = append(relSecChecks, models.CheckResult{Name: "Signed releases", Status: "PASS", Detail: "Releases are cryptographically signed"})
	} else {
		ossfSigned := 0
		if result.Metadata.OSSFChecks != nil {
			if sr, ok := result.Metadata.OSSFChecks["Signed-Releases"]; ok {
				ossfSigned = sr
			}
		}
		if ossfSigned >= 7 {
			points++
			evidence = append(evidence, fmt.Sprintf("OSSF Signed-Releases: %d/10", ossfSigned))
			relSecChecks = append(relSecChecks, models.CheckResult{Name: "Signed releases", Status: "PASS", Detail: fmt.Sprintf("OSSF Signed-Releases score: %d/10 (>= 7 threshold)", ossfSigned)})
		} else if result.Metadata.TotalReleaseCount == 0 && ossfSigned == 0 {
			relSecChecks = append(relSecChecks, models.CheckResult{Name: "Signed releases", Status: "SKIPPED", Detail: "No GitHub releases found to check for signatures"})
		} else {
			evidence = append(evidence, "Releases not signed")
			relSecChecks = append(relSecChecks, models.CheckResult{Name: "Signed releases", Status: "FAIL", Detail: "Releases are not cryptographically signed"})
		}
	}

	// Component 4: Required PR Reviews
	if result.Metadata.RequiredReviewers > 0 {
		points++
		evidence = append(evidence, fmt.Sprintf("%d required reviewers for PRs", result.Metadata.RequiredReviewers))
		relSecChecks = append(relSecChecks, models.CheckResult{Name: "Required PR reviews", Status: "PASS", Detail: fmt.Sprintf("%d required reviewer(s) configured", result.Metadata.RequiredReviewers)})
	} else if result.Metadata.CodeReviewRate >= 75 {
		points++
		evidence = append(evidence, fmt.Sprintf("%.0f%% PRs reviewed (strong review practice)", result.Metadata.CodeReviewRate))
		relSecChecks = append(relSecChecks, models.CheckResult{Name: "Required PR reviews", Status: "PASS", Detail: fmt.Sprintf("%.0f%% PRs reviewed (>= 75%% threshold)", result.Metadata.CodeReviewRate)})
	} else {
		ossfReview := 0
		if result.Metadata.OSSFChecks != nil {
			if cr, ok := result.Metadata.OSSFChecks["Code-Review"]; ok {
				ossfReview = cr
			}
		}
		if ossfReview >= 7 {
			points++
			evidence = append(evidence, fmt.Sprintf("OSSF Code-Review: %d/10", ossfReview))
			relSecChecks = append(relSecChecks, models.CheckResult{Name: "Required PR reviews", Status: "PASS", Detail: fmt.Sprintf("OSSF Code-Review score: %d/10 (>= 7 threshold)", ossfReview)})
		} else if result.Metadata.CodeReviewRate >= 50 {
			evidence = append(evidence, fmt.Sprintf("%.0f%% PRs reviewed (moderate)", result.Metadata.CodeReviewRate))
			relSecChecks = append(relSecChecks, models.CheckResult{Name: "Required PR reviews", Status: "FAIL", Detail: fmt.Sprintf("%.0f%% PRs reviewed (< 75%% threshold)", result.Metadata.CodeReviewRate)})
		} else {
			evidence = append(evidence, "No required code reviews detected")
			relSecChecks = append(relSecChecks, models.CheckResult{Name: "Required PR reviews", Status: "FAIL", Detail: "No required code reviews or review data detected"})
		}
	}

	// Component 5: Documented Release Process
	// Release documentation that describes CI/CD automation or multi-approval
	// requirements indicates formalized controls beyond what CI detection alone
	// can verify. A documented process means the project has intentionally
	// designed their release pipeline to resist compromise.
	if result.Metadata.ReleaseDocumentation != nil {
		relDocs := result.Metadata.ReleaseDocumentation
		if relDocs.HasAutomatedReleaseProcess {
			points++
			evidence = append(evidence, "Documented automated release process in release/contributing docs")
			relSecChecks = append(relSecChecks, models.CheckResult{Name: "Documented release process", Status: "PASS", Detail: fmt.Sprintf("Release documentation describes automated CI/CD process (%s)", strings.Join(relDocs.FilesFound, ", "))})
		} else if relDocs.HasMultiApprovalRequirement || relDocs.HasReleaseChecklist {
			points++
			details := []string{}
			if relDocs.HasMultiApprovalRequirement {
				details = append(details, "multi-approval requirement")
			}
			if relDocs.HasReleaseChecklist {
				details = append(details, "release checklist")
			}
			evidence = append(evidence, fmt.Sprintf("Documented release controls: %s", strings.Join(details, ", ")))
			relSecChecks = append(relSecChecks, models.CheckResult{Name: "Documented release process", Status: "PASS", Detail: fmt.Sprintf("Release documentation includes %s (%s)", strings.Join(details, " and "), strings.Join(relDocs.FilesFound, ", "))})
		} else if relDocs.HasDocumentedReleaseProcess {
			// Basic release docs exist but without specific control signals
			evidence = append(evidence, "Basic release documentation exists")
			relSecChecks = append(relSecChecks, models.CheckResult{Name: "Documented release process", Status: "PASS", Detail: fmt.Sprintf("Release/contributing documentation found (%s) but no specific CI/CD or approval controls documented", strings.Join(relDocs.FilesFound, ", "))})
		}
	} else {
		relSecChecks = append(relSecChecks, models.CheckResult{Name: "Documented release process", Status: "FAIL", Detail: "No release/contributing documentation found (checked CONTRIBUTING.md, RELEASING.md, RELEASE.md)"})
	}

	// Component 6: CI/CD Workflow Security (parsed from config files)
	// Insecure CI configurations create direct attack vectors: unpinned actions can be
	// hijacked, excessive permissions widen blast radius, script injection enables RCE.
	// Source: GitHub Actions Security Hardening; SLSA Build Level Requirements
	// (Note: was Component 5 before release docs check was added)
	ciWorkflowRiskCount := 0
	for _, ciRisk := range result.Metadata.CIWorkflowRisks {
		ciWorkflowRiskCount += ciRisk.RiskCount
		if ciRisk.HasScriptInjection {
			evidence = append(evidence, fmt.Sprintf("CI script injection risk in %s workflow", ciRisk.Platform))
		}
		if len(ciRisk.DangerousTriggers) > 0 {
			evidence = append(evidence, fmt.Sprintf("Dangerous CI triggers: %s", strings.Join(ciRisk.DangerousTriggers, ", ")))
		}
		if len(ciRisk.UnpinnedActions) > 0 {
			evidence = append(evidence, fmt.Sprintf("%d unpinned CI dependencies (tag hijacking risk)", len(ciRisk.UnpinnedActions)))
		}
		if ciRisk.HasExcessivePermissions {
			evidence = append(evidence, fmt.Sprintf("Excessive permissions in %s workflow", ciRisk.Platform))
		}
		if ciRisk.MissingEnvironmentProtection {
			evidence = append(evidence, fmt.Sprintf("No environment protection on %s publish workflow", ciRisk.Platform))
		}
		if ciRisk.SecretsInLogs {
			evidence = append(evidence, fmt.Sprintf("Secrets may be exposed in %s logs", ciRisk.Platform))
		}
	}
	// Penalize for significant CI workflow risks (3+ signals = -1 point)
	if ciWorkflowRiskCount >= 3 {
		points--
		if points < 0 {
			points = 0
		}
	}

	// Component 7: Build System Location (self-hosted runner detection)
	// Self-hosted runners give attackers who compromise the runner full control over
	// the build environment and published artifacts. Cloud-hosted runners are isolated.
	// Source: SLSA Build L3 - https://slsa.dev/spec/v1.0/levels
	if result.Metadata.HasSelfHosted {
		// Self-hosted runners negate the value of CI-based publishing
		// because the build environment is not controlled by a trusted provider
		points-- // Penalize: self-hosted erodes release security regardless of other controls
		if points < 0 {
			points = 0
		}
		selfHostedNames := []string{}
		for _, bs := range result.Metadata.BuildSystems {
			if bs.IsSelfHosted {
				selfHostedNames = append(selfHostedNames, bs.Platform)
			}
		}
		evidence = append(evidence, fmt.Sprintf("Self-hosted CI runners detected (%s): build environment not controlled by trusted provider",
			strings.Join(selfHostedNames, ", ")))
	} else if len(result.Metadata.BuildSystems) > 0 && len(result.Metadata.CISystems) > 0 {
		evidence = append(evidence, fmt.Sprintf("Cloud-hosted CI: %s", result.Metadata.CISystems[0]))
	}

	// Calculate risk points based on total security controls
	// Previous thresholds (4+ for low risk) classified 80% of packages as high risk,
	// providing no differentiation. Adjusted to recognize that any layered defense
	// meaningfully reduces compromise risk compared to zero controls.
	//   0 points earned = high risk (2 risk points) - no controls at all
	//   1-2 points earned = medium risk (1 risk point) - some controls
	//   3+ points earned = low risk (0 risk points) - strong controls
	riskPoints := 2
	if points >= 3 {
		riskPoints = 0
	} else if points >= 1 {
		riskPoints = 1
	}

	// Build description from actual evidence
	var description string
	if points >= 3 {
		description = strings.Join(evidence, "; ") + ". Multiple release security controls are in place, reducing the risk of unauthorized or tampered releases."
	} else if points >= 1 {
		description = strings.Join(evidence, "; ") + ". Some release security controls are present but gaps remain — missing controls create potential vectors for injecting malicious code into releases."
	} else {
		description = strings.Join(evidence, "; ") + ". No release security controls detected. Without CI/CD automation, branch protection, signing, or review requirements, releases may come directly from developer machines with no verification."
		if len(evidence) == 0 {
			description = "No release security controls detected. Without CI/CD automation, branch protection, signing, or review requirements, releases may come directly from developer machines with no verification."
		}
	}

	return models.CategoryScore{
		Score:           points,
		RiskPoints:      riskPoints,
		Description:     description,
		Evidence:        strings.Join(evidence, "; "),
		Verified:        verified,
		Methodology:     relSecMethodology,
		ChecksPerformed: relSecChecks,
	}
}
