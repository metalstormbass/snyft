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
	const releaseSecSource = " [Source: SLSA v1.0 Build Level Requirements; Backstabber's Knife Collection (Ohm et al., 2020)]"

	// When no repository URL is available, assign moderate risk (1 point) rather
	// than maximum (2 points). The absence of a URL may be due to an API failure
	// rather than genuinely missing release security. This requires investigation.
	if result.RepositoryURL == "" {
		return models.CategoryScore{
			Score:       1,
			RiskPoints:  1,
			Description: "Unable to verify release security controls: no repository URL",
			Evidence:    "No repository URL available; further investigation recommended" + releaseSecSource,
			Verified:    false,
		}
	}

	points := 0
	evidence := []string{}
	// If we have a repository URL, we can attempt verification even if controls are absent
	verified := true

	// Component 1: CI-based Publishing (automated releases)
	// Local publishing from developer machines is a major attack vector
	if result.Metadata.HasReleaseProcess {
		points++
		evidence = append(evidence, "Automated CI/CD release process detected")
	} else {
		// Fallback: OSSF Scorecard "Packaging" check indicates automated packaging/publishing
		ossfPackaging := 0
		if result.Metadata.OSSFChecks != nil {
			if ps, ok := result.Metadata.OSSFChecks["Packaging"]; ok {
				ossfPackaging = ps
			}
		}
		if ossfPackaging >= 7 {
			points++
			evidence = append(evidence, fmt.Sprintf("OSSF Packaging: %d/10 (automated publishing)", ossfPackaging))
		} else {
			evidence = append(evidence, "No automated release process (local publishing risk)")
		}
	}

	// Component 2: Branch Protection
	// Without branch protection, attackers with push access can bypass all controls.
	// The GitHub branch protection API requires admin access, so direct checks often
	// fail for third-party packages. OSSF Scorecard provides this data without requiring
	// admin permissions.
	if result.Metadata.HasBranchProtection {
		points++
		evidence = append(evidence, "Branch protection enabled on default branch")
	} else {
		// Fallback: OSSF Scorecard "Branch-Protection" check
		ossfBranchProt := 0
		if result.Metadata.OSSFChecks != nil {
			if bp, ok := result.Metadata.OSSFChecks["Branch-Protection"]; ok {
				ossfBranchProt = bp
			}
		}
		if ossfBranchProt >= 7 {
			points++
			evidence = append(evidence, fmt.Sprintf("OSSF Branch-Protection: %d/10", ossfBranchProt))
		} else if ossfBranchProt > 0 {
			evidence = append(evidence, fmt.Sprintf("OSSF Branch-Protection: %d/10 (weak)", ossfBranchProt))
		} else {
			evidence = append(evidence, "No branch protection detected")
		}
	}

	// Component 3: Signed Releases/Tags
	// Cryptographic signatures verify release authenticity
	if result.Metadata.SignedReleases {
		points++
		evidence = append(evidence, "Releases are cryptographically signed")
	} else {
		// Fallback: OSSF Scorecard "Signed-Releases" check
		ossfSigned := 0
		if result.Metadata.OSSFChecks != nil {
			if sr, ok := result.Metadata.OSSFChecks["Signed-Releases"]; ok {
				ossfSigned = sr
			}
		}
		if ossfSigned >= 7 {
			points++
			evidence = append(evidence, fmt.Sprintf("OSSF Signed-Releases: %d/10", ossfSigned))
		} else {
			evidence = append(evidence, "Releases not signed")
		}
	}

	// Component 4: Required PR Reviews
	// Code review is critical for catching malicious code before merge.
	// The branch protection API (which provides RequiredReviewers) requires admin access,
	// so we fall back to code review rate and OSSF Scorecard data.
	if result.Metadata.RequiredReviewers > 0 {
		points++
		evidence = append(evidence, fmt.Sprintf("%d required reviewers for PRs", result.Metadata.RequiredReviewers))
	} else if result.Metadata.CodeReviewRate >= 75 {
		// High code review rate is strong evidence of review practices even without
		// branch protection API access
		points++
		evidence = append(evidence, fmt.Sprintf("%.0f%% PRs reviewed (strong review practice)", result.Metadata.CodeReviewRate))
	} else {
		// Fallback: OSSF Scorecard "Code-Review" check
		ossfReview := 0
		if result.Metadata.OSSFChecks != nil {
			if cr, ok := result.Metadata.OSSFChecks["Code-Review"]; ok {
				ossfReview = cr
			}
		}
		if ossfReview >= 7 {
			points++
			evidence = append(evidence, fmt.Sprintf("OSSF Code-Review: %d/10", ossfReview))
		} else if result.Metadata.CodeReviewRate >= 50 {
			evidence = append(evidence, fmt.Sprintf("%.0f%% PRs reviewed (moderate)", result.Metadata.CodeReviewRate))
		} else {
			evidence = append(evidence, "No required code reviews detected")
		}
	}

	// Component 5: CI/CD Workflow Security (parsed from config files)
	// Insecure CI configurations create direct attack vectors: unpinned actions can be
	// hijacked, excessive permissions widen blast radius, script injection enables RCE.
	// Source: GitHub Actions Security Hardening; SLSA Build Level Requirements
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
	}
	// Penalize for significant CI workflow risks (3+ signals = -1 point)
	if ciWorkflowRiskCount >= 3 {
		points--
		if points < 0 {
			points = 0
		}
	}

	// Component 6: Build System Location (self-hosted runner detection)
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
	// Strong release security requires multiple layers of defense
	// 0-1 points earned = high risk (2 risk points) - minimal controls
	// 2-3 points earned = medium risk (1 risk point) - some controls
	// 4+ points earned = low risk (0 risk points) - comprehensive controls
	riskPoints := 2
	if points >= 4 {
		riskPoints = 0
	} else if points >= 2 {
		riskPoints = 1
	}

	// Determine description based on risk level
	description := "Poor release security: local publishing or no protections"
	if points >= 4 {
		description = "Strong release security: CI publishing with comprehensive protections"
	} else if points >= 2 {
		description = "Moderate release security: some controls present but gaps remain"
	} else if points >= 1 {
		description = "Weak release security: minimal controls in place"
	}

	return models.CategoryScore{
		Score:       points,
		RiskPoints:  riskPoints,
		Description: description,
		Evidence:    strings.Join(evidence, "; ") + releaseSecSource,
		Verified:    verified,
	}
}
