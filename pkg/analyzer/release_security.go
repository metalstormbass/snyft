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
//   - Query branch protection rules via GitHub/GitLab/Bitbucket APIs
//   - Verify signed releases via GetProvenanceInfo and CheckSignedReleases
//   - Check required PR reviews from branch protection settings
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
	if result.RepositoryURL == "" {
		return models.CategoryScore{
			Score:       0,
			RiskPoints:  2,
			Description: "Unable to verify release security controls",
			Evidence:    "No repository URL available",
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
		evidence = append(evidence, "No automated release process (local publishing risk)")
	}

	// Component 2: Branch Protection
	// Without branch protection, attackers with push access can bypass all controls
	if result.Metadata.HasBranchProtection {
		points++
		evidence = append(evidence, "Branch protection enabled on default branch")
	} else {
		evidence = append(evidence, "No branch protection (direct push allowed)")
	}

	// Component 3: Signed Releases/Tags
	// Cryptographic signatures verify release authenticity
	if result.Metadata.SignedReleases {
		points++
		evidence = append(evidence, "Releases are cryptographically signed")
	} else {
		evidence = append(evidence, "Releases not signed")
	}

	// Component 4: Required PR Reviews
	// Code review is critical for catching malicious code before merge
	if result.Metadata.RequiredReviewers > 0 {
		points++
		evidence = append(evidence, fmt.Sprintf("%d required reviewers for PRs", result.Metadata.RequiredReviewers))
	} else {
		evidence = append(evidence, "No required code reviews")
	}

	// Component 5: Build System Location (self-hosted runner detection)
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
		Evidence:    strings.Join(evidence, "; "),
		Verified:    verified,
	}
}
