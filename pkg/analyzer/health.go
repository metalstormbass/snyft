package analyzer

import (
	"fmt"
	"strings"

	"github.com/metalstormbass/snyft/pkg/models"
)

// scoreHealth: bus factor + review oversight (0-2 pts)
//
// Two components focused on compromise resistance:
//   - Bus Factor: single contributor = single point of compromise
//   - Review Oversight: prevents direct push of malicious code
//
// CI quality is NOT scored here — test coverage measures code correctness,
// not compromise resistance.
//
// Scoring:
//   2 points = 0 risk (distributed development + review oversight)
//   1 point  = 1 risk (one signal present)
//   0 points = 2 risk (concentrated development, no reviews)
func (a *Analyzer) scoreHealth(result *models.AnalysisResult) models.CategoryScore {
	points := 0
	evidence := []string{}
	verified := false

	// Component 1: Bus Factor (from commit distribution)
	// Low bus factor = concentrated development = single point of compromise
	busFactor := result.Metadata.BusFactor
	if busFactor > 0 {
		verified = true
		if busFactor >= 3 {
			// Multiple contributors (low risk)
			points++
			evidence = append(evidence, fmt.Sprintf("Bus factor: %d", busFactor))
		} else if busFactor == 2 {
			// Moderate risk - 2 contributors
			evidence = append(evidence, fmt.Sprintf("Bus factor: %d (moderate)", busFactor))
		} else {
			// High risk - single contributor
			evidence = append(evidence, fmt.Sprintf("Bus factor: %d (high risk)", busFactor))
		}

		// Additional evidence: top contributor concentration
		if result.Metadata.TopContributorPct > 0 {
			if result.Metadata.TopContributorPct >= 80 {
				evidence = append(evidence, fmt.Sprintf("Top contributor: %.0f%% of commits", result.Metadata.TopContributorPct))
			}
		}
	} else {
		// Fallback to maintainer count if bus factor unavailable.
		// Ecosystem-aware: some registries (e.g. Maven Central) do not expose
		// maintainer lists. A zero count in those ecosystems means "data unavailable",
		// not "zero maintainers". We skip the fallback rather than penalizing.
		maintainerCount := len(result.Metadata.Maintainers)
		caps := models.GetEcosystemCapabilities(result.Dependency.Ecosystem)
		if maintainerCount >= 3 {
			points++
			evidence = append(evidence, fmt.Sprintf("%d maintainers", maintainerCount))
			verified = true
		} else if maintainerCount > 0 {
			evidence = append(evidence, fmt.Sprintf("Only %d maintainer(s)", maintainerCount))
			verified = true
		} else if !caps.HasMaintainerList {
			// Ecosystem does not expose maintainer data — do not penalize
			evidence = append(evidence, fmt.Sprintf("Maintainer count unavailable (%s does not expose this data)", result.Dependency.Ecosystem))
		}
	}

	// Component 2: Review Oversight (branch protection + required reviewers)
	// Prevents direct push of malicious code to the default branch
	if result.Metadata.HasBranchProtection && result.Metadata.RequiredReviewers > 0 {
		// Branch protection with required reviews (best case)
		points++
		evidence = append(evidence, fmt.Sprintf("%d required reviewers, branch protection enabled", result.Metadata.RequiredReviewers))
		verified = true
	} else if result.Metadata.CodeReviewRate >= 75 {
		// Most PRs reviewed (good proxy for review culture)
		points++
		evidence = append(evidence, fmt.Sprintf("%.0f%% PRs reviewed", result.Metadata.CodeReviewRate))
		verified = true
	} else if result.Metadata.HasBranchProtection {
		// Branch protection without required reviewers
		evidence = append(evidence, "Branch protection enabled (no required reviewers)")
		verified = true
	} else if result.Metadata.CodeReviewRate > 0 {
		evidence = append(evidence, fmt.Sprintf("%.0f%% PRs reviewed (insufficient)", result.Metadata.CodeReviewRate))
		verified = true
	} else {
		evidence = append(evidence, "No review oversight detected")
	}

	// Calculate risk points from two components (0-2 points possible)
	// 2 points = 0 risk, 1 point = 1 risk, 0 points = 2 risk
	riskPoints := 2 - points

	// Determine description
	description := "Poor health: concentrated development, no review oversight"
	switch points {
	case 2:
		description = "Good health: distributed development with review oversight"
	case 1:
		description = "Moderate health: bus factor or review oversight present, but not both"
	}

	return models.CategoryScore{
		Score:       points,
		RiskPoints:  riskPoints,
		Description: description,
		Evidence:    strings.Join(evidence, "; "),
		Verified:    verified,
	}
}
