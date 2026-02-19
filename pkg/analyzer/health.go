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
	healthChecks := []models.CheckResult{}
	verified := false
	healthMethodology := "Analyzed commit distribution to calculate bus factor (number of contributors needed for 50% of commits). Checked branch protection rules and code review rates via GitHub API. Threshold: bus factor >= 3 earns a point; branch protection with required reviewers or >= 75% PR review rate earns a point."

	// Component 1: Bus Factor (from commit distribution)
	busFactor := result.Metadata.BusFactor
	if busFactor > 0 {
		verified = true
		if busFactor >= 3 {
			points++
			evidence = append(evidence, fmt.Sprintf("Bus factor: %d", busFactor))
			healthChecks = append(healthChecks, models.CheckResult{Name: "Bus factor", Status: "PASS", Detail: fmt.Sprintf("Bus factor %d >= 3 threshold (distributed development)", busFactor)})
		} else if busFactor == 2 {
			evidence = append(evidence, fmt.Sprintf("Bus factor: %d (moderate)", busFactor))
			healthChecks = append(healthChecks, models.CheckResult{Name: "Bus factor", Status: "FAIL", Detail: fmt.Sprintf("Bus factor %d < 3 threshold (moderate concentration)", busFactor)})
		} else {
			evidence = append(evidence, fmt.Sprintf("Bus factor: %d (high risk)", busFactor))
			healthChecks = append(healthChecks, models.CheckResult{Name: "Bus factor", Status: "FAIL", Detail: fmt.Sprintf("Bus factor %d (single contributor dominates)", busFactor)})
		}

		if result.Metadata.TopContributorPct > 0 {
			if result.Metadata.TopContributorPct >= 80 {
				evidence = append(evidence, fmt.Sprintf("Top contributor: %.0f%% of commits", result.Metadata.TopContributorPct))
			}
		}
	} else {
		maintainerCount := len(result.Metadata.Maintainers)
		caps := models.GetEcosystemCapabilities(result.Dependency.Ecosystem)
		if maintainerCount >= 3 {
			points++
			evidence = append(evidence, fmt.Sprintf("%d maintainers", maintainerCount))
			verified = true
			healthChecks = append(healthChecks, models.CheckResult{Name: "Bus factor", Status: "UNAVAILABLE", Detail: "Commit distribution unavailable; fell back to maintainer count"})
			healthChecks = append(healthChecks, models.CheckResult{Name: "Maintainer count (fallback)", Status: "PASS", Detail: fmt.Sprintf("%d maintainers >= 3 threshold", maintainerCount)})
		} else if maintainerCount > 0 {
			evidence = append(evidence, fmt.Sprintf("Only %d maintainer(s)", maintainerCount))
			verified = true
			healthChecks = append(healthChecks, models.CheckResult{Name: "Bus factor", Status: "UNAVAILABLE", Detail: "Commit distribution unavailable; fell back to maintainer count"})
			healthChecks = append(healthChecks, models.CheckResult{Name: "Maintainer count (fallback)", Status: "FAIL", Detail: fmt.Sprintf("Only %d maintainer(s) < 3 threshold", maintainerCount)})
		} else if !caps.HasMaintainerList {
			evidence = append(evidence, fmt.Sprintf("Maintainer count unavailable (%s does not expose this data)", result.Dependency.Ecosystem))
			healthChecks = append(healthChecks, models.CheckResult{Name: "Bus factor", Status: "UNAVAILABLE", Detail: fmt.Sprintf("%s does not expose commit distribution or maintainer data", result.Dependency.Ecosystem)})
		} else {
			healthChecks = append(healthChecks, models.CheckResult{Name: "Bus factor", Status: "UNAVAILABLE", Detail: "No commit distribution or maintainer data available"})
		}
	}

	// Component 2: Review Oversight
	if result.Metadata.HasBranchProtection && result.Metadata.RequiredReviewers > 0 {
		points++
		evidence = append(evidence, fmt.Sprintf("%d required reviewers, branch protection enabled", result.Metadata.RequiredReviewers))
		verified = true
		healthChecks = append(healthChecks, models.CheckResult{Name: "Review oversight", Status: "PASS", Detail: fmt.Sprintf("Branch protection with %d required reviewer(s)", result.Metadata.RequiredReviewers)})
	} else if result.Metadata.CodeReviewRate >= 75 {
		points++
		evidence = append(evidence, fmt.Sprintf("%.0f%% PRs reviewed", result.Metadata.CodeReviewRate))
		verified = true
		healthChecks = append(healthChecks, models.CheckResult{Name: "Review oversight", Status: "PASS", Detail: fmt.Sprintf("%.0f%% PRs reviewed (>= 75%% threshold)", result.Metadata.CodeReviewRate)})
	} else if result.Metadata.HasBranchProtection {
		evidence = append(evidence, "Branch protection enabled (no required reviewers)")
		verified = true
		healthChecks = append(healthChecks, models.CheckResult{Name: "Review oversight", Status: "FAIL", Detail: "Branch protection enabled but no required reviewers configured"})
	} else if result.Metadata.CodeReviewRate > 0 {
		evidence = append(evidence, fmt.Sprintf("%.0f%% PRs reviewed (insufficient)", result.Metadata.CodeReviewRate))
		verified = true
		healthChecks = append(healthChecks, models.CheckResult{Name: "Review oversight", Status: "FAIL", Detail: fmt.Sprintf("%.0f%% PRs reviewed (< 75%% threshold)", result.Metadata.CodeReviewRate)})
	} else {
		evidence = append(evidence, "No review oversight detected")
		healthChecks = append(healthChecks, models.CheckResult{Name: "Review oversight", Status: "FAIL", Detail: "No branch protection or code review data detected"})
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
		Score:           points,
		RiskPoints:      riskPoints,
		Description:     description,
		Evidence:        strings.Join(evidence, "; "),
		Verified:        verified,
		Methodology:     healthMethodology,
		ChecksPerformed: healthChecks,
	}
}
