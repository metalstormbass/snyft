package analyzer

import (
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/metalstormbass/snyft/pkg/fetcher"
	"github.com/metalstormbass/snyft/pkg/models"
)

// scorePackageMaturity: package age, update frequency, and staleness (0-2 pts)
//
// Check: Package age and update frequency (PackageMaturity)
// Justification: Very new packages lack community vetting; stale packages
//                may be abandoned and vulnerable to takeover (Ohm et al., 2020).
//                New packages have not been reviewed by the community and have
//                a higher likelihood of containing malicious code or being
//                subject to dependency confusion attacks.
// Source: "Backstabber's Knife Collection" (Ohm et al., 2020)
//         https://arxiv.org/abs/2005.09535
//         "Small World with High Risks" (Zimmermann et al., 2019)
//         "Towards Measuring Supply Chain Attacks" (NDSS 2020)
// Methodology: Compare PublishedAt, RepoLastCommit, release history cadence
//              - Package age: time since first publish (PublishedAt)
//              - Staleness: time since last commit (RepoLastCommit)
//              - Cadence: coefficient of variation of inter-release intervals
// Result: 0-2 risk points based on age, update recency, and release cadence
//
// Scoring logic:
//   - 0 risk points (low risk):    Package >2yr old AND last updated <180d ago AND consistent cadence
//   - 1 risk point (medium risk):  Package 6mo-2yr old OR last updated 180-365d ago OR irregular cadence
//   - 2 risk points (high risk):   Package <6mo old OR last updated >365d ago (stale/abandoned)
func (a *Analyzer) scorePackageMaturity(result *models.AnalysisResult) models.CategoryScore {
	evidenceParts := []string{}
	verified := false

	now := time.Now()

	// Sub-check 1: Package age (PublishedAt = first publish to registry)
	// Very new packages have not been vetted by the community.
	// Dependency confusion and typosquatting attacks frequently target new namespaces.
	ageRisk := 0
	if !result.Metadata.PublishedAt.IsZero() {
		verified = true
		packageAgeDays := now.Sub(result.Metadata.PublishedAt).Hours() / 24

		if packageAgeDays < 180 { // < 6 months
			ageRisk = 2
			evidenceParts = append(evidenceParts,
				fmt.Sprintf("Package age: %.0f days (very new, <6 months)", packageAgeDays))
		} else if packageAgeDays < 730 { // 6 months – 2 years
			ageRisk = 1
			evidenceParts = append(evidenceParts,
				fmt.Sprintf("Package age: %.0f days (maturing, 6mo–2yr)", packageAgeDays))
		} else {
			ageRisk = 0
			evidenceParts = append(evidenceParts,
				fmt.Sprintf("Package age: %.0f days (established, >2yr)", packageAgeDays))
		}
	}

	// Sub-check 2: Staleness (RepoLastCommit = most recent push to repository)
	// Stale/abandoned packages are prime targets for account takeover.
	// Attackers register abandoned package names or wait for maintainers to lapse.
	stalenessRisk := 0
	if !result.Metadata.RepoLastCommit.IsZero() {
		verified = true
		daysSinceCommit := now.Sub(result.Metadata.RepoLastCommit).Hours() / 24

		if daysSinceCommit > 365 { // > 1 year stale
			stalenessRisk = 2
			evidenceParts = append(evidenceParts,
				fmt.Sprintf("Last commit: %.0f days ago (stale, >1yr)", daysSinceCommit))
		} else if daysSinceCommit > 180 { // 6–12 months
			stalenessRisk = 1
			evidenceParts = append(evidenceParts,
				fmt.Sprintf("Last commit: %.0f days ago (aging, 6–12mo)", daysSinceCommit))
		} else {
			stalenessRisk = 0
			evidenceParts = append(evidenceParts,
				fmt.Sprintf("Last commit: %.0f days ago (recent)", daysSinceCommit))
		}
	} else if !result.Metadata.RepoUpdatedAt.IsZero() {
		// Fallback to registry-reported update timestamp
		verified = true
		daysSinceUpdate := now.Sub(result.Metadata.RepoUpdatedAt).Hours() / 24

		if daysSinceUpdate > 365 {
			stalenessRisk = 2
			evidenceParts = append(evidenceParts,
				fmt.Sprintf("Last registry update: %.0f days ago (stale, >1yr)", daysSinceUpdate))
		} else if daysSinceUpdate > 180 {
			stalenessRisk = 1
			evidenceParts = append(evidenceParts,
				fmt.Sprintf("Last registry update: %.0f days ago (aging)", daysSinceUpdate))
		} else {
			stalenessRisk = 0
			evidenceParts = append(evidenceParts,
				fmt.Sprintf("Last registry update: %.0f days ago (recent)", daysSinceUpdate))
		}
	}

	// Sub-check 3: Release cadence regularity (if repository available)
	// Highly erratic release frequency can signal a compromised or hijacked package.
	// A sudden burst of releases after a long gap is a known supply chain attack pattern.
	cadenceRisk := 0
	if result.RepositoryURL != "" {
		gitClient := a.getGitClient(result.RepositoryURL)
		releases, err := gitClient.GetReleaseHistory(result.RepositoryURL, 20)
		if err == nil && len(releases) >= 3 {
			verified = true
			var cadenceEvidence string
			cadenceRisk, cadenceEvidence = scoreCadenceRegularity(releases)
			if cadenceEvidence != "" {
				evidenceParts = append(evidenceParts, cadenceEvidence)
			}
		}
	}

	// Combine sub-checks: take the maximum risk across the three sub-checks.
	// A package that is either very new OR very stale OR has erratic cadence is risky.
	riskPoints := ageRisk
	if stalenessRisk > riskPoints {
		riskPoints = stalenessRisk
	}
	if cadenceRisk > riskPoints {
		riskPoints = cadenceRisk
	}

	// If no data was available at all, default to medium risk (unknown = uncertain)
	if !verified {
		return models.CategoryScore{
			Score:       1,
			RiskPoints:  1,
			Description: "Unable to verify package maturity",
			Evidence:    "No publish date or commit history available",
			Verified:    false,
		}
	}

	var description string
	switch riskPoints {
	case 0:
		description = "Mature package: established age, recently updated, consistent releases"
	case 1:
		description = "Maturing package: moderate age or recent inactivity"
	default:
		description = "Immature or stale package: very new or long-dormant (high compromise risk)"
	}

	return models.CategoryScore{
		Score:       2 - riskPoints,
		RiskPoints:  riskPoints,
		Description: description,
		Evidence:    strings.Join(evidenceParts, "; "),
		Verified:    verified,
	}
}

// scoreCadenceRegularity measures how consistent a package's release intervals are.
// Returns a risk level (0-2) and a human-readable evidence string.
//
// Methodology: Compute the coefficient of variation (CV = stddev/mean) of inter-release
// intervals. High CV = highly irregular cadence = elevated risk.
// A CV > 2.0 indicates releases are clustered or bursty rather than steady,
// which can indicate sudden reactivation of a dormant package.
func scoreCadenceRegularity(releases []fetcher.GitHubRelease) (int, string) {
	// Filter to valid, non-draft, non-prerelease versions with publish dates
	valid := []fetcher.GitHubRelease{}
	for _, r := range releases {
		if !r.Draft && !r.Prerelease && !r.PublishedAt.IsZero() {
			valid = append(valid, r)
		}
	}

	if len(valid) < 3 {
		return 0, "" // Not enough data for cadence analysis
	}

	// Compute inter-release intervals in days (releases are newest-first from API)
	intervals := []float64{}
	for i := 0; i < len(valid)-1; i++ {
		gap := valid[i].PublishedAt.Sub(valid[i+1].PublishedAt).Hours() / 24
		if gap > 0 {
			intervals = append(intervals, gap)
		}
	}

	if len(intervals) < 2 {
		return 0, ""
	}

	// Calculate mean
	sum := 0.0
	for _, v := range intervals {
		sum += v
	}
	mean := sum / float64(len(intervals))

	if mean == 0 {
		return 0, ""
	}

	// Calculate standard deviation
	variance := 0.0
	for _, v := range intervals {
		diff := v - mean
		variance += diff * diff
	}
	variance /= float64(len(intervals))
	stddev := math.Sqrt(variance)

	// Coefficient of variation: lower is more regular
	cv := stddev / mean

	if cv > 2.0 {
		return 2, fmt.Sprintf("Highly irregular release cadence (CV=%.1f, avg %.0f days between releases)", cv, mean)
	} else if cv > 1.0 {
		return 1, fmt.Sprintf("Somewhat irregular release cadence (CV=%.1f, avg %.0f days between releases)", cv, mean)
	}

	return 0, fmt.Sprintf("Consistent release cadence (CV=%.1f, avg %.0f days between releases)", cv, mean)
}
