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
	maturityChecks := []models.CheckResult{}
	verified := false
	maturityMethodology := "Checked package age (time since first publish), staleness (time since last commit or registry update), and release cadence regularity (coefficient of variation of inter-release intervals). Release cadence uses Git platform releases when available, falling back to registry version history (npm time field, PyPI releases, Maven Central timestamps). Thresholds: age <6mo = high risk, 6mo-2yr = moderate; staleness >1yr = high risk, 6-12mo = moderate; CV > 2.5 = irregular cadence (only flagged when combined with single maintainer)."

	now := time.Now()

	// Sub-check 1: Package age
	ageRisk := 0
	if !result.Metadata.PublishedAt.IsZero() {
		verified = true
		packageAgeDays := now.Sub(result.Metadata.PublishedAt).Hours() / 24

		if packageAgeDays < 180 {
			ageRisk = 2
			evidenceParts = append(evidenceParts,
				fmt.Sprintf("Package age: %.0f days (very new, <6 months)", packageAgeDays))
			maturityChecks = append(maturityChecks, models.CheckResult{Name: "Package age", Status: "FAIL", Detail: fmt.Sprintf("First published %.0f days ago (< 180 day threshold); published %s", packageAgeDays, result.Metadata.PublishedAt.Format("2006-01-02"))})
		} else if packageAgeDays < 730 {
			ageRisk = 1
			evidenceParts = append(evidenceParts,
				fmt.Sprintf("Package age: %.0f days (maturing, 6mo–2yr)", packageAgeDays))
			maturityChecks = append(maturityChecks, models.CheckResult{Name: "Package age", Status: "FAIL", Detail: fmt.Sprintf("First published %.0f days ago (< 730 day threshold); published %s", packageAgeDays, result.Metadata.PublishedAt.Format("2006-01-02"))})
		} else {
			ageRisk = 0
			evidenceParts = append(evidenceParts,
				fmt.Sprintf("Package age: %.0f days (established, >2yr)", packageAgeDays))
			maturityChecks = append(maturityChecks, models.CheckResult{Name: "Package age", Status: "PASS", Detail: fmt.Sprintf("First published %.0f days ago (> 2 year threshold); published %s", packageAgeDays, result.Metadata.PublishedAt.Format("2006-01-02"))})
		}
	} else {
		maturityChecks = append(maturityChecks, models.CheckResult{Name: "Package age", Status: "UNAVAILABLE", Detail: "No publish date available in registry metadata"})
	}

	// Sub-check 2: Staleness
	stalenessRisk := 0
	if !result.Metadata.RepoLastCommit.IsZero() {
		verified = true
		daysSinceCommit := now.Sub(result.Metadata.RepoLastCommit).Hours() / 24

		if daysSinceCommit > 365 {
			stalenessRisk = 2
			evidenceParts = append(evidenceParts,
				fmt.Sprintf("Last commit: %.0f days ago (stale, >1yr)", daysSinceCommit))
			maturityChecks = append(maturityChecks, models.CheckResult{Name: "Staleness", Status: "FAIL", Detail: fmt.Sprintf("Last commit %.0f days ago (> 365 day threshold); date: %s", daysSinceCommit, result.Metadata.RepoLastCommit.Format("2006-01-02"))})
		} else if daysSinceCommit > 180 {
			stalenessRisk = 1
			evidenceParts = append(evidenceParts,
				fmt.Sprintf("Last commit: %.0f days ago (aging, 6–12mo)", daysSinceCommit))
			maturityChecks = append(maturityChecks, models.CheckResult{Name: "Staleness", Status: "FAIL", Detail: fmt.Sprintf("Last commit %.0f days ago (> 180 day threshold); date: %s", daysSinceCommit, result.Metadata.RepoLastCommit.Format("2006-01-02"))})
		} else {
			stalenessRisk = 0
			evidenceParts = append(evidenceParts,
				fmt.Sprintf("Last commit: %.0f days ago (recent)", daysSinceCommit))
			maturityChecks = append(maturityChecks, models.CheckResult{Name: "Staleness", Status: "PASS", Detail: fmt.Sprintf("Last commit %.0f days ago (within 180 days); date: %s", daysSinceCommit, result.Metadata.RepoLastCommit.Format("2006-01-02"))})
		}
	} else if !result.Metadata.RepoUpdatedAt.IsZero() {
		verified = true
		daysSinceUpdate := now.Sub(result.Metadata.RepoUpdatedAt).Hours() / 24

		if daysSinceUpdate > 365 {
			stalenessRisk = 2
			evidenceParts = append(evidenceParts,
				fmt.Sprintf("Last registry update: %.0f days ago (stale, >1yr)", daysSinceUpdate))
			maturityChecks = append(maturityChecks, models.CheckResult{Name: "Staleness", Status: "FAIL", Detail: fmt.Sprintf("Last registry update %.0f days ago (> 365 day threshold, via registry fallback)", daysSinceUpdate)})
		} else if daysSinceUpdate > 180 {
			stalenessRisk = 1
			evidenceParts = append(evidenceParts,
				fmt.Sprintf("Last registry update: %.0f days ago (aging)", daysSinceUpdate))
			maturityChecks = append(maturityChecks, models.CheckResult{Name: "Staleness", Status: "FAIL", Detail: fmt.Sprintf("Last registry update %.0f days ago (> 180 day threshold, via registry fallback)", daysSinceUpdate)})
		} else {
			stalenessRisk = 0
			evidenceParts = append(evidenceParts,
				fmt.Sprintf("Last registry update: %.0f days ago (recent)", daysSinceUpdate))
			maturityChecks = append(maturityChecks, models.CheckResult{Name: "Staleness", Status: "PASS", Detail: fmt.Sprintf("Last registry update %.0f days ago (via registry fallback)", daysSinceUpdate)})
		}
	} else {
		maturityChecks = append(maturityChecks, models.CheckResult{Name: "Staleness", Status: "UNAVAILABLE", Detail: "No commit or registry update timestamp available"})
	}

	// Sub-check 3: Release cadence regularity
	// Try Git platform releases first, fall back to registry version history
	cadenceRisk := 0
	var registryReleases []fetcher.RegistryRelease
	if result.RepositoryURL != "" {
		gitClient := a.getGitClient(result.RepositoryURL)
		ghReleases, err := gitClient.GetReleaseHistory(result.RepositoryURL, 20)
		if err == nil && len(ghReleases) > 0 {
			registryReleases = fetcher.GitHubReleasesToRegistryReleases(ghReleases)
		}
	}
	// Fall back to registry version history when Git releases are unavailable
	if len(registryReleases) == 0 {
		registryReleases = a.getRegistryVersionHistory(result.Dependency, 20)
	}
	if len(registryReleases) >= 3 {
		verified = true
		var cadenceEvidence string
		cadenceRisk, cadenceEvidence = scoreCadenceRegularity(registryReleases)
		// Only flag irregular cadence when combined with single maintainer.
		// Irregular cadence alone is common in healthy projects; it becomes a
		// risk signal only when a single maintainer could be compromised.
		isSingleMaintainer := len(result.Metadata.Maintainers) == 1
		if cadenceRisk >= 1 && !isSingleMaintainer {
			cadenceEvidence = cadenceEvidence + " (not flagged: multiple maintainers)"
			cadenceRisk = 0
		}
		if cadenceEvidence != "" {
			evidenceParts = append(evidenceParts, cadenceEvidence)
		}
		status := "PASS"
		if cadenceRisk >= 1 {
			status = "FAIL"
		}
		maturityChecks = append(maturityChecks, models.CheckResult{Name: "Release cadence", Status: status, Detail: cadenceEvidence})
	} else if len(registryReleases) > 0 {
		maturityChecks = append(maturityChecks, models.CheckResult{Name: "Release cadence", Status: "SKIPPED", Detail: fmt.Sprintf("Insufficient releases for cadence analysis (%d < 3 required)", len(registryReleases))})
	} else if result.RepositoryURL != "" {
		maturityChecks = append(maturityChecks, models.CheckResult{Name: "Release cadence", Status: "UNAVAILABLE", Detail: "Could not fetch release history from Git API or package registry"})
	} else {
		maturityChecks = append(maturityChecks, models.CheckResult{Name: "Release cadence", Status: "SKIPPED", Detail: "No repository URL available and registry version history unavailable"})
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

	// Source: Backstabber's Knife Collection (Ohm et al., 2020); Small World with High Risks (Zimmermann et al., 2019)

	// If no data was available at all, default to medium risk
	if !verified {
		return models.CategoryScore{
			Score:       1,
			RiskPoints:  1,
			Description: "No publish date or commit history available to assess package maturity. Unable to determine package age, staleness, or release cadence.",
			Evidence:    "No publish date or commit history available",
			Verified:    false,
			DataAvailable: false,
			Methodology: maturityMethodology,
			ChecksPerformed: maturityChecks,
		}
	}

	// Build description from actual evidence, tailored to the specific risk driver
	var description string
	evidenceJoined := strings.Join(evidenceParts, "; ")
	switch riskPoints {
	case 0:
		description = evidenceJoined + ". Established packages with recent activity and consistent release cadence have been community-vetted over time."
	case 1:
		switch {
		case cadenceRisk >= 1 && ageRisk == 0 && stalenessRisk == 0:
			description = evidenceJoined + ". Irregular release cadence may indicate inconsistent maintenance or sudden bursts of activity worth monitoring."
		case stalenessRisk >= 1 && ageRisk == 0:
			description = evidenceJoined + ". Package shows signs of reduced maintenance — stale projects may be at higher risk of account takeover."
		case ageRisk >= 1 && stalenessRisk == 0:
			description = evidenceJoined + ". Relatively new package with limited community vetting history."
		default:
			description = evidenceJoined + ". Moderate maturity concerns — the package is either relatively new, showing signs of reduced maintenance, or has irregular release cadence."
		}
	default:
		switch {
		case cadenceRisk >= 2 && ageRisk == 0 && stalenessRisk == 0:
			description = evidenceJoined + ". Highly irregular release cadence can indicate sudden reactivation of a dormant package — a common supply chain attack pattern."
		case stalenessRisk >= 2 && ageRisk == 0:
			description = evidenceJoined + ". Very stale packages may be abandoned and vulnerable to account takeover."
		case ageRisk >= 2 && stalenessRisk == 0:
			description = evidenceJoined + ". Very new packages lack community vetting and may be subject to dependency confusion attacks."
		default:
			description = evidenceJoined + ". Multiple maturity concerns detected — new or stale packages with irregular release patterns are at elevated risk of supply chain compromise."
		}
	}

	return models.CategoryScore{
		Score:           2 - riskPoints,
		RiskPoints:      riskPoints,
		Description:     description,
		Evidence:        strings.Join(evidenceParts, "; "),
		Verified:        verified,
		DataAvailable:   verified,
		Methodology:     maturityMethodology,
		ChecksPerformed: maturityChecks,
	}
}

// scoreCadenceRegularity measures how consistent a package's release intervals are.
// Returns a risk level (0-2) and a human-readable evidence string.
//
// Methodology: Compute the coefficient of variation (CV = stddev/mean) of inter-release
// intervals. High CV = highly irregular cadence = elevated risk.
// A CV > 2.5 indicates releases are clustered or bursty rather than steady,
// which can indicate sudden reactivation of a dormant package.
// Note: cadence risk is only applied when combined with single maintainer
// (checked by caller), since irregular cadence alone is common in healthy projects.
func scoreCadenceRegularity(releases []fetcher.RegistryRelease) (int, string) {
	// Filter to valid, non-prerelease versions with publish dates
	valid := []fetcher.RegistryRelease{}
	for _, r := range releases {
		if !r.IsPrerelease && !r.PublishedAt.IsZero() {
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

	if cv > 2.5 {
		return 1, fmt.Sprintf("Irregular release cadence (CV=%.1f, avg %.0f days between releases)", cv, mean)
	}

	return 0, fmt.Sprintf("Consistent release cadence (CV=%.1f, avg %.0f days between releases)", cv, mean)
}
