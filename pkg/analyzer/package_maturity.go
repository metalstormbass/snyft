package analyzer

import (
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/metalstormbass/snyft/pkg/fetcher"
	"github.com/metalstormbass/snyft/pkg/models"
)

// deprecationKeywords are phrases that indicate a package has been explicitly
// deprecated or abandoned by its maintainers. Matched case-insensitively
// against the repository description and package description.
var deprecationKeywords = []string{
	"deprecated",
	"unmaintained",
	"archived",
	"end of life",
	"end-of-life",
	"no longer maintained",
	"no longer supported",
	"use instead",
	"use x instead",
	"moved to",
	"superseded by",
	"replaced by",
}

// scorePackageMaturity: package age, update frequency, staleness, and abandonment/deprecation (0-2 pts)
//
// Check: Package age, update frequency, and lifecycle status (PackageMaturity)
// Justification: Very new packages lack community vetting; stale packages
//                may be abandoned and vulnerable to takeover (Ohm et al., 2020).
//                New packages have not been reviewed by the community and have
//                a higher likelihood of containing malicious code or being
//                subject to dependency confusion attacks. Packages with no
//                releases for 3+ years are likely abandoned and highly vulnerable
//                to account takeover. Explicitly deprecated packages should be
//                distinguished from silently abandoned ones.
// Source: "Backstabber's Knife Collection" (Ohm et al., 2020)
//         https://arxiv.org/abs/2005.09535
//         "Small World with High Risks" (Zimmermann et al., 2019)
//         "Towards Measuring Supply Chain Attacks" (NDSS 2020)
// Methodology: Compare RepoCreatedAt/PublishedAt, RepoLastCommit, release history cadence,
//              deprecation keywords in description, and GitHub archived status.
//              - Package age: time since repo creation (RepoCreatedAt) or first publish (PublishedAt)
//              - Staleness: time since last commit (RepoLastCommit)
//              - Abandonment: no releases for 3+ years = HIGH risk
//              - Deprecation: keywords in description (deprecated, unmaintained, archived, etc.)
//              - Archived: GitHub archived status from API or scraping
//              - Cadence: coefficient of variation of inter-release intervals
// Result: 0-2 risk points based on age, update recency, lifecycle status, and release cadence
//
// Scoring logic:
//   - 0 risk points (low risk):    Package >2yr old AND last updated <180d ago AND consistent cadence
//   - 1 risk point (medium risk):  Package 6mo-2yr old OR last updated 180-365d ago OR irregular cadence
//   - 2 risk points (high risk):   Package <6mo old OR last updated >365d ago OR abandoned (3yr+) OR deprecated OR archived
func (a *Analyzer) scorePackageMaturity(result *models.AnalysisResult) models.CategoryScore {
	evidenceParts := []string{}
	maturityChecks := []models.CheckResult{}
	verified := false
	maturityMethodology := "Checked package age (time since first publish), staleness (time since last commit or registry update), abandonment (no releases for 3+ years), deprecation keywords in description (deprecated, unmaintained, archived, end of life, etc.), GitHub archived status, and release cadence regularity (coefficient of variation of inter-release intervals). Release cadence uses Git platform releases when available, falling back to registry version history (npm time field, PyPI releases, Maven Central timestamps). Thresholds: age <6mo = high risk, 6mo-2yr = moderate; staleness >1yr = high risk, 6-12mo = moderate; 3yr+ staleness = abandoned; CV > 2.5 = irregular cadence (only flagged when combined with single maintainer)."

	now := time.Now()

	// -----------------------------------------------------------------------
	// Early return: Deprecated package (explicit maintainer signal)
	// Deprecated packages have been intentionally abandoned by their maintainers.
	// This is distinct from silent abandonment — the maintainer has acknowledged
	// the package should not be used. While explicit deprecation is better than
	// silent abandonment, the package is still unmaintained and vulnerable.
	// -----------------------------------------------------------------------
	deprecationSignal := detectDeprecation(result)
	if deprecationSignal != "" {
		verified = true
		evidenceParts = append(evidenceParts, deprecationSignal)
		maturityChecks = append(maturityChecks, models.CheckResult{
			Name:   "Deprecation detection",
			Status: "FAIL",
			Detail: deprecationSignal,
		})

		return models.CategoryScore{
			Score:       0,
			RiskPoints:  2,
			Description: deprecationSignal + ". Deprecated packages are no longer maintained — security issues will not be patched, and maintainer accounts may go unmonitored. Unlike silently abandoned packages, deprecation is an explicit signal from the maintainer that this package should not be used.",
			Evidence:    deprecationSignal,
			Verified:    true,
			DataAvailable: true,
			Methodology: maturityMethodology,
			ChecksPerformed: maturityChecks,
		}
	}

	// -----------------------------------------------------------------------
	// Early return: Archived repository (GitHub archived status)
	// Archived repos are permanently read-only. This is handled here in addition
	// to governance because it directly affects package maturity assessment.
	// -----------------------------------------------------------------------
	if result.Metadata.RepoArchived {
		verified = true
		archiveEvidence := "Repository is archived (read-only, no longer accepting contributions)"
		evidenceParts = append(evidenceParts, archiveEvidence)
		maturityChecks = append(maturityChecks, models.CheckResult{
			Name:   "Archived status",
			Status: "FAIL",
			Detail: archiveEvidence,
		})

		return models.CategoryScore{
			Score:       0,
			RiskPoints:  2,
			Description: archiveEvidence + ". Archived repositories cannot receive security patches. This is an explicit signal that the project is no longer maintained.",
			Evidence:    archiveEvidence,
			Verified:    true,
			DataAvailable: true,
			Methodology: maturityMethodology,
			ChecksPerformed: maturityChecks,
		}
	}

	// Sub-check 1: Package age
	// Use repo creation date (from GitHub/GitLab) as primary age source — it reflects
	// when the project actually started, not when an artifact was indexed. Fall back to
	// registry first-publish date if repo creation date is unavailable.
	ageRisk := 0
	var packageAgeDate time.Time
	var ageSource string
	if !result.Metadata.RepoCreatedAt.IsZero() {
		packageAgeDate = result.Metadata.RepoCreatedAt
		ageSource = "repo created"
	} else if !result.Metadata.PublishedAt.IsZero() {
		packageAgeDate = result.Metadata.PublishedAt
		ageSource = "first published"
	}

	if !packageAgeDate.IsZero() {
		verified = true
		packageAgeDays := now.Sub(packageAgeDate).Hours() / 24

		if packageAgeDays < 180 {
			ageRisk = 2
			evidenceParts = append(evidenceParts,
				fmt.Sprintf("Package age: %.0f days (very new, <6 months)", packageAgeDays))
			maturityChecks = append(maturityChecks, models.CheckResult{Name: "Package age", Status: "FAIL", Detail: fmt.Sprintf("Project %.0f days old (< 180 day threshold); %s %s", packageAgeDays, ageSource, packageAgeDate.Format("2006-01-02"))})
		} else if packageAgeDays < 730 {
			ageRisk = 1
			evidenceParts = append(evidenceParts,
				fmt.Sprintf("Package age: %.0f days (maturing, 6mo–2yr)", packageAgeDays))
			maturityChecks = append(maturityChecks, models.CheckResult{Name: "Package age", Status: "FAIL", Detail: fmt.Sprintf("Project %.0f days old (< 730 day threshold); %s %s", packageAgeDays, ageSource, packageAgeDate.Format("2006-01-02"))})
		} else {
			ageRisk = 0
			evidenceParts = append(evidenceParts,
				fmt.Sprintf("Package age: %.0f days (established, >2yr)", packageAgeDays))
			maturityChecks = append(maturityChecks, models.CheckResult{Name: "Package age", Status: "PASS", Detail: fmt.Sprintf("Project %.0f days old (> 2 year threshold); %s %s", packageAgeDays, ageSource, packageAgeDate.Format("2006-01-02"))})
		}
	} else {
		maturityChecks = append(maturityChecks, models.CheckResult{Name: "Package age", Status: "UNAVAILABLE", Detail: "No repo creation date or registry publish date available"})
	}

	// Sub-check 2: Staleness (with 3+ year abandonment escalation)
	// Packages with no activity for 3+ years are considered abandoned (HIGH risk).
	// This is distinct from deprecated packages — abandoned packages have been
	// silently left without any maintainer signal.
	stalenessRisk := 0
	isAbandoned := false
	var daysSinceActivity float64
	if !result.Metadata.RepoLastCommit.IsZero() {
		verified = true
		daysSinceActivity = now.Sub(result.Metadata.RepoLastCommit).Hours() / 24

		if daysSinceActivity > 1095 { // 3+ years = abandoned
			stalenessRisk = 2
			isAbandoned = true
			years := daysSinceActivity / 365
			evidenceParts = append(evidenceParts,
				fmt.Sprintf("ABANDONED: Last commit %.0f days ago (%.1f years, no activity for 3+ years)", daysSinceActivity, years))
			maturityChecks = append(maturityChecks, models.CheckResult{
				Name:   "Abandonment detection",
				Status: "FAIL",
				Detail: fmt.Sprintf("Package abandoned: last commit %.0f days ago (%.1f years, > 3 year threshold); date: %s", daysSinceActivity, years, result.Metadata.RepoLastCommit.Format("2006-01-02")),
			})
		} else if daysSinceActivity > 365 {
			stalenessRisk = 2
			evidenceParts = append(evidenceParts,
				fmt.Sprintf("Last commit: %.0f days ago (stale, >1yr)", daysSinceActivity))
			maturityChecks = append(maturityChecks, models.CheckResult{Name: "Staleness", Status: "FAIL", Detail: fmt.Sprintf("Last commit %.0f days ago (> 365 day threshold); date: %s", daysSinceActivity, result.Metadata.RepoLastCommit.Format("2006-01-02"))})
		} else if daysSinceActivity > 180 {
			stalenessRisk = 1
			evidenceParts = append(evidenceParts,
				fmt.Sprintf("Last commit: %.0f days ago (aging, 6–12mo)", daysSinceActivity))
			maturityChecks = append(maturityChecks, models.CheckResult{Name: "Staleness", Status: "FAIL", Detail: fmt.Sprintf("Last commit %.0f days ago (> 180 day threshold); date: %s", daysSinceActivity, result.Metadata.RepoLastCommit.Format("2006-01-02"))})
		} else {
			stalenessRisk = 0
			evidenceParts = append(evidenceParts,
				fmt.Sprintf("Last commit: %.0f days ago (recent)", daysSinceActivity))
			maturityChecks = append(maturityChecks, models.CheckResult{Name: "Staleness", Status: "PASS", Detail: fmt.Sprintf("Last commit %.0f days ago (within 180 days); date: %s", daysSinceActivity, result.Metadata.RepoLastCommit.Format("2006-01-02"))})
		}
	} else if !result.Metadata.RepoUpdatedAt.IsZero() {
		verified = true
		daysSinceUpdate := now.Sub(result.Metadata.RepoUpdatedAt).Hours() / 24

		if daysSinceUpdate > 1095 { // 3+ years = abandoned
			stalenessRisk = 2
			isAbandoned = true
			years := daysSinceUpdate / 365
			evidenceParts = append(evidenceParts,
				fmt.Sprintf("ABANDONED: Last registry update %.0f days ago (%.1f years, no activity for 3+ years)", daysSinceUpdate, years))
			maturityChecks = append(maturityChecks, models.CheckResult{
				Name:   "Abandonment detection",
				Status: "FAIL",
				Detail: fmt.Sprintf("Package abandoned: last registry update %.0f days ago (%.1f years, > 3 year threshold, via registry fallback)", daysSinceUpdate, years),
			})
		} else if daysSinceUpdate > 365 {
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
		case isAbandoned:
			years := daysSinceActivity / 365
			description = evidenceJoined + fmt.Sprintf(". Package appears abandoned (%.1f years without activity). Abandoned packages are silently left without maintainer notice — unlike deprecated packages, there is no explicit signal to users. Maintainer accounts may be unmonitored and vulnerable to takeover.", years)
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

// detectDeprecation checks the repository description for deprecation keywords.
// Returns a human-readable signal string if deprecation is detected, or empty string if not.
//
// This distinguishes explicitly deprecated packages from silently abandoned ones:
// - Deprecated: maintainer has explicitly marked the package as end-of-life
// - Abandoned: package has simply gone silent with no maintainer communication
//
// Keywords checked: deprecated, unmaintained, archived, end of life, no longer maintained,
// no longer supported, use instead, moved to, superseded by, replaced by
func detectDeprecation(result *models.AnalysisResult) string {
	desc := strings.ToLower(result.Metadata.RepoDescription)
	if desc == "" {
		return ""
	}

	for _, keyword := range deprecationKeywords {
		if strings.Contains(desc, keyword) {
			return fmt.Sprintf("Deprecated: description contains '%s' (\"%s\")", keyword, truncateString(result.Metadata.RepoDescription, 120))
		}
	}

	return ""
}

// truncateString truncates a string to maxLen characters, adding "..." if truncated.
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
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
