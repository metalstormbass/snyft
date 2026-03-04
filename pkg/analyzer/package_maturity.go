package analyzer

import (
	"fmt"
	"math"
	"regexp"
	"strings"
	"time"

	"github.com/metalstormbass/snyft/pkg/fetcher"
	"github.com/metalstormbass/snyft/pkg/models"
)

// deprecationPatterns matches common deprecation keywords in README and description text.
// These indicate a package has been intentionally marked as deprecated or unmaintained.
//
// Justification: Deprecated packages are no longer receiving security patches,
//                making them vulnerable to supply chain compromise. The distinction
//                between "deprecated" (intentional) and "abandoned" (unintentional)
//                helps users understand whether a replacement exists.
// Source: "Backstabber's Knife Collection" (Ohm et al., 2020)
//         "Small World with High Risks" (Zimmermann et al., 2019)
var deprecationPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\b(this\s+(package|project|library|module)\s+is\s+)?deprecated\b`),
	regexp.MustCompile(`(?i)\b(this\s+(package|project|library|module)\s+is\s+)?unmaintained\b`),
	regexp.MustCompile(`(?i)\b(this\s+(package|project|library|module)\s+is\s+)?no\s+longer\s+maintained\b`),
	regexp.MustCompile(`(?i)\barchived\b`),
	regexp.MustCompile(`(?i)\bend[- ]of[- ]life\b`),
	regexp.MustCompile(`(?i)\buse\s+\S+\s+instead\b`),
}

// scorePackageMaturity: package age, update frequency, staleness, and deprecation (0-2 pts)
//
// Check: Package age, update frequency, abandonment, and deprecation (PackageMaturity)
// Justification: Very new packages lack community vetting; stale packages
//                may be abandoned and vulnerable to takeover (Ohm et al., 2020).
//                Packages inactive for 3+ years are considered abandoned — a HIGH
//                supply chain risk. Packages explicitly marked as deprecated or
//                unmaintained should be reported differently from silently abandoned ones.
// Source: "Backstabber's Knife Collection" (Ohm et al., 2020)
//         https://arxiv.org/abs/2005.09535
//         "Small World with High Risks" (Zimmermann et al., 2019)
//         "Towards Measuring Supply Chain Attacks" (NDSS 2020)
// Methodology: Compare PublishedAt, RepoLastCommit, release history cadence,
//              deprecation notices in README/description, GitHub archived status
//              - Package age: time since first publish (PublishedAt)
//              - Staleness: time since last commit (RepoLastCommit), 3+ years = abandoned
//              - Cadence: coefficient of variation of inter-release intervals
//              - Deprecation: keyword scan of README.md and repo description
// Result: 0-2 risk points based on age, update recency, release cadence, and deprecation
//
// Scoring logic:
//   - 0 risk points (low risk):    Package >2yr old AND last updated <180d ago AND consistent cadence AND not deprecated
//   - 1 risk point (medium risk):  Package 6mo-2yr old OR last updated 180-365d ago OR irregular cadence
//   - 2 risk points (high risk):   Package <6mo old OR last updated >365d ago OR deprecated/abandoned (3+ years)
func (a *Analyzer) scorePackageMaturity(result *models.AnalysisResult) models.CategoryScore {
	evidenceParts := []string{}
	maturityChecks := []models.CheckResult{}
	verified := false
	maturityMethodology := "Checked package age (time since first publish), staleness (time since last commit or registry update), release cadence regularity (coefficient of variation of inter-release intervals), and deprecation signals (README keywords, repo description, GitHub archived status). Release cadence uses Git platform releases when available, falling back to registry version history (npm time field, PyPI releases, Maven Central timestamps). Thresholds: age <6mo = high risk, 6mo-2yr = moderate; staleness >3yr = abandoned (HIGH risk), >1yr = high risk, 6-12mo = moderate; CV > 2.0 = highly irregular cadence. Deprecation keywords: deprecated, unmaintained, archived, end of life, use X instead."

	now := time.Now()

	// -----------------------------------------------------------------------
	// Sub-check 1: Deprecation detection
	// Detect explicit deprecation notices before other checks. A deprecated
	// package is reported differently from a silently abandoned one.
	// -----------------------------------------------------------------------
	deprecationRisk := 0
	isDeprecated := result.Metadata.IsDeprecated
	deprecationNotice := result.Metadata.DeprecationNotice
	deprecationSource := result.Metadata.DeprecationSource

	// Check GitHub archived status
	if !isDeprecated && result.Metadata.RepoArchived {
		isDeprecated = true
		deprecationNotice = "Repository is archived on GitHub"
		deprecationSource = "archived"
	}

	// Check repo description for deprecation keywords
	if !isDeprecated && result.Metadata.RepoDescription != "" {
		if keyword := detectDeprecationKeyword(result.Metadata.RepoDescription); keyword != "" {
			isDeprecated = true
			deprecationNotice = fmt.Sprintf("Repository description contains deprecation signal: %q", keyword)
			deprecationSource = "description"
		}
	}

	// Check README for deprecation keywords (only if not already flagged)
	if !isDeprecated && result.RepositoryURL != "" {
		if notice, found := a.checkREADMEDeprecation(result.RepositoryURL); found {
			isDeprecated = true
			deprecationNotice = notice
			deprecationSource = "readme"
		}
	}

	// Populate metadata for downstream consumers
	if isDeprecated {
		result.Metadata.IsDeprecated = true
		result.Metadata.DeprecationNotice = deprecationNotice
		result.Metadata.DeprecationSource = deprecationSource

		verified = true
		deprecationRisk = 2
		evidenceParts = append(evidenceParts,
			fmt.Sprintf("DEPRECATED: %s (source: %s)", deprecationNotice, deprecationSource))
		maturityChecks = append(maturityChecks, models.CheckResult{
			Name:   "Deprecation status",
			Status: "FAIL",
			Detail: fmt.Sprintf("Package is deprecated — %s (detected from %s)", deprecationNotice, deprecationSource),
		})
	} else {
		maturityChecks = append(maturityChecks, models.CheckResult{
			Name:   "Deprecation status",
			Status: "PASS",
			Detail: "No deprecation notices found in README, description, or repository status",
		})
	}

	// -----------------------------------------------------------------------
	// Sub-check 2: Package age
	// -----------------------------------------------------------------------
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

	// -----------------------------------------------------------------------
	// Sub-check 3: Staleness (with 3+ year abandonment threshold)
	// -----------------------------------------------------------------------
	stalenessRisk := 0
	isAbandoned := false // Tracks silent abandonment (3+ years, no deprecation notice)
	if !result.Metadata.RepoLastCommit.IsZero() {
		verified = true
		daysSinceCommit := now.Sub(result.Metadata.RepoLastCommit).Hours() / 24

		if daysSinceCommit > 1095 { // 3+ years = abandoned
			stalenessRisk = 2
			isAbandoned = !isDeprecated // Only "abandoned" if not already flagged as deprecated
			label := "abandoned, >3yr"
			if isDeprecated {
				label = "stale, >3yr, also deprecated"
			}
			evidenceParts = append(evidenceParts,
				fmt.Sprintf("Last commit: %.0f days ago (%s)", daysSinceCommit, label))
			maturityChecks = append(maturityChecks, models.CheckResult{
				Name:   "Staleness",
				Status: "FAIL",
				Detail: fmt.Sprintf("Last commit %.0f days ago (> 1095 day abandonment threshold); date: %s", daysSinceCommit, result.Metadata.RepoLastCommit.Format("2006-01-02")),
			})
		} else if daysSinceCommit > 365 {
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

		if daysSinceUpdate > 1095 { // 3+ years = abandoned
			stalenessRisk = 2
			isAbandoned = !isDeprecated
			label := "abandoned, >3yr"
			if isDeprecated {
				label = "stale, >3yr, also deprecated"
			}
			evidenceParts = append(evidenceParts,
				fmt.Sprintf("Last registry update: %.0f days ago (%s)", daysSinceUpdate, label))
			maturityChecks = append(maturityChecks, models.CheckResult{
				Name:   "Staleness",
				Status: "FAIL",
				Detail: fmt.Sprintf("Last registry update %.0f days ago (> 1095 day abandonment threshold, via registry fallback)", daysSinceUpdate),
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

	// -----------------------------------------------------------------------
	// Sub-check 4: Release cadence regularity
	// Try Git platform releases first, fall back to registry version history
	// -----------------------------------------------------------------------
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

	// -----------------------------------------------------------------------
	// Combine sub-checks: take the maximum risk across all sub-checks.
	// -----------------------------------------------------------------------
	riskPoints := ageRisk
	if stalenessRisk > riskPoints {
		riskPoints = stalenessRisk
	}
	if cadenceRisk > riskPoints {
		riskPoints = cadenceRisk
	}
	if deprecationRisk > riskPoints {
		riskPoints = deprecationRisk
	}

	// Source: Backstabber's Knife Collection (Ohm et al., 2020); Small World with High Risks (Zimmermann et al., 2019)

	// If no data was available at all, default to medium risk
	if !verified {
		return models.CategoryScore{
			Score:           1,
			RiskPoints:      1,
			Description:     "No publish date or commit history available to assess package maturity. Unable to determine package age, staleness, or release cadence.",
			Evidence:        "No publish date or commit history available",
			Verified:        false,
			DataAvailable:   false,
			Methodology:     maturityMethodology,
			ChecksPerformed: maturityChecks,
		}
	}

	// Build description from actual evidence, tailored to the specific risk driver.
	// Deprecated and abandoned packages get distinct messaging.
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
	default: // riskPoints == 2
		switch {
		case isDeprecated && isAbandoned:
			// Both deprecated AND abandoned
			description = evidenceJoined + ". Package is both deprecated and abandoned — no security patches will be released, and maintainer accounts may be unmonitored and vulnerable to takeover."
		case isDeprecated:
			description = evidenceJoined + ". Package has been explicitly deprecated. Deprecated packages no longer receive security patches, making them vulnerable to supply chain compromise. Consider migrating to an actively maintained alternative."
		case isAbandoned:
			description = evidenceJoined + ". Package appears abandoned (no activity for 3+ years) without any deprecation notice. Silently abandoned packages are HIGH risk — maintainer accounts may be unmonitored, vulnerable to takeover, and no replacement has been communicated."
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

// checkREADMEDeprecation fetches the README.md from a repository and scans
// the first 2000 characters for deprecation keywords. Returns the matched
// notice and true if a deprecation signal is found.
//
// Justification: Maintainers commonly announce deprecation at the top of README.
//                Detecting this distinguishes intentionally deprecated packages from
//                silently abandoned ones — both are risky but for different reasons.
// Source: "Backstabber's Knife Collection" (Ohm et al., 2020)
func (a *Analyzer) checkREADMEDeprecation(repoURL string) (string, bool) {
	gitClient := a.getGitClient(repoURL)
	content, err := gitClient.GetFileContent(repoURL, "README.md")
	if err != nil {
		return "", false
	}

	// Only scan the first 2000 chars — deprecation notices are at the top
	if len(content) > 2000 {
		content = content[:2000]
	}

	if keyword := detectDeprecationKeyword(content); keyword != "" {
		return fmt.Sprintf("README.md contains deprecation signal: %q", keyword), true
	}

	return "", false
}

// detectDeprecationKeyword scans text for deprecation-related keywords.
// Returns the matched keyword phrase, or empty string if none found.
func detectDeprecationKeyword(text string) string {
	for _, pat := range deprecationPatterns {
		if match := pat.FindString(text); match != "" {
			return match
		}
	}
	return ""
}

// scoreCadenceRegularity measures how consistent a package's release intervals are.
// Returns a risk level (0-2) and a human-readable evidence string.
//
// Methodology: Compute the coefficient of variation (CV = stddev/mean) of inter-release
// intervals. High CV = highly irregular cadence = elevated risk.
// A CV > 2.0 indicates releases are clustered or bursty rather than steady,
// which can indicate sudden reactivation of a dormant package.
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

	if cv > 2.0 {
		return 2, fmt.Sprintf("Highly irregular release cadence (CV=%.1f, avg %.0f days between releases)", cv, mean)
	} else if cv > 1.0 {
		return 1, fmt.Sprintf("Somewhat irregular release cadence (CV=%.1f, avg %.0f days between releases)", cv, mean)
	}

	return 0, fmt.Sprintf("Consistent release cadence (CV=%.1f, avg %.0f days between releases)", cv, mean)
}
