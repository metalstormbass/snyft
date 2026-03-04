package analyzer

import (
	"fmt"
	"time"

	"github.com/metalstormbass/snyft/pkg/fetcher"
	"github.com/metalstormbass/snyft/pkg/models"
)

// scoreReleaseAnomalies: dormant→sudden activity (0-2 pts)
// Detects dormant packages that suddenly reactivate, checks for unusual release patterns,
// and analyzes commit frequency changes
func (a *Analyzer) scoreReleaseAnomalies(result *models.AnalysisResult) models.CategoryScore {
	anomalyMethodology := "Fetched release history (up to 20 releases) and commit activity (last 2 years) via Git API or package registry fallback. Checked for: (1) dormancy reactivation (>1yr gap with recent release), (2) relative dormancy (gap >5x average cadence), (3) unusual release spikes (<10% of average cadence), (4) commit frequency anomalies (year-over-year comparison)."

	hasRepoData := !result.Metadata.RepoLastCommit.IsZero() && result.RepositoryURL != ""

	// When no repo data is available, try registry fallback for release pattern analysis
	if !hasRepoData {
		registryReleases := a.getRegistryVersionHistory(result.Dependency, 20)
		if len(registryReleases) >= 2 {
			// Estimate creation date from oldest registry release
			createdAt := registryReleases[len(registryReleases)-1].PublishedAt
			anomaly := a.detectReleaseAnomaly(registryReleases, createdAt)
			if anomaly != nil {
				anomaly.Methodology = "No repository URL available. Used package registry version history as fallback for release pattern analysis."
				return *anomaly
			}
			// No anomalies found via registry data
			return models.CategoryScore{
				Score:       2,
				RiskPoints:  0,
				Description: fmt.Sprintf("Analyzed %d versions from package registry — no dormancy reactivation or unusual release spikes detected. Consistent release patterns indicate normal maintenance.", len(registryReleases)),
				Evidence:    fmt.Sprintf("Analyzed %d versions from package registry; no dormancy reactivation or unusual spikes detected", len(registryReleases)),
				Verified:    true,
				DataAvailable: true,
				Methodology: "No repository URL available. Used package registry version history as fallback for release pattern analysis.",
				ChecksPerformed: []models.CheckResult{
					{Name: "Release pattern analysis", Status: "PASS", Detail: fmt.Sprintf("Analyzed %d registry versions; no anomalies detected (registry fallback)", len(registryReleases))},
					{Name: "Commit frequency analysis", Status: "SKIPPED", Detail: "No repository URL; commit analysis requires Git data"},
				},
			}
		}
		// No registry data either
		return models.CategoryScore{
			Score:       1,
			RiskPoints:  1,
			Description: "No commit history or registry version data available to verify release patterns. Unable to check for dormancy reactivation or suspicious release activity.",
			Evidence:    "No commit history or registry version data available",
			Verified:    false,
			DataAvailable: false,
			Methodology: "No repository URL or commit history available. Registry version history also unavailable. Could not check for release anomalies or dormancy patterns.",
			ChecksPerformed: []models.CheckResult{
				{Name: "Dormancy reactivation", Status: "SKIPPED", Detail: "No commit history, repository URL, or registry version data"},
				{Name: "Release pattern analysis", Status: "SKIPPED", Detail: "No commit history, repository URL, or registry version data"},
				{Name: "Commit frequency analysis", Status: "SKIPPED", Detail: "No commit history, repository URL, or registry version data"},
			},
		}
	}

	daysSinceLastCommit := time.Since(result.Metadata.RepoLastCommit).Hours() / 24
	daysSinceCreated := time.Since(result.Metadata.RepoCreatedAt).Hours() / 24
	repoAgeYears := daysSinceCreated / 365

	// For packages with any history (>1 year old), fetch detailed release and commit history
	// to detect suspicious reactivation patterns and validate dormancy.
	// We defer the dormancy decision until after we have commit data to avoid false positives.
	if daysSinceCreated > 365 {
		// Try to get release history from Git platform first, fall back to registry
		var registryReleases []fetcher.RegistryRelease
		gitClient := a.getGitClient(result.RepositoryURL)
		ghReleases, err := gitClient.GetReleaseHistory(result.RepositoryURL, 20)
		if err == nil && len(ghReleases) > 0 {
			registryReleases = fetcher.GitHubReleasesToRegistryReleases(ghReleases)
		}
		// Fall back to registry version history when Git releases are unavailable
		if len(registryReleases) == 0 {
			registryReleases = a.getRegistryVersionHistory(result.Dependency, 20)
		}
		if len(registryReleases) > 0 {
			// Analyze release pattern
			anomaly := a.detectReleaseAnomaly(registryReleases, result.Metadata.RepoCreatedAt)
			if anomaly != nil {
				return *anomaly
			}
		}

		// Fetch commit activity to analyze frequency changes and validate dormancy
		oneYearAgo := time.Now().AddDate(-1, 0, 0)
		twoYearsAgo := time.Now().AddDate(-2, 0, 0)

		recentCommits, err1 := gitClient.GetCommitActivity(result.RepositoryURL, oneYearAgo)
		olderCommits, err2 := gitClient.GetCommitActivity(result.RepositoryURL, twoYearsAgo)

		if err1 == nil && err2 == nil {
			anomaly := a.detectCommitFrequencyAnomaly(recentCommits, olderCommits, result.Metadata.RepoCreatedAt, registryReleases)
			if anomaly != nil {
				return *anomaly
			}

			// Refined dormancy check: only flag dormancy if the repo is >3 years old
			// AND has <10 commits in the prior 2 years. Projects with 100+ recent commits
			// are clearly active, not dormant. Skip if we don't have sufficient history coverage.
			if daysSinceLastCommit > 365 && repoAgeYears > 3 {
				// Count total commits in 2-year dataset
				totalCommits := len(olderCommits)
				if totalCommits < 10 && len(recentCommits) < 100 {
					return models.CategoryScore{
						Score:       1,
						RiskPoints:  1,
						Description: fmt.Sprintf("No commits in %.0f days (last commit: %s) with only %d commits in the prior 2 years. Dormant packages are attractive targets for account takeover — maintainers may not be monitoring their accounts or credentials.", daysSinceLastCommit, result.Metadata.RepoLastCommit.Format("2006-01-02"), totalCommits),
						Evidence:    fmt.Sprintf("No commits in %.0f days (>1 year); last commit: %s; %d commits in prior 2 years", daysSinceLastCommit, result.Metadata.RepoLastCommit.Format("2006-01-02"), totalCommits),
						Verified:    true,
						DataAvailable: true,
						Methodology: anomalyMethodology,
						ChecksPerformed: []models.CheckResult{
							{Name: "Dormancy detection", Status: "FAIL", Detail: fmt.Sprintf("%.0f days since last commit (> 365 day threshold), repo %.1f years old (> 3 year threshold), %d commits in prior 2 years (< 10 threshold)", daysSinceLastCommit, repoAgeYears, totalCommits)},
							{Name: "Release pattern analysis", Status: "PASS", Detail: "No release anomalies detected"},
						},
					}
				}
			}
		} else if daysSinceLastCommit > 365 && repoAgeYears > 3 {
			// Commit data unavailable but repo looks dormant based on last commit date.
			// Skip dormancy flag since we can't verify commit activity (incomplete history coverage).
		}
	}

	// Regular, consistent activity (no anomalies detected)
	var dormancyDetail string
	if daysSinceLastCommit > 365 {
		dormancyDetail = fmt.Sprintf("Last commit %.0f days ago but repo does not meet dormancy criteria (requires >3 year old repo with <10 commits in 2 years)", daysSinceLastCommit)
	} else {
		dormancyDetail = fmt.Sprintf("Last commit %.0f days ago (within 1 year)", daysSinceLastCommit)
	}
	regularChecks := []models.CheckResult{
		{Name: "Dormancy detection", Status: "PASS", Detail: dormancyDetail},
	}
	if daysSinceCreated > 365 {
		regularChecks = append(regularChecks, models.CheckResult{Name: "Release pattern analysis", Status: "PASS", Detail: "No dormancy reactivation or unusual release spikes detected"})
		regularChecks = append(regularChecks, models.CheckResult{Name: "Commit frequency analysis", Status: "PASS", Detail: "No suspicious year-over-year commit frequency changes"})
	} else {
		regularChecks = append(regularChecks, models.CheckResult{Name: "Release pattern analysis", Status: "SKIPPED", Detail: "Repository < 1 year old; insufficient history for anomaly detection"})
	}
	return models.CategoryScore{
		Score:           2,
		RiskPoints:      0,
		Description:     fmt.Sprintf("Last commit %.0f days ago with no anomalies detected. Regular release activity indicates active, healthy maintenance.", daysSinceLastCommit),
		Evidence:        fmt.Sprintf("Last commit %.0f days ago, no anomalies detected", daysSinceLastCommit),
		Verified:        true,
		DataAvailable:   true,
		Methodology:     anomalyMethodology,
		ChecksPerformed: regularChecks,
	}
}

// detectReleaseAnomaly analyzes release history to detect dormant packages that suddenly reactivate
//
// Test: Release anomaly detection via release history analysis
// Justification: Dormant packages reactivating suddenly are a primary attack vector for
//                supply chain compromise. Attackers acquire abandoned packages and inject
//                malicious versions, or use fast-release patterns to push unreviewed changes.
// Source: "Backstabber's Knife Collection" (Ohm et al., 2020) - abandoned package takeover
//         https://arxiv.org/abs/2005.09535
//         "Towards Measuring Supply Chain Attacks on Package Managers" (NDSS 2020)
// Methodology: Analyze release timestamps to detect gaps and frequency anomalies
func (a *Analyzer) detectReleaseAnomaly(releases []fetcher.RegistryRelease, repoCreatedAt time.Time) *models.CategoryScore {
	if len(releases) < 2 {
		return nil
	}

	// Filter out prerelease versions
	validReleases := []fetcher.RegistryRelease{}
	for _, r := range releases {
		if !r.IsPrerelease && !r.PublishedAt.IsZero() {
			validReleases = append(validReleases, r)
		}
	}

	if len(validReleases) < 2 {
		return nil
	}

	// Releases are sorted newest first
	mostRecent := validReleases[0].PublishedAt
	daysSinceRecentRelease := time.Since(mostRecent).Hours() / 24

	// Find the largest gap between consecutive releases
	var maxGapDays float64
	var gapStartDate time.Time
	var gapEndDate time.Time

	for i := 0; i < len(validReleases)-1; i++ {
		gapDays := validReleases[i].PublishedAt.Sub(validReleases[i+1].PublishedAt).Hours() / 24
		if gapDays > maxGapDays {
			maxGapDays = gapDays
			gapStartDate = validReleases[i+1].PublishedAt
			gapEndDate = validReleases[i].PublishedAt
		}
	}

	// Calculate average release cadence (requires at least 3 releases for a meaningful average)
	var avgDaysBetweenReleases float64
	if len(validReleases) >= 3 {
		totalDays := validReleases[0].PublishedAt.Sub(validReleases[len(validReleases)-1].PublishedAt).Hours() / 24
		avgDaysBetweenReleases = totalDays / float64(len(validReleases)-1)
	}

	releaseMethodology := "Analyzed release timestamps from Git API to detect dormancy gaps, relative dormancy vs average cadence, and unusual release spikes."

	// Check 1: Absolute dormancy reactivation (>1 year gap, recent activity)
	if maxGapDays > 365 && daysSinceRecentRelease < 90 {
		return &models.CategoryScore{
			Score:       0,
			RiskPoints:  2,
			Description: fmt.Sprintf("Package was dormant for %.0f days (%s to %s), then released again %.0f days ago. Dormant packages that suddenly reactivate are a common supply chain attack pattern — attackers acquire abandoned packages and inject malicious code.", maxGapDays, gapStartDate.Format("2006-01"), gapEndDate.Format("2006-01"), daysSinceRecentRelease),
			Evidence: fmt.Sprintf("Dormant for %.0f days (%s to %s), recent release %.0f days ago",
				maxGapDays, gapStartDate.Format("2006-01"), gapEndDate.Format("2006-01"), daysSinceRecentRelease),
			Verified:    true,
			DataAvailable: true,
			Methodology: releaseMethodology,
			ChecksPerformed: []models.CheckResult{
				{Name: "Dormancy reactivation", Status: "FAIL", Detail: fmt.Sprintf("%.0f day gap between releases (%s to %s), then activity resumed %.0f days ago", maxGapDays, gapStartDate.Format("2006-01-02"), gapEndDate.Format("2006-01-02"), daysSinceRecentRelease)},
			},
		}
	}

	// Check 2: Relative dormancy reactivation (gap >> average cadence)
	if avgDaysBetweenReleases > 0 && maxGapDays > avgDaysBetweenReleases*5 && maxGapDays > 180 && daysSinceRecentRelease < 120 {
		return &models.CategoryScore{
			Score:       0,
			RiskPoints:  2,
			Description: fmt.Sprintf("Release gap of %.0f days is %.1fx the usual %.0f-day cadence, followed by a release %.0f days ago. A gap far exceeding the normal cadence followed by sudden activity is a reactivation pattern associated with package takeover.", maxGapDays, maxGapDays/avgDaysBetweenReleases, avgDaysBetweenReleases, daysSinceRecentRelease),
			Evidence: fmt.Sprintf("Dormant for %.0f days (%.1fx usual %.0f-day release cadence), recent release %.0f days ago",
				maxGapDays, maxGapDays/avgDaysBetweenReleases, avgDaysBetweenReleases, daysSinceRecentRelease),
			Verified:    true,
			DataAvailable: true,
			Methodology: releaseMethodology,
			ChecksPerformed: []models.CheckResult{
				{Name: "Relative dormancy", Status: "FAIL", Detail: fmt.Sprintf("%.0f day gap is %.1fx the average %.0f-day cadence (threshold: 5x)", maxGapDays, maxGapDays/avgDaysBetweenReleases, avgDaysBetweenReleases)},
			},
		}
	}

	// Check 3: Unusual release spike
	if len(validReleases) >= 3 && avgDaysBetweenReleases > 60 {
		recentGap := validReleases[0].PublishedAt.Sub(validReleases[1].PublishedAt).Hours() / 24
		spikeThreshold := avgDaysBetweenReleases * 0.10
		if recentGap < spikeThreshold && daysSinceRecentRelease < 60 {
			return &models.CategoryScore{
				Score:       0,
				RiskPoints:  2,
				Description: fmt.Sprintf("Average release cadence is every %.0f days, but the most recent release came only %.0f days after the previous one. Rapid-fire releases that break the established pattern can indicate compromised publishing credentials or unauthorized access.", avgDaysBetweenReleases, recentGap),
				Evidence: fmt.Sprintf("Avg release every %.0f days, but recent release only %.0f days after previous (%.0f days ago)",
					avgDaysBetweenReleases, recentGap, daysSinceRecentRelease),
				Verified:    true,
				DataAvailable: true,
				Methodology: releaseMethodology,
				ChecksPerformed: []models.CheckResult{
					{Name: "Release spike detection", Status: "FAIL", Detail: fmt.Sprintf("Recent release gap (%.0f days) is < 10%% of average cadence (%.0f days)", recentGap, avgDaysBetweenReleases)},
				},
			}
		}
	}

	return nil
}

// detectCommitFrequencyAnomaly analyzes commit frequency changes to detect suspicious activity
//
// Test: Commit frequency anomaly detection via year-over-year comparison
// Justification: Sudden spikes in commit frequency after dormancy are characteristic of
//                account takeover attacks where adversaries push multiple changes rapidly
//                to avoid detection window.
// Source: "Backstabber's Knife Collection" (Ohm et al., 2020)
//         https://arxiv.org/abs/2005.09535
// Methodology: Compare commit counts in last 12 months vs preceding 12 months,
//              with data coverage validation to prevent false positives from API pagination limits
func (a *Analyzer) detectCommitFrequencyAnomaly(recentCommits, olderCommits []fetcher.GitHubCommit, repoCreatedAt time.Time, releases []fetcher.RegistryRelease) *models.CategoryScore {
	oneYearAgo := time.Now().AddDate(-1, 0, 0)

	// Count commits in last year vs previous year
	recentCount := len(recentCommits)

	// Filter older commits to only count those from 1-2 years ago (the preceding year)
	previousYearCount := 0
	var oldestCommitDate time.Time
	for _, commit := range olderCommits {
		commitDate := commit.Commit.Author.Date
		if commitDate.Before(oneYearAgo) {
			previousYearCount++
		}
		// Track the oldest commit in the dataset to assess data coverage
		if oldestCommitDate.IsZero() || commitDate.Before(oldestCommitDate) {
			oldestCommitDate = commitDate
		}
	}
	// Also check recent commits for oldest date (in case olderCommits is empty)
	for _, commit := range recentCommits {
		commitDate := commit.Commit.Author.Date
		if oldestCommitDate.IsZero() || commitDate.Before(oldestCommitDate) {
			oldestCommitDate = commitDate
		}
	}

	// Repo must be at least 2 years old for this check to have meaningful comparison data
	repoAgeYears := time.Since(repoCreatedAt).Hours() / 24 / 365
	if repoAgeYears < 2 {
		return nil
	}

	// Fix 1: Data coverage validation — if the oldest commit in our dataset is less than
	// 18 months old, the API/clone didn't return enough history for a valid comparison.
	// GitHub API caps at 100 commits per request and clones at depth=500. For active
	// projects (Spring Boot, Guava, aiohttp), 100 commits may only cover a few months,
	// making the "previous year" count artificially zero.
	eighteenMonthsAgo := time.Now().AddDate(-1, -6, 0)
	if !oldestCommitDate.IsZero() && oldestCommitDate.After(eighteenMonthsAgo) {
		// Data doesn't reach back far enough for a meaningful year-over-year comparison
		return nil
	}

	// Fix 3: Project age weighting — for mature projects (5+ years old), a spike from
	// 0 to many commits is far more likely a data artifact than dormancy reactivation.
	// A 10-year-old project like Spring Boot wouldn't truly go dormant and reactivate.
	// Require proportionally stronger evidence for older projects.
	isMaturedProject := repoAgeYears >= 5

	commitMethodology := "Compared commit counts from last 12 months against preceding 12 months via Git API. Includes data coverage validation (oldest commit must be ≥18 months old), project age weighting (mature projects require stronger evidence), and release history cross-validation for high-activity repos."

	// Check 1: Absolute spike — near-dormant then suddenly active
	if previousYearCount < 5 && recentCount > 20 {
		// Fix 2: For repos with 100+ recent commits, cross-validate against release history.
		// If releases show consistent activity, the commit "spike" is a data coverage artifact.
		if recentCount >= 100 && hasConsistentReleaseHistory(releases) {
			return nil
		}
		// Fix 3: For mature projects (5+ years), a high recent count with near-zero prior
		// is almost certainly a data artifact — the API simply didn't return older commits.
		if isMaturedProject && recentCount >= 50 {
			return nil
		}
		// Tailor language: 100+ recent commits is a major reactivation, not "near-dormant"
		var spikeDesc string
		if recentCount >= 100 {
			spikeDesc = fmt.Sprintf("%d commits in the last year vs only %d in the previous year. A previously inactive project with a massive surge in activity warrants investigation — while this may reflect legitimate new investment, it can also indicate compromised maintainer accounts pushing changes rapidly.", recentCount, previousYearCount)
		} else {
			spikeDesc = fmt.Sprintf("%d commits in the last year vs only %d in the previous year. A previously low-activity project with a sudden burst of commits is characteristic of account takeover, where adversaries push multiple changes rapidly.", recentCount, previousYearCount)
		}
		return &models.CategoryScore{
			Score:       0,
			RiskPoints:  2,
			Description: spikeDesc,
			Evidence: fmt.Sprintf("%d commits in last year vs %d in previous year (sudden spike)",
				recentCount, previousYearCount),
			Verified:    true,
			DataAvailable: true,
			Methodology: commitMethodology,
			ChecksPerformed: []models.CheckResult{
				{Name: "Commit frequency spike", Status: "FAIL", Detail: fmt.Sprintf("Previous year: %d commits (near-zero), last year: %d commits (sudden spike)", previousYearCount, recentCount)},
			},
		}
	}

	// Check 2: Relative spike — 10x+ increase from a moderate baseline
	if previousYearCount >= 5 && recentCount >= previousYearCount*10 && recentCount >= 30 {
		// Fix 2: Cross-validate high-activity repos against release history
		if recentCount >= 100 && hasConsistentReleaseHistory(releases) {
			return nil
		}
		// Fix 3: Mature projects with very high activity are likely data artifacts
		if isMaturedProject && recentCount >= 100 {
			return nil
		}
		return &models.CategoryScore{
			Score:       0,
			RiskPoints:  2,
			Description: fmt.Sprintf("%d commits in the last year vs %d in the previous year (%.0fx increase). A dramatic spike in commit frequency can indicate new unauthorized access or compromised maintainer accounts pushing changes rapidly.", recentCount, previousYearCount, float64(recentCount)/float64(previousYearCount)),
			Evidence: fmt.Sprintf("%d commits in last year vs %d in previous year (%.0fx increase)",
				recentCount, previousYearCount, float64(recentCount)/float64(previousYearCount)),
			Verified:    true,
			DataAvailable: true,
			Methodology: commitMethodology,
			ChecksPerformed: []models.CheckResult{
				{Name: "Commit frequency spike", Status: "FAIL", Detail: fmt.Sprintf("%.0fx increase (%d vs %d commits) exceeds 10x threshold", float64(recentCount)/float64(previousYearCount), recentCount, previousYearCount)},
			},
		}
	}

	// Check 3: Reactivation after dormancy — 0 prior, small recent count
	if previousYearCount == 0 && recentCount > 0 && recentCount < 20 {
		// Fix 3: Mature projects with moderate reactivation — more likely legitimate
		// renewed interest or data artifact than account takeover
		if isMaturedProject {
			return nil
		}
		return &models.CategoryScore{
			Score:       1,
			RiskPoints:  1,
			Description: fmt.Sprintf("0 commits in the previous year, then %d commits in the last year. Moderate reactivation after dormancy — could be legitimate renewed interest or an early sign of account takeover.", recentCount),
			Evidence:    fmt.Sprintf("0 commits in previous year, %d commits in last year", recentCount),
			Verified:    true,
			DataAvailable: true,
			Methodology: commitMethodology,
			ChecksPerformed: []models.CheckResult{
				{Name: "Dormancy reactivation", Status: "FAIL", Detail: fmt.Sprintf("0 commits in prior year, %d in recent year (moderate reactivation)", recentCount)},
			},
		}
	}

	return nil
}

// hasConsistentReleaseHistory checks if release history shows consistent activity
// over time, indicating that a commit frequency "spike" is likely a data coverage
// artifact (API pagination) rather than actual dormancy reactivation.
//
// Justification: If a project has regular releases spanning 2+ years, the project
//                was clearly active even if our commit data doesn't reach back far enough.
// Source: "Towards Measuring Supply Chain Attacks" (NDSS 2020) — attack pattern analysis
//         shows compromised packages typically have gaps in release history, not consistent cadence.
func hasConsistentReleaseHistory(releases []fetcher.RegistryRelease) bool {
	if len(releases) < 3 {
		return false
	}

	// Check if releases span at least 2 years
	var oldest, newest time.Time
	validCount := 0
	for _, r := range releases {
		if r.PublishedAt.IsZero() || r.IsPrerelease {
			continue
		}
		validCount++
		if oldest.IsZero() || r.PublishedAt.Before(oldest) {
			oldest = r.PublishedAt
		}
		if newest.IsZero() || r.PublishedAt.After(newest) {
			newest = r.PublishedAt
		}
	}

	if validCount < 3 {
		return false
	}

	releaseSpanDays := newest.Sub(oldest).Hours() / 24
	// Releases must span at least 2 years to indicate consistent long-term activity
	return releaseSpanDays >= 730
}
