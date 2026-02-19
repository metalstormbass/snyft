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
	anomalyMethodology := "Fetched release history (up to 20 releases) and commit activity (last 2 years) via Git API. Checked for: (1) dormancy reactivation (>1yr gap with recent release), (2) relative dormancy (gap >5x average cadence), (3) unusual release spikes (<10% of average cadence), (4) commit frequency anomalies (year-over-year comparison)."

	if result.Metadata.RepoLastCommit.IsZero() || result.RepositoryURL == "" {
		return models.CategoryScore{
			Score:       1,
			RiskPoints:  1,
			Description: "Unable to verify release patterns",
			Evidence:    "No commit history available",
			Verified:    false,
			Methodology: "No repository URL or commit history available. Could not check for release anomalies or dormancy patterns.",
			ChecksPerformed: []models.CheckResult{
				{Name: "Dormancy reactivation", Status: "SKIPPED", Detail: "No commit history or repository URL"},
				{Name: "Release pattern analysis", Status: "SKIPPED", Detail: "No commit history or repository URL"},
				{Name: "Commit frequency analysis", Status: "SKIPPED", Detail: "No commit history or repository URL"},
			},
		}
	}

	daysSinceLastCommit := time.Since(result.Metadata.RepoLastCommit).Hours() / 24
	daysSinceCreated := time.Since(result.Metadata.RepoCreatedAt).Hours() / 24

	// Very inactive (dormant for over a year)
	if daysSinceLastCommit > 365 {
		return models.CategoryScore{
			Score:       1,
			RiskPoints:  1,
			Description: "Package appears dormant",
			Evidence:    fmt.Sprintf("No commits in %.0f days (>1 year); last commit: %s", daysSinceLastCommit, result.Metadata.RepoLastCommit.Format("2006-01-02")),
			Verified:    true,
			Methodology: anomalyMethodology,
			ChecksPerformed: []models.CheckResult{
				{Name: "Dormancy detection", Status: "FAIL", Detail: fmt.Sprintf("%.0f days since last commit (> 365 day threshold); last commit %s", daysSinceLastCommit, result.Metadata.RepoLastCommit.Format("2006-01-02"))},
				{Name: "Release pattern analysis", Status: "SKIPPED", Detail: "Package is dormant; release pattern analysis not applicable"},
			},
		}
	}

	// For packages with recent activity, fetch detailed release and commit history
	// to detect suspicious reactivation patterns
	if daysSinceCreated > 365 {
		gitClient := a.getGitClient(result.RepositoryURL)
		// Fetch release history
		releases, err := gitClient.GetReleaseHistory(result.RepositoryURL, 20)
		if err == nil && len(releases) > 0 {
			// Analyze release pattern
			anomaly := a.detectReleaseAnomaly(releases, result.Metadata.RepoCreatedAt)
			if anomaly != nil {
				return *anomaly
			}
		}

		// Fetch commit activity to analyze frequency changes
		oneYearAgo := time.Now().AddDate(-1, 0, 0)
		twoYearsAgo := time.Now().AddDate(-2, 0, 0)

		recentCommits, err1 := gitClient.GetCommitActivity(result.RepositoryURL, oneYearAgo)
		olderCommits, err2 := gitClient.GetCommitActivity(result.RepositoryURL, twoYearsAgo)

		if err1 == nil && err2 == nil {
			anomaly := a.detectCommitFrequencyAnomaly(recentCommits, olderCommits, result.Metadata.RepoCreatedAt)
			if anomaly != nil {
				return *anomaly
			}
		}
	}

	// Regular, consistent activity (active within the year, no anomalies detected)
	regularChecks := []models.CheckResult{
		{Name: "Dormancy detection", Status: "PASS", Detail: fmt.Sprintf("Last commit %.0f days ago (within 1 year)", daysSinceLastCommit)},
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
		Description:     "Regular, consistent releases",
		Evidence:        fmt.Sprintf("Last commit %.0f days ago, no anomalies detected", daysSinceLastCommit),
		Verified:        true,
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
func (a *Analyzer) detectReleaseAnomaly(releases []fetcher.GitHubRelease, repoCreatedAt time.Time) *models.CategoryScore {
	if len(releases) < 2 {
		return nil
	}

	// Filter out draft and prerelease versions
	validReleases := []fetcher.GitHubRelease{}
	for _, r := range releases {
		if !r.Draft && !r.Prerelease && !r.PublishedAt.IsZero() {
			validReleases = append(validReleases, r)
		}
	}

	if len(validReleases) < 2 {
		return nil
	}

	// Releases are already sorted by GitHub API (most recent first)
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
			Description: "Suspicious reactivation after dormancy",
			Evidence: fmt.Sprintf("Dormant for %.0f days (%s to %s), recent release %.0f days ago",
				maxGapDays, gapStartDate.Format("2006-01"), gapEndDate.Format("2006-01"), daysSinceRecentRelease),
			Verified:    true,
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
			Description: "Suspicious reactivation after relative dormancy",
			Evidence: fmt.Sprintf("Dormant for %.0f days (%.1fx usual %.0f-day release cadence), recent release %.0f days ago",
				maxGapDays, maxGapDays/avgDaysBetweenReleases, avgDaysBetweenReleases, daysSinceRecentRelease),
			Verified:    true,
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
				Description: "Unusual release pattern detected",
				Evidence: fmt.Sprintf("Avg release every %.0f days, but recent release only %.0f days after previous (%.0f days ago)",
					avgDaysBetweenReleases, recentGap, daysSinceRecentRelease),
				Verified:    true,
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
// Methodology: Compare commit counts in last 12 months vs preceding 12 months
func (a *Analyzer) detectCommitFrequencyAnomaly(recentCommits, olderCommits []fetcher.GitHubCommit, repoCreatedAt time.Time) *models.CategoryScore {
	oneYearAgo := time.Now().AddDate(-1, 0, 0)

	// Count commits in last year vs previous year
	recentCount := len(recentCommits)

	// Filter older commits to only count those from 1-2 years ago (the preceding year)
	previousYearCount := 0
	for _, commit := range olderCommits {
		if commit.Commit.Author.Date.Before(oneYearAgo) {
			previousYearCount++
		}
	}

	// Repo must be at least 2 years old for this check to have meaningful comparison data
	repoAgeYears := time.Since(repoCreatedAt).Hours() / 24 / 365
	if repoAgeYears < 2 {
		return nil
	}

	commitMethodology := "Compared commit counts from last 12 months against preceding 12 months via Git API. Thresholds: <5 prior + >20 recent = absolute spike; >=5 prior + 10x increase = relative spike; 0 prior + any recent = reactivation."

	// Check 1: Absolute spike
	if previousYearCount < 5 && recentCount > 20 {
		return &models.CategoryScore{
			Score:       0,
			RiskPoints:  2,
			Description: "Suspicious commit frequency spike",
			Evidence: fmt.Sprintf("%d commits in last year vs %d in previous year (sudden spike)",
				recentCount, previousYearCount),
			Verified:    true,
			Methodology: commitMethodology,
			ChecksPerformed: []models.CheckResult{
				{Name: "Commit frequency spike", Status: "FAIL", Detail: fmt.Sprintf("Previous year: %d commits (near-zero), last year: %d commits (sudden spike)", previousYearCount, recentCount)},
			},
		}
	}

	// Check 2: Relative spike
	if previousYearCount >= 5 && recentCount >= previousYearCount*10 && recentCount >= 30 {
		return &models.CategoryScore{
			Score:       0,
			RiskPoints:  2,
			Description: "Suspicious commit frequency increase",
			Evidence: fmt.Sprintf("%d commits in last year vs %d in previous year (%.0fx increase)",
				recentCount, previousYearCount, float64(recentCount)/float64(previousYearCount)),
			Verified:    true,
			Methodology: commitMethodology,
			ChecksPerformed: []models.CheckResult{
				{Name: "Commit frequency spike", Status: "FAIL", Detail: fmt.Sprintf("%.0fx increase (%d vs %d commits) exceeds 10x threshold", float64(recentCount)/float64(previousYearCount), recentCount, previousYearCount)},
			},
		}
	}

	// Check 3: Reactivation after dormancy
	if previousYearCount == 0 && recentCount > 0 && recentCount < 20 {
		return &models.CategoryScore{
			Score:       1,
			RiskPoints:  1,
			Description: "Package reactivated after dormancy",
			Evidence:    fmt.Sprintf("0 commits in previous year, %d commits in last year", recentCount),
			Verified:    true,
			Methodology: commitMethodology,
			ChecksPerformed: []models.CheckResult{
				{Name: "Dormancy reactivation", Status: "FAIL", Detail: fmt.Sprintf("0 commits in prior year, %d in recent year (moderate reactivation)", recentCount)},
			},
		}
	}

	return nil
}
