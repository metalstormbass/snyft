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
	if result.Metadata.RepoLastCommit.IsZero() || result.RepositoryURL == "" {
		return models.CategoryScore{
			Score:       1,
			RiskPoints:  1,
			Description: "Unable to verify release patterns",
			Evidence:    "No commit history available",
			Verified:    false,
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
			Evidence:    fmt.Sprintf("No commits in %.0f days (>1 year)", daysSinceLastCommit),
			Verified:    true,
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
	return models.CategoryScore{
		Score:       2,
		RiskPoints:  0,
		Description: "Regular, consistent releases",
		Evidence:    fmt.Sprintf("Last commit %.0f days ago, no anomalies detected", daysSinceLastCommit),
		Verified:    true,
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

	// Check 1: Absolute dormancy reactivation (>1 year gap, recent activity)
	// Classic abandoned-package-takeover pattern: acquire dormant package, release malicious version
	if maxGapDays > 365 && daysSinceRecentRelease < 90 {
		return &models.CategoryScore{
			Score:       0,
			RiskPoints:  2,
			Description: "Suspicious reactivation after dormancy",
			Evidence: fmt.Sprintf("Dormant for %.0f days (%s to %s), recent release %.0f days ago",
				maxGapDays, gapStartDate.Format("2006-01"), gapEndDate.Format("2006-01"), daysSinceRecentRelease),
			Verified: true,
		}
	}

	// Check 2: Relative dormancy reactivation (gap >> average cadence)
	// A gap much larger than usual cadence signals potential compromise even if < 1 year absolute
	// Threshold: gap > 5x average cadence AND > 6 months absolute AND recent release within 4 months
	if avgDaysBetweenReleases > 0 && maxGapDays > avgDaysBetweenReleases*5 && maxGapDays > 180 && daysSinceRecentRelease < 120 {
		return &models.CategoryScore{
			Score:       0,
			RiskPoints:  2,
			Description: "Suspicious reactivation after relative dormancy",
			Evidence: fmt.Sprintf("Dormant for %.0f days (%.1fx usual %.0f-day release cadence), recent release %.0f days ago",
				maxGapDays, maxGapDays/avgDaysBetweenReleases, avgDaysBetweenReleases, daysSinceRecentRelease),
			Verified: true,
		}
	}

	// Check 3: Unusual release spike (recent release much faster than historical cadence)
	// Attacker pattern: inject malicious version quickly after account compromise
	// Use relative threshold: spike if recent gap < 10% of average (not a fixed 7-day cutoff)
	if len(validReleases) >= 3 && avgDaysBetweenReleases > 60 {
		recentGap := validReleases[0].PublishedAt.Sub(validReleases[1].PublishedAt).Hours() / 24
		spikeThreshold := avgDaysBetweenReleases * 0.10 // Gap < 10% of average is a suspicious spike
		if recentGap < spikeThreshold && daysSinceRecentRelease < 60 {
			return &models.CategoryScore{
				Score:       0,
				RiskPoints:  2,
				Description: "Unusual release pattern detected",
				Evidence: fmt.Sprintf("Avg release every %.0f days, but recent release only %.0f days after previous (%.0f days ago)",
					avgDaysBetweenReleases, recentGap, daysSinceRecentRelease),
				Verified: true,
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

	// Check 1: Absolute spike - near-zero prior activity, high recent activity
	// Classic abandoned-package-takeover: dormant for a year, suddenly many commits
	if previousYearCount < 5 && recentCount > 20 {
		return &models.CategoryScore{
			Score:       0,
			RiskPoints:  2,
			Description: "Suspicious commit frequency spike",
			Evidence: fmt.Sprintf("%d commits in last year vs %d in previous year (sudden spike)",
				recentCount, previousYearCount),
			Verified: true,
		}
	}

	// Check 2: Relative spike - large proportional increase from moderate baseline
	// A 10x+ increase even from a moderate baseline signals unusual activity
	if previousYearCount >= 5 && recentCount >= previousYearCount*10 && recentCount >= 30 {
		return &models.CategoryScore{
			Score:       0,
			RiskPoints:  2,
			Description: "Suspicious commit frequency increase",
			Evidence: fmt.Sprintf("%d commits in last year vs %d in previous year (%.0fx increase)",
				recentCount, previousYearCount, float64(recentCount)/float64(previousYearCount)),
			Verified: true,
		}
	}

	// Check 3: Complete dormancy then some activity (moderate concern)
	// Package was completely inactive but now has some commits - could be legitimate or takeover
	if previousYearCount == 0 && recentCount > 0 && recentCount < 20 {
		return &models.CategoryScore{
			Score:       1,
			RiskPoints:  1,
			Description: "Package reactivated after dormancy",
			Evidence:    fmt.Sprintf("0 commits in previous year, %d commits in last year", recentCount),
			Verified:    true,
		}
	}

	return nil
}
