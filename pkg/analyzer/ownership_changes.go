package analyzer

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/metalstormbass/snyft/pkg/fetcher"
	"github.com/metalstormbass/snyft/pkg/models"
)

// classifyOwnershipFromCommitStats analyzes commit authorship patterns to detect ownership transfers.
//
// Test: Commit author pattern analysis for ownership transfer detection
// Justification: Complete or near-complete replacement of active committers is the primary
//                behavioral signal of a malicious ownership transfer. Normal team growth adds
//                new contributors while retaining historical ones; a transfer replaces them.
// Source: "Backstabber's Knife Collection" (Ohm et al., 2020) - ownership takeover pattern analysis
//         https://arxiv.org/abs/2005.09535
// Methodology: Compare authors with recent commits (last 90 days) against historical authors
//              (committed previously but not recently). High ratio of entirely-new recent authors
//              indicates team replacement rather than natural growth.
// Result:
//   - 0 risk: stable ownership (same team or healthy growth with continuity)
//   - 1 risk: partial team turnover (>50% new authors but continuity exists, or dormant project)
//   - 2 risk: near-complete team replacement (≥80% of recent committers are new)
func classifyOwnershipFromCommitStats(stats *fetcher.CommitAuthorStats) (riskPoints int, evidence string) {
	hasRecent := len(stats.RecentAuthors) > 0
	hasHistorical := len(stats.HistoricalAuthors) > 0

	if hasRecent && hasHistorical {
		// We have both recent and historical authors: detect ownership-change pattern
		historicalSet := make(map[string]bool)
		for _, author := range stats.HistoricalAuthors {
			historicalSet[author] = true
		}

		newAuthors := 0
		for _, author := range stats.RecentAuthors {
			if !historicalSet[author] {
				newAuthors++
			}
		}

		newAuthorRatio := float64(newAuthors) / float64(len(stats.RecentAuthors))

		switch {
		case newAuthorRatio >= 0.8:
			// ≥80% of recent committers are entirely new: near-complete team replacement
			// This is the primary behavioral signal of a malicious ownership transfer.
			return 2, fmt.Sprintf(
				"%d/%d recent authors are new (%.0f%% team change; %d historical authors stepped back)",
				newAuthors, len(stats.RecentAuthors), newAuthorRatio*100, len(stats.HistoricalAuthors))

		case newAuthorRatio >= 0.5:
			// Majority new but some continuity: notable churn, moderate concern
			return 1, fmt.Sprintf(
				"%d/%d recent authors are new (%.0f%% partial team change)",
				newAuthors, len(stats.RecentAuthors), newAuthorRatio*100)

		default:
			// Mostly same team with some new contributors: healthy, stable ownership
			return 0, fmt.Sprintf(
				"%d unique authors, %d recent, %d new (stable ownership with continuity)",
				len(stats.UniqueAuthors), len(stats.RecentAuthors), newAuthors)
		}

	} else if hasRecent && !hasHistorical {
		// Only recent authors — project is new or all original contributors are still active
		if len(stats.UniqueAuthors) == 1 {
			return 0, "Single active author (stable, consistent commits)"
		}
		return 0, fmt.Sprintf(
			"%d active authors, all with recent commits (new or continuously active project)",
			len(stats.RecentAuthors))

	} else if !hasRecent && hasHistorical {
		// No recent commits at all: dormant project
		// Dormancy risk is primarily captured by scoreReleaseAnomalies; record here for context
		return 1, fmt.Sprintf(
			"%d authors, none active in last 90 days (dormant project)",
			len(stats.HistoricalAuthors))

	}
	// No author data at all (empty repo or API returned nothing useful)
	return 1, "No commit author data available"
}

// scoreOwnershipChanges: ownership transfers (0-2 pts)
//
// Test: Ownership change risk scoring for supply chain security
// Justification: Recent or sudden ownership changes are one of the most direct signals of a
//                supply chain attack — attackers acquire npm packages, GitHub repos, or PyPI
//                projects from maintainers who no longer monitor them.
// Source: "Backstabber's Knife Collection" (Ohm et al., 2020) - https://arxiv.org/abs/2005.09535
//         "Towards Measuring Supply Chain Attacks" (NDSS 2020)
// Methodology: Multi-source analysis:
//              1. Git commit author change patterns (recent vs. historical committers)
//              2. npm registry maintainer history
//              3. PyPI release author history
//              4. Repository creation date vs. package first-published date (transfer signal)
//              5. Fallback: repository age + maintainer count heuristic
// Result:
//   - 0 risk points (best):  Stable, long-term ownership with continuity
//   - 1 risk point (moderate): Some changes detected, partial data, or unverifiable
//   - 2 risk points (worst): Recent transfer or near-complete team replacement detected
func (a *Analyzer) scoreOwnershipChanges(result *models.AnalysisResult) models.CategoryScore {
	evidenceParts := []string{}
	ownerChecks := []models.CheckResult{}
	verified := false
	riskPoints := 1 // Default to medium risk when unable to verify
	ownerMethodology := "Multi-source analysis: (1) Git commit author change patterns (recent vs historical committers, 90-day window), (2) npm/PyPI registry ownership history, (3) repository creation date vs package first-published date (transfer signal), (4) fallback: repository age + maintainer count heuristic."

	// 1. Check Git platform commit author changes (if repository available)
	if result.RepositoryURL != "" {
		gitClient := a.getGitClient(result.RepositoryURL)
		commitStats, err := gitClient.GetCommitAuthors(result.RepositoryURL)
		if errors.Is(err, fetcher.ErrDataUnavailable) {
			evidenceParts = append(evidenceParts, fmt.Sprintf(
				"%s: commit author analysis not available", gitClient.GetPlatformName()))
			ownerChecks = append(ownerChecks, models.CheckResult{Name: "Commit author analysis", Status: "UNAVAILABLE", Detail: fmt.Sprintf("%s does not support commit author analysis", gitClient.GetPlatformName())})
		} else if errors.Is(err, fetcher.ErrRateLimited) {
			evidenceParts = append(evidenceParts, fmt.Sprintf(
				"%s: commit author analysis could not be performed (API rate limited)", gitClient.GetPlatformName()))
			ownerChecks = append(ownerChecks, models.CheckResult{Name: "Commit author analysis", Status: "UNAVAILABLE", Detail: "Could not check: API rate limited"})
		} else if err == nil && commitStats != nil {
			verified = true
			pts, ev := classifyOwnershipFromCommitStats(commitStats)
			riskPoints = pts
			if ev != "" {
				evidenceParts = append(evidenceParts, gitClient.GetPlatformName()+": "+ev)
			}
			status := "PASS"
			if pts >= 2 {
				status = "FAIL"
			} else if pts == 1 {
				status = "FAIL"
			}
			ownerChecks = append(ownerChecks, models.CheckResult{Name: "Commit author analysis", Status: status, Detail: ev})
		} else {
			ownerChecks = append(ownerChecks, models.CheckResult{Name: "Commit author analysis", Status: "UNAVAILABLE", Detail: "API error fetching commit authors"})
		}
	} else {
		ownerChecks = append(ownerChecks, models.CheckResult{Name: "Commit author analysis", Status: "SKIPPED", Detail: "No repository URL available"})
	}

	// 2. Cross-registry transfer signal
	if !result.Metadata.RepoCreatedAt.IsZero() && !result.Metadata.PublishedAt.IsZero() {
		ageDiff := result.Metadata.RepoCreatedAt.Sub(result.Metadata.PublishedAt)
		if ageDiff > 90*24*time.Hour {
			riskPoints = 2
			verified = true
			evidenceParts = append(evidenceParts,
				fmt.Sprintf("Repository created %d days after package first published (possible repo transfer)",
					int(ageDiff.Hours()/24)))
			ownerChecks = append(ownerChecks, models.CheckResult{Name: "Repo-package date mismatch", Status: "FAIL", Detail: fmt.Sprintf("Repository created %s, package published %s (%d day gap > 90 day threshold)", result.Metadata.RepoCreatedAt.Format("2006-01-02"), result.Metadata.PublishedAt.Format("2006-01-02"), int(ageDiff.Hours()/24))})
		} else {
			ownerChecks = append(ownerChecks, models.CheckResult{Name: "Repo-package date mismatch", Status: "PASS", Detail: "Repository and package creation dates are consistent"})
		}
	}

	// 3. Check npm package ownership history
	if result.Dependency.Ecosystem == models.EcosystemNPM {
		npmHistory, err := a.npmClient.GetOwnershipHistory(result.Dependency.Name)
		if err == nil && npmHistory != nil {
			verified = true

			if npmHistory.RecentTransfer {
				riskPoints = 2
				evidenceParts = append(evidenceParts,
					fmt.Sprintf("npm: Recent ownership transfer detected (%s)",
						npmHistory.TransferDate.Format("2006-01-02")))
				ownerChecks = append(ownerChecks, models.CheckResult{Name: "npm ownership history", Status: "FAIL", Detail: fmt.Sprintf("Recent ownership transfer on %s", npmHistory.TransferDate.Format("2006-01-02"))})
			} else if npmHistory.MaintainerChanges > 0 {
				if riskPoints < 2 {
					riskPoints = 1
				}
				evidenceParts = append(evidenceParts,
					fmt.Sprintf("npm: %d historical maintainer changes", npmHistory.MaintainerChanges))
				ownerChecks = append(ownerChecks, models.CheckResult{Name: "npm ownership history", Status: "FAIL", Detail: fmt.Sprintf("%d historical maintainer changes detected", npmHistory.MaintainerChanges)})
			} else {
				if riskPoints > 0 {
					riskPoints = 0
				}
				if len(npmHistory.CurrentMaintainers) > 0 {
					evidenceParts = append(evidenceParts,
						fmt.Sprintf("npm: Stable ownership (%d maintainers, no transfers detected)",
							len(npmHistory.CurrentMaintainers)))
				} else {
					evidenceParts = append(evidenceParts, "npm: No ownership changes detected")
				}
				ownerChecks = append(ownerChecks, models.CheckResult{Name: "npm ownership history", Status: "PASS", Detail: "Stable ownership, no transfers detected"})
			}
		} else {
			ownerChecks = append(ownerChecks, models.CheckResult{Name: "npm ownership history", Status: "UNAVAILABLE", Detail: "Could not fetch npm ownership history"})
		}
	}

	// 4. Check PyPI package ownership history
	if result.Dependency.Ecosystem == models.EcosystemPyPI {
		pypiHistory, err := a.pypiClient.GetOwnershipHistory(result.Dependency.Name)
		if err == nil && pypiHistory != nil {
			verified = true

			if pypiHistory.RecentTransfer {
				riskPoints = 2
				evidenceParts = append(evidenceParts,
					fmt.Sprintf("PyPI: Recent ownership transfer detected (%s)",
						pypiHistory.TransferDate.Format("2006-01-02")))
				ownerChecks = append(ownerChecks, models.CheckResult{Name: "PyPI ownership history", Status: "FAIL", Detail: fmt.Sprintf("Recent ownership transfer on %s", pypiHistory.TransferDate.Format("2006-01-02"))})
			} else if pypiHistory.AuthorChanges > 0 {
				if riskPoints < 2 {
					riskPoints = 1
				}
				evidenceParts = append(evidenceParts,
					fmt.Sprintf("PyPI: %d historical author changes", pypiHistory.AuthorChanges))
				ownerChecks = append(ownerChecks, models.CheckResult{Name: "PyPI ownership history", Status: "FAIL", Detail: fmt.Sprintf("%d historical author changes detected", pypiHistory.AuthorChanges)})
			} else {
				if riskPoints > 0 {
					riskPoints = 0
				}
				if pypiHistory.CurrentAuthor != "" {
					evidenceParts = append(evidenceParts,
						fmt.Sprintf("PyPI: Stable ownership (no transfers detected, author: %s)", pypiHistory.CurrentAuthor))
				} else {
					evidenceParts = append(evidenceParts, "PyPI: No ownership changes detected")
				}
				ownerChecks = append(ownerChecks, models.CheckResult{Name: "PyPI ownership history", Status: "PASS", Detail: "Stable ownership, no transfers detected"})
			}
		} else {
			ownerChecks = append(ownerChecks, models.CheckResult{Name: "PyPI ownership history", Status: "UNAVAILABLE", Detail: "Could not fetch PyPI ownership history"})
		}
	}

	// 5. Fallback to repository age heuristic if no other data available
	//    Justification: Very new packages with a single maintainer have not had time to
	//    establish a track record, making ownership-change detection impossible and
	//    account-takeover risk higher per Ohm et al. (2020).
	if !verified && !result.Metadata.RepoCreatedAt.IsZero() {
		repoAge := time.Since(result.Metadata.RepoCreatedAt).Hours() / 24 / 365
		verified = true

		switch {
		case repoAge < 0.5 && len(result.Metadata.Maintainers) <= 1:
			// Very new single-maintainer package: no ownership transfer evidence found.
			// Score as moderate (1) not max (2) — being new is not evidence of compromise.
			// Publisher Control already scores single-maintainer risk separately.
			riskPoints = 1
			evidenceParts = append(evidenceParts,
				fmt.Sprintf("Repository %.1f years old, single maintainer (no ownership transfer detected, limited history)", repoAge))
		case repoAge < 1.0:
			riskPoints = 1
			evidenceParts = append(evidenceParts,
				fmt.Sprintf("Repository %.1f years old (relatively new, limited ownership history)", repoAge))
		default:
			riskPoints = 0
			evidenceParts = append(evidenceParts,
				fmt.Sprintf("Repository %.1f years old (established)", repoAge))
		}
	}

	// Build final evidence string
	evidence := "No ownership data available"
	if len(evidenceParts) > 0 {
		evidence = strings.Join(evidenceParts, "; ")
	}

	// Build description from actual evidence, explaining what was found and why it matters
	description := ""
	switch riskPoints {
	case 2:
		description = evidence + ". Ownership transfers and near-complete team replacement are primary signals of malicious package acquisition."
	case 1:
		description = evidence + ". Partial team changes or limited history reduce confidence in ownership continuity."
	default:
		description = evidence + ". Stable ownership with author continuity indicates low risk of malicious transfer."
	}

	return models.CategoryScore{
		Score:           2 - riskPoints,
		RiskPoints:      riskPoints,
		Description:     description,
		Evidence:        evidence,
		Verified:        verified,
		DataAvailable:   verified,
		Methodology:     ownerMethodology,
		ChecksPerformed: ownerChecks,
	}
}
