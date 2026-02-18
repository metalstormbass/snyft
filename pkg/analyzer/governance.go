package analyzer

import (
	"fmt"
	"strings"
	"time"

	"github.com/metalstormbass/snyft/pkg/fetcher"
	"github.com/metalstormbass/snyft/pkg/models"
)

// GovernanceMetrics contains governance-related metrics for risk assessment
type GovernanceMetrics struct {
	HasSecurityPolicy    bool
	HasContributing      bool
	HasCodeOwners        bool
	HasCodeOfConduct     bool    // CODE_OF_CONDUCT.md indicates community governance
	AvgIssueResponseDays float64
	RecentActivityGap    float64 // Days since last activity
	HasAbandonmentPattern bool
	Verified             bool
}

// AnalyzeGovernance checks for governance documentation and maintainer responsiveness
// Test: Governance risk assessment for supply chain security
// Justification: Poor governance = unmaintained packages = higher likelihood of
//
//	account takeover or malicious code injection. Abandoned packages
//	that suddenly reactivate are a common supply chain attack pattern.
//
// Source: "Backstabber's Knife Collection" (Ohm et al., 2020)
//
//	https://arxiv.org/abs/2005.09535
//	"Towards Measuring Supply Chain Attacks" (NDSS 2020)
//
// Methodology: Check for SECURITY.md (+ .github/SECURITY.md), CONTRIBUTING.md,
//
//	CODEOWNERS, CODE_OF_CONDUCT.md files via Git API;
//	Analyze issue response times; Detect dormancy patterns
//
// Result: Assigns 0-2 risk points based on governance quality and abandonment signals
func (a *Analyzer) analyzeGovernance(result *models.AnalysisResult, repoURL string) *GovernanceMetrics {
	if repoURL == "" {
		return &GovernanceMetrics{Verified: false}
	}

	gitClient := a.getGitClient(repoURL)
	metrics := &GovernanceMetrics{Verified: true}

	// Check for security policy in both common locations
	metrics.HasSecurityPolicy = a.checkGovernanceFile(gitClient, repoURL, "SECURITY.md") ||
		a.checkGovernanceFile(gitClient, repoURL, ".github/SECURITY.md")

	// Check for other governance documentation files
	metrics.HasContributing = a.checkGovernanceFile(gitClient, repoURL, "CONTRIBUTING.md")
	metrics.HasCodeOwners = a.checkGovernanceFile(gitClient, repoURL, "CODEOWNERS") ||
		a.checkGovernanceFile(gitClient, repoURL, ".github/CODEOWNERS")
	metrics.HasCodeOfConduct = a.checkGovernanceFile(gitClient, repoURL, "CODE_OF_CONDUCT.md")

	// Analyze issue response times (GitHub-specific for now)
	if gitClient.GetPlatformName() == "GitHub" {
		if ghClient, ok := gitClient.(*fetcher.GitHubClient); ok {
			if avgResponseTime, err := ghClient.GetAverageIssueResponseTime(repoURL); err == nil {
				metrics.AvgIssueResponseDays = avgResponseTime
			}
		}
	}

	// Check for abandonment patterns
	if !result.Metadata.RepoLastCommit.IsZero() {
		daysSinceLastCommit := time.Since(result.Metadata.RepoLastCommit).Hours() / 24
		metrics.RecentActivityGap = daysSinceLastCommit

		// Abandonment pattern: long inactivity followed by sudden release
		// This is already checked in scoreReleaseAnomalies, but we track it here too
		if daysSinceLastCommit > 180 { // 6 months of inactivity
			metrics.HasAbandonmentPattern = true
		}
	}

	return metrics
}

// checkGovernanceFile checks if a governance file exists in the repository
func (a *Analyzer) checkGovernanceFile(gitClient fetcher.GitPlatformClient, repoURL, filePath string) bool {
	content, err := gitClient.GetFileContent(repoURL, filePath)
	if err != nil {
		return false
	}
	// File exists and has content
	return len(strings.TrimSpace(content)) > 0
}

// scoreGovernance: governance documentation and maintainer responsiveness (0-2 pts)
// Test: Governance risk scoring for supply chain security
// Justification: Packages without clear governance = unclear maintainership =
//
//	higher risk of account takeover going unnoticed. Poor responsiveness
//	indicates unmaintained packages that could be compromised.
//	Abandonment followed by sudden activity is a red flag for takeover.
//	Archived repositories represent permanently unmaintained packages.
//
// Source: "Backstabber's Knife Collection" (Ohm et al., 2020)
//
//	"Towards Measuring Supply Chain Attacks" (NDSS 2020)
//	OSSF Scorecard Specification (Security Policy check)
//
// Methodology: Score based on presence of governance docs (SECURITY.md, CONTRIBUTING.md,
//
//	CODEOWNERS, CODE_OF_CONDUCT.md), OSSF Security-Policy check, issue response
//	times, branch protection, and activity patterns
//
// Scoring:
//
//	Points are earned from two components:
//	  Docs component (0-2 pts): 1 pt for any governance doc, 2 pts for 2+ docs
//	  Process component (0-1 pt): fast issue response OR branch protection enabled
//	Total 3 points = 0 risk (strong governance)
//	Total 1-2 points = 1 risk (moderate governance)
//	Total 0 points = 2 risk (poor governance)
//	Override: Archived repos and abandoned packages always get 2 risk
func (a *Analyzer) scoreGovernance(result *models.AnalysisResult) models.CategoryScore {
	const govSource = " [Source: OSSF Scorecard; Backstabber's Knife Collection (Ohm et al., 2020)]"

	// Early return if no repository URL
	// Assign moderate risk (1 point) rather than maximum (2 points) because
	// the absence of a repository URL may be due to an API failure rather than
	// genuine lack of governance. This requires further investigation.
	if result.RepositoryURL == "" {
		return models.CategoryScore{
			Score:       1,
			RiskPoints:  1,
			Description: "Unable to assess governance: no repository URL available",
			Evidence:    "No source repository URL found; further investigation recommended" + govSource,
			Verified:    false,
		}
	}

	// Early return for archived repositories (permanently unmaintained)
	if result.Metadata.RepoArchived {
		return models.CategoryScore{
			Score:       0,
			RiskPoints:  2,
			Description: "Archived repository: no active governance",
			Evidence:    "Repository is archived and no longer accepting contributions" + govSource,
			Verified:    true,
		}
	}

	// Early return for abandoned packages (avoid expensive HTTP calls)
	// If metadata already tells us the package is abandoned, skip file fetching.
	if !result.Metadata.RepoLastCommit.IsZero() {
		daysSince := time.Since(result.Metadata.RepoLastCommit).Hours() / 24
		if daysSince > 180 {
			return models.CategoryScore{
				Score:       0,
				RiskPoints:  2,
				Description: "Abandoned project: high risk of compromise",
				Evidence:    fmt.Sprintf("Abandoned: %.0f days since last commit", daysSince) + govSource,
				Verified:    true,
			}
		}
	}

	// Analyze governance metrics
	govMetrics := a.analyzeGovernance(result, result.RepositoryURL)

	if !govMetrics.Verified {
		return models.CategoryScore{
			Score:       0,
			RiskPoints:  1,
			Description: "Unable to verify governance",
			Evidence:    "Could not fetch repository information" + govSource,
			Verified:    false,
		}
	}

	// Build evidence list
	evidenceParts := []string{}

	// -----------------------------------------------------------------------
	// Component 1: Governance Documentation (0-2 points)
	// 1 point for any governance doc, 2 points for 2+ governance docs.
	// A security policy is the most important individual document.
	// -----------------------------------------------------------------------
	docsCount := 0
	docsList := []string{}

	if govMetrics.HasSecurityPolicy {
		docsCount++
		docsList = append(docsList, "SECURITY.md")
	}
	if govMetrics.HasContributing {
		docsCount++
		docsList = append(docsList, "CONTRIBUTING.md")
	}
	if govMetrics.HasCodeOwners {
		docsCount++
		docsList = append(docsList, "CODEOWNERS")
	}
	if govMetrics.HasCodeOfConduct {
		docsCount++
		docsList = append(docsList, "CODE_OF_CONDUCT.md")
	}

	// OSSF Security-Policy check is a more authoritative source than file presence
	// If OSSF confirms a security policy (score >= 5/10), count it even if file check missed it
	if result.Metadata.OSSFChecks != nil {
		if spScore, exists := result.Metadata.OSSFChecks["Security-Policy"]; exists && spScore >= 5 {
			if !govMetrics.HasSecurityPolicy {
				docsCount++
				docsList = append(docsList, "OSSF:Security-Policy")
			}
		}
	}

	docsPoints := 0
	switch {
	case docsCount >= 2:
		docsPoints = 2
		evidenceParts = append(evidenceParts, fmt.Sprintf("Governance docs: %s", strings.Join(docsList, ", ")))
	case docsCount == 1:
		docsPoints = 1
		evidenceParts = append(evidenceParts, fmt.Sprintf("Single governance doc: %s", strings.Join(docsList, ", ")))
	default:
		evidenceParts = append(evidenceParts, "No governance documentation found")
	}

	// -----------------------------------------------------------------------
	// Component 2: Maintainer Process (0-1 point)
	// Fast issue response OR branch protection both indicate active governance.
	// Either signal earns the point; no data = 0 points (not penalized further).
	// -----------------------------------------------------------------------
	processPoints := 0

	if govMetrics.AvgIssueResponseDays > 0 && govMetrics.AvgIssueResponseDays <= 14 {
		// Responsive maintainers (within 2 weeks)
		processPoints = 1
		evidenceParts = append(evidenceParts, fmt.Sprintf("Avg issue response: %.1f days", govMetrics.AvgIssueResponseDays))
	} else if result.Metadata.HasBranchProtection {
		// Branch protection signals an enforced review/merge process
		processPoints = 1
		if result.Metadata.RequiredReviewers > 0 {
			evidenceParts = append(evidenceParts, fmt.Sprintf("Branch protection with %d required reviewer(s)", result.Metadata.RequiredReviewers))
		} else {
			evidenceParts = append(evidenceParts, "Branch protection enabled")
		}
	} else if govMetrics.AvgIssueResponseDays > 14 {
		// Slow response is worth noting even though it doesn't earn a point
		evidenceParts = append(evidenceParts, fmt.Sprintf("Avg issue response: %.1f days (slow)", govMetrics.AvgIssueResponseDays))
	}

	// Note slight inactivity (90-180 days) in evidence without overriding the score
	if govMetrics.RecentActivityGap > 90 {
		evidenceParts = append(evidenceParts, fmt.Sprintf("Inactive: %.0f days since last commit", govMetrics.RecentActivityGap))
	}

	// -----------------------------------------------------------------------
	// Final risk calculation
	// Total possible: 3 points (2 docs + 1 process)
	// 3 pts = 0 risk (strong governance)
	// 1-2 pts = 1 risk (moderate governance)
	// 0 pts = 2 risk (poor governance)
	// Abandonment/archive are handled as early returns above.
	// -----------------------------------------------------------------------
	totalPoints := docsPoints + processPoints

	riskPoints := 2
	switch {
	case totalPoints >= 3:
		riskPoints = 0
	case totalPoints >= 1:
		riskPoints = 1
	}

	// Determine description based on risk level
	var description string
	switch {
	case riskPoints == 0:
		description = "Strong governance: comprehensive documentation and active maintenance process"
	case riskPoints == 1:
		description = "Moderate governance: some documentation or maintenance signals present"
	default:
		description = "Poor governance: no documentation or maintenance signals"
	}

	return models.CategoryScore{
		Score:       2 - riskPoints, // Invert for display
		RiskPoints:  riskPoints,
		Description: description,
		Evidence:    strings.Join(evidenceParts, "; ") + govSource,
		Verified:    true,
	}
}
