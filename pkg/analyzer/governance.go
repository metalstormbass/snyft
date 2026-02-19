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
	HasSecurityPolicy    bool    // SECURITY.md — indicates vulnerability disclosure process
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
	// SECURITY.md is the only governance doc we check — it indicates a vulnerability
	// disclosure process, meaning compromises are more likely to be reported.
	metrics.HasSecurityPolicy = a.checkGovernanceFile(gitClient, repoURL, "SECURITY.md") ||
		a.checkGovernanceFile(gitClient, repoURL, ".github/SECURITY.md")

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

// checkGovernanceFile checks if a governance file exists in the repository.
// For GitHub repositories, this uses cached HEAD requests with a
// raw.githubusercontent.com fallback when rate-limited — much more efficient
// than fetching full file contents via the API. Other platforms fall back to
// GetFileContent.
func (a *Analyzer) checkGovernanceFile(gitClient fetcher.GitPlatformClient, repoURL, filePath string) bool {
	// For GitHub, use the efficient cached HEAD-based check with rate-limit fallback.
	// This avoids consuming API quota with full GET requests for each governance file.
	if ghClient, ok := gitClient.(*fetcher.GitHubClient); ok {
		return ghClient.FileExistsInRepo(repoURL, filePath)
	}
	// For other platforms, fall back to GetFileContent (content-based check).
	content, err := gitClient.GetFileContent(repoURL, filePath)
	if err != nil {
		return false
	}
	return len(strings.TrimSpace(content)) > 0
}

// scoreGovernance: governance documentation and maintainer responsiveness (0-2 pts)
//
// Test: Governance risk scoring for supply chain security
// Justification: Packages without a security policy have no vulnerability disclosure
//                process — compromises go unreported. Unresponsive maintainers indicate
//                abandoned packages vulnerable to takeover. Archived repos are permanently
//                unmaintained.
// Source: "Backstabber's Knife Collection" (Ohm et al., 2020)
//         "Towards Measuring Supply Chain Attacks" (NDSS 2020)
//         OSSF Scorecard Specification (Security Policy check)
// Methodology: Check for SECURITY.md, issue response times, abandonment signals
//
// Scoring (two components):
//   Security Policy (0-1 pt): SECURITY.md present or OSSF Security-Policy >= 5
//   Responsiveness (0-1 pt): fast issue response (<=14 days) OR branch protection
//   Total 2 points = 0 risk (responsive + security policy)
//   Total 1 point  = 1 risk (partial signals)
//   Total 0 points = 2 risk (no signals)
//   Override: Archived repos and abandoned packages (>180 days) always get 2 risk
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
	// Component 1: Security Policy (0-1 point)
	// SECURITY.md indicates a vulnerability disclosure process — compromises
	// are more likely to be reported and addressed quickly.
	// OSSF Security-Policy check is a more authoritative source than file presence.
	// -----------------------------------------------------------------------
	securityPolicyPoints := 0

	hasPolicy := govMetrics.HasSecurityPolicy
	if !hasPolicy && result.Metadata.OSSFChecks != nil {
		if spScore, exists := result.Metadata.OSSFChecks["Security-Policy"]; exists && spScore >= 5 {
			hasPolicy = true
		}
	}

	if hasPolicy {
		securityPolicyPoints = 1
		if govMetrics.HasSecurityPolicy {
			evidenceParts = append(evidenceParts, "Security policy: SECURITY.md")
		} else {
			evidenceParts = append(evidenceParts, "Security policy: OSSF confirmed")
		}
	} else {
		evidenceParts = append(evidenceParts, "No security policy found")
	}

	// -----------------------------------------------------------------------
	// Component 2: Responsiveness (0-1 point)
	// Fast issue response OR branch protection both indicate active governance.
	// Either signal earns the point; no data = 0 points (not penalized further).
	// -----------------------------------------------------------------------
	responsivenessPoints := 0

	if govMetrics.AvgIssueResponseDays > 0 && govMetrics.AvgIssueResponseDays <= 14 {
		// Responsive maintainers (within 2 weeks)
		responsivenessPoints = 1
		evidenceParts = append(evidenceParts, fmt.Sprintf("Avg issue response: %.1f days", govMetrics.AvgIssueResponseDays))
	} else if result.Metadata.HasBranchProtection {
		// Branch protection signals an enforced review/merge process
		responsivenessPoints = 1
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
	// Total possible: 2 points (1 security policy + 1 responsiveness)
	// 2 pts = 0 risk (responsive + security policy)
	// 1 pt  = 1 risk (partial signals)
	// 0 pts = 2 risk (no signals)
	// Abandonment/archive are handled as early returns above.
	// -----------------------------------------------------------------------
	totalPoints := securityPolicyPoints + responsivenessPoints

	riskPoints := 2
	switch {
	case totalPoints >= 2:
		riskPoints = 0
	case totalPoints >= 1:
		riskPoints = 1
	}

	// Determine description based on risk level
	var description string
	switch {
	case riskPoints == 0:
		description = "Strong governance: security policy and responsive maintenance"
	case riskPoints == 1:
		description = "Partial governance: security policy or responsive maintenance present"
	default:
		description = "Poor governance: no security policy or responsiveness signals"
	}

	return models.CategoryScore{
		Score:       2 - riskPoints, // Invert for display
		RiskPoints:  riskPoints,
		Description: description,
		Evidence:    strings.Join(evidenceParts, "; ") + govSource,
		Verified:    true,
	}
}
