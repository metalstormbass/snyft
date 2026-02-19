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
	govMethodology := "Checked for SECURITY.md (and .github/SECURITY.md) via Git API. Analyzed issue response times via GitHub API. Checked OSSF Scorecard Security-Policy score. Detected abandonment via last commit date."

	// Early return if no repository URL
	if result.RepositoryURL == "" {
		return models.CategoryScore{
			Score:       1,
			RiskPoints:  1,
			Description: "Unable to assess governance: no repository URL available",
			Evidence:    "No source repository URL found; further investigation recommended" + govSource,
			Verified:    false,
			Methodology: "No repository URL available. Could not check for SECURITY.md, issue response times, or abandonment patterns.",
			ChecksPerformed: []models.CheckResult{
				{Name: "SECURITY.md", Status: "SKIPPED", Detail: "No repository URL to check"},
				{Name: "Issue response time", Status: "SKIPPED", Detail: "No repository URL to check"},
				{Name: "Abandonment detection", Status: "SKIPPED", Detail: "No repository URL to check"},
				{Name: "OSSF Security-Policy", Status: "SKIPPED", Detail: "No repository URL to check"},
			},
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
			Methodology: govMethodology,
			ChecksPerformed: []models.CheckResult{
				{Name: "Repository archived status", Status: "FAIL", Detail: "Repository is archived — no active governance possible"},
			},
		}
	}

	// Early return for abandoned packages
	if !result.Metadata.RepoLastCommit.IsZero() {
		daysSince := time.Since(result.Metadata.RepoLastCommit).Hours() / 24
		if daysSince > 180 {
			return models.CategoryScore{
				Score:       0,
				RiskPoints:  2,
				Description: "Abandoned project: high risk of compromise",
				Evidence:    fmt.Sprintf("Abandoned: %.0f days since last commit", daysSince) + govSource,
				Verified:    true,
				Methodology: govMethodology,
				ChecksPerformed: []models.CheckResult{
					{Name: "Abandonment detection", Status: "FAIL", Detail: fmt.Sprintf("%.0f days since last commit (>180 day threshold)", daysSince)},
				},
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
			Methodology: govMethodology,
			ChecksPerformed: []models.CheckResult{
				{Name: "Repository access", Status: "UNAVAILABLE", Detail: "Could not fetch repository information via Git API"},
			},
		}
	}

	// Build evidence list
	evidenceParts := []string{}
	govChecks := []models.CheckResult{}

	// -----------------------------------------------------------------------
	// Component 1: Security Policy (0-1 point)
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
			govChecks = append(govChecks, models.CheckResult{Name: "SECURITY.md", Status: "PASS", Detail: "SECURITY.md found in repository (or .github/SECURITY.md)"})
		} else {
			evidenceParts = append(evidenceParts, "Security policy: OSSF confirmed")
			govChecks = append(govChecks, models.CheckResult{Name: "SECURITY.md", Status: "FAIL", Detail: "No SECURITY.md file found"})
			govChecks = append(govChecks, models.CheckResult{Name: "OSSF Security-Policy", Status: "PASS", Detail: "OSSF Scorecard confirms security policy exists"})
		}
	} else {
		evidenceParts = append(evidenceParts, "No security policy found")
		govChecks = append(govChecks, models.CheckResult{Name: "SECURITY.md", Status: "FAIL", Detail: "No SECURITY.md or .github/SECURITY.md found"})
		if result.Metadata.OSSFChecks != nil {
			if spScore, exists := result.Metadata.OSSFChecks["Security-Policy"]; exists {
				govChecks = append(govChecks, models.CheckResult{Name: "OSSF Security-Policy", Status: "FAIL", Detail: fmt.Sprintf("Score: %d/10 (below threshold of 5)", spScore)})
			}
		}
	}

	// -----------------------------------------------------------------------
	// Component 2: Responsiveness (0-1 point)
	// -----------------------------------------------------------------------
	responsivenessPoints := 0

	if govMetrics.AvgIssueResponseDays > 0 && govMetrics.AvgIssueResponseDays <= 14 {
		responsivenessPoints = 1
		evidenceParts = append(evidenceParts, fmt.Sprintf("Avg issue response: %.1f days", govMetrics.AvgIssueResponseDays))
		govChecks = append(govChecks, models.CheckResult{Name: "Issue response time", Status: "PASS", Detail: fmt.Sprintf("Average response: %.1f days (<= 14 day threshold)", govMetrics.AvgIssueResponseDays)})
	} else if result.Metadata.HasBranchProtection {
		responsivenessPoints = 1
		if result.Metadata.RequiredReviewers > 0 {
			evidenceParts = append(evidenceParts, fmt.Sprintf("Branch protection with %d required reviewer(s)", result.Metadata.RequiredReviewers))
			govChecks = append(govChecks, models.CheckResult{Name: "Branch protection", Status: "PASS", Detail: fmt.Sprintf("Branch protection enabled with %d required reviewer(s)", result.Metadata.RequiredReviewers)})
		} else {
			evidenceParts = append(evidenceParts, "Branch protection enabled")
			govChecks = append(govChecks, models.CheckResult{Name: "Branch protection", Status: "PASS", Detail: "Branch protection enabled"})
		}
	} else if govMetrics.AvgIssueResponseDays > 14 {
		evidenceParts = append(evidenceParts, fmt.Sprintf("Avg issue response: %.1f days (slow)", govMetrics.AvgIssueResponseDays))
		govChecks = append(govChecks, models.CheckResult{Name: "Issue response time", Status: "FAIL", Detail: fmt.Sprintf("Average response: %.1f days (> 14 day threshold)", govMetrics.AvgIssueResponseDays)})
	} else {
		govChecks = append(govChecks, models.CheckResult{Name: "Issue response time", Status: "UNAVAILABLE", Detail: "No issue response data available"})
	}

	if govMetrics.RecentActivityGap > 90 {
		evidenceParts = append(evidenceParts, fmt.Sprintf("Inactive: %.0f days since last commit", govMetrics.RecentActivityGap))
		govChecks = append(govChecks, models.CheckResult{Name: "Recent activity", Status: "FAIL", Detail: fmt.Sprintf("%.0f days since last commit (> 90 day concern threshold)", govMetrics.RecentActivityGap)})
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
	switch riskPoints {
	case 0:
		description = "Strong governance: security policy and responsive maintenance"
	case 1:
		description = "Partial governance: security policy or responsive maintenance present"
	default:
		description = "Poor governance: no security policy or responsiveness signals"
	}

	return models.CategoryScore{
		Score:           2 - riskPoints,
		RiskPoints:      riskPoints,
		Description:     description,
		Evidence:        strings.Join(evidenceParts, "; ") + govSource,
		Verified:        true,
		Methodology:     govMethodology,
		ChecksPerformed: govChecks,
	}
}
