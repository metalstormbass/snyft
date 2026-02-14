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
	HasSecurityPolicy   bool
	HasContributing     bool
	HasCodeOwners       bool
	AvgIssueResponseDays float64
	RecentActivityGap    float64  // Days since last activity
	HasAbandonmentPattern bool
	Verified            bool
}

// AnalyzeGovernance checks for governance documentation and maintainer responsiveness
// Test: Governance risk assessment for supply chain security
// Justification: Poor governance = unmaintained packages = higher likelihood of
//                account takeover or malicious code injection. Abandoned packages
//                that suddenly reactivate are a common supply chain attack pattern.
// Source: "Backstabber's Knife Collection" (Ohm et al., 2020)
//         https://arxiv.org/abs/2005.09535
//         "Towards Measuring Supply Chain Attacks" (NDSS 2020)
// Methodology: Check for SECURITY.md, CONTRIBUTING.md, CODEOWNERS files via Git API;
//              Analyze issue response times; Detect dormancy patterns
// Result: Assigns 0-2 risk points based on governance quality and abandonment signals
func (a *Analyzer) analyzeGovernance(result *models.AnalysisResult, repoURL string) *GovernanceMetrics {
	if repoURL == "" {
		return &GovernanceMetrics{Verified: false}
	}

	gitClient := a.getGitClient(repoURL)
	metrics := &GovernanceMetrics{Verified: true}

	// Check for governance documentation files
	metrics.HasSecurityPolicy = a.checkGovernanceFile(gitClient, repoURL, "SECURITY.md")
	metrics.HasContributing = a.checkGovernanceFile(gitClient, repoURL, "CONTRIBUTING.md")
	metrics.HasCodeOwners = a.checkGovernanceFile(gitClient, repoURL, "CODEOWNERS") ||
		a.checkGovernanceFile(gitClient, repoURL, ".github/CODEOWNERS")

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
//                higher risk of account takeover going unnoticed. Poor responsiveness
//                indicates unmaintained packages that could be compromised.
//                Abandonment followed by sudden activity is a red flag for takeover.
// Source: "Backstabber's Knife Collection" (Ohm et al., 2020)
//         "Towards Measuring Supply Chain Attacks" (NDSS 2020)
//         OSSF Scorecard Specification (Security Policy check)
// Methodology: Score based on presence of governance docs, issue response times,
//              and activity patterns
// Result: 0 risk points = Strong governance (all docs, fast response)
//         1 risk point = Moderate governance (some docs, slow response)
//         2 risk points = Poor governance (no docs, unresponsive, or abandoned)
// Scoring:
//   - 0 risk points (best): Has governance docs + responsive maintainers
//   - 1 risk point (moderate): Partial governance or slow response
//   - 2 risk points (worst): No governance docs or abandoned/unresponsive
func (a *Analyzer) scoreGovernance(result *models.AnalysisResult) models.CategoryScore {
	// Early return if no repository URL
	if result.RepositoryURL == "" {
		return models.CategoryScore{
			Score:       0,
			RiskPoints:  2,
			Description: "No repository available for governance assessment",
			Evidence:    "No source repository URL found",
			Verified:    false,
		}
	}

	// Analyze governance metrics
	govMetrics := a.analyzeGovernance(result, result.RepositoryURL)

	if !govMetrics.Verified {
		return models.CategoryScore{
			Score:       0,
			RiskPoints:  1,
			Description: "Unable to verify governance",
			Evidence:    "Could not fetch repository information",
			Verified:    false,
		}
	}

	// Build evidence list
	evidenceParts := []string{}
	points := 0

	// Component 1: Governance Documentation (worth up to 1 point)
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

	if docsCount >= 2 {
		// Has multiple governance docs
		points++
		evidenceParts = append(evidenceParts, fmt.Sprintf("Governance docs: %s", strings.Join(docsList, ", ")))
	} else if docsCount == 1 {
		// Has some governance docs
		evidenceParts = append(evidenceParts, fmt.Sprintf("Limited governance: %s", strings.Join(docsList, ", ")))
	} else {
		// No governance docs
		evidenceParts = append(evidenceParts, "No governance documentation found")
	}

	// Component 2: Maintainer Responsiveness (worth up to 1 point)
	if govMetrics.AvgIssueResponseDays > 0 {
		if govMetrics.AvgIssueResponseDays <= 7 {
			// Fast response (<= 1 week)
			points++
			evidenceParts = append(evidenceParts, fmt.Sprintf("Avg issue response: %.1f days", govMetrics.AvgIssueResponseDays))
		} else if govMetrics.AvgIssueResponseDays <= 30 {
			// Moderate response (1-4 weeks)
			evidenceParts = append(evidenceParts, fmt.Sprintf("Avg issue response: %.1f days (moderate)", govMetrics.AvgIssueResponseDays))
		} else {
			// Slow response (>30 days)
			evidenceParts = append(evidenceParts, fmt.Sprintf("Avg issue response: %.1f days (slow)", govMetrics.AvgIssueResponseDays))
		}
	}

	// Component 3: Abandonment Detection (negative indicator)
	if govMetrics.HasAbandonmentPattern {
		// Abandonment is a strong negative signal
		points = 0 // Override any points earned
		evidenceParts = append(evidenceParts, fmt.Sprintf("Abandoned: %.0f days since last commit", govMetrics.RecentActivityGap))
	} else if govMetrics.RecentActivityGap > 90 {
		// Long gap but not quite abandoned
		evidenceParts = append(evidenceParts, fmt.Sprintf("Inactive: %.0f days since last commit", govMetrics.RecentActivityGap))
	}

	// Calculate final risk points (invert points earned)
	// 2+ points earned = 0 risk points (good governance)
	// 1 point earned = 1 risk point (moderate governance)
	// 0 points earned = 2 risk points (poor governance)
	riskPoints := 2
	if points >= 2 {
		riskPoints = 0
	} else if points >= 1 {
		riskPoints = 1
	}

	// Override: Abandoned packages always get highest risk
	if govMetrics.HasAbandonmentPattern {
		riskPoints = 2
	}

	// Determine description based on risk level
	var description string
	switch riskPoints {
	case 0:
		description = "Strong governance: documented policies and responsive maintenance"
	case 1:
		description = "Moderate governance: some documentation or moderate responsiveness"
	default:
		description = "Poor governance: no documentation or unresponsive"
	}

	// Special case for abandonment
	if govMetrics.HasAbandonmentPattern {
		description = "Abandoned project: high risk of compromise"
	}

	return models.CategoryScore{
		Score:       2 - riskPoints, // Invert for display
		RiskPoints:  riskPoints,
		Description: description,
		Evidence:    strings.Join(evidenceParts, "; "),
		Verified:    true,
	}
}
