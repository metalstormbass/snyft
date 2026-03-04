package analyzer

import (
	"fmt"
	"strings"

	"github.com/metalstormbass/snyft/pkg/fetcher"
	"github.com/metalstormbass/snyft/pkg/models"
)

// GovernanceMetrics contains governance-related metrics for risk assessment
type GovernanceMetrics struct {
	HasSecurityPolicy    bool    // SECURITY.md — indicates vulnerability disclosure process
	AvgIssueResponseDays float64
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
//	Analyze issue response times
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
// Methodology: Check for SECURITY.md, issue response times
//
// Scoring (two components):
//   Security Policy (0-1 pt): SECURITY.md present or OSSF Security-Policy >= 5
//   Responsiveness (0-1 pt): fast issue response (<=14 days) OR branch protection
//   Total 2 points = 0 risk (responsive + security policy)
//   Total 1 point  = 1 risk (partial signals)
//   Total 0 points = 2 risk (no signals)
//   Override: Archived repos always get 2 risk
func (a *Analyzer) scoreGovernance(result *models.AnalysisResult) models.CategoryScore {
	// Source: OSSF Scorecard; Backstabber's Knife Collection (Ohm et al., 2020)
	govMethodology := "Checked for SECURITY.md (and .github/SECURITY.md) via Git API. Analyzed issue response times via GitHub API. Checked OSSF Scorecard Security-Policy score. Checked for contributing/release documentation (CONTRIBUTING.md, RELEASING.md, RELEASE.md)."

	// Early return if no repository URL
	if result.RepositoryURL == "" {
		return models.CategoryScore{
			Score:       1,
			RiskPoints:  1,
			Description: "No source repository URL found — unable to check for SECURITY.md or issue response times. Governance quality is unknown.",
			Evidence:    "No source repository URL found; further investigation recommended",
			Verified:    false,
			DataAvailable: false,
			Methodology: "No repository URL available. Could not check for SECURITY.md or issue response times.",
			ChecksPerformed: []models.CheckResult{
				{Name: "SECURITY.md", Status: "SKIPPED", Detail: "No repository URL to check"},
				{Name: "Issue response time", Status: "SKIPPED", Detail: "No repository URL to check"},
				{Name: "OSSF Security-Policy", Status: "SKIPPED", Detail: "No repository URL to check"},
			},
		}
	}

	// Early return for archived repositories (permanently unmaintained)
	if result.Metadata.RepoArchived {
		return models.CategoryScore{
			Score:       0,
			RiskPoints:  2,
			Description: "Repository is archived and no longer accepting contributions. Archived projects have no active governance, no vulnerability disclosure process, and no maintainers monitoring for compromises.",
			Evidence:    "Repository is archived and no longer accepting contributions",
			Verified:    true,
			DataAvailable: true,
			Methodology: govMethodology,
			ChecksPerformed: []models.CheckResult{
				{Name: "Repository archived status", Status: "FAIL", Detail: "Repository is archived — no active governance possible"},
			},
		}
	}

	// Analyze governance metrics
	// Note: dormancy/staleness is assessed solely by Package Maturity to avoid
	// triple-counting the same signal across multiple categories.
	govMetrics := a.analyzeGovernance(result, result.RepositoryURL)

	if !govMetrics.Verified {
		return models.CategoryScore{
			Score:       0,
			RiskPoints:  1,
			Description: "Could not fetch repository information to assess governance. Unable to check for SECURITY.md or issue response times.",
			Evidence:    "Could not fetch repository information",
			Verified:    false,
			DataAvailable: false,
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
			govChecks = append(govChecks, models.CheckResult{Name: "OSSF Security-Policy", Status: "PASS", Detail: "OSSF Scorecard confirms security policy with vulnerability reporting contact information"})
		}
	} else {
		evidenceParts = append(evidenceParts, "No security policy found")
		govChecks = append(govChecks, models.CheckResult{Name: "SECURITY.md", Status: "FAIL", Detail: "No SECURITY.md or .github/SECURITY.md found"})
		if result.Metadata.OSSFChecks != nil {
			if spScore, exists := result.Metadata.OSSFChecks["Security-Policy"]; exists {
				govChecks = append(govChecks, models.CheckResult{Name: "OSSF Security-Policy", Status: "FAIL", Detail: fmt.Sprintf("Score: %d/10 (below threshold of 5; may lack vulnerability reporting contact links)", spScore)})
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
	} else if result.Metadata.ReleaseDocumentation != nil && result.Metadata.ReleaseDocumentation.HasDocumentedReleaseProcess {
		// Documented contributing/release process is a positive governance signal:
		// it indicates formalized project management even when issue response data
		// is unavailable.
		responsivenessPoints = 1
		docFiles := strings.Join(result.Metadata.ReleaseDocumentation.FilesFound, ", ")
		evidenceParts = append(evidenceParts, fmt.Sprintf("Documented release/contributing process (%s)", docFiles))
		govChecks = append(govChecks, models.CheckResult{Name: "Release documentation", Status: "PASS", Detail: fmt.Sprintf("Contributing/release documentation found: %s", docFiles)})
	} else if govMetrics.AvgIssueResponseDays > 14 {
		evidenceParts = append(evidenceParts, fmt.Sprintf("Avg issue response: %.1f days (slow)", govMetrics.AvgIssueResponseDays))
		govChecks = append(govChecks, models.CheckResult{Name: "Issue response time", Status: "FAIL", Detail: fmt.Sprintf("Average response: %.1f days (> 14 day threshold)", govMetrics.AvgIssueResponseDays)})
	} else {
		govChecks = append(govChecks, models.CheckResult{Name: "Issue response time", Status: "UNAVAILABLE", Detail: "No issue response data available"})
		govChecks = append(govChecks, models.CheckResult{Name: "Release documentation", Status: "FAIL", Detail: "No contributing/release documentation found"})
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

	// Build description from actual evidence
	var description string
	switch riskPoints {
	case 0:
		description = strings.Join(evidenceParts, "; ") + ". Active governance with a security disclosure process and responsive maintainers means compromises are more likely to be detected and reported."
	case 1:
		description = strings.Join(evidenceParts, "; ") + ". Partial governance — either a security policy or responsive maintenance is present, but not both. Gaps reduce the likelihood of detecting or reporting compromises."
	default:
		description = "No SECURITY.md found and no responsive maintenance signals detected. Without a security policy, vulnerability reports have no disclosure channel, and compromises may go unreported."
		if len(evidenceParts) > 0 {
			description = strings.Join(evidenceParts, "; ") + ". No security policy or responsiveness signals — compromises may go undetected and unreported."
		}
	}

	return models.CategoryScore{
		Score:           2 - riskPoints,
		RiskPoints:      riskPoints,
		Description:     description,
		Evidence:        strings.Join(evidenceParts, "; "),
		Verified:        true,
		DataAvailable:   true,
		Methodology:     govMethodology,
		ChecksPerformed: govChecks,
	}
}
