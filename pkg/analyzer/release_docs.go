package analyzer

import (
	"strings"

	"github.com/metalstormbass/snyft/pkg/fetcher"
	"github.com/metalstormbass/snyft/pkg/models"
)

// releaseDocFiles lists the files to check for release/contributing documentation,
// in priority order. We check multiple locations because projects follow different
// conventions for where they place these files.
var releaseDocFiles = []string{
	"CONTRIBUTING.md",
	"RELEASING.md",
	"RELEASE.md",
	".github/CONTRIBUTING.md",
	"docs/RELEASING.md",
	"docs/RELEASE.md",
	"docs/releasing.md",
	"docs/release.md",
}

// analyzeReleaseDocumentation fetches and parses contributing/release documentation
// files from a repository to extract signals about the project's release process.
//
// Check: Release process documentation analysis
// Justification: Projects with documented release processes have formalized controls
//                that reduce the risk of a single compromised maintainer pushing
//                malicious code. Documented multi-approval requirements, release
//                checklists, and CI/CD automation create barriers an attacker must
//                bypass beyond just compromising one account.
// Source: SLSA Build Level Requirements (https://slsa.dev/spec/v1.0/levels)
//         "Backstabber's Knife Collection" (Ohm et al., 2020)
// Methodology: Fetch release/contributing docs via web scraping (raw.githubusercontent.com
//              or platform-specific raw URLs). Parse content for release process keywords.
// Result: Populates ReleaseDocumentation struct on PackageMetadata
func (a *Analyzer) analyzeReleaseDocumentation(result *models.AnalysisResult, repoURL string) {
	if repoURL == "" {
		return
	}

	gitClient := a.getGitClient(repoURL)
	releaseDocs := &models.ReleaseDocumentation{}

	for _, filePath := range releaseDocFiles {
		content := a.fetchReleaseDocFile(gitClient, repoURL, filePath)
		if content == "" {
			continue
		}

		releaseDocs.FilesFound = append(releaseDocs.FilesFound, filePath)
		releaseDocs.HasDocumentedReleaseProcess = true

		// Parse the content for specific signals
		parseReleaseDocContent(content, filePath, releaseDocs)
	}

	// Only attach to metadata if we found something
	if len(releaseDocs.FilesFound) > 0 {
		result.Metadata.ReleaseDocumentation = releaseDocs
	}
}

// fetchReleaseDocFile fetches a single documentation file from the repository.
// Uses the same pattern as checkGovernanceFile: efficient HEAD-based check for
// GitHub, content-based check for other platforms.
func (a *Analyzer) fetchReleaseDocFile(gitClient fetcher.GitPlatformClient, repoURL, filePath string) string {
	// For GitHub, first check if file exists (cheap HEAD request), then fetch content
	if ghClient, ok := gitClient.(*fetcher.GitHubClient); ok {
		if !ghClient.FileExistsInRepo(repoURL, filePath) {
			return ""
		}
	}

	content, err := gitClient.GetFileContent(repoURL, filePath)
	if err != nil {
		return ""
	}

	if len(strings.TrimSpace(content)) == 0 {
		return ""
	}

	return content
}

// parseReleaseDocContent analyzes the text content of a release/contributing document
// to extract specific supply chain risk signals.
//
// We look for keywords and patterns that indicate:
// 1. Multi-approval requirements (reduces single-point-of-compromise risk)
// 2. Release checklists (structured process harder to subvert)
// 3. CI/CD automation for releases (removes human from publish path)
// 4. Release manager role (designated responsibility)
func parseReleaseDocContent(content, filePath string, docs *models.ReleaseDocumentation) {
	lower := strings.ToLower(content)

	// Check for multi-approval requirements
	// Patterns: "two approvals", "2 approvals", "multiple reviewers", "sign-off from",
	//           "requires approval from", "at least 2", "two maintainers"
	multiApprovalPatterns := []string{
		"two approval",
		"2 approval",
		"multiple reviewer",
		"multiple approval",
		"sign-off from",
		"sign off from",
		"requires approval",
		"require approval",
		"at least 2",
		"at least two",
		"two maintainer",
		"2 maintainer",
		"lgtm from",
		"approved by at least",
	}
	for _, pattern := range multiApprovalPatterns {
		if strings.Contains(lower, pattern) {
			docs.HasMultiApprovalRequirement = true
			docs.Evidence = append(docs.Evidence, filePath+": multi-approval requirement detected (\""+pattern+"\")")
			break
		}
	}

	// Check for release checklists
	// Patterns: "[ ]" (markdown checkbox), "checklist", "release steps",
	//           "before releasing", "release process"
	checklistPatterns := []string{
		"[ ]",
		"[x]",
		"checklist",
		"release steps",
		"before releasing",
		"release process",
		"release procedure",
		"how to release",
		"creating a release",
		"making a release",
		"cutting a release",
	}
	for _, pattern := range checklistPatterns {
		if strings.Contains(lower, pattern) {
			docs.HasReleaseChecklist = true
			docs.Evidence = append(docs.Evidence, filePath+": release checklist/process detected (\""+pattern+"\")")
			break
		}
	}

	// Check for automated release process via CI/CD
	// Patterns: "github actions", "ci/cd", "automated release", "release workflow",
	//           "publish workflow", "deploy pipeline"
	automationPatterns := []string{
		"github actions",
		"gitlab ci",
		"ci/cd",
		"ci cd",
		"automated release",
		"automatic release",
		"release workflow",
		"publish workflow",
		"release pipeline",
		"deploy pipeline",
		"continuous delivery",
		"continuous deployment",
		"semantic-release",
		"goreleaser",
		"release-please",
		"auto-publish",
		"autopublish",
	}
	for _, pattern := range automationPatterns {
		if strings.Contains(lower, pattern) {
			docs.HasAutomatedReleaseProcess = true
			docs.Evidence = append(docs.Evidence, filePath+": automated release process detected (\""+pattern+"\")")
			break
		}
	}

	// Check for release manager role
	// Patterns: "release manager", "release captain", "release lead",
	//           "release coordinator", "designated releaser"
	releaseManagerPatterns := []string{
		"release manager",
		"release captain",
		"release lead",
		"release coordinator",
		"designated releaser",
		"release owner",
		"release shepherd",
	}
	for _, pattern := range releaseManagerPatterns {
		if strings.Contains(lower, pattern) {
			docs.HasReleaseManagerRole = true
			docs.Evidence = append(docs.Evidence, filePath+": release manager role detected (\""+pattern+"\")")
			break
		}
	}
}
