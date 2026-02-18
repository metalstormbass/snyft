package fetcher

import (
	"strings"
	"time"

	"github.com/metalstormbass/snyft/pkg/models"
)

// GitPlatformClient defines the interface that all git hosting platforms must implement
// This allows the analyzer to work with GitHub, GitLab, Bitbucket, and other platforms uniformly
type GitPlatformClient interface {
	// GetRepositoryInfo fetches repository metadata
	GetRepositoryInfo(repoURL string) (*models.RepositoryInfo, error)

	// CheckGitTag verifies if a specific version tag exists in the repository
	// Returns true if the tag exists, along with the tag URL
	CheckGitTag(repoURL, version string) (bool, string, error)

	// DetectCISystems checks for common CI/CD systems in the repository
	DetectCISystems(repoURL string) ([]string, error)

	// HasAutomatedReleases checks if the repository has automated releases
	HasAutomatedReleases(repoURL string) (bool, error)

	// GetReleaseHistory fetches detailed release history for a repository
	GetReleaseHistory(repoURL string, limit int) ([]GitHubRelease, error)

	// GetCommitActivity fetches recent commit activity for a repository
	GetCommitActivity(repoURL string, since time.Time) ([]GitHubCommit, error)

	// GetFileContent fetches the content of a file from the repository
	GetFileContent(repoURL, filePath string) (string, error)

	// GetProvenanceInfo checks for various provenance indicators in the repository
	GetProvenanceInfo(repoURL string) (*models.ProvenanceInfo, error)

	// GetCommitAuthors analyzes commit authorship patterns for ownership change detection
	GetCommitAuthors(repoURL string) (*CommitAuthorStats, error)

	// CheckSignedCommits checks if recent commits in the repository are GPG signed
	CheckSignedCommits(repoURL string) (bool, int, error)

	// CheckSignedReleases checks if releases have GPG signatures
	CheckSignedReleases(repoURL string) (bool, error)

	// GetCommitStats fetches commit distribution to calculate bus factor
	GetCommitStats(repoURL string) (*CommitStats, error)

	// GetPullRequestStats analyzes PR statistics for code review verification
	GetPullRequestStats(repoURL string) (*PRStats, error)

	// AnalyzeCIQuality evaluates CI/CD quality beyond just presence
	AnalyzeCIQuality(repoURL string, ciSystems []string) (*CIQuality, error)

	// GetPlatformName returns the name of the platform (e.g., "GitHub", "GitLab", "Bitbucket")
	GetPlatformName() string

	// CheckOrgMFARequired checks if an organization has mandatory MFA/2FA enforcement.
	// Returns (required, available):
	//   (true, true)   = MFA is enforced by the organization
	//   (false, true)  = MFA is NOT enforced (high risk)
	//   (false, false) = data unavailable (owner is a user, platform doesn't expose it, or API error)
	//
	// Justification: Org-level MFA enforcement is the single most impactful account
	// security control. Without it, all maintainer accounts are vulnerable to credential
	// stuffing attacks - the leading cause of supply chain compromise.
	// Source: "Backstabber's Knife Collection" (Ohm et al., 2020)
	// Note: Only GitHub exposes this publicly. GitLab/Bitbucket require admin auth.
	CheckOrgMFARequired(owner string) (required bool, available bool)

	// CheckIfOrganization checks if a repository owner is an organization or personal account
	// Returns (isOrg bool, orgName string)
	CheckIfOrganization(owner string) (bool, string)

	// CheckVerifiedOrganization checks if an organization has verified status
	CheckVerifiedOrganization(owner string) bool

	// GetUserAccountCreatedDate fetches the account creation date for a user
	GetUserAccountCreatedDate(username string) (time.Time, error)
}

// PlatformType represents the type of git hosting platform
type PlatformType string

const (
	PlatformGitHub      PlatformType = "github"
	PlatformGitLab      PlatformType = "gitlab"
	PlatformBitbucket   PlatformType = "bitbucket"
	PlatformSourcehut   PlatformType = "sourcehut"   // sr.ht
	PlatformCodeberg    PlatformType = "codeberg"    // codeberg.org (runs Gitea)
	PlatformGitea       PlatformType = "gitea"       // self-hosted Gitea instances
	PlatformForgejo     PlatformType = "forgejo"     // self-hosted Forgejo instances
	PlatformApache      PlatformType = "apache"      // gitbox.apache.org, git.apache.org
	PlatformEclipse     PlatformType = "eclipse"     // git.eclipse.org
	PlatformSavannah    PlatformType = "savannah"    // savannah.gnu.org, savannah.nongnu.org
	PlatformLaunchpad   PlatformType = "launchpad"   // launchpad.net
	PlatformSourceForge PlatformType = "sourceforge" // sourceforge.net, sourceforge.io
	PlatformGenericGit  PlatformType = "generic_git" // any git URL we cannot identify specifically
	PlatformUnknown     PlatformType = "unknown"
)

// DetectPlatform determines which git hosting platform a URL belongs to
func DetectPlatform(repoURL string) PlatformType {
	if repoURL == "" {
		return PlatformUnknown
	}

	// Normalize URL for comparison
	url := normalizeURL(repoURL)

	// Check for each platform
	if containsAny(url, []string{"github.com", "github"}) {
		return PlatformGitHub
	}
	if containsAny(url, []string{"gitlab.com", "gitlab"}) {
		return PlatformGitLab
	}
	if containsAny(url, []string{"bitbucket.org", "bitbucket"}) {
		return PlatformBitbucket
	}
	if containsAny(url, []string{"sr.ht", "sourcehut"}) {
		return PlatformSourcehut
	}
	if containsAny(url, []string{"codeberg.org", "codeberg"}) {
		return PlatformCodeberg
	}
	if containsAny(url, []string{"gitbox.apache.org", "git.apache.org"}) {
		return PlatformApache
	}
	if containsAny(url, []string{"git.eclipse.org"}) {
		return PlatformEclipse
	}
	if containsAny(url, []string{"sourceforge.net", "sourceforge.io"}) {
		return PlatformSourceForge
	}
	if containsAny(url, []string{"launchpad.net"}) {
		return PlatformLaunchpad
	}

	// Generic fallback: any URL ending in .git or containing /git/
	if strings.HasSuffix(strings.ToLower(repoURL), ".git") || strings.Contains(strings.ToLower(repoURL), "/git/") {
		return PlatformGenericGit
	}

	return PlatformUnknown
}

// NewGitPlatformClient creates the appropriate client based on the repository URL
func NewGitPlatformClient(repoURL string) GitPlatformClient {
	platform := DetectPlatform(repoURL)

	switch platform {
	case PlatformGitHub:
		return NewGitHubClient()
	case PlatformGitLab:
		return NewGitLabClient()
	case PlatformBitbucket:
		return NewBitbucketClient()
	case PlatformSourcehut, PlatformCodeberg,
		PlatformApache, PlatformEclipse, PlatformSourceForge, PlatformLaunchpad,
		PlatformGenericGit:
		// For these platforms use the generic Git client which performs basic
		// HTTP-level checks without requiring a platform-specific API.
		return NewGenericGitClient()
	case PlatformUnknown:
		// Unknown URLs: fall back to GitHub client for backward compatibility
		return NewGitHubClient()
	default:
		return NewGitHubClient()
	}
}

// normalizeURL removes common prefixes from URLs for easier comparison
func normalizeURL(url string) string {
	// Remove protocol prefixes
	url = removePrefix(url, "git+https://")
	url = removePrefix(url, "git+http://")
	url = removePrefix(url, "https://")
	url = removePrefix(url, "http://")
	url = removePrefix(url, "git://")
	url = removePrefix(url, "ssh://")
	url = removePrefix(url, "git@")
	return url
}

// removePrefix removes a prefix from a string if it exists
func removePrefix(s, prefix string) string {
	if len(s) >= len(prefix) && s[:len(prefix)] == prefix {
		return s[len(prefix):]
	}
	return s
}

// containsAny checks if a string contains any of the provided substrings
func containsAny(s string, substrs []string) bool {
	for _, substr := range substrs {
		if stringContains(s, substr) {
			return true
		}
	}
	return false
}

// stringContains checks if a string contains a substring (case-insensitive)
func stringContains(s, substr string) bool {
	// Simple case-insensitive check
	sLower := stringToLower(s)
	substrLower := stringToLower(substr)
	return stringIndexOf(sLower, substrLower) >= 0
}

// stringToLower converts a string to lowercase
func stringToLower(s string) string {
	result := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c = c + ('a' - 'A')
		}
		result[i] = c
	}
	return string(result)
}

// stringIndexOf returns the index of substr in s, or -1 if not found
func stringIndexOf(s, substr string) int {
	if len(substr) == 0 {
		return 0
	}
	if len(substr) > len(s) {
		return -1
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		match := true
		for j := 0; j < len(substr); j++ {
			if s[i+j] != substr[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}
