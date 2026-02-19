package fetcher

import (
	"fmt"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/metalstormbass/snyft/pkg/models"
)

// GenericGitClient is a minimal GitPlatformClient for unknown or generic Git
// hosting platforms (e.g. Apache Gitbox, Eclipse, SourceForge, Launchpad,
// Codeberg, SourceHut, and any URL ending in .git).
//
// It performs basic HTTP-level checks without relying on a platform-specific API.
// All methods that cannot be meaningfully implemented return safe zero values.
type GenericGitClient struct {
	httpClient *http.Client
}

// NewGenericGitClient creates a new GenericGitClient with a 10-second timeout.
func NewGenericGitClient() *GenericGitClient {
	return &GenericGitClient{
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// GetPlatformName returns the display name of this client.
func (c *GenericGitClient) GetPlatformName() string {
	return "Generic Git"
}

// GetRepositoryInfo performs an HTTP HEAD request to the repository URL.
// If the server responds with 200 OK, a minimal RepositoryInfo is returned
// with the URL and Name extracted from the URL path. On non-200 responses an
// error is returned so callers can degrade gracefully.
func (c *GenericGitClient) GetRepositoryInfo(repoURL string) (*models.RepositoryInfo, error) {
	req, err := http.NewRequest("HEAD", repoURL, nil)
	if err != nil {
		return nil, fmt.Errorf("generic git: failed to create request for %s: %w", repoURL, err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("generic git: HEAD request failed for %s: %w", repoURL, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("generic git: repository %s returned HTTP %d", repoURL, resp.StatusCode)
	}

	// Extract repo name from the URL path (last non-empty segment, strip .git)
	repoName := path.Base(strings.TrimSuffix(strings.TrimRight(repoURL, "/"), ".git"))
	if repoName == "." || repoName == "/" {
		repoName = repoURL
	}

	return &models.RepositoryInfo{
		URL:  repoURL,
		Name: repoName,
	}, nil
}

// GetFileContent tries to fetch a file from the repository using common raw-content
// URL patterns appropriate to several generic platforms.
//
// Patterns tried (in order):
//  1. Codeberg: https://codeberg.org/{owner}/{repo}/raw/branch/main/{filePath}
//  2. SourceHut: https://git.sr.ht/{owner}/{repo}/blob/HEAD/{filePath}
//  3. Generic main: {repoURL}/raw/main/{filePath}
//  4. Generic master: {repoURL}/raw/master/{filePath}
func (c *GenericGitClient) GetFileContent(repoURL, filePath string) (string, error) {
	candidates := genericRawURLs(repoURL, filePath)

	for _, rawURL := range candidates {
		content, err := c.fetchText(rawURL)
		if err == nil && content != "" {
			return content, nil
		}
	}

	return "", fmt.Errorf("generic git: file %s not found in %s", filePath, repoURL)
}

// genericRawURLs builds the list of candidate raw-content URLs for a given repo
// URL and file path.
func genericRawURLs(repoURL, filePath string) []string {
	base := strings.TrimSuffix(strings.TrimRight(repoURL, "/"), ".git")

	var candidates []string

	// Codeberg
	if strings.Contains(strings.ToLower(base), "codeberg.org") {
		// Extract owner/repo from the URL
		owner, repo := extractOwnerRepo(base)
		if owner != "" && repo != "" {
			candidates = append(candidates,
				fmt.Sprintf("https://codeberg.org/%s/%s/raw/branch/main/%s", owner, repo, filePath),
				fmt.Sprintf("https://codeberg.org/%s/%s/raw/branch/master/%s", owner, repo, filePath),
			)
		}
	}

	// SourceHut
	if strings.Contains(strings.ToLower(base), "sr.ht") {
		owner, repo := extractOwnerRepo(base)
		if owner != "" && repo != "" {
			candidates = append(candidates,
				fmt.Sprintf("https://git.sr.ht/%s/%s/blob/HEAD/%s", owner, repo, filePath),
			)
		}
	}

	// Generic fallbacks
	candidates = append(candidates,
		base+"/raw/main/"+filePath,
		base+"/raw/master/"+filePath,
	)

	return candidates
}

// extractOwnerRepo attempts to extract the owner and repository name from a
// repository URL path (e.g. "https://codeberg.org/owner/repo" → "owner", "repo").
func extractOwnerRepo(baseURL string) (owner, repo string) {
	owner, repo, err := ParseRepoURL(baseURL)
	if err != nil {
		return "", ""
	}
	return owner, repo
}

// fetchText performs an HTTP GET and returns the response body as a string.
// Only HTTP 200 responses are accepted; all others return an error.
func (c *GenericGitClient) fetchText(url string) (string, error) {
	resp, err := c.httpClient.Get(url)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	var buf strings.Builder
	buf.Grow(4096)
	tmp := make([]byte, 4096)
	for {
		n, readErr := resp.Body.Read(tmp)
		if n > 0 {
			buf.Write(tmp[:n])
		}
		if readErr != nil {
			break
		}
	}
	return buf.String(), nil
}

// DetectCISystems attempts to detect CI/CD systems by looking for their
// configuration files via GetFileContent. Returns names of any found systems.
func (c *GenericGitClient) DetectCISystems(repoURL string) ([]string, error) {
	// CI config files to probe — a representative subset from ci_detection.go
	ciFiles := []struct {
		path string
		name string
	}{
		{".github/workflows", "GitHub Actions"},
		{".gitlab-ci.yml", "GitLab CI"},
		{"Jenkinsfile", "Jenkins"},
		{".travis.yml", "Travis CI"},
		{".circleci/config.yml", "CircleCI"},
		{"azure-pipelines.yml", "Azure Pipelines"},
		{".drone.yml", "Drone CI"},
		{".woodpecker.yml", "Woodpecker CI"},
	}

	var detected []string
	for _, ci := range ciFiles {
		_, err := c.GetFileContent(repoURL, ci.path)
		if err == nil {
			detected = append(detected, ci.name)
		}
	}
	return detected, nil
}

// --- Stub implementations for the remainder of the GitPlatformClient interface ---
// These return ErrDataUnavailable so that scoring functions can distinguish between
// "data checked and found absent" (nil error) and "data not available on this platform"
// (ErrDataUnavailable). The latter should be scored as "unknown" (moderate risk)
// rather than "worst case" (maximum risk).

// CheckGitTag returns ErrDataUnavailable — tag lookup requires a platform API.
func (c *GenericGitClient) CheckGitTag(repoURL, version string) (bool, string, error) {
	return false, "", ErrDataUnavailable
}

// HasAutomatedReleases returns ErrDataUnavailable — release detection requires a platform API.
func (c *GenericGitClient) HasAutomatedReleases(repoURL string) (bool, error) {
	return false, ErrDataUnavailable
}

// GetReleaseHistory returns ErrDataUnavailable — release history requires a platform API.
func (c *GenericGitClient) GetReleaseHistory(repoURL string, limit int) ([]GitHubRelease, error) {
	return nil, ErrDataUnavailable
}

// GetCommitActivity returns ErrDataUnavailable — commit history requires a platform API.
func (c *GenericGitClient) GetCommitActivity(repoURL string, since time.Time) ([]GitHubCommit, error) {
	return nil, ErrDataUnavailable
}

// GetProvenanceInfo returns ErrDataUnavailable — provenance checks require a platform API.
func (c *GenericGitClient) GetProvenanceInfo(repoURL string) (*models.ProvenanceInfo, error) {
	return nil, ErrDataUnavailable
}

// GetCommitAuthors returns ErrDataUnavailable — commit authorship analysis requires a platform API.
func (c *GenericGitClient) GetCommitAuthors(repoURL string) (*CommitAuthorStats, error) {
	return nil, ErrDataUnavailable
}

// CheckSignedCommits returns ErrDataUnavailable — signature verification requires a platform API.
func (c *GenericGitClient) CheckSignedCommits(repoURL string) (bool, int, error) {
	return false, 0, ErrDataUnavailable
}

// CheckSignedReleases returns ErrDataUnavailable — release signature checks require a platform API.
func (c *GenericGitClient) CheckSignedReleases(repoURL string) (bool, error) {
	return false, ErrDataUnavailable
}

// GetCommitStats returns ErrDataUnavailable — commit statistics require a platform API.
func (c *GenericGitClient) GetCommitStats(repoURL string) (*CommitStats, error) {
	return nil, ErrDataUnavailable
}

// GetPullRequestStats returns ErrDataUnavailable — PR statistics require a platform API.
func (c *GenericGitClient) GetPullRequestStats(repoURL string) (*PRStats, error) {
	return nil, ErrDataUnavailable
}

// AnalyzeCIQuality returns ErrDataUnavailable — CI quality analysis requires a platform API.
func (c *GenericGitClient) AnalyzeCIQuality(repoURL string, ciSystems []string) (*CIQuality, error) {
	return nil, ErrDataUnavailable
}

// CheckIfOrganization always returns (false, "").
func (c *GenericGitClient) CheckIfOrganization(owner string) (bool, string) {
	return false, ""
}

// CheckVerifiedOrganization always returns false.
func (c *GenericGitClient) CheckVerifiedOrganization(owner string) bool {
	return false
}

// GetUserAccountCreatedDate always returns an error — not supported for generic hosts.
func (c *GenericGitClient) GetUserAccountCreatedDate(username string) (time.Time, error) {
	return time.Time{}, fmt.Errorf("not supported")
}

// CheckOrgMFARequired always returns (false, false) — unavailable without a platform API.
func (c *GenericGitClient) CheckOrgMFARequired(owner string) (required bool, available bool) {
	return false, false
}
