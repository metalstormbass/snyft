package fetcher

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/metalstormbass/snyft/pkg/models"
)

// GitHubClient handles interactions with GitHub API
type GitHubClient struct {
	token      string
	httpClient *http.Client
	baseURL    string
}

// NewGitHubClient creates a new GitHub API client
func NewGitHubClient() *GitHubClient {
	return &GitHubClient{
		token: os.Getenv("GITHUB_TOKEN"),
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		baseURL: "https://api.github.com",
	}
}

// GetRepositoryInfo fetches repository information from GitHub
func (c *GitHubClient) GetRepositoryInfo(repoURL string) (*models.RepositoryInfo, error) {
	owner, repo, err := parseGitHubURL(repoURL)
	if err != nil {
		return nil, err
	}

	url := fmt.Sprintf("%s/repos/%s/%s", c.baseURL, owner, repo)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("GitHub API returned %d: %s", resp.StatusCode, string(body))
	}

	var ghRepo GitHubRepository
	if err := json.NewDecoder(resp.Body).Decode(&ghRepo); err != nil {
		return nil, err
	}

	return &models.RepositoryInfo{
		URL:           ghRepo.HTMLURL,
		Owner:         ghRepo.Owner.Login,
		Name:          ghRepo.Name,
		Description:   ghRepo.Description,
		Stars:         ghRepo.StargazersCount,
		Forks:         ghRepo.ForksCount,
		Watchers:      ghRepo.WatchersCount,
		OpenIssues:    ghRepo.OpenIssuesCount,
		DefaultBranch: ghRepo.DefaultBranch,
		Archived:      ghRepo.Archived,
		CreatedAt:     ghRepo.CreatedAt,
		UpdatedAt:     ghRepo.UpdatedAt,
		PushedAt:      ghRepo.PushedAt,
		License:       getLicenseName(ghRepo.License),
		Topics:        ghRepo.Topics,
	}, nil
}

// DetectCISystems checks for common CI/CD systems in the repository
func (c *GitHubClient) DetectCISystems(repoURL string) ([]string, error) {
	owner, repo, err := parseGitHubURL(repoURL)
	if err != nil {
		return nil, err
	}

	var ciSystems []string

	// Check for GitHub Actions
	if c.fileExists(owner, repo, ".github/workflows") {
		ciSystems = append(ciSystems, "GitHub Actions")
	}

	// Check for Travis CI
	if c.fileExists(owner, repo, ".travis.yml") {
		ciSystems = append(ciSystems, "Travis CI")
	}

	// Check for Circle CI
	if c.fileExists(owner, repo, ".circleci/config.yml") {
		ciSystems = append(ciSystems, "Circle CI")
	}

	// Check for Jenkins
	if c.fileExists(owner, repo, "Jenkinsfile") {
		ciSystems = append(ciSystems, "Jenkins")
	}

	// Check for GitLab CI
	if c.fileExists(owner, repo, ".gitlab-ci.yml") {
		ciSystems = append(ciSystems, "GitLab CI")
	}

	return ciSystems, nil
}

// HasAutomatedReleases checks if the repository has automated releases
func (c *GitHubClient) HasAutomatedReleases(repoURL string) (bool, error) {
	owner, repo, err := parseGitHubURL(repoURL)
	if err != nil {
		return false, err
	}

	url := fmt.Sprintf("%s/repos/%s/%s/releases", c.baseURL, owner, repo)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return false, err
	}

	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return false, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return false, nil
	}

	var releases []GitHubRelease
	if err := json.NewDecoder(resp.Body).Decode(&releases); err != nil {
		return false, err
	}

	return len(releases) > 0, nil
}

// GetReleaseHistory fetches detailed release history for a repository
func (c *GitHubClient) GetReleaseHistory(repoURL string, limit int) ([]GitHubRelease, error) {
	owner, repo, err := parseGitHubURL(repoURL)
	if err != nil {
		return nil, err
	}

	url := fmt.Sprintf("%s/repos/%s/%s/releases?per_page=%d", c.baseURL, owner, repo, limit)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API returned %d", resp.StatusCode)
	}

	var releases []GitHubRelease
	if err := json.NewDecoder(resp.Body).Decode(&releases); err != nil {
		return nil, err
	}

	return releases, nil
}

// GetCommitActivity fetches recent commit activity for a repository
func (c *GitHubClient) GetCommitActivity(repoURL string, since time.Time) ([]GitHubCommit, error) {
	owner, repo, err := parseGitHubURL(repoURL)
	if err != nil {
		return nil, err
	}

	url := fmt.Sprintf("%s/repos/%s/%s/commits?since=%s&per_page=100",
		c.baseURL, owner, repo, since.Format(time.RFC3339))
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API returned %d", resp.StatusCode)
	}

	var commits []GitHubCommit
	if err := json.NewDecoder(resp.Body).Decode(&commits); err != nil {
		return nil, err
	}

	return commits, nil
}

// CheckGitTag verifies if a specific version tag exists in the repository
// Returns true if the tag exists, along with the tag URL
func (c *GitHubClient) CheckGitTag(repoURL, version string) (bool, string, error) {
	owner, repo, err := parseGitHubURL(repoURL)
	if err != nil {
		return false, "", err
	}

	// Try common version tag formats: v1.2.3, 1.2.3, v1.2.3-beta, release-1.2.3
	tagVariants := []string{
		version,
		"v" + version,
		"V" + version,
		"release-" + version,
		"Release-" + version,
	}

	for _, tag := range tagVariants {
		url := fmt.Sprintf("%s/repos/%s/%s/git/ref/tags/%s", c.baseURL, owner, repo, tag)
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			continue
		}

		if c.token != "" {
			req.Header.Set("Authorization", "Bearer "+c.token)
		}
		req.Header.Set("Accept", "application/vnd.github.v3+json")

		resp, err := c.httpClient.Do(req)
		if err != nil {
			continue
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode == http.StatusOK {
			tagURL := fmt.Sprintf("https://github.com/%s/%s/releases/tag/%s", owner, repo, tag)
			return true, tagURL, nil
		}
	}

	return false, "", nil
}

func (c *GitHubClient) fileExists(owner, repo, path string) bool {
	url := fmt.Sprintf("%s/repos/%s/%s/contents/%s", c.baseURL, owner, repo, path)
	req, err := http.NewRequest("HEAD", url, nil)
	if err != nil {
		return false
	}

	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return false
	}
	defer func() { _ = resp.Body.Close() }()

	return resp.StatusCode == http.StatusOK
}

// GitHub API response structures
type GitHubRepository struct {
	Name            string         `json:"name"`
	FullName        string         `json:"full_name"`
	HTMLURL         string         `json:"html_url"`
	Description     string         `json:"description"`
	StargazersCount int            `json:"stargazers_count"`
	ForksCount      int            `json:"forks_count"`
	WatchersCount   int            `json:"watchers_count"`
	OpenIssuesCount int            `json:"open_issues_count"`
	DefaultBranch   string         `json:"default_branch"`
	Archived        bool           `json:"archived"`
	CreatedAt       time.Time      `json:"created_at"`
	UpdatedAt       time.Time      `json:"updated_at"`
	PushedAt        time.Time      `json:"pushed_at"`
	License         *GitHubLicense `json:"license"`
	Topics          []string       `json:"topics"`
	Owner           GitHubUser     `json:"owner"`
}

type GitHubUser struct {
	Login string `json:"login"`
}

type GitHubLicense struct {
	Key  string `json:"key"`
	Name string `json:"name"`
}

type GitHubRelease struct {
	TagName     string        `json:"tag_name"`
	Name        string        `json:"name"`
	Draft       bool          `json:"draft"`
	Prerelease  bool          `json:"prerelease"`
	CreatedAt   time.Time     `json:"created_at"`
	PublishedAt time.Time     `json:"published_at"`
	Assets      []GitHubAsset `json:"assets"`
}

type GitHubAsset struct {
	Name               string `json:"name"`
	ContentType        string `json:"content_type"`
	Size               int64  `json:"size"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

type GitHubCommit struct {
	SHA    string           `json:"sha"`
	Commit GitHubCommitInfo `json:"commit"`
	Author *GitHubUser      `json:"author"`
}

type GitHubCommitInfo struct {
	Author       GitHubCommitAuthor       `json:"author"`
	Committer    GitHubCommitAuthor       `json:"committer"`
	Message      string                   `json:"message"`
	Verification GitHubCommitVerification `json:"verification"`
}

type GitHubCommitAuthor struct {
	Name  string    `json:"name"`
	Email string    `json:"email"`
	Date  time.Time `json:"date"`
}

// CommitAuthorStats represents commit author statistics for ownership analysis
type CommitAuthorStats struct {
	TotalCommits      int
	UniqueAuthors     []string
	AuthorCommitCounts map[string]int
	AuthorFirstCommit  map[string]time.Time
	AuthorLastCommit   map[string]time.Time
	RecentAuthors      []string // Authors with commits in last 90 days
	HistoricalAuthors  []string // Authors with no recent commits
}

type GitHubCommitVerification struct{
	Verified  bool   `json:"verified"`
	Reason    string `json:"reason"`
	Signature string `json:"signature"`
}

func parseGitHubURL(repoURL string) (owner, repo string, err error) {
	// Handle various GitHub URL formats:
	// https://github.com/owner/repo
	// git://github.com/owner/repo.git
	// git+https://github.com/owner/repo.git

	repoURL = strings.TrimSpace(repoURL)
	repoURL = strings.TrimPrefix(repoURL, "git+")
	repoURL = strings.TrimPrefix(repoURL, "git://")
	repoURL = strings.TrimPrefix(repoURL, "https://")
	repoURL = strings.TrimPrefix(repoURL, "http://")
	repoURL = strings.TrimSuffix(repoURL, ".git")

	parts := strings.Split(repoURL, "/")
	if len(parts) < 3 || !strings.Contains(parts[0], "github") {
		return "", "", fmt.Errorf("invalid GitHub URL: %s", repoURL)
	}

	// Find github.com and get owner/repo
	for i, part := range parts {
		if strings.Contains(part, "github") && i+2 < len(parts) {
			return parts[i+1], parts[i+2], nil
		}
	}

	return "", "", fmt.Errorf("could not parse GitHub URL: %s", repoURL)
}

func getLicenseName(license *GitHubLicense) string {
	if license == nil {
		return ""
	}
	return license.Name
}

// GetProvenanceInfo checks for various provenance indicators in a GitHub repository
func (c *GitHubClient) GetProvenanceInfo(repoURL string) (*models.ProvenanceInfo, error) {
	owner, repo, err := parseGitHubURL(repoURL)
	if err != nil {
		return nil, err
	}

	info := &models.ProvenanceInfo{}

	// Check for SLSA attestations
	info.HasSLSAAttestation, info.SLSALevel = c.checkSLSAAttestation(owner, repo)

	// Check for Sigstore signatures
	info.HasSigstoreSignature = c.checkSigstoreSignatures(owner, repo)

	// Check signed releases
	signedCount, totalCount := c.checkSignedReleases(owner, repo)
	info.SignedReleaseCount = signedCount
	info.TotalReleaseCount = totalCount

	// Check for reproducible build indicators
	info.ReproducibleBuild = c.checkReproducibleBuild(owner, repo)

	return info, nil
}

// checkSLSAAttestation checks for SLSA attestations in the repository
func (c *GitHubClient) checkSLSAAttestation(owner, repo string) (bool, string) {
	// Check for SLSA provenance files
	slsaFiles := []string{
		".slsa-provenance.json",
		".github/workflows/slsa-generic-generator.yml",
		".github/workflows/slsa.yml",
	}

	for _, file := range slsaFiles {
		if c.fileExists(owner, repo, file) {
			// If SLSA workflow exists, assume at least SLSA Level 2
			return true, "SLSA_LEVEL_2"
		}
	}

	// Check GitHub Actions for SLSA generator usage
	// This would require parsing workflow files - simplified version
	if c.fileExists(owner, repo, ".github/workflows") {
		// If workflows exist, check for SLSA generator references
		return false, ""
	}

	return false, ""
}

// checkSigstoreSignatures checks for Sigstore/Cosign signatures
func (c *GitHubClient) checkSigstoreSignatures(owner, repo string) bool {
	// Check for cosign signature files or Sigstore configuration
	sigstoreFiles := []string{
		".cosign",
		".sigstore",
		".rekor",
	}

	for _, file := range sigstoreFiles {
		if c.fileExists(owner, repo, file) {
			return true
		}
	}

	// Check releases for .sig files (common signature extension)
	releases, err := c.getReleases(owner, repo)
	if err != nil {
		return false
	}

	for _, release := range releases {
		for _, asset := range release.Assets {
			if strings.HasSuffix(asset.Name, ".sig") ||
			   strings.HasSuffix(asset.Name, ".asc") ||
			   strings.HasSuffix(asset.Name, ".minisig") {
				return true
			}
		}
	}

	return false
}

// checkSignedReleases checks how many releases have signatures
func (c *GitHubClient) checkSignedReleases(owner, repo string) (signedCount, totalCount int) {
	releases, err := c.getReleases(owner, repo)
	if err != nil {
		return 0, 0
	}

	totalCount = len(releases)
	signedCount = 0

	for _, release := range releases {
		hasSignature := false
		for _, asset := range release.Assets {
			// Check for common signature file extensions
			name := strings.ToLower(asset.Name)
			if strings.HasSuffix(name, ".sig") ||
			   strings.HasSuffix(name, ".asc") ||
			   strings.HasSuffix(name, ".gpg") ||
			   strings.HasSuffix(name, ".minisig") ||
			   strings.Contains(name, "checksum") ||
			   strings.Contains(name, "sha256") ||
			   strings.Contains(name, "sha512") {
				hasSignature = true
				break
			}
		}
		if hasSignature {
			signedCount++
		}
	}

	return signedCount, totalCount
}

// checkReproducibleBuild checks for reproducible build indicators
func (c *GitHubClient) checkReproducibleBuild(owner, repo string) bool {
	// Check for reproducible build configuration files
	reproducibleFiles := []string{
		".reproducible-build",
		"reproducible-build.yml",
		".github/workflows/reproducible.yml",
		"BUILD.bazel", // Bazel is often used for reproducible builds
	}

	for _, file := range reproducibleFiles {
		if c.fileExists(owner, repo, file) {
			return true
		}
	}

	return false
}

// getReleases fetches all releases for a repository
func (c *GitHubClient) getReleases(owner, repo string) ([]GitHubRelease, error) {
	url := fmt.Sprintf("%s/repos/%s/%s/releases", c.baseURL, owner, repo)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API returned %d", resp.StatusCode)
	}

	var releases []GitHubRelease
	if err := json.NewDecoder(resp.Body).Decode(&releases); err != nil {
		return nil, err
	}

	return releases, nil
}

// GetFileContent fetches the content of a file from a GitHub repository
func (c *GitHubClient) GetFileContent(repoURL, filePath string) (string, error) {
	owner, repo, err := parseGitHubURL(repoURL)
	if err != nil {
		return "", err
	}

	url := fmt.Sprintf("%s/repos/%s/%s/contents/%s", c.baseURL, owner, repo, filePath)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}

	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	req.Header.Set("Accept", "application/vnd.github.v3.raw")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("file not found or inaccessible: %s", filePath)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(body), nil
}

// GetCommitAuthors analyzes commit authorship patterns for ownership change detection
func (c *GitHubClient) GetCommitAuthors(repoURL string) (*CommitAuthorStats, error) {
	owner, repo, err := parseGitHubURL(repoURL)
	if err != nil {
		return nil, err
	}

	// Fetch commits from the last 2 years (or up to 500 commits)
	url := fmt.Sprintf("%s/repos/%s/%s/commits?per_page=100", c.baseURL, owner, repo)

	stats := &CommitAuthorStats{
		AuthorCommitCounts: make(map[string]int),
		AuthorFirstCommit:  make(map[string]time.Time),
		AuthorLastCommit:   make(map[string]time.Time),
		RecentAuthors:      []string{},
		HistoricalAuthors:  []string{},
	}

	// Fetch multiple pages (up to 5 pages = 500 commits)
	for page := 1; page <= 5; page++ {
		pageURL := fmt.Sprintf("%s&page=%d", url, page)
		req, err := http.NewRequest("GET", pageURL, nil)
		if err != nil {
			return nil, err
		}

		if c.token != "" {
			req.Header.Set("Authorization", "Bearer "+c.token)
		}
		req.Header.Set("Accept", "application/vnd.github.v3+json")

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return nil, err
		}

		if resp.StatusCode != http.StatusOK {
			_ = resp.Body.Close()
			if page == 1 {
				body, _ := io.ReadAll(resp.Body)
				return nil, fmt.Errorf("GitHub API returned %d: %s", resp.StatusCode, string(body))
			}
			// No more pages
			break
		}

		var commits []GitHubCommit
		if err := json.NewDecoder(resp.Body).Decode(&commits); err != nil {
			_ = resp.Body.Close()
			return nil, err
		}
		_ = resp.Body.Close()

		if len(commits) == 0 {
			break
		}

		// Analyze commits
		for _, commit := range commits {
			authorName := commit.Commit.Author.Name
			authorEmail := commit.Commit.Author.Email
			commitDate := commit.Commit.Author.Date

			// Use email as unique identifier (more reliable than name)
			authorID := authorEmail
			if authorID == "" {
				authorID = authorName
			}

			if authorID == "" {
				continue
			}

			stats.TotalCommits++
			stats.AuthorCommitCounts[authorID]++

			// Track first and last commit for each author
			if firstCommit, exists := stats.AuthorFirstCommit[authorID]; !exists || commitDate.Before(firstCommit) {
				stats.AuthorFirstCommit[authorID] = commitDate
			}
			if lastCommit, exists := stats.AuthorLastCommit[authorID]; !exists || commitDate.After(lastCommit) {
				stats.AuthorLastCommit[authorID] = commitDate
			}
		}
	}

	// Build unique authors list and categorize recent vs historical
	seen := make(map[string]bool)
	ninetyDaysAgo := time.Now().AddDate(0, 0, -90)

	for authorID, lastCommit := range stats.AuthorLastCommit {
		if !seen[authorID] {
			stats.UniqueAuthors = append(stats.UniqueAuthors, authorID)
			seen[authorID] = true

			if lastCommit.After(ninetyDaysAgo) {
				stats.RecentAuthors = append(stats.RecentAuthors, authorID)
			} else {
				stats.HistoricalAuthors = append(stats.HistoricalAuthors, authorID)
			}
		}
	}

	return stats, nil
}

// CheckSignedCommits checks if recent commits in the repository are GPG signed
func (c *GitHubClient) CheckSignedCommits(repoURL string) (bool, int, error) {
	owner, repo, err := parseGitHubURL(repoURL)
	if err != nil {
		return false, 0, err
	}

	// Get recent commits (last 30)
	url := fmt.Sprintf("%s/repos/%s/%s/commits?per_page=30", c.baseURL, owner, repo)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return false, 0, err
	}

	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return false, 0, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return false, 0, fmt.Errorf("GitHub API returned %d", resp.StatusCode)
	}

	var commits []GitHubCommit
	if err := json.NewDecoder(resp.Body).Decode(&commits); err != nil {
		return false, 0, err
	}

	if len(commits) == 0 {
		return false, 0, nil
	}

	// Count verified commits
	verifiedCount := 0
	for _, commit := range commits {
		if commit.Commit.Verification.Verified {
			verifiedCount++
		}
	}

	// Consider "signed commits enabled" if >50% of recent commits are signed
	hasSigning := float64(verifiedCount)/float64(len(commits)) > 0.5

	return hasSigning, verifiedCount, nil
}

// CheckSignedReleases checks if releases have GPG signatures
func (c *GitHubClient) CheckSignedReleases(repoURL string) (bool, error) {
	owner, repo, err := parseGitHubURL(repoURL)
	if err != nil {
		return false, err
	}

	url := fmt.Sprintf("%s/repos/%s/%s/releases?per_page=10", c.baseURL, owner, repo)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return false, err
	}

	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return false, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return false, nil
	}

	var releases []GitHubRelease
	if err := json.NewDecoder(resp.Body).Decode(&releases); err != nil {
		return false, err
	}

	if len(releases) == 0 {
		return false, nil
	}

	// Check for signature files (.asc, .sig) in release assets
	for _, release := range releases {
		for _, asset := range release.Assets {
			name := strings.ToLower(asset.Name)
			if strings.HasSuffix(name, ".asc") || strings.HasSuffix(name, ".sig") || strings.HasSuffix(name, ".gpg") {
				return true, nil
			}
		}
	}

	return false, nil
}

// CommitStats contains commit distribution statistics for bus factor calculation
type CommitStats struct{
	TotalCommits       int
	AuthorCommits      map[string]int // author -> commit count
	BusFactor          int            // Number of authors responsible for 50% of commits
	TopContributorPct  float64        // Percentage of commits by top contributor
}

// PRStats contains pull request statistics for code review verification
type PRStats struct {
	TotalPRs           int
	MergedPRs          int
	PRsWithReviews     int
	CodeReviewRate     float64 // Percentage of PRs with reviews
	RequiredReviewers  int     // Number of required reviewers (from branch protection)
	HasBranchProtection bool
}

// CIQuality contains CI/CD quality metrics
type CIQuality struct {
	HasCI              bool
	CISystems          []string
	HasTests           bool     // Workflows contain test steps
	WorkflowCount      int
	QualityScore       int      // 0-10 score based on CI setup
}

// calculateBusFactor determines how many contributors are needed to account for 50% of commits
func calculateBusFactor(authorCommits map[string]int, totalCommits int) int {
	if totalCommits == 0 {
		return 0
	}

	// Sort authors by commit count (descending)
	type authorCount struct {
		author string
		count  int
	}
	var authors []authorCount
	for author, count := range authorCommits {
		authors = append(authors, authorCount{author, count})
	}

	// Simple bubble sort (fine for small datasets)
	for i := 0; i < len(authors); i++ {
		for j := i + 1; j < len(authors); j++ {
			if authors[j].count > authors[i].count {
				authors[i], authors[j] = authors[j], authors[i]
			}
		}
	}


	// Count how many authors needed to reach >50%
	threshold := float64(totalCommits) * 0.5
	cumulative := 0
	busFactor := 0
	for _, ac := range authors {
		cumulative += ac.count
		busFactor++
		if float64(cumulative) > threshold {
			break
		}
	}

	return busFactor
}

// GetCommitStats fetches commit distribution to calculate bus factor
// Analyzes the last 100 commits to determine contributor concentration
func (c *GitHubClient) GetCommitStats(repoURL string) (*CommitStats, error) {
	owner, repo, err := parseGitHubURL(repoURL)
	if err != nil {
		return nil, err
	}

	// Fetch recent commits (last 100)
	url := fmt.Sprintf("%s/repos/%s/%s/commits?per_page=100", c.baseURL, owner, repo)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("GitHub API returned %d: %s", resp.StatusCode, string(body))
	}

	var commits []GitHubCommit
	if err := json.NewDecoder(resp.Body).Decode(&commits); err != nil {
		return nil, err
	}

	// Calculate commit distribution
	authorCommits := make(map[string]int)
	for _, commit := range commits {
		if commit.Author != nil && commit.Author.Login != "" {
			authorCommits[commit.Author.Login]++
		} else if commit.Commit.Author.Name != "" {
			// Fallback to commit author name if GitHub user not available
			authorCommits[commit.Commit.Author.Name]++
		}
	}

	// Calculate bus factor (number of people needed to reach 50% of commits)
	totalCommits := len(commits)
	busFactor := calculateBusFactor(authorCommits, totalCommits)

	// Calculate top contributor percentage
	topContributorPct := 0.0
	if totalCommits > 0 {
		maxCommits := 0
		for _, count := range authorCommits {
			if count > maxCommits {
				maxCommits = count
			}
		}
		topContributorPct = float64(maxCommits) / float64(totalCommits) * 100
	}

	return &CommitStats{
		TotalCommits:      totalCommits,
		AuthorCommits:     authorCommits,
		BusFactor:         busFactor,
		TopContributorPct: topContributorPct,
	}, nil
}

// GetPullRequestStats analyzes PR statistics for code review verification
func (c *GitHubClient) GetPullRequestStats(repoURL string) (*PRStats, error) {
	owner, repo, err := parseGitHubURL(repoURL)
	if err != nil {
		return nil, err
	}

	stats := &PRStats{}

	// Fetch recent merged PRs
	url := fmt.Sprintf("%s/repos/%s/%s/pulls?state=closed&per_page=100", c.baseURL, owner, repo)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return stats, nil // Return empty stats if we can't fetch PRs
	}

	var prs []GitHubPullRequest
	if err := json.NewDecoder(resp.Body).Decode(&prs); err != nil {
		return stats, nil
	}

	// Analyze PRs
	for _, pr := range prs {
		if pr.MergedAt != nil {
			stats.TotalPRs++
			stats.MergedPRs++

			// Check if PR has reviews
			if c.prHasReviews(owner, repo, pr.Number) {
				stats.PRsWithReviews++
			}
		}
	}

	// Calculate code review rate
	if stats.MergedPRs > 0 {
		stats.CodeReviewRate = float64(stats.PRsWithReviews) / float64(stats.MergedPRs) * 100
	}

	// Check branch protection rules
	branchProtection := c.getBranchProtection(owner, repo)
	stats.HasBranchProtection = branchProtection != nil
	if branchProtection != nil && branchProtection.RequiredReviews != nil {
		stats.RequiredReviewers = branchProtection.RequiredReviews.RequiredApprovingReviewCount
	}

	return stats, nil
}
// prHasReviews checks if a PR has any reviews
func (c *GitHubClient) prHasReviews(owner, repo string, prNumber int) bool {
	url := fmt.Sprintf("%s/repos/%s/%s/pulls/%d/reviews", c.baseURL, owner, repo, prNumber)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return false
	}

	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false
	}

	var reviews []GitHubReview
	if err := json.NewDecoder(resp.Body).Decode(&reviews); err != nil {
		return false
	}

	return len(reviews) > 0
}

// getBranchProtection fetches branch protection rules for the default branch
func (c *GitHubClient) getBranchProtection(owner, repo string) *GitHubBranchProtection {
	// First get the default branch
	repoInfo, err := c.GetRepositoryInfo(fmt.Sprintf("https://github.com/%s/%s", owner, repo))
	if err != nil {
		return nil
	}

	url := fmt.Sprintf("%s/repos/%s/%s/branches/%s/protection", c.baseURL, owner, repo, repoInfo.DefaultBranch)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil
	}

	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	var protection GitHubBranchProtection
	if err := json.NewDecoder(resp.Body).Decode(&protection); err != nil {
		return nil
	}

	return &protection
}

// AnalyzeCIQuality evaluates CI/CD quality beyond just presence
func (c *GitHubClient) AnalyzeCIQuality(repoURL string, ciSystems []string) (*CIQuality, error) {
	owner, repo, err := parseGitHubURL(repoURL)
	if err != nil {
		return nil, err
	}

	quality := &CIQuality{
		HasCI:     len(ciSystems) > 0,
		CISystems: ciSystems,
	}

	if !quality.HasCI {
		return quality, nil
	}

	// Analyze GitHub Actions workflows if present
	if c.containsString(ciSystems, "GitHub Actions") {
		workflows, err := c.getWorkflowFiles(owner, repo)
		if err == nil {
			quality.WorkflowCount = len(workflows)
			quality.HasTests = c.workflowsContainTests(workflows)
		}
	}

	// Calculate quality score (0-10)
	qualityScore := 0

	// Base points for having CI
	if quality.HasCI {
		qualityScore += 3
	}

	// Points for having tests in CI
	if quality.HasTests {
		qualityScore += 4
	}

	// Points for multiple workflows (suggests comprehensive CI)
	if quality.WorkflowCount >= 2 {
		qualityScore += 2
	} else if quality.WorkflowCount >= 1 {
		qualityScore += 1
	}

	quality.QualityScore = qualityScore
	return quality, nil
}

// getWorkflowFiles fetches GitHub Actions workflow files
func (c *GitHubClient) getWorkflowFiles(owner, repo string) ([]string, error) {
	url := fmt.Sprintf("%s/repos/%s/%s/contents/.github/workflows", c.baseURL, owner, repo)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch workflows")
	}

	var files []GitHubContent
	if err := json.NewDecoder(resp.Body).Decode(&files); err != nil {
		return nil, err
	}

	var workflows []string
	for _, file := range files {
		if strings.HasSuffix(file.Name, ".yml") || strings.HasSuffix(file.Name, ".yaml") {
			workflows = append(workflows, file.Name)
		}
	}

	return workflows, nil
}

// workflowsContainTests checks if any workflow appears to run tests
func (c *GitHubClient) workflowsContainTests(workflows []string) bool {
	// Simple heuristic: check workflow names for test-related keywords
	testKeywords := []string{"test", "ci", "check", "lint"}
	for _, workflow := range workflows {
		lower := strings.ToLower(workflow)
		for _, keyword := range testKeywords {
			if strings.Contains(lower, keyword) {
				return true
			}
		}
	}
	return false
}

func (c *GitHubClient) containsString(slice []string, str string) bool {
	for _, s := range slice {
		if s == str {
			return true
		}
	}
	return false
}

// Additional GitHub API structures
type GitHubPullRequest struct {
	Number   int        `json:"number"`
	State    string     `json:"state"`
	MergedAt *time.Time `json:"merged_at"`
}

type GitHubReview struct {
	ID    int    `json:"id"`
	State string `json:"state"`
}

type GitHubBranchProtection struct {
	RequiredReviews *GitHubRequiredReviews `json:"required_pull_request_reviews"`
}

type GitHubRequiredReviews struct {
	RequiredApprovingReviewCount int `json:"required_approving_review_count"`
}

type GitHubContent struct {
	Name string `json:"name"`
	Path string `json:"path"`
	Type string `json:"type"`
}
