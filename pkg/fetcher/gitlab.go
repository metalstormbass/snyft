package fetcher

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/metalstormbass/snyft/pkg/models"
)

// GitLabClient handles interactions with GitLab API (both gitlab.com and self-hosted)
type GitLabClient struct {
	token      string
	httpClient *http.Client
	baseURL    string
}

// NewGitLabClient creates a new GitLab API client
func NewGitLabClient() *GitLabClient {
	return &GitLabClient{
		token: os.Getenv("GITLAB_TOKEN"),
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		baseURL: "https://gitlab.com/api/v4",
	}
}

// GetPlatformName returns "GitLab"
func (c *GitLabClient) GetPlatformName() string {
	return "GitLab"
}

// GetRepositoryInfo fetches repository information from GitLab
func (c *GitLabClient) GetRepositoryInfo(repoURL string) (*models.RepositoryInfo, error) {
	owner, repo, instance, err := parseGitLabURL(repoURL)
	if err != nil {
		return nil, err
	}

	// Use custom instance base URL if not gitlab.com
	baseURL := c.baseURL
	if instance != "gitlab.com" {
		baseURL = fmt.Sprintf("https://%s/api/v4", instance)
	}

	// Encode the project path (owner/repo)
	projectPath := url.PathEscape(fmt.Sprintf("%s/%s", owner, repo))
	apiURL := fmt.Sprintf("%s/projects/%s", baseURL, projectPath)

	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return nil, err
	}

	if c.token != "" {
		req.Header.Set("PRIVATE-TOKEN", c.token)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		// Network error — try scraping fallback
		return c.scrapeRepositoryInfo(instance, owner, repo)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		// Try scraping fallback on rate limit or auth errors
		if shouldFallbackToScraping(nil, resp.StatusCode) {
			return c.scrapeRepositoryInfo(instance, owner, repo)
		}
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("GitLab API returned %d: %s", resp.StatusCode, string(body))
	}

	var glProject GitLabProject
	if err := json.NewDecoder(resp.Body).Decode(&glProject); err != nil {
		return nil, err
	}

	return &models.RepositoryInfo{
		URL:           glProject.WebURL,
		Owner:         glProject.Namespace.Path,
		Name:          glProject.Name,
		Description:   glProject.Description,
		Stars:         glProject.StarCount,
		Forks:         glProject.ForksCount,
		Watchers:      glProject.StarCount, // GitLab doesn't have separate watchers
		OpenIssues:    glProject.OpenIssuesCount,
		DefaultBranch: glProject.DefaultBranch,
		Archived:      glProject.Archived,
		CreatedAt:     glProject.CreatedAt,
		UpdatedAt:     glProject.LastActivityAt,
		PushedAt:      glProject.LastActivityAt,
		License:       getLicenseNameFromGitLab(glProject.License),
		Topics:        glProject.Topics,
	}, nil
}

// scrapeRepositoryInfo scrapes repository information from the GitLab web page
func (c *GitLabClient) scrapeRepositoryInfo(instance, owner, repo string) (*models.RepositoryInfo, error) {
	pageURL := fmt.Sprintf("https://%s/%s/%s", instance, owner, repo)
	doc, err := scrapeWithUserAgent(pageURL)
	if err != nil {
		return nil, fmt.Errorf("scraping fallback failed: %w", err)
	}

	info := &models.RepositoryInfo{
		URL:   pageURL,
		Owner: owner,
		Name:  repo,
	}

	// Extract description
	doc.Find("meta[property='og:description']").Each(func(i int, s *goquery.Selection) {
		if content, exists := s.Attr("content"); exists {
			info.Description = strings.TrimSpace(content)
		}
	})

	// Extract stars from the page
	doc.Find("a[href$='/starrers']").Each(func(i int, s *goquery.Selection) {
		text := strings.TrimSpace(s.Text())
		info.Stars = extractNumber(text)
	})

	// Extract forks
	doc.Find("a[href$='/forks']").Each(func(i int, s *goquery.Selection) {
		text := strings.TrimSpace(s.Text())
		info.Forks = extractNumber(text)
	})

	// Set current time for updated_at as approximation
	info.UpdatedAt = time.Now()
	info.PushedAt = time.Now()

	return info, nil
}

// CheckGitTag verifies if a specific version tag exists in the repository
func (c *GitLabClient) CheckGitTag(repoURL, version string) (bool, string, error) {
	owner, repo, instance, err := parseGitLabURL(repoURL)
	if err != nil {
		return false, "", err
	}

	baseURL := c.baseURL
	if instance != "gitlab.com" {
		baseURL = fmt.Sprintf("https://%s/api/v4", instance)
	}

	projectPath := url.PathEscape(fmt.Sprintf("%s/%s", owner, repo))

	// Try common version tag formats
	tagVariants := []string{
		version,
		"v" + version,
		"V" + version,
		"release-" + version,
		"Release-" + version,
	}

	for _, tag := range tagVariants {
		encodedTag := url.PathEscape(tag)
		apiURL := fmt.Sprintf("%s/projects/%s/repository/tags/%s", baseURL, projectPath, encodedTag)

		req, err := http.NewRequest("GET", apiURL, nil)
		if err != nil {
			continue
		}

		if c.token != "" {
			req.Header.Set("PRIVATE-TOKEN", c.token)
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			continue
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode == http.StatusOK {
			tagURL := fmt.Sprintf("https://%s/%s/%s/-/tags/%s", instance, owner, repo, tag)
			return true, tagURL, nil
		}
	}

	return false, "", nil
}

// DetectCISystems checks for common CI/CD systems in the repository
func (c *GitLabClient) DetectCISystems(repoURL string) ([]string, error) {
	owner, repo, instance, err := parseGitLabURL(repoURL)
	if err != nil {
		return nil, err
	}

	var ciSystems []string

	for _, entry := range ExtendedCIConfigFiles() {
		if c.fileExists(instance, owner, repo, entry.Path) {
			alreadyAdded := false
			for _, existing := range ciSystems {
				if existing == entry.Name {
					alreadyAdded = true
					break
				}
			}
			if !alreadyAdded {
				ciSystems = append(ciSystems, entry.Name)
			}
		}
	}

	return ciSystems, nil
}

// HasAutomatedReleases checks if the repository has automated releases.
// Returns false (not error) when rate-limited — degrades gracefully.
func (c *GitLabClient) HasAutomatedReleases(repoURL string) (bool, error) {
	owner, repo, instance, err := parseGitLabURL(repoURL)
	if err != nil {
		return false, err
	}

	baseURL := c.baseURL
	if instance != "gitlab.com" {
		baseURL = fmt.Sprintf("https://%s/api/v4", instance)
	}

	projectPath := url.PathEscape(fmt.Sprintf("%s/%s", owner, repo))
	apiURL := fmt.Sprintf("%s/projects/%s/releases", baseURL, projectPath)

	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return false, err
	}

	if c.token != "" {
		req.Header.Set("PRIVATE-TOKEN", c.token)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return false, nil
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return false, nil
	}

	var releases []GitLabRelease
	if err := json.NewDecoder(resp.Body).Decode(&releases); err != nil {
		return false, err
	}

	return len(releases) > 0, nil
}

// GetReleaseHistory fetches detailed release history for a repository.
// Returns empty list when rate-limited — degrades gracefully.
func (c *GitLabClient) GetReleaseHistory(repoURL string, limit int) ([]GitHubRelease, error) {
	// Note: Returning GitHubRelease for interface compatibility
	// In a production system, we'd want a common Release type
	owner, repo, instance, err := parseGitLabURL(repoURL)
	if err != nil {
		return nil, err
	}

	baseURL := c.baseURL
	if instance != "gitlab.com" {
		baseURL = fmt.Sprintf("https://%s/api/v4", instance)
	}

	projectPath := url.PathEscape(fmt.Sprintf("%s/%s", owner, repo))
	apiURL := fmt.Sprintf("%s/projects/%s/releases?per_page=%d", baseURL, projectPath, limit)

	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return nil, err
	}

	if c.token != "" {
		req.Header.Set("PRIVATE-TOKEN", c.token)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		// Rate limit — return empty list so callers degrade gracefully
		if shouldFallbackToScraping(nil, resp.StatusCode) {
			return []GitHubRelease{}, nil
		}
		return nil, fmt.Errorf("GitLab API returned %d", resp.StatusCode)
	}

	var glReleases []GitLabRelease
	if err := json.NewDecoder(resp.Body).Decode(&glReleases); err != nil {
		return nil, err
	}

	// Convert to GitHubRelease format for compatibility
	releases := make([]GitHubRelease, len(glReleases))
	for i, glr := range glReleases {
		releases[i] = GitHubRelease{
			TagName:     glr.TagName,
			Name:        glr.Name,
			CreatedAt:   glr.CreatedAt,
			PublishedAt: glr.ReleasedAt,
		}
	}

	return releases, nil
}

// GetCommitActivity fetches recent commit activity for a repository.
// Returns empty list when rate-limited — degrades gracefully.
func (c *GitLabClient) GetCommitActivity(repoURL string, since time.Time) ([]GitHubCommit, error) {
	owner, repo, instance, err := parseGitLabURL(repoURL)
	if err != nil {
		return nil, err
	}

	baseURL := c.baseURL
	if instance != "gitlab.com" {
		baseURL = fmt.Sprintf("https://%s/api/v4", instance)
	}

	projectPath := url.PathEscape(fmt.Sprintf("%s/%s", owner, repo))
	apiURL := fmt.Sprintf("%s/projects/%s/repository/commits?since=%s&per_page=100",
		baseURL, projectPath, since.Format(time.RFC3339))

	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return nil, err
	}

	if c.token != "" {
		req.Header.Set("PRIVATE-TOKEN", c.token)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		// Rate limit — return empty list so callers degrade gracefully
		if shouldFallbackToScraping(nil, resp.StatusCode) {
			return []GitHubCommit{}, nil
		}
		return nil, fmt.Errorf("GitLab API returned %d", resp.StatusCode)
	}

	var glCommits []GitLabCommit
	if err := json.NewDecoder(resp.Body).Decode(&glCommits); err != nil {
		return nil, err
	}

	// Convert to GitHubCommit format
	commits := make([]GitHubCommit, len(glCommits))
	for i, glc := range glCommits {
		commits[i] = GitHubCommit{
			SHA: glc.ID,
			Commit: GitHubCommitInfo{
				Author: GitHubCommitAuthor{
					Name:  glc.AuthorName,
					Email: glc.AuthorEmail,
					Date:  glc.CommittedDate,
				},
				Message: glc.Message,
			},
		}
	}

	return commits, nil
}

// GetFileContent fetches the content of a file from a GitLab repository.
// Falls back to scraping the raw file URL when the API is rate-limited.
func (c *GitLabClient) GetFileContent(repoURL, filePath string) (string, error) {
	owner, repo, instance, err := parseGitLabURL(repoURL)
	if err != nil {
		return "", err
	}

	baseURL := c.baseURL
	if instance != "gitlab.com" {
		baseURL = fmt.Sprintf("https://%s/api/v4", instance)
	}

	projectPath := url.PathEscape(fmt.Sprintf("%s/%s", owner, repo))
	encodedFilePath := url.PathEscape(filePath)
	apiURL := fmt.Sprintf("%s/projects/%s/repository/files/%s/raw", baseURL, projectPath, encodedFilePath)

	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return "", err
	}

	if c.token != "" {
		req.Header.Set("PRIVATE-TOKEN", c.token)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		// Network error — try raw URL fallback
		return c.getFileContentViaRawURL(instance, owner, repo, filePath)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		// Rate limit or auth errors — try raw URL fallback
		if shouldFallbackToScraping(nil, resp.StatusCode) {
			return c.getFileContentViaRawURL(instance, owner, repo, filePath)
		}
		return "", fmt.Errorf("file not found or inaccessible: %s", filePath)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(body), nil
}

// getFileContentViaRawURL fetches file content from the GitLab raw file endpoint.
// GitLab serves raw files at /{owner}/{repo}/-/raw/{branch}/{path} which may
// bypass API rate limits.
func (c *GitLabClient) getFileContentViaRawURL(instance, owner, repo, path string) (string, error) {
	for _, branch := range []string{"main", "master"} {
		rawURL := fmt.Sprintf("https://%s/%s/%s/-/raw/%s/%s", instance, owner, repo, branch, path)
		resp, err := c.httpClient.Get(rawURL)
		if err != nil {
			continue
		}
		if resp.StatusCode == http.StatusOK {
			body, err := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if err != nil {
				continue
			}
			return string(body), nil
		}
		_ = resp.Body.Close()
	}
	return "", fmt.Errorf("file not found via raw URL: %s", path)
}

// GetProvenanceInfo checks for various provenance indicators in a GitLab repository.
// It inspects .gitlab-ci.yml for sigstore/cosign and SLSA usage, and checks for
// a .cosign directory or cosign.pub file indicating signing infrastructure.
func (c *GitLabClient) GetProvenanceInfo(repoURL string) (*models.ProvenanceInfo, error) {
	info := &models.ProvenanceInfo{}

	// Check for basic CI/CD which could indicate provenance
	ciSystems, _ := c.DetectCISystems(repoURL)
	for _, ci := range ciSystems {
		if ci == "GitLab CI" {
			info.BuildSystem = "GitLab CI"
			break
		}
	}

	// Fetch .gitlab-ci.yml and inspect for signing/attestation tooling.
	// Missing file is acceptable - we degrade gracefully.
	ciContent, err := c.GetFileContent(repoURL, ".gitlab-ci.yml")
	if err == nil {
		ciLower := strings.ToLower(ciContent)

		// Sigstore/cosign usage in the pipeline indicates artifact signing.
		// Source: Sigstore project - https://www.sigstore.dev/
		if strings.Contains(ciLower, "cosign") || strings.Contains(ciLower, "sigstore") {
			info.HasSigstoreSignature = true
		}

		// SLSA generator usage indicates provenance attestation.
		// Source: SLSA specification - https://slsa.dev/spec/v1.0/
		if strings.Contains(ciLower, "slsa") {
			info.HasSLSAAttestation = true
		}
	}

	// Check for a cosign public key or config directory in the repository root.
	// Presence indicates the project has set up signing infrastructure.
	// Source: Sigstore/cosign documentation - https://github.com/sigstore/cosign
	cosignFiles := []string{".cosign/", "cosign.pub"}
	for _, f := range cosignFiles {
		if _, ferr := c.GetFileContent(repoURL, f); ferr == nil {
			info.HasSigstoreSignature = true
			break
		}
	}

	return info, nil
}

// GetCommitAuthors analyzes commit authorship patterns (stub implementation)
func (c *GitLabClient) GetCommitAuthors(repoURL string) (*CommitAuthorStats, error) {
	// Fetch recent commits
	oneYearAgo := time.Now().AddDate(-1, 0, 0)
	commits, err := c.GetCommitActivity(repoURL, oneYearAgo)
	if err != nil {
		return nil, err
	}

	stats := &CommitAuthorStats{
		AuthorCommitCounts: make(map[string]int),
		AuthorFirstCommit:  make(map[string]time.Time),
		AuthorLastCommit:   make(map[string]time.Time),
		RecentAuthors:      []string{},
		HistoricalAuthors:  []string{},
	}

	ninetyDaysAgo := time.Now().AddDate(0, 0, -90)

	for _, commit := range commits {
		authorEmail := commit.Commit.Author.Email
		if authorEmail == "" {
			authorEmail = commit.Commit.Author.Name
		}
		if authorEmail == "" {
			continue
		}

		stats.TotalCommits++
		stats.AuthorCommitCounts[authorEmail]++

		commitDate := commit.Commit.Author.Date
		if firstCommit, exists := stats.AuthorFirstCommit[authorEmail]; !exists || commitDate.Before(firstCommit) {
			stats.AuthorFirstCommit[authorEmail] = commitDate
		}
		if lastCommit, exists := stats.AuthorLastCommit[authorEmail]; !exists || commitDate.After(lastCommit) {
			stats.AuthorLastCommit[authorEmail] = commitDate
		}
	}

	// Categorize authors
	seen := make(map[string]bool)
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

// CheckSignedCommits returns ErrDataUnavailable — GitLab API does not easily expose
// commit signature verification without complex per-commit queries.
func (c *GitLabClient) CheckSignedCommits(repoURL string) (bool, int, error) {
	return false, 0, ErrDataUnavailable
}

// CheckSignedReleases returns ErrDataUnavailable — GitLab release signature checking
// requires inspecting release artifacts, which is not implemented.
func (c *GitLabClient) CheckSignedReleases(repoURL string) (bool, error) {
	return false, ErrDataUnavailable
}

// GetCommitStats fetches commit distribution to calculate bus factor.
// Returns nil when rate-limited — degrades gracefully.
func (c *GitLabClient) GetCommitStats(repoURL string) (*CommitStats, error) {
	owner, repo, instance, err := parseGitLabURL(repoURL)
	if err != nil {
		return nil, err
	}

	baseURL := c.baseURL
	if instance != "gitlab.com" {
		baseURL = fmt.Sprintf("https://%s/api/v4", instance)
	}

	projectPath := url.PathEscape(fmt.Sprintf("%s/%s", owner, repo))
	apiURL := fmt.Sprintf("%s/projects/%s/repository/commits?per_page=100", baseURL, projectPath)

	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return nil, err
	}

	if c.token != "" {
		req.Header.Set("PRIVATE-TOKEN", c.token)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		// Rate limit — return nil so callers degrade gracefully
		if shouldFallbackToScraping(nil, resp.StatusCode) {
			return nil, nil
		}
		return nil, fmt.Errorf("GitLab API returned %d", resp.StatusCode)
	}

	var commits []GitLabCommit
	if err := json.NewDecoder(resp.Body).Decode(&commits); err != nil {
		return nil, err
	}

	// Calculate commit distribution
	authorCommits := make(map[string]int)
	for _, commit := range commits {
		author := commit.AuthorEmail
		if author == "" {
			author = commit.AuthorName
		}
		if author != "" {
			authorCommits[author]++
		}
	}

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

// GetPullRequestStats analyzes MR statistics (stub)
func (c *GitLabClient) GetPullRequestStats(repoURL string) (*PRStats, error) {
	// GitLab uses Merge Requests (MRs) instead of Pull Requests
	// Simplified stub implementation
	return &PRStats{}, nil
}

// AnalyzeCIQuality evaluates CI/CD quality (stub)
func (c *GitLabClient) AnalyzeCIQuality(repoURL string, ciSystems []string) (*CIQuality, error) {
	quality := &CIQuality{
		HasCI:     len(ciSystems) > 0,
		CISystems: ciSystems,
	}

	if quality.HasCI {
		quality.QualityScore = 5 // Default moderate score
	}

	return quality, nil
}

// fileExists checks if a file exists in the repository.
// Falls back to the raw file URL when the API is rate-limited.
func (c *GitLabClient) fileExists(instance, owner, repo, path string) bool {
	baseURL := c.baseURL
	if instance != "gitlab.com" {
		baseURL = fmt.Sprintf("https://%s/api/v4", instance)
	}

	projectPath := url.PathEscape(fmt.Sprintf("%s/%s", owner, repo))
	encodedPath := url.PathEscape(path)
	apiURL := fmt.Sprintf("%s/projects/%s/repository/files/%s", baseURL, projectPath, encodedPath)

	req, err := http.NewRequest("HEAD", apiURL, nil)
	if err != nil {
		return false
	}

	if c.token != "" {
		req.Header.Set("PRIVATE-TOKEN", c.token)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return false
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusOK {
		return true
	}

	// Rate limit — try raw URL fallback
	if shouldFallbackToScraping(nil, resp.StatusCode) {
		return c.checkFileViaRawURL(instance, owner, repo, path)
	}

	return false
}

// checkFileViaRawURL checks if a file exists by requesting the raw file URL.
// GitLab serves raw files at /{owner}/{repo}/-/raw/{branch}/{path}.
func (c *GitLabClient) checkFileViaRawURL(instance, owner, repo, path string) bool {
	for _, branch := range []string{"main", "master"} {
		rawURL := fmt.Sprintf("https://%s/%s/%s/-/raw/%s/%s", instance, owner, repo, branch, path)
		req, err := http.NewRequest("HEAD", rawURL, nil)
		if err != nil {
			continue
		}
		resp, err := c.httpClient.Do(req)
		if err != nil {
			continue
		}
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			return true
		}
	}
	return false
}

// GitLab API response structures
type GitLabProject struct {
	ID                int               `json:"id"`
	Name              string            `json:"name"`
	Path              string            `json:"path"`
	Description       string            `json:"description"`
	WebURL            string            `json:"web_url"`
	StarCount         int               `json:"star_count"`
	ForksCount        int               `json:"forks_count"`
	OpenIssuesCount   int               `json:"open_issues_count"`
	DefaultBranch     string            `json:"default_branch"`
	Archived          bool              `json:"archived"`
	CreatedAt         time.Time         `json:"created_at"`
	LastActivityAt    time.Time         `json:"last_activity_at"`
	Namespace         GitLabNamespace   `json:"namespace"`
	License           *GitLabLicense    `json:"license"`
	Topics            []string          `json:"topics"`
}

type GitLabNamespace struct {
	Path string `json:"path"`
	Name string `json:"name"`
}

type GitLabLicense struct {
	Key  string `json:"key"`
	Name string `json:"name"`
}

type GitLabRelease struct {
	TagName    string    `json:"tag_name"`
	Name       string    `json:"name"`
	CreatedAt  time.Time `json:"created_at"`
	ReleasedAt time.Time `json:"released_at"`
}

type GitLabCommit struct {
	ID            string    `json:"id"`
	ShortID       string    `json:"short_id"`
	Title         string    `json:"title"`
	Message       string    `json:"message"`
	AuthorName    string    `json:"author_name"`
	AuthorEmail   string    `json:"author_email"`
	CommittedDate time.Time `json:"committed_date"`
}

func parseGitLabURL(repoURL string) (owner, repo, instance string, err error) {
	// Handle various GitLab URL formats:
	// https://gitlab.com/owner/repo
	// https://gitlab.example.com/owner/repo
	// git@gitlab.com:owner/repo.git

	repoURL = strings.TrimSpace(repoURL)
	repoURL = strings.TrimPrefix(repoURL, "git+")
	repoURL = strings.TrimSuffix(repoURL, ".git")

	// Handle SSH format (git@gitlab.com:owner/repo)
	if strings.Contains(repoURL, "git@") {
		parts := strings.Split(repoURL, "@")
		if len(parts) >= 2 {
			hostAndPath := strings.Split(parts[1], ":")
			if len(hostAndPath) >= 2 {
				instance = hostAndPath[0]
				pathParts := strings.Split(hostAndPath[1], "/")
				if len(pathParts) >= 2 {
					owner = pathParts[0]
					repo = pathParts[1]
					return owner, repo, instance, nil
				}
			}
		}
	}

	// Handle HTTPS format
	repoURL = strings.TrimPrefix(repoURL, "git://")
	repoURL = strings.TrimPrefix(repoURL, "https://")
	repoURL = strings.TrimPrefix(repoURL, "http://")

	parts := strings.Split(repoURL, "/")
	if len(parts) < 3 {
		return "", "", "", fmt.Errorf("invalid GitLab URL: %s", repoURL)
	}

	// Find the instance (gitlab.com or self-hosted)
	instance = parts[0]
	if !strings.Contains(instance, "gitlab") {
		return "", "", "", fmt.Errorf("not a GitLab URL: %s", repoURL)
	}

	// Get owner and repo (handle nested groups)
	if len(parts) >= 3 {
		owner = parts[1]
		repo = parts[2]
		return owner, repo, instance, nil
	}

	return "", "", "", fmt.Errorf("could not parse GitLab URL: %s", repoURL)
}

func getLicenseNameFromGitLab(license *GitLabLicense) string {
	if license == nil {
		return ""
	}
	return license.Name
}

// CheckIfOrganization checks if a GitLab user is an organization or personal account (stub)
// GitLab uses "groups" instead of organizations
func (c *GitLabClient) CheckIfOrganization(owner string) (bool, string) {
	// Stub implementation - would require GitLab API call to /groups/{owner}
	// For now, return false (conservative approach)
	return false, ""
}

// CheckVerifiedOrganization checks if a GitLab group has verified status (stub)
func (c *GitLabClient) CheckVerifiedOrganization(owner string) bool {
	// GitLab doesn't have a "verified" badge like GitHub
	return false
}

// GetUserAccountCreatedDate fetches account creation date for a GitLab user (stub)
func (c *GitLabClient) GetUserAccountCreatedDate(username string) (time.Time, error) {
	// Stub implementation - would require GitLab API call to /users
	// Return zero time to indicate unavailable
	return time.Time{}, fmt.Errorf("account age check not implemented for GitLab")
}

// CheckOrgMFARequired checks for MFA enforcement on GitLab groups.
// GitLab's require_two_factor_authentication field is only accessible to group admins
// and is not exposed via the public API without authentication.
// Returns (false, false) to indicate data is not publicly available.
func (c *GitLabClient) CheckOrgMFARequired(owner string) (required bool, available bool) {
	return false, false
}
