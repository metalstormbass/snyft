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

// BitbucketClient handles interactions with Bitbucket API
type BitbucketClient struct {
	token      string
	httpClient *http.Client
	baseURL    string
}

// NewBitbucketClient creates a new Bitbucket API client
func NewBitbucketClient() *BitbucketClient {
	return &BitbucketClient{
		token: os.Getenv("BITBUCKET_TOKEN"),
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		baseURL: "https://api.bitbucket.org/2.0",
	}
}

// GetPlatformName returns "Bitbucket"
func (c *BitbucketClient) GetPlatformName() string {
	return "Bitbucket"
}

// GetRepositoryInfo fetches repository information from Bitbucket
func (c *BitbucketClient) GetRepositoryInfo(repoURL string) (*models.RepositoryInfo, error) {
	owner, repo, err := parseBitbucketURL(repoURL)
	if err != nil {
		return nil, err
	}

	apiURL := fmt.Sprintf("%s/repositories/%s/%s", c.baseURL, owner, repo)

	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return nil, err
	}

	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		// Try scraping fallback
		if shouldFallbackToScraping(nil, resp.StatusCode) {
			return c.scrapeRepositoryInfo(owner, repo)
		}
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("bitbucket API returned %d: %s", resp.StatusCode, string(body))
	}

	var bbRepo BitbucketRepository
	if err := json.NewDecoder(resp.Body).Decode(&bbRepo); err != nil {
		return nil, err
	}

	// Bitbucket doesn't have stars/watchers in the same way
	// We'll need to fetch these separately or from scraping
	info := &models.RepositoryInfo{
		URL:           bbRepo.Links.HTML.Href,
		Owner:         bbRepo.Owner.Username,
		Name:          bbRepo.Name,
		Description:   bbRepo.Description,
		Stars:         0, // Bitbucket uses "watchers" instead of stars
		Forks:         0, // Need separate API call
		Watchers:      0, // Need separate API call
		DefaultBranch: bbRepo.Mainbranch.Name,
		Archived:      false, // Bitbucket doesn't have archived status in API
		CreatedAt:     bbRepo.CreatedOn,
		UpdatedAt:     bbRepo.UpdatedOn,
		PushedAt:      bbRepo.UpdatedOn,
		License:       "",
		Topics:        []string{},
	}

	return info, nil
}

// scrapeRepositoryInfo scrapes repository information from the Bitbucket web page
func (c *BitbucketClient) scrapeRepositoryInfo(owner, repo string) (*models.RepositoryInfo, error) {
	pageURL := fmt.Sprintf("https://bitbucket.org/%s/%s", owner, repo)
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

	// Extract watchers (Bitbucket's equivalent of stars)
	doc.Find("a[href$='/watchers']").Each(func(i int, s *goquery.Selection) {
		text := strings.TrimSpace(s.Text())
		info.Watchers = extractNumber(text)
		info.Stars = info.Watchers // Use watchers as stars
	})

	// Extract forks
	doc.Find("a[href$='/forks']").Each(func(i int, s *goquery.Selection) {
		text := strings.TrimSpace(s.Text())
		info.Forks = extractNumber(text)
	})

	// Set current time as approximation
	info.UpdatedAt = time.Now()
	info.PushedAt = time.Now()

	return info, nil
}

// CheckGitTag verifies if a specific version tag exists in the repository
func (c *BitbucketClient) CheckGitTag(repoURL, version string) (bool, string, error) {
	owner, repo, err := parseBitbucketURL(repoURL)
	if err != nil {
		return false, "", err
	}

	// Try common version tag formats
	tagVariants := []string{
		version,
		"v" + version,
		"V" + version,
		"release-" + version,
		"Release-" + version,
	}

	for _, tag := range tagVariants {
		apiURL := fmt.Sprintf("%s/repositories/%s/%s/refs/tags/%s", c.baseURL, owner, repo, url.PathEscape(tag))

		req, err := http.NewRequest("GET", apiURL, nil)
		if err != nil {
			continue
		}

		if c.token != "" {
			req.Header.Set("Authorization", "Bearer "+c.token)
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			continue
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode == http.StatusOK {
			tagURL := fmt.Sprintf("https://bitbucket.org/%s/%s/src/%s", owner, repo, tag)
			return true, tagURL, nil
		}
	}

	return false, "", nil
}

// DetectCISystems checks for common CI/CD systems in the repository
func (c *BitbucketClient) DetectCISystems(repoURL string) ([]string, error) {
	owner, repo, err := parseBitbucketURL(repoURL)
	if err != nil {
		return nil, err
	}

	var ciSystems []string

	// Check for Bitbucket Pipelines
	if c.fileExists(owner, repo, "bitbucket-pipelines.yml") {
		ciSystems = append(ciSystems, "Bitbucket Pipelines")
	}

	// Check for other CI systems
	if c.fileExists(owner, repo, ".github/workflows") {
		ciSystems = append(ciSystems, "GitHub Actions")
	}

	if c.fileExists(owner, repo, ".travis.yml") {
		ciSystems = append(ciSystems, "Travis CI")
	}

	if c.fileExists(owner, repo, ".circleci/config.yml") {
		ciSystems = append(ciSystems, "Circle CI")
	}

	if c.fileExists(owner, repo, "Jenkinsfile") {
		ciSystems = append(ciSystems, "Jenkins")
	}

	if c.fileExists(owner, repo, ".gitlab-ci.yml") {
		ciSystems = append(ciSystems, "GitLab CI")
	}

	return ciSystems, nil
}

// HasAutomatedReleases checks if the repository has automated releases (stub)
func (c *BitbucketClient) HasAutomatedReleases(repoURL string) (bool, error) {
	// Bitbucket doesn't have a releases API like GitHub/GitLab
	// We'll check for tags instead
	owner, repo, err := parseBitbucketURL(repoURL)
	if err != nil {
		return false, err
	}

	apiURL := fmt.Sprintf("%s/repositories/%s/%s/refs/tags", c.baseURL, owner, repo)

	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return false, err
	}

	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return false, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return false, nil
	}

	var tagsResp BitbucketTagsResponse
	if err := json.NewDecoder(resp.Body).Decode(&tagsResp); err != nil {
		return false, err
	}

	return len(tagsResp.Values) > 0, nil
}

// GetReleaseHistory fetches tag history (Bitbucket doesn't have releases like GitHub)
func (c *BitbucketClient) GetReleaseHistory(repoURL string, limit int) ([]GitHubRelease, error) {
	owner, repo, err := parseBitbucketURL(repoURL)
	if err != nil {
		return nil, err
	}

	apiURL := fmt.Sprintf("%s/repositories/%s/%s/refs/tags?pagelen=%d", c.baseURL, owner, repo, limit)

	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return nil, err
	}

	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bitbucket API returned %d", resp.StatusCode)
	}

	var tagsResp BitbucketTagsResponse
	if err := json.NewDecoder(resp.Body).Decode(&tagsResp); err != nil {
		return nil, err
	}

	// Convert tags to GitHubRelease format
	releases := make([]GitHubRelease, len(tagsResp.Values))
	for i, tag := range tagsResp.Values {
		releases[i] = GitHubRelease{
			TagName:     tag.Name,
			Name:        tag.Name,
			CreatedAt:   tag.Date,
			PublishedAt: tag.Date,
		}
	}

	return releases, nil
}

// GetCommitActivity fetches recent commit activity
func (c *BitbucketClient) GetCommitActivity(repoURL string, since time.Time) ([]GitHubCommit, error) {
	owner, repo, err := parseBitbucketURL(repoURL)
	if err != nil {
		return nil, err
	}

	apiURL := fmt.Sprintf("%s/repositories/%s/%s/commits?pagelen=100", c.baseURL, owner, repo)

	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return nil, err
	}

	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bitbucket API returned %d", resp.StatusCode)
	}

	var commitsResp BitbucketCommitsResponse
	if err := json.NewDecoder(resp.Body).Decode(&commitsResp); err != nil {
		return nil, err
	}

	// Filter commits since the given date and convert to GitHubCommit format
	var commits []GitHubCommit
	for _, bbCommit := range commitsResp.Values {
		if bbCommit.Date.After(since) || bbCommit.Date.Equal(since) {
			commits = append(commits, GitHubCommit{
				SHA: bbCommit.Hash,
				Commit: GitHubCommitInfo{
					Author: GitHubCommitAuthor{
						Name:  bbCommit.Author.User.DisplayName,
						Email: "", // Bitbucket doesn't expose email in API
						Date:  bbCommit.Date,
					},
					Message: bbCommit.Message,
				},
			})
		}
	}

	return commits, nil
}

// GetFileContent fetches the content of a file from a Bitbucket repository
func (c *BitbucketClient) GetFileContent(repoURL, filePath string) (string, error) {
	owner, repo, err := parseBitbucketURL(repoURL)
	if err != nil {
		return "", err
	}

	// Get default branch first
	repoInfo, err := c.GetRepositoryInfo(repoURL)
	if err != nil {
		return "", err
	}

	branch := repoInfo.DefaultBranch
	if branch == "" {
		branch = "master" // fallback
	}

	apiURL := fmt.Sprintf("%s/repositories/%s/%s/src/%s/%s",
		c.baseURL, owner, repo, branch, filePath)

	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return "", err
	}

	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

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

// GetProvenanceInfo checks for provenance indicators (stub)
func (c *BitbucketClient) GetProvenanceInfo(repoURL string) (*models.ProvenanceInfo, error) {
	info := &models.ProvenanceInfo{}

	ciSystems, _ := c.DetectCISystems(repoURL)
	if len(ciSystems) > 0 {
		for _, ci := range ciSystems {
			if ci == "Bitbucket Pipelines" {
				info.BuildSystem = "Bitbucket Pipelines"
				break
			}
		}
	}

	return info, nil
}

// GetCommitAuthors analyzes commit authorship patterns (stub)
func (c *BitbucketClient) GetCommitAuthors(repoURL string) (*CommitAuthorStats, error) {
	oneYearAgo := time.Now().AddDate(-1, 0, 0)
	commits, err := c.GetCommitActivity(repoURL, oneYearAgo)
	if err != nil {
		return nil, err
	}

	stats := &CommitAuthorStats{
		AuthorCommitCounts: make(map[string]int),
		AuthorFirstCommit:  make(map[string]time.Time),
		AuthorLastCommit:   make(map[string]time.Time),
		AuthorEmails:       make(map[string]bool),
		RecentAuthors:      []string{},
		HistoricalAuthors:  []string{},
	}

	ninetyDaysAgo := time.Now().AddDate(0, 0, -90)

	for _, commit := range commits {
		authorName := commit.Commit.Author.Name
		if authorName == "" {
			continue
		}

		stats.TotalCommits++
		stats.AuthorCommitCounts[authorName]++

		commitDate := commit.Commit.Author.Date
		if firstCommit, exists := stats.AuthorFirstCommit[authorName]; !exists || commitDate.Before(firstCommit) {
			stats.AuthorFirstCommit[authorName] = commitDate
		}
		if lastCommit, exists := stats.AuthorLastCommit[authorName]; !exists || commitDate.After(lastCommit) {
			stats.AuthorLastCommit[authorName] = commitDate
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

// CheckSignedCommits stub implementation
func (c *BitbucketClient) CheckSignedCommits(repoURL string) (bool, int, error) {
	return false, 0, nil
}

// CheckSignedReleases stub implementation
func (c *BitbucketClient) CheckSignedReleases(repoURL string) (bool, error) {
	return false, nil
}

// GetCommitStats fetches commit distribution
func (c *BitbucketClient) GetCommitStats(repoURL string) (*CommitStats, error) {
	owner, repo, err := parseBitbucketURL(repoURL)
	if err != nil {
		return nil, err
	}

	apiURL := fmt.Sprintf("%s/repositories/%s/%s/commits?pagelen=100", c.baseURL, owner, repo)

	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return nil, err
	}

	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bitbucket API returned %d", resp.StatusCode)
	}

	var commitsResp BitbucketCommitsResponse
	if err := json.NewDecoder(resp.Body).Decode(&commitsResp); err != nil {
		return nil, err
	}

	// Calculate commit distribution
	authorCommits := make(map[string]int)
	for _, commit := range commitsResp.Values {
		author := commit.Author.User.DisplayName
		if author != "" {
			authorCommits[author]++
		}
	}

	totalCommits := len(commitsResp.Values)
	busFactor := calculateBusFactor(authorCommits, totalCommits)

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

// GetPullRequestStats stub implementation
func (c *BitbucketClient) GetPullRequestStats(repoURL string) (*PRStats, error) {
	return &PRStats{}, nil
}

// AnalyzeCIQuality stub implementation
func (c *BitbucketClient) AnalyzeCIQuality(repoURL string, ciSystems []string) (*CIQuality, error) {
	quality := &CIQuality{
		HasCI:     len(ciSystems) > 0,
		CISystems: ciSystems,
	}

	if quality.HasCI {
		quality.QualityScore = 5 // Default moderate score
	}

	return quality, nil
}

// fileExists checks if a file exists in the repository
func (c *BitbucketClient) fileExists(owner, repo, path string) bool {
	// Get default branch first (simplified - assumes master/main)
	branch := "master"

	apiURL := fmt.Sprintf("%s/repositories/%s/%s/src/%s/%s",
		c.baseURL, owner, repo, branch, path)

	req, err := http.NewRequest("HEAD", apiURL, nil)
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

// Bitbucket API response structures
type BitbucketRepository struct {
	Name        string              `json:"name"`
	FullName    string              `json:"full_name"`
	Description string              `json:"description"`
	CreatedOn   time.Time           `json:"created_on"`
	UpdatedOn   time.Time           `json:"updated_on"`
	Owner       BitbucketOwner      `json:"owner"`
	Mainbranch  BitbucketBranch     `json:"mainbranch"`
	Links       BitbucketLinks      `json:"links"`
}

type BitbucketOwner struct {
	Username    string `json:"username"`
	DisplayName string `json:"display_name"`
}

type BitbucketBranch struct {
	Name string `json:"name"`
}

type BitbucketLinks struct {
	HTML BitbucketLink `json:"html"`
}

type BitbucketLink struct {
	Href string `json:"href"`
}

type BitbucketTagsResponse struct {
	Values []BitbucketTag `json:"values"`
}

type BitbucketTag struct {
	Name string    `json:"name"`
	Date time.Time `json:"date"`
}

type BitbucketCommitsResponse struct {
	Values []BitbucketCommit `json:"values"`
}

type BitbucketCommit struct {
	Hash    string               `json:"hash"`
	Date    time.Time            `json:"date"`
	Message string               `json:"message"`
	Author  BitbucketCommitAuthor `json:"author"`
}

type BitbucketCommitAuthor struct {
	User BitbucketUser `json:"user"`
}

type BitbucketUser struct {
	DisplayName string `json:"display_name"`
	Username    string `json:"username"`
}

func parseBitbucketURL(repoURL string) (owner, repo string, err error) {
	// Handle various Bitbucket URL formats:
	// https://bitbucket.org/owner/repo
	// git@bitbucket.org:owner/repo.git

	repoURL = strings.TrimSpace(repoURL)
	repoURL = strings.TrimPrefix(repoURL, "git+")
	repoURL = strings.TrimSuffix(repoURL, ".git")

	// Handle SSH format
	if strings.Contains(repoURL, "git@") {
		parts := strings.Split(repoURL, "@")
		if len(parts) >= 2 {
			hostAndPath := strings.Split(parts[1], ":")
			if len(hostAndPath) >= 2 {
				pathParts := strings.Split(hostAndPath[1], "/")
				if len(pathParts) >= 2 {
					owner = pathParts[0]
					repo = pathParts[1]
					return owner, repo, nil
				}
			}
		}
	}

	// Handle HTTPS format
	repoURL = strings.TrimPrefix(repoURL, "git://")
	repoURL = strings.TrimPrefix(repoURL, "https://")
	repoURL = strings.TrimPrefix(repoURL, "http://")

	parts := strings.Split(repoURL, "/")
	if len(parts) < 3 || !strings.Contains(parts[0], "bitbucket") {
		return "", "", fmt.Errorf("invalid Bitbucket URL: %s", repoURL)
	}

	// Find bitbucket.org and get owner/repo
	for i, part := range parts {
		if strings.Contains(part, "bitbucket") && i+2 < len(parts) {
			return parts[i+1], parts[i+2], nil
		}
	}

	return "", "", fmt.Errorf("could not parse Bitbucket URL: %s", repoURL)
}

// GetAccountType returns whether an account is "organization" or "user"
// For Bitbucket, we always return "user" as a stub implementation
func (c *BitbucketClient) GetAccountType(repoURL, username string) string {
	// TODO: Implement Bitbucket-specific account type detection
	return "user"
}

// GetAccountCreationDate returns when an account was created
// For Bitbucket, we return zero time as a stub implementation
func (c *BitbucketClient) GetAccountCreationDate(repoURL, username string) time.Time {
	// TODO: Implement Bitbucket-specific account creation date detection
	return time.Time{}
}
