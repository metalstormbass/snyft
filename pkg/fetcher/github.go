package fetcher

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/metalstormbass/snyft/pkg/models"
)

// repoCache stores fetched data (scraped or API) in memory to prevent redundant
// network calls within a single scan session.
//
// Web scraping is the primary data-fetching method. When a GITHUB_TOKEN is set,
// API calls supplement scraped data with richer metadata and higher rate limits
// (5,000 req/hour vs 60 unauthenticated). Caching eliminates repeated
// round-trips for the same repo across multiple checks.
type repoCache struct {
	mu         sync.RWMutex
	repoInfo   map[string]*models.RepositoryInfo // key: "owner/repo"
	releases   map[string][]GitHubRelease        // key: "owner/repo"
	fileExists map[string]bool                   // key: "owner/repo/path"
}

func newRepoCache() *repoCache {
	return &repoCache{
		repoInfo:   make(map[string]*models.RepositoryInfo),
		releases:   make(map[string][]GitHubRelease),
		fileExists: make(map[string]bool),
	}
}

func (rc *repoCache) getRepoInfo(key string) (*models.RepositoryInfo, bool) {
	rc.mu.RLock()
	defer rc.mu.RUnlock()
	v, ok := rc.repoInfo[key]
	return v, ok
}

func (rc *repoCache) setRepoInfo(key string, info *models.RepositoryInfo) {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	rc.repoInfo[key] = info
}

func (rc *repoCache) getCachedReleases(key string) ([]GitHubRelease, bool) {
	rc.mu.RLock()
	defer rc.mu.RUnlock()
	v, ok := rc.releases[key]
	return v, ok
}

func (rc *repoCache) setCachedReleases(key string, releases []GitHubRelease) {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	rc.releases[key] = releases
}

func (rc *repoCache) getFileExists(key string) (bool, bool) {
	rc.mu.RLock()
	defer rc.mu.RUnlock()
	v, ok := rc.fileExists[key]
	return v, ok
}

func (rc *repoCache) setFileExists(key string, exists bool) {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	rc.fileExists[key] = exists
}

// GitHubClient handles interactions with GitHub API and web scraping.
// By default, web scraping is the primary data-fetching method, with API calls
// used to supplement when a GITHUB_TOKEN is available.
type GitHubClient struct {
	token      string
	httpClient *http.Client
	baseURL    string
	cache      *repoCache
	preferAPI  bool // when true, always try API first (used by test helpers with mock servers)
}

// NewGitHubClient creates a new GitHub client. Web scraping is the primary
// data-fetching method. When GITHUB_TOKEN is set, API calls supplement
// scraped data with richer metadata and higher rate limits.
func NewGitHubClient() *GitHubClient {
	return &GitHubClient{
		token: os.Getenv("GITHUB_TOKEN"),
		httpClient: &http.Client{
			// 10s timeout keeps failures fast — both API rate-limit
			// responses and slow scraping targets are bounded.
			Timeout: 10 * time.Second,
		},
		baseURL: "https://api.github.com",
		cache:   newRepoCache(),
	}
}

// NewGitHubClientWithBaseURL creates a GitHubClient pointing at a custom API base URL.
// This is primarily used for testing with httptest servers. The client uses
// API-first mode since mock servers don't support web scraping.
func NewGitHubClientWithBaseURL(baseURL string) *GitHubClient {
	return &GitHubClient{
		httpClient: &http.Client{Timeout: 10 * time.Second},
		baseURL:    baseURL,
		cache:      newRepoCache(),
		preferAPI:  true,
	}
}

// shouldPreferScraping returns true when web scraping should be tried first.
// Scraping is preferred when no API token is configured and we're using the
// default GitHub API URL, since unauthenticated API calls are limited to
// 60 req/hour. With a token, the API provides richer data at 5,000 req/hour.
// Custom base URLs (test servers) always use API-first since scraping
// targets real github.com regardless of the base URL.
func (c *GitHubClient) shouldPreferScraping() bool {
	return c.token == "" && !c.preferAPI && c.baseURL == "https://api.github.com"
}

// GetRepositoryInfo fetches repository information from GitHub.
// When no GITHUB_TOKEN is set, web scraping is tried first to avoid consuming
// the limited unauthenticated API quota. With a token, the API is used for
// richer data (exact dates, issue counts, license, topics).
func (c *GitHubClient) GetRepositoryInfo(repoURL string) (*models.RepositoryInfo, error) {
	owner, repo, err := parseGitHubURL(repoURL)
	if err != nil {
		return nil, err
	}

	// Return cached result if available — GetRepositoryInfo is called multiple
	// times per package (analyzeRepository, getBranchProtection, etc.)
	cacheKey := owner + "/" + repo
	if c.cache != nil {
		if cached, ok := c.cache.getRepoInfo(cacheKey); ok {
			return cached, nil
		}
	}

	// Scraping-first path: when no token is set, scrape the GitHub web page
	// to avoid burning limited unauthenticated API quota.
	if c.shouldPreferScraping() {
		info, scrapeErr := c.scrapeRepositoryInfo(repoURL, owner, repo)
		if scrapeErr == nil {
			if c.cache != nil {
				c.cache.setRepoInfo(cacheKey, info)
			}
			return info, nil
		}
		// Scraping failed — fall through to try the API
	}

	// API path: primary when token is set, fallback when scraping fails.
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
		// API unreachable — try scraping if we haven't already
		if !c.shouldPreferScraping() {
			info, scrapeErr := c.scrapeRepositoryInfo(repoURL, owner, repo)
			if scrapeErr == nil && c.cache != nil {
				c.cache.setRepoInfo(cacheKey, info)
			}
			return info, scrapeErr
		}
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		// Try scraping fallback on rate limit or auth errors (if we haven't already)
		if !c.shouldPreferScraping() && shouldFallbackToScraping(nil, resp.StatusCode) {
			info, scrapeErr := c.scrapeRepositoryInfo(repoURL, owner, repo)
			if scrapeErr == nil && c.cache != nil {
				c.cache.setRepoInfo(cacheKey, info)
			}
			return info, scrapeErr
		}
		return nil, fmt.Errorf("GitHub API returned %d: %s", resp.StatusCode, string(body))
	}

	var ghRepo GitHubRepository
	if err := json.NewDecoder(resp.Body).Decode(&ghRepo); err != nil {
		return nil, err
	}

	info := &models.RepositoryInfo{
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
	}
	if c.cache != nil {
		c.cache.setRepoInfo(cacheKey, info)
	}
	return info, nil
}

// scrapeRepositoryInfo scrapes repository information from the GitHub web page.
// This is the primary data source when no GITHUB_TOKEN is set.
func (c *GitHubClient) scrapeRepositoryInfo(repoURL, owner, repo string) (*models.RepositoryInfo, error) {
	pageURL := fmt.Sprintf("https://github.com/%s/%s", owner, repo)
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
	doc.Find("p.f4.my-3").Each(func(i int, s *goquery.Selection) {
		info.Description = strings.TrimSpace(s.Text())
	})

	// Extract stars, forks, watchers from the sidebar
	doc.Find("a[href$='/stargazers']").Each(func(i int, s *goquery.Selection) {
		text := strings.TrimSpace(s.Text())
		info.Stars = extractNumber(text)
	})

	doc.Find("a[href$='/forks']").Each(func(i int, s *goquery.Selection) {
		text := strings.TrimSpace(s.Text())
		info.Forks = extractNumber(text)
	})

	doc.Find("a[href$='/watchers']").Each(func(i int, s *goquery.Selection) {
		text := strings.TrimSpace(s.Text())
		info.Watchers = extractNumber(text)
	})

	// Extract last commit date from the commit bar
	doc.Find("relative-time").Each(func(i int, s *goquery.Selection) {
		if datetime, exists := s.Attr("datetime"); exists && i == 0 {
			if t, err := time.Parse(time.RFC3339, datetime); err == nil {
				info.PushedAt = t
			}
		}
	})

	// Set current time for updated_at as approximation
	info.UpdatedAt = time.Now()

	return info, nil
}


// DetectCISystems checks for common CI/CD systems in the repository
func (c *GitHubClient) DetectCISystems(repoURL string) ([]string, error) {
	owner, repo, err := parseGitHubURL(repoURL)
	if err != nil {
		return nil, err
	}

	var ciSystems []string
	detected := make(map[string]bool)

	for _, entry := range ExtendedCIConfigFiles() {
		// Skip remaining config files once a platform is already detected.
		// GitHub Actions lists ~16 fallback paths (directory + common filenames)
		// but only the first match matters. This avoids unnecessary API/HEAD calls.
		if detected[entry.Name] {
			continue
		}
		if c.fileExists(owner, repo, entry.Path) {
			detected[entry.Name] = true
			ciSystems = append(ciSystems, entry.Name)
		}
	}

	return ciSystems, nil
}

// HasAutomatedReleases checks if the repository has automated releases.
// Uses the cached getReleases helper which includes scraping fallback on rate limit.
func (c *GitHubClient) HasAutomatedReleases(repoURL string) (bool, error) {
	owner, repo, err := parseGitHubURL(repoURL)
	if err != nil {
		return false, err
	}

	releases, err := c.getReleases(owner, repo)
	if err != nil {
		return false, nil
	}

	return len(releases) > 0, nil
}

// GetReleaseHistory fetches detailed release history for a repository.
// Uses the cached getReleases helper which includes scraping fallback on rate limit.
func (c *GitHubClient) GetReleaseHistory(repoURL string, limit int) ([]GitHubRelease, error) {
	owner, repo, err := parseGitHubURL(repoURL)
	if err != nil {
		return nil, err
	}

	releases, err := c.getReleases(owner, repo)
	if err != nil {
		return nil, err
	}

	// Apply the limit
	if limit > 0 && len(releases) > limit {
		releases = releases[:limit]
	}

	return releases, nil
}

// GetCommitActivity fetches recent commit activity for a repository.
// Returns empty list (not error) when rate-limited — commit history cannot be
// meaningfully scraped, but callers handle empty results gracefully.
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
		// Rate limit — return empty list so callers degrade gracefully
		// rather than treating the failure as a risk signal.
		if shouldFallbackToScraping(nil, resp.StatusCode) {
			return []GitHubCommit{}, nil
		}
		return nil, fmt.Errorf("GitHub API returned %d", resp.StatusCode)
	}

	var commits []GitHubCommit
	if err := json.NewDecoder(resp.Body).Decode(&commits); err != nil {
		return nil, err
	}

	return commits, nil
}

// CheckGitTag verifies if a specific version tag exists in the repository.
// Uses web scraping as the primary method (HEAD request to github.com tag page),
// falling back to the API only when a token is available and scraping fails.
// Returns true if the tag exists, along with the tag URL.
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

	// Scraping-first path: check the GitHub web page for each tag variant.
	// HEAD request to github.com/owner/repo/releases/tag/{tag} is served by
	// the web frontend, not the API, and is not subject to API rate limits.
	if c.shouldPreferScraping() {
		for _, tag := range tagVariants {
			tagURL := fmt.Sprintf("https://github.com/%s/%s/releases/tag/%s", owner, repo, tag)
			if c.checkTagViaWeb(tagURL) {
				return true, tagURL, nil
			}
		}
		// Scraping didn't find a tag — fall through to try the API as a last resort.
		// The tag may exist but not have a releases page (lightweight tags).
	}

	// API path: primary when token is set, fallback when scraping didn't find the tag.
	rateLimited := false
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
		_ = resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			tagURL := fmt.Sprintf("https://github.com/%s/%s/releases/tag/%s", owner, repo, tag)
			return true, tagURL, nil
		}

		if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests {
			rateLimited = true
			break // No point trying more variants — they'll all be rate-limited.
		}
	}

	// If the API was rate-limited and we haven't tried scraping yet, try now.
	if rateLimited && !c.shouldPreferScraping() {
		for _, tag := range tagVariants {
			tagURL := fmt.Sprintf("https://github.com/%s/%s/releases/tag/%s", owner, repo, tag)
			if c.checkTagViaWeb(tagURL) {
				return true, tagURL, nil
			}
		}
	}

	// Graceful degradation: when rate-limited and scraping didn't find the tag,
	// return (false, "", nil) — "could not confirm tag" — rather than an error.
	// The caller treats nil error + false as "tag not found" which is the safest
	// interpretation: the provenance scorer already handles missing tags.
	return false, "", nil
}

// checkTagViaWeb checks if a GitHub tag/release page exists by issuing a HEAD
// request to the web frontend. This is NOT subject to API rate limits.
func (c *GitHubClient) checkTagViaWeb(tagURL string) bool {
	req, err := http.NewRequest("HEAD", tagURL, nil)
	if err != nil {
		return false
	}
	req.Header.Set("User-Agent", userAgent)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return false
	}
	_ = resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

func (c *GitHubClient) fileExists(owner, repo, path string) bool {
	// Cache responses — DetectCISystems issues ~20 requests per repo
	// and provenance checks add ~10 more.
	cacheKey := owner + "/" + repo + "/" + path
	if c.cache != nil {
		if cached, ok := c.cache.getFileExists(cacheKey); ok {
			return cached
		}
	}

	// Raw-URL-first path: when no token is set, use raw.githubusercontent.com
	// (CDN, not subject to API rate limits) as the primary check.
	if c.shouldPreferScraping() {
		exists := c.checkFileViaRawURL(owner, repo, path)
		if c.cache != nil {
			c.cache.setFileExists(cacheKey, exists)
		}
		return exists
	}

	// API path: primary when token is set (more reliable, handles private repos).
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

	if resp.StatusCode == http.StatusOK {
		if c.cache != nil {
			c.cache.setFileExists(cacheKey, true)
		}
		return true
	}

	// Rate-limited: try raw.githubusercontent.com (not subject to API rate limits).
	// Do NOT cache false for rate-limited responses — the file may exist but the API
	// refused to answer. A cached false here would poison subsequent checks.
	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests {
		exists := c.checkFileViaRawURL(owner, repo, path)
		if exists && c.cache != nil {
			c.cache.setFileExists(cacheKey, true)
		}
		return exists
	}

	// File genuinely not found (404) or other client error — safe to cache.
	if c.cache != nil {
		c.cache.setFileExists(cacheKey, false)
	}
	return false
}

// checkFileViaRawURL checks if a file exists by issuing a HEAD request to
// raw.githubusercontent.com, which is served by a CDN and is not subject to
// the GitHub API rate limit. This is used as a fallback when the API returns
// 403/429.
func (c *GitHubClient) checkFileViaRawURL(owner, repo, path string) bool {
	for _, branch := range []string{"main", "master"} {
		rawURL := fmt.Sprintf("https://raw.githubusercontent.com/%s/%s/%s/%s", owner, repo, branch, path)
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

// FileExistsInRepo checks if a file exists in a GitHub repository using a
// cached HEAD request. This is more efficient than GetFileContent when only
// file existence matters (no content needed). Falls back to
// raw.githubusercontent.com when the API is rate-limited.
func (c *GitHubClient) FileExistsInRepo(repoURL, filePath string) bool {
	owner, repo, err := parseGitHubURL(repoURL)
	if err != nil {
		return false
	}
	return c.fileExists(owner, repo, filePath)
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

	// Check signed releases
	signedCount, totalCount := c.checkSignedReleases(owner, repo)
	info.SignedReleaseCount = signedCount
	info.TotalReleaseCount = totalCount

	return info, nil
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


// getReleases fetches all releases for a repository.
// When no token is set, the GitHub releases page is scraped first.
// With a token, the API provides richer release data (assets, draft status).
func (c *GitHubClient) getReleases(owner, repo string) ([]GitHubRelease, error) {
	// Cache releases — called from provenance checks (checkSignedReleases).
	// A cache hit eliminates redundant network calls.
	cacheKey := owner + "/" + repo
	if c.cache != nil {
		if cached, ok := c.cache.getCachedReleases(cacheKey); ok {
			return cached, nil
		}
	}

	// Scraping-first path: when no token, scrape the releases page directly.
	if c.shouldPreferScraping() {
		releases, scrapeErr := c.scrapeReleases(owner, repo)
		if scrapeErr == nil {
			if c.cache != nil {
				c.cache.setCachedReleases(cacheKey, releases)
			}
			return releases, nil
		}
		// Scraping failed — fall through to try the API
	}

	// API path: primary when token is set, fallback when scraping fails.
	// Paginate through all pages (up to maxPaginationPages) to get full release
	// history. This is critical for release anomaly detection — we need the complete
	// version timeline to spot dormancy reactivation and cadence irregularities.
	// Source: "Backstabber's Knife Collection" (Ohm et al., 2020) — dormancy
	// reactivation is a key supply chain attack pattern.
	var allReleases []GitHubRelease
	nextURL := fmt.Sprintf("%s/repos/%s/%s/releases?per_page=100", c.baseURL, owner, repo)

	for page := 0; page < maxPaginationPages && nextURL != ""; page++ {
		req, err := http.NewRequest("GET", nextURL, nil)
		if err != nil {
			return nil, err
		}

		if c.token != "" {
			req.Header.Set("Authorization", "Bearer "+c.token)
		}
		req.Header.Set("Accept", "application/vnd.github.v3+json")

		resp, err := c.httpClient.Do(req)
		if err != nil {
			// Network error — try scraping if we haven't already
			if page == 0 && !c.shouldPreferScraping() {
				releases, scrapeErr := c.scrapeReleases(owner, repo)
				if scrapeErr == nil && c.cache != nil {
					c.cache.setCachedReleases(cacheKey, releases)
				}
				return releases, scrapeErr
			}
			break
		}

		if resp.StatusCode != http.StatusOK {
			// Rate limit or auth errors — try scraping if we haven't already
			_ = resp.Body.Close()
			if page == 0 && !c.shouldPreferScraping() && shouldFallbackToScraping(nil, resp.StatusCode) {
				releases, scrapeErr := c.scrapeReleases(owner, repo)
				if scrapeErr == nil && c.cache != nil {
					c.cache.setCachedReleases(cacheKey, releases)
				}
				return releases, scrapeErr
			}
			if page == 0 {
				return nil, fmt.Errorf("GitHub API returned %d", resp.StatusCode)
			}
			break
		}

		var pageReleases []GitHubRelease
		if err := json.NewDecoder(resp.Body).Decode(&pageReleases); err != nil {
			_ = resp.Body.Close()
			if page == 0 {
				return nil, err
			}
			break
		}

		// Parse Link header for next page URL
		nextURL = parseLinkHeaderNextURL(resp.Header.Get("Link"))
		_ = resp.Body.Close()

		allReleases = append(allReleases, pageReleases...)

		// Stop if there's no next page link AND we got fewer results than per_page
		if nextURL == "" || len(pageReleases) == 0 {
			break
		}
	}

	if c.cache != nil {
		c.cache.setCachedReleases(cacheKey, allReleases)
	}
	return allReleases, nil
}

// scrapeReleases scrapes release information from the GitHub releases page.
// This is the primary release data source when no GITHUB_TOKEN is set.
// Paginates through all release pages (up to maxPaginationPages) to get the
// full release history needed for release anomaly detection.
func (c *GitHubClient) scrapeReleases(owner, repo string) ([]GitHubRelease, error) {
	var allReleases []GitHubRelease
	nextPageURL := fmt.Sprintf("https://github.com/%s/%s/releases", owner, repo)

	for page := 0; page < maxPaginationPages && nextPageURL != ""; page++ {
		doc, err := scrapeWithUserAgent(nextPageURL)
		if err != nil {
			if page == 0 {
				return nil, fmt.Errorf("scraping releases fallback failed: %w", err)
			}
			break // Return what we have so far
		}

		pageHadReleases := false

		// Each release is in a section with the release tag name and date
		doc.Find("div[data-hpc] section").Each(func(i int, s *goquery.Selection) {
			var release GitHubRelease

			// Extract tag name from the release heading link
			s.Find("a[href*='/releases/tag/']").First().Each(func(_ int, a *goquery.Selection) {
				if href, exists := a.Attr("href"); exists {
					parts := strings.Split(href, "/tag/")
					if len(parts) == 2 {
						release.TagName = parts[1]
						release.Name = strings.TrimSpace(a.Text())
					}
				}
			})

			// Extract date from relative-time element
			s.Find("relative-time").First().Each(func(_ int, rt *goquery.Selection) {
				if datetime, exists := rt.Attr("datetime"); exists {
					if t, parseErr := time.Parse(time.RFC3339, datetime); parseErr == nil {
						release.PublishedAt = t
						release.CreatedAt = t
					}
				}
			})

			// Check for pre-release label
			s.Find("span:contains('Pre-release')").Each(func(_ int, _ *goquery.Selection) {
				release.Prerelease = true
			})

			// Extract asset names from the assets list
			s.Find("a[href*='/releases/download/']").Each(func(_ int, a *goquery.Selection) {
				if href, exists := a.Attr("href"); exists {
					name := strings.TrimSpace(a.Text())
					if name != "" {
						release.Assets = append(release.Assets, GitHubAsset{
							Name:               name,
							BrowserDownloadURL: "https://github.com" + href,
						})
					}
				}
			})

			if release.TagName != "" {
				allReleases = append(allReleases, release)
				pageHadReleases = true
			}
		})

		// Look for the "Next" pagination link
		nextPageURL = ""
		doc.Find("a.next_page, a[rel='next']").Each(func(_ int, a *goquery.Selection) {
			if href, exists := a.Attr("href"); exists && href != "" {
				// Handle relative URLs
				if strings.HasPrefix(href, "/") {
					nextPageURL = "https://github.com" + href
				} else if strings.HasPrefix(href, "http") {
					nextPageURL = href
				}
			}
		})

		// If no releases were found on this page, stop paginating
		if !pageHadReleases {
			break
		}
	}

	return allReleases, nil
}

// GetFileContent fetches the content of a file from a GitHub repository.
// When no token is set, raw.githubusercontent.com (CDN) is tried first.
// With a token, the API is used for reliability and private repo support.
func (c *GitHubClient) GetFileContent(repoURL, filePath string) (string, error) {
	owner, repo, err := parseGitHubURL(repoURL)
	if err != nil {
		return "", err
	}

	// Raw-URL-first path: when no token, use CDN (not subject to API rate limits).
	if c.shouldPreferScraping() {
		content, rawErr := c.getFileContentViaRawURL(owner, repo, filePath)
		if rawErr == nil {
			return content, nil
		}
		// Raw URL failed — fall through to try the API
	}

	// API path: primary when token is set, fallback when raw URL fails.
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
		// Network error — try raw URL if we haven't already
		if !c.shouldPreferScraping() {
			return c.getFileContentViaRawURL(owner, repo, filePath)
		}
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		// Rate limit or auth errors — try raw URL if we haven't already
		if !c.shouldPreferScraping() && shouldFallbackToScraping(nil, resp.StatusCode) {
			return c.getFileContentViaRawURL(owner, repo, filePath)
		}
		return "", fmt.Errorf("file not found or inaccessible: %s", filePath)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(body), nil
}

// getFileContentViaRawURL fetches file content from raw.githubusercontent.com,
// which is served by a CDN and is not subject to the GitHub API rate limit.
// Tries both main and master branches.
func (c *GitHubClient) getFileContentViaRawURL(owner, repo, path string) (string, error) {
	for _, branch := range []string{"main", "master"} {
		rawURL := fmt.Sprintf("https://raw.githubusercontent.com/%s/%s/%s/%s", owner, repo, branch, path)
		req, err := http.NewRequest("GET", rawURL, nil)
		if err != nil {
			continue
		}
		resp, err := c.httpClient.Do(req)
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
	return "", fmt.Errorf("file not found via raw.githubusercontent.com: %s", path)
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
			if page == 1 {
				return nil, err
			}
			break
		}

		if resp.StatusCode != http.StatusOK {
			_ = resp.Body.Close()
			if page == 1 {
				// Rate limit on first page — return error so callers can distinguish
				// "could not check" from "no ownership changes detected"
				if shouldFallbackToScraping(nil, resp.StatusCode) {
					return nil, fmt.Errorf("%w: GitHub API returned %d for commit authors", ErrRateLimited, resp.StatusCode)
				}
				return nil, fmt.Errorf("GitHub API returned %d", resp.StatusCode)
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

// CheckSignedCommits checks if recent commits in the repository are GPG signed.
// Returns (false, 0, nil) when rate-limited — cannot verify signatures without API.
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
		// Rate limit — return unknown rather than error so callers degrade gracefully
		if shouldFallbackToScraping(nil, resp.StatusCode) {
			return false, 0, nil
		}
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

// CheckSignedReleases checks if releases have GPG signatures.
// Uses the cached getReleases helper which includes scraping fallback on rate limit.
func (c *GitHubClient) CheckSignedReleases(repoURL string) (bool, error) {
	owner, repo, err := parseGitHubURL(repoURL)
	if err != nil {
		return false, err
	}

	releases, err := c.getReleases(owner, repo)
	if err != nil {
		return false, nil // Degrade gracefully
	}

	if len(releases) == 0 {
		return false, nil
	}

	// Limit to last 10 releases
	if len(releases) > 10 {
		releases = releases[:10]
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
	TotalPRs               int
	MergedPRs              int
	PRsWithReviews         int
	CodeReviewRate         float64 // Percentage of PRs with reviews
	RequiredReviewers      int     // Number of required reviewers (from branch protection)
	HasBranchProtection    bool
	BranchProtectionDenied bool // True when API returned 403/404 (admin access required)
}

// CIQuality contains CI/CD quality metrics
type CIQuality struct {
	HasCI              bool
	CISystems          []string
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

// GetCommitStats fetches commit distribution to calculate bus factor.
// When no token is set, the GitHub contributors page is scraped first.
// With a token, the API provides per-commit author data for more accurate analysis.
func (c *GitHubClient) GetCommitStats(repoURL string) (*CommitStats, error) {
	owner, repo, err := parseGitHubURL(repoURL)
	if err != nil {
		return nil, err
	}

	// Scraping-first path: when no token, scrape contributor data.
	if c.shouldPreferScraping() {
		stats, scrapeErr := c.scrapeCommitStats(owner, repo)
		if scrapeErr == nil {
			return stats, nil
		}
		// Scraping failed — fall through to try the API
	}

	// API path: primary when token is set, fallback when scraping fails.
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
		// Network error — try scraping if we haven't already
		if !c.shouldPreferScraping() {
			return c.scrapeCommitStats(owner, repo)
		}
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		// Rate limit or auth errors — try scraping if we haven't already
		if !c.shouldPreferScraping() && shouldFallbackToScraping(nil, resp.StatusCode) {
			return c.scrapeCommitStats(owner, repo)
		}
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

// scrapeCommitStats scrapes contributor data from the GitHub repository page.
// This is the primary contributor data source when no GITHUB_TOKEN is set.
func (c *GitHubClient) scrapeCommitStats(owner, repo string) (*CommitStats, error) {
	pageURL := fmt.Sprintf("https://github.com/%s/%s", owner, repo)
	doc, err := scrapeWithUserAgent(pageURL)
	if err != nil {
		return nil, fmt.Errorf("scraping commit stats fallback failed: %w", err)
	}

	authorCommits := make(map[string]int)
	totalContributors := 0

	// Extract total contributor count from the repo page (e.g., "329" next to contributors link)
	doc.Find("a[href*='/graphs/contributors'] span, a[href*='/contributors'] span").Each(func(i int, s *goquery.Selection) {
		text := strings.TrimSpace(s.Text())
		num := extractNumber(text)
		if num > 0 {
			totalContributors = num
		}
	})

	// Extract individual contributor usernames from the sidebar
	doc.Find("a[data-hovercard-type='user']").Each(func(i int, s *goquery.Selection) {
		if href, exists := s.Attr("href"); exists {
			username := strings.TrimPrefix(href, "/")
			if username != "" && !strings.Contains(username, "/") {
				authorCommits[username] = 1
			}
		}
	})

	// If we found a total contributor count larger than the visible sidebar avatars,
	// use it to build a more representative distribution. Each contributor is assigned
	// 1 commit (equal weight) so calculateBusFactor returns a proportional result
	// instead of being dominated by a single "unknown" mega-author.
	if totalContributors > len(authorCommits) {
		for i := len(authorCommits); i < totalContributors; i++ {
			authorCommits[fmt.Sprintf("contributor-%d", i)] = 1
		}
	}

	totalCommits := 0
	for _, count := range authorCommits {
		totalCommits += count
	}

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
	defer func() { _ = resp.Body.Close() }()

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
	branchProtection, accessDenied := c.getBranchProtection(owner, repo)
	stats.HasBranchProtection = branchProtection != nil
	stats.BranchProtectionDenied = accessDenied
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
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return false
	}

	var reviews []GitHubReview
	if err := json.NewDecoder(resp.Body).Decode(&reviews); err != nil {
		return false
	}

	return len(reviews) > 0
}

// getBranchProtection fetches branch protection rules for the default branch.
// Returns (protection, accessDenied) where accessDenied is true when the API
// returned 403/404 (admin access required), distinguishing "can't check" from
// "no protection configured".
func (c *GitHubClient) getBranchProtection(owner, repo string) (*GitHubBranchProtection, bool) {
	// First get the default branch
	repoInfo, err := c.GetRepositoryInfo(fmt.Sprintf("https://github.com/%s/%s", owner, repo))
	if err != nil {
		return nil, false
	}

	url := fmt.Sprintf("%s/repos/%s/%s/branches/%s/protection", c.baseURL, owner, repo, repoInfo.DefaultBranch)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, false
	}

	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, false
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusNotFound {
		return nil, true
	}
	if resp.StatusCode != http.StatusOK {
		return nil, false
	}

	var protection GitHubBranchProtection
	if err := json.NewDecoder(resp.Body).Decode(&protection); err != nil {
		return nil, false
	}

	return &protection, false
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
		}
	}

	// Calculate quality score (0-10)
	qualityScore := 0

	// Base points for having CI
	if quality.HasCI {
		qualityScore += 3
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

// getWorkflowFiles lists workflow filenames in .github/workflows/.
// Uses web scraping as the primary method when no token is set. Falls back
// to the API when a token is available or scraping fails. Returns empty list
// (not error) when all methods fail so CI detection degrades gracefully.
func (c *GitHubClient) getWorkflowFiles(owner, repo string) ([]string, error) {
	// Scraping-first path: scrape the GitHub tree page for the workflows directory.
	if c.shouldPreferScraping() {
		workflows, scrapeErr := c.scrapeWorkflowFiles(owner, repo)
		if scrapeErr == nil {
			return workflows, nil
		}
		// Scraping failed — fall through to try the API
	}

	// API path: primary when token is set, fallback when scraping fails.
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
		// Network error — try scraping if we haven't already
		if !c.shouldPreferScraping() {
			workflows, scrapeErr := c.scrapeWorkflowFiles(owner, repo)
			if scrapeErr == nil {
				return workflows, nil
			}
		}
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		// Rate limit or auth errors — try scraping if we haven't already
		if !c.shouldPreferScraping() && shouldFallbackToScraping(nil, resp.StatusCode) {
			workflows, scrapeErr := c.scrapeWorkflowFiles(owner, repo)
			if scrapeErr == nil {
				return workflows, nil
			}
		}
		// Graceful degradation: return empty list so callers don't error out
		if shouldFallbackToScraping(nil, resp.StatusCode) {
			return []string{}, nil
		}
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

// scrapeWorkflowFiles scrapes workflow filenames from the GitHub repository tree page.
// This is the primary method when no token is set, avoiding API rate limits entirely.
func (c *GitHubClient) scrapeWorkflowFiles(owner, repo string) ([]string, error) {
	pageURL := fmt.Sprintf("https://github.com/%s/%s/tree/HEAD/.github/workflows", owner, repo)
	doc, scrapeErr := scrapeWithUserAgent(pageURL)
	if scrapeErr != nil {
		// Also try with explicit main branch
		pageURL = fmt.Sprintf("https://github.com/%s/%s/tree/main/.github/workflows", owner, repo)
		doc, scrapeErr = scrapeWithUserAgent(pageURL)
		if scrapeErr != nil {
			return nil, scrapeErr
		}
	}

	var workflows []string
	// GitHub renders file listings as links within the tree view.
	// Each file link href ends with the filename.
	doc.Find("a").Each(func(_ int, a *goquery.Selection) {
		href, exists := a.Attr("href")
		if !exists {
			return
		}
		// Match links to workflow files in the .github/workflows directory
		prefix := fmt.Sprintf("/%s/%s/blob/", owner, repo)
		if !strings.Contains(href, prefix) {
			return
		}
		if !strings.Contains(href, "/.github/workflows/") {
			return
		}
		// Extract just the filename from the full path
		parts := strings.Split(href, "/")
		if len(parts) > 0 {
			name := parts[len(parts)-1]
			if strings.HasSuffix(name, ".yml") || strings.HasSuffix(name, ".yaml") {
				workflows = append(workflows, name)
			}
		}
	})

	return workflows, nil
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

// GetAverageIssueResponseTime calculates the average time to first response on issues
// This helps assess maintainer responsiveness and governance quality
func (c *GitHubClient) GetAverageIssueResponseTime(repoURL string) (float64, error) {
	owner, repo, err := parseGitHubURL(repoURL)
	if err != nil {
		return 0, err
	}

	// Fetch recent closed issues (limit to last 30 for performance)
	url := fmt.Sprintf("%s/repos/%s/%s/issues?state=closed&per_page=30&sort=updated&direction=desc", c.baseURL, owner, repo)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return 0, err
	}

	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		// Rate limit — return 0 with nil error so callers degrade gracefully
		// rather than treating API unavailability as a risk signal
		if shouldFallbackToScraping(nil, resp.StatusCode) {
			return 0, nil
		}
		return 0, fmt.Errorf("GitHub API returned %d", resp.StatusCode)
	}

	var issues []GitHubIssue
	if err := json.NewDecoder(resp.Body).Decode(&issues); err != nil {
		return 0, err
	}

	if len(issues) == 0 {
		return 0, fmt.Errorf("no closed issues found")
	}

	// Calculate average response time
	totalResponseTime := 0.0
	issuesWithResponse := 0

	for _, issue := range issues {
		// Skip pull requests (they have a pull_request field)
		if issue.PullRequest != nil {
			continue
		}

		// Fetch comments to find first response
		commentsURL := fmt.Sprintf("%s/repos/%s/%s/issues/%d/comments", c.baseURL, owner, repo, issue.Number)
		commentsReq, err := http.NewRequest("GET", commentsURL, nil)
		if err != nil {
			continue
		}

		if c.token != "" {
			commentsReq.Header.Set("Authorization", "Bearer "+c.token)
		}
		commentsReq.Header.Set("Accept", "application/vnd.github.v3+json")

		commentsResp, err := c.httpClient.Do(commentsReq)
		if err != nil {
			continue
		}

		if commentsResp.StatusCode == http.StatusOK {
			var comments []GitHubComment
			if err := json.NewDecoder(commentsResp.Body).Decode(&comments); err == nil && len(comments) > 0 {
				// Calculate time to first comment
				firstCommentTime := comments[0].CreatedAt
				issueCreatedTime := issue.CreatedAt
				responseTime := firstCommentTime.Sub(issueCreatedTime).Hours() / 24 // Convert to days

				totalResponseTime += responseTime
				issuesWithResponse++
			}
		}
		_ = commentsResp.Body.Close()

		// Limit API calls to avoid rate limiting
		if issuesWithResponse >= 10 {
			break
		}
	}

	if issuesWithResponse == 0 {
		return 0, fmt.Errorf("no issues with responses found")
	}

	return totalResponseTime / float64(issuesWithResponse), nil
}

// GitHubIssue represents a GitHub issue
type GitHubIssue struct {
	Number      int                `json:"number"`
	State       string             `json:"state"`
	CreatedAt   time.Time          `json:"created_at"`
	ClosedAt    *time.Time         `json:"closed_at"`
	PullRequest *GitHubPullRequest `json:"pull_request,omitempty"`
}

// GitHubComment represents a GitHub issue comment
type GitHubComment struct {
	ID        int       `json:"id"`
	Body      string    `json:"body"`
	CreatedAt time.Time `json:"created_at"`
	User      struct {
		Login string `json:"login"`
	} `json:"user"`
}

// GetPlatformName returns "GitHub" to identify this platform
func (c *GitHubClient) GetPlatformName() string {
	return "GitHub"
}

// CheckIfOrganization checks if a GitHub user is an organization or personal account
// Returns (isOrg bool, orgName string)
//
// Methodology:
// - Query GitHub API: GET /users/{username}
// - Check "type" field: "Organization" or "User"
//
// API Response:
// {
//   "login": "microsoft",
//   "type": "Organization",
//   "name": "Microsoft",
//   ...
// }
func (c *GitHubClient) CheckIfOrganization(owner string) (bool, string) {
	url := fmt.Sprintf("%s/users/%s", c.baseURL, owner)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return false, ""
	}

	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return false, ""
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		// Rate limit — try scraping the profile page to detect org vs user
		if shouldFallbackToScraping(nil, resp.StatusCode) {
			return c.scrapeIsOrganization(owner)
		}
		return false, ""
	}

	var user struct {
		Login string `json:"login"`
		Type  string `json:"type"` // "User" or "Organization"
		Name  string `json:"name"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return false, ""
	}

	isOrg := user.Type == "Organization"
	orgName := user.Name
	if orgName == "" {
		orgName = user.Login
	}

	return isOrg, orgName
}

// scrapeIsOrganization checks whether a GitHub owner is an organization by
// scraping the profile page. GitHub uses different page structures for orgs
// and users (orgs show "People" tab, users show "Repositories" tab).
func (c *GitHubClient) scrapeIsOrganization(owner string) (bool, string) {
	pageURL := fmt.Sprintf("https://github.com/%s", owner)
	doc, err := scrapeWithUserAgent(pageURL)
	if err != nil {
		return false, ""
	}

	// GitHub org pages have an "org-" prefix in the body class or a "People" tab
	isOrg := false
	doc.Find("nav a[data-tab='people']").Each(func(_ int, _ *goquery.Selection) {
		isOrg = true
	})
	name := owner
	doc.Find("h1.h2.lh-condensed, span[itemprop='name']").First().Each(func(_ int, s *goquery.Selection) {
		if text := strings.TrimSpace(s.Text()); text != "" {
			name = text
		}
	})

	return isOrg, name
}

// CheckVerifiedOrganization checks if a GitHub organization has verified status
//
// Methodology:
// - Query GitHub API: GET /orgs/{org}
// - Check for "is_verified" field (requires authentication)
//
// Note: GitHub's verified organization badge requires specific API permissions
// If unavailable, this returns false (conservative approach)
func (c *GitHubClient) CheckVerifiedOrganization(owner string) bool {
	url := fmt.Sprintf("%s/orgs/%s", c.baseURL, owner)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return false
	}

	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return false
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		// Rate limit — return false (unknown, not negative signal).
		// The caller should not treat this as "not verified" risk signal.
		return false
	}

	var org struct {
		IsVerified bool `json:"is_verified"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&org); err != nil {
		return false
	}

	return org.IsVerified
}

// CheckOrgMFARequired checks if a GitHub organization enforces mandatory MFA/2FA.
//
// Check: MFA/2FA enforcement at the organization level
// Justification: Organizations without mandatory MFA allow account takeover via
//                credential stuffing - the leading cause of supply chain compromise.
//                Phishing and credential stuffing attacks become trivially easy without MFA.
// Source: "Backstabber's Knife Collection" (Ohm et al., 2020)
//         https://arxiv.org/abs/2005.09535
// Methodology: Query GET /orgs/{owner} - two_factor_requirement_enabled field.
//              This field is publicly visible for public organizations (no auth required).
//              Returns (false, false) if the owner is a user (not an org) or API unavailable.
// Result: (true, true) = MFA enforced; (false, true) = MFA not enforced; (false, false) = unknown
func (c *GitHubClient) CheckOrgMFARequired(owner string) (required bool, available bool) {
	apiURL := fmt.Sprintf("%s/orgs/%s", c.baseURL, owner)
	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return false, false
	}

	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return false, false
	}
	defer func() { _ = resp.Body.Close() }()

	// 404 = owner is a user, not an org; other non-200 = API unavailable
	if resp.StatusCode != http.StatusOK {
		return false, false
	}

	var org struct {
		TwoFactorRequirementEnabled bool `json:"two_factor_requirement_enabled"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&org); err != nil {
		return false, false
	}

	return org.TwoFactorRequirementEnabled, true
}

// GetUserAccountCreatedDate fetches the account creation date for a GitHub user
//
// Methodology:
// - Query GitHub API: GET /users/{username}
// - Extract "created_at" field
//
// Returns account creation timestamp
// Used to detect new accounts (< 6 months = suspicious, < 1 month = red flag)
func (c *GitHubClient) GetUserAccountCreatedDate(username string) (time.Time, error) {
	url := fmt.Sprintf("%s/users/%s", c.baseURL, username)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return time.Time{}, err
	}

	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return time.Time{}, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		// Rate limit — return zero time so callers degrade gracefully
		// rather than treating unavailable data as a risk signal
		if shouldFallbackToScraping(nil, resp.StatusCode) {
			return time.Time{}, nil
		}
		return time.Time{}, fmt.Errorf("GitHub API returned %d for user %s", resp.StatusCode, username)
	}

	var user struct {
		Login     string    `json:"login"`
		CreatedAt time.Time `json:"created_at"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return time.Time{}, err
	}

	return user.CreatedAt, nil
}
