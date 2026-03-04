package fetcher

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
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
// cachedIdentity stores the result of a GET /users/{owner} call so that
// CheckIfOrganization, GetUserAccountCreatedDate, etc. can share it.
type cachedIdentity struct {
	isOrg     bool
	name      string // display name or login
	createdAt time.Time
}

// cachedOrgInfo stores the result of a GET /orgs/{owner} call so that
// CheckVerifiedOrganization and CheckOrgMFARequired share a single request.
type cachedOrgInfo struct {
	isVerified  bool
	mfaRequired bool
	found       bool // false when owner is not an org (404)
}

// OrgCache is a scan-level cache for organization and identity data. It is
// shared across ALL GitHubClient instances within a single scan so that
// org-level API calls (GET /users/{owner}, GET /orgs/{owner}) are made at most
// once per owner, even when packages from the same GitHub org are analyzed by
// different workers or different GitHubClient instances.
//
// Justification: When scanning 100+ packages from orgs like aws/, apache/,
// google/, the org identity and verification status is identical for every
// package. Sharing this cache eliminates redundant API calls and reduces
// GitHub API rate limit consumption.
type OrgCache struct {
	mu       sync.RWMutex
	identity map[string]*cachedIdentity // key: owner (user/org identity)
	orgInfo  map[string]*cachedOrgInfo  // key: owner (org details)
}

// NewOrgCache creates a new thread-safe organization cache. Create one per scan
// and pass it to all GitHubClient instances via WithSharedOrgCache.
func NewOrgCache() *OrgCache {
	return &OrgCache{
		identity: make(map[string]*cachedIdentity),
		orgInfo:  make(map[string]*cachedOrgInfo),
	}
}

func (oc *OrgCache) getIdentity(key string) (*cachedIdentity, bool) {
	oc.mu.RLock()
	defer oc.mu.RUnlock()
	v, ok := oc.identity[key]
	return v, ok
}

func (oc *OrgCache) setIdentity(key string, id *cachedIdentity) {
	oc.mu.Lock()
	defer oc.mu.Unlock()
	oc.identity[key] = id
}

func (oc *OrgCache) getOrgInfo(key string) (*cachedOrgInfo, bool) {
	oc.mu.RLock()
	defer oc.mu.RUnlock()
	v, ok := oc.orgInfo[key]
	return v, ok
}

func (oc *OrgCache) setOrgInfo(key string, info *cachedOrgInfo) {
	oc.mu.Lock()
	defer oc.mu.Unlock()
	oc.orgInfo[key] = info
}

// cachedSignedCommits stores the result of CheckSignedCommits so that
// multiple packages from the same repo don't re-fetch commit signatures.
type cachedSignedCommits struct {
	hasSigning    bool
	verifiedCount int
}

// cachedIssueResponseTime stores the result of GetAverageIssueResponseTime
// so that multiple packages from the same repo share the expensive
// per-issue comment fetching.
type cachedIssueResponseTime struct {
	avgDays float64
	hasData bool // true when at least one issue had a response
}

type repoCache struct {
	mu                sync.RWMutex
	repoInfo          map[string]*models.RepositoryInfo   // key: "owner/repo"
	releases          map[string][]GitHubRelease          // key: "owner/repo"
	fileExists        map[string]bool                     // key: "owner/repo/path"
	tags              map[string][]string                 // key: "owner/repo" → all discovered tag names
	commitStats       map[string]*CommitStats             // key: "owner/repo"
	commitAuthors     map[string]*CommitAuthorStats       // key: "owner/repo"
	signedCommits     map[string]*cachedSignedCommits     // key: "owner/repo"
	prStats           map[string]*PRStats                 // key: "owner/repo"
	issueResponseTime map[string]*cachedIssueResponseTime // key: "owner/repo"
	workflowFiles     map[string][]string                 // key: "owner/repo"
	cloneData         map[string]*gitCloneData            // key: "owner/repo" — data from bare git clone
}

func newRepoCache() *repoCache {
	return &repoCache{
		repoInfo:          make(map[string]*models.RepositoryInfo),
		releases:          make(map[string][]GitHubRelease),
		fileExists:        make(map[string]bool),
		tags:              make(map[string][]string),
		commitStats:       make(map[string]*CommitStats),
		commitAuthors:     make(map[string]*CommitAuthorStats),
		signedCommits:     make(map[string]*cachedSignedCommits),
		prStats:           make(map[string]*PRStats),
		issueResponseTime: make(map[string]*cachedIssueResponseTime),
		workflowFiles:     make(map[string][]string),
		cloneData:         make(map[string]*gitCloneData),
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

func (rc *repoCache) getTagNames(key string) ([]string, bool) {
	rc.mu.RLock()
	defer rc.mu.RUnlock()
	v, ok := rc.tags[key]
	return v, ok
}

func (rc *repoCache) setTagNames(key string, names []string) {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	rc.tags[key] = names
}

func (rc *repoCache) getCommitStats(key string) (*CommitStats, bool) {
	rc.mu.RLock()
	defer rc.mu.RUnlock()
	v, ok := rc.commitStats[key]
	return v, ok
}

func (rc *repoCache) setCommitStats(key string, stats *CommitStats) {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	rc.commitStats[key] = stats
}

func (rc *repoCache) getCommitAuthors(key string) (*CommitAuthorStats, bool) {
	rc.mu.RLock()
	defer rc.mu.RUnlock()
	v, ok := rc.commitAuthors[key]
	return v, ok
}

func (rc *repoCache) setCommitAuthors(key string, stats *CommitAuthorStats) {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	rc.commitAuthors[key] = stats
}

func (rc *repoCache) getSignedCommits(key string) (*cachedSignedCommits, bool) {
	rc.mu.RLock()
	defer rc.mu.RUnlock()
	v, ok := rc.signedCommits[key]
	return v, ok
}

func (rc *repoCache) setSignedCommits(key string, sc *cachedSignedCommits) {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	rc.signedCommits[key] = sc
}

func (rc *repoCache) getPRStats(key string) (*PRStats, bool) {
	rc.mu.RLock()
	defer rc.mu.RUnlock()
	v, ok := rc.prStats[key]
	return v, ok
}

func (rc *repoCache) setPRStats(key string, stats *PRStats) {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	rc.prStats[key] = stats
}

func (rc *repoCache) getIssueResponseTime(key string) (*cachedIssueResponseTime, bool) {
	rc.mu.RLock()
	defer rc.mu.RUnlock()
	v, ok := rc.issueResponseTime[key]
	return v, ok
}

func (rc *repoCache) setIssueResponseTime(key string, irt *cachedIssueResponseTime) {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	rc.issueResponseTime[key] = irt
}

func (rc *repoCache) getWorkflowFiles(key string) ([]string, bool) {
	rc.mu.RLock()
	defer rc.mu.RUnlock()
	v, ok := rc.workflowFiles[key]
	return v, ok
}

func (rc *repoCache) setWorkflowFiles(key string, files []string) {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	rc.workflowFiles[key] = files
}

// GitHubClient handles interactions with GitHub API and web scraping.
// By default, web scraping is the primary data-fetching method, with API calls
// used to supplement when a GITHUB_TOKEN is available.
type GitHubClient struct {
	token        string
	httpClient   *http.Client
	baseURL      string
	cache        *repoCache
	orgCache     *OrgCache // scan-level shared cache for org identity/info
	preferAPI    bool      // when true, always try API first (used by test helpers with mock servers)
	rateLimiter  *GitHubRateLimiter
	scrapingOnly atomic.Bool // when true, all API calls are skipped; only web scraping is used
}

// NewGitHubClient creates a new GitHub client. Web scraping is the primary
// data-fetching method. When GITHUB_TOKEN is set, API calls supplement
// scraped data with richer metadata and higher rate limits.
// GitHubClientOption configures a GitHubClient during construction.
type GitHubClientOption func(*GitHubClient)

// WithSharedOrgCache injects a scan-level shared OrgCache into the client.
// All GitHubClient instances that share the same OrgCache will reuse org-level
// API results (identity, org info) instead of making duplicate requests.
func WithSharedOrgCache(oc *OrgCache) GitHubClientOption {
	return func(c *GitHubClient) {
		c.orgCache = oc
	}
}

func NewGitHubClient(opts ...GitHubClientOption) *GitHubClient {
	token := os.Getenv("GITHUB_TOKEN")
	c := &GitHubClient{
		token: token,
		httpClient: &http.Client{
			// 10s timeout keeps failures fast — both API rate-limit
			// responses and slow scraping targets are bounded.
			Timeout: 10 * time.Second,
		},
		baseURL:     "https://api.github.com",
		cache:       newRepoCache(),
		orgCache:    NewOrgCache(), // default: per-client cache; override with WithSharedOrgCache
		rateLimiter: NewGitHubRateLimiter(token != ""),
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// NewGitHubClientWithBaseURL creates a GitHubClient pointing at a custom API base URL.
// This is primarily used for testing with httptest servers. The client uses
// API-first mode since mock servers don't support web scraping.
// No rate limiter is configured since mock servers are not rate-limited.
func NewGitHubClientWithBaseURL(baseURL string) *GitHubClient {
	return &GitHubClient{
		httpClient: &http.Client{Timeout: 10 * time.Second},
		baseURL:    baseURL,
		cache:      newRepoCache(),
		orgCache:   NewOrgCache(),
		preferAPI:  true,
	}
}

// RateLimitRemaining returns the last observed GitHub API rate limit remaining count.
// Returns -1 if no rate limit header has been received yet.
func (c *GitHubClient) RateLimitRemaining() int {
	if c.rateLimiter == nil {
		return -1
	}
	return c.rateLimiter.Remaining()
}

// ShouldFallbackToScraping returns true when the GitHub API quota is below the
// given threshold, indicating the scan should switch to scraping-only mode for
// remaining packages. The scan never stops — it continues with web scraping.
func (c *GitHubClient) ShouldFallbackToScraping(threshold int) bool {
	if c.rateLimiter == nil {
		return false
	}
	return c.rateLimiter.ShouldFallbackToScraping(threshold)
}

// SetScrapingOnlyMode enables or disables scraping-only mode. When enabled,
// all GitHub API calls are skipped and only web scraping is used for data
// collection. This is activated when the rate limit gate triggers, allowing
// remaining packages to be analyzed with reduced fidelity rather than being
// skipped entirely.
func (c *GitHubClient) SetScrapingOnlyMode(enabled bool) {
	c.scrapingOnly.Store(enabled)
}

// IsScrapingOnly returns true when the client is in scraping-only mode.
func (c *GitHubClient) IsScrapingOnly() bool {
	return c.scrapingOnly.Load()
}

// shouldPreferScraping returns true when web scraping should be the primary
// data fetching method. Scraping is always preferred for real GitHub requests
// to minimize API consumption. API calls are reserved as a fallback when
// scraping fails, and for checks that genuinely cannot be scraped (signed
// commits verification, attestations/provenance, branch protection).
//
// Returns false only for:
//   - Test servers (preferAPI flag set) — mock handlers must be exercised
//   - Custom base URLs — scraping targets real github.com
func (c *GitHubClient) shouldPreferScraping() bool {
	if c.preferAPI {
		return false // test servers always use API
	}
	if c.baseURL != "https://api.github.com" {
		return false // custom base URLs use API (scraping targets real github.com)
	}
	return true // always prefer scraping for real GitHub
}

// errScrapingOnly is returned by doRequest when the client is in scraping-only
// mode, preventing any GitHub API calls from being made.
var errScrapingOnly = fmt.Errorf("scraping-only mode: API calls disabled to preserve rate limit")

// doRequest executes an HTTP request with proactive rate limiting for GitHub
// API calls. It waits for the rate limiter to permit the request, executes it,
// then updates the limiter based on GitHub's X-RateLimit-* response headers.
//
// When scraping-only mode is enabled, doRequest returns errScrapingOnly without
// making any network call. Methods that call doRequest will then fall through
// to their scraping fallbacks or return gracefully degraded results.
//
// Use this for all requests to c.baseURL (the GitHub API). Do NOT use for
// requests to raw.githubusercontent.com or github.com web pages, as those
// have separate (or no) rate limits.
func (c *GitHubClient) doRequest(req *http.Request) (*http.Response, error) {
	if c.scrapingOnly.Load() {
		return nil, errScrapingOnly
	}
	if c.rateLimiter != nil {
		c.rateLimiter.Wait()
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	if c.rateLimiter != nil {
		c.rateLimiter.Update(resp)
	}
	return resp, nil
}

// GetRepositoryInfo fetches repository information from GitHub.
// Web scraping is always tried first to minimize API consumption. The API is
// used as a fallback when scraping fails, providing richer data (exact dates,
// issue counts, license, topics). GraphQL batch calls are only made when
// scraping fails and a token is available.
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

	// Scraping-first path: always try web scraping first to minimize API usage.
	// API calls are reserved for data that cannot be scraped (signed commits,
	// branch protection, provenance).
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

	// GraphQL batch path: fallback when scraping fails. Fetches repo info +
	// releases + governance files + branch protection in a single API call.
	// Results are cached so subsequent callers get cache hits.
	if c.token != "" && !c.preferAPI {
		batch := c.fetchBatchRepoData(owner, repo)
		if batch != nil && batch.RepoInfo != nil {
			return batch.RepoInfo, nil
		}
		// GraphQL failed — fall through to REST API
	}

	// REST API path: fallback when both scraping and GraphQL fail.
	url := fmt.Sprintf("%s/repos/%s/%s", c.baseURL, owner, repo)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := c.doRequest(req)
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
// This is the primary data source for all GitHub requests.
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


// DetectCISystems checks for common CI/CD systems in the repository.
// Uses bare git clone file tree when available (fastest, no network calls).
// Falls back to Git Trees API call, then individual fileExists checks.
func (c *GitHubClient) DetectCISystems(repoURL string) ([]string, error) {
	owner, repo, err := parseGitHubURL(repoURL)
	if err != nil {
		return nil, err
	}

	// Clone-first path: use cached clone file tree if available
	if treePaths, ok := c.getFileTreeFromClone(owner, repo); ok {
		return c.detectCIFromTree(treePaths), nil
	}

	// Try the efficient tree-based API approach.
	if ciSystems, ok := c.detectCIViaTree(owner, repo); ok {
		return ciSystems, nil
	}

	// Fallback: individual fileExists checks (original behavior).
	return c.detectCIViaFileExists(owner, repo), nil
}

// detectCIFromTree detects CI systems from a file tree (either from clone or API).
func (c *GitHubClient) detectCIFromTree(treePaths map[string]bool) []string {
	var ciSystems []string
	detected := make(map[string]bool)

	for _, entry := range ExtendedCIConfigFiles() {
		if detected[entry.Name] {
			continue
		}
		if treePaths[entry.Path] {
			detected[entry.Name] = true
			ciSystems = append(ciSystems, entry.Name)
			continue
		}
		if c.treeHasPrefix(treePaths, entry.Path) {
			detected[entry.Name] = true
			ciSystems = append(ciSystems, entry.Name)
		}
	}

	return ciSystems
}

// detectCIViaTree fetches the repo's full file tree in a single API call and
// matches CI config paths against it. Returns (results, true) on success, or
// (nil, false) if the tree API is unavailable (no token, API error, etc.).
// When the tree is truncated (large repos), files not found in the partial tree
// are verified via individual fileExists() calls to avoid false negatives.
func (c *GitHubClient) detectCIViaTree(owner, repo string) ([]string, bool) {
	treePaths, truncated, ok := c.getRepoTree(owner, repo)
	if !ok {
		return nil, false
	}

	var ciSystems []string
	detected := make(map[string]bool)

	for _, entry := range ExtendedCIConfigFiles() {
		if detected[entry.Name] {
			continue
		}
		// Check exact match first (files like ".travis.yml").
		if treePaths[entry.Path] {
			detected[entry.Name] = true
			ciSystems = append(ciSystems, entry.Name)
			continue
		}
		// Check if entry.Path is a directory by looking for any tree path
		// that has it as a prefix (e.g. ".github/workflows" matches
		// ".github/workflows/ci.yml" in the tree).
		if c.treeHasPrefix(treePaths, entry.Path) {
			detected[entry.Name] = true
			ciSystems = append(ciSystems, entry.Name)
			continue
		}
		// When the tree is truncated, files may be missing from the
		// results. Fall back to individual fileExists() checks for any
		// CI config not found in the partial tree.
		if truncated && c.fileExists(owner, repo, entry.Path) {
			detected[entry.Name] = true
			ciSystems = append(ciSystems, entry.Name)
		}
	}

	return ciSystems, true
}

// treeHasPrefix checks if any path in the tree starts with the given prefix
// followed by a "/". This detects directory entries like ".github/workflows".
func (c *GitHubClient) treeHasPrefix(treePaths map[string]bool, prefix string) bool {
	dirPrefix := prefix + "/"
	for p := range treePaths {
		if strings.HasPrefix(p, dirPrefix) {
			return true
		}
	}
	return false
}

// detectCIViaFileExists is the original per-file detection approach, used as
// fallback when the tree API is unavailable.
func (c *GitHubClient) detectCIViaFileExists(owner, repo string) []string {
	var ciSystems []string
	detected := make(map[string]bool)

	for _, entry := range ExtendedCIConfigFiles() {
		if detected[entry.Name] {
			continue
		}
		if c.fileExists(owner, repo, entry.Path) {
			detected[entry.Name] = true
			ciSystems = append(ciSystems, entry.Name)
		}
	}

	return ciSystems
}

// getRepoTree fetches the full recursive file tree for a repository using the
// Git Trees API (GET /repos/{owner}/{repo}/git/trees/{branch}?recursive=1).
// Returns a set of file paths, whether the tree was truncated, and true on
// success. Returns (nil, false, false) on failure. When the tree is truncated
// (repos with 100k+ entries), the paths set may be incomplete — callers must
// verify missing entries via individual API calls.
// When scraping is preferred (no token), this is skipped since the Git Trees
// API requires authentication for useful results on large repos.
func (c *GitHubClient) getRepoTree(owner, repo string) (map[string]bool, bool, bool) {
	// Clone-first path: use cached clone file tree if available (complete, never truncated)
	if treePaths, ok := c.getFileTreeFromClone(owner, repo); ok {
		return treePaths, false, true
	}

	if c.shouldPreferScraping() {
		return nil, false, false
	}

	branches := c.defaultBranchCandidates(owner, repo)
	for _, branch := range branches {
		url := fmt.Sprintf("%s/repos/%s/%s/git/trees/%s?recursive=1", c.baseURL, owner, repo, branch)
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			continue
		}
		if c.token != "" {
			req.Header.Set("Authorization", "Bearer "+c.token)
		}

		resp, err := c.doRequest(req)
		if err != nil {
			continue
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusOK {
			continue
		}

		var treeResp struct {
			Tree []struct {
				Path string `json:"path"`
				Type string `json:"type"`
			} `json:"tree"`
			Truncated bool `json:"truncated"`
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			continue
		}
		if err := json.Unmarshal(body, &treeResp); err != nil {
			continue
		}

		paths := make(map[string]bool, len(treeResp.Tree))
		for _, entry := range treeResp.Tree {
			paths[entry.Path] = true
		}

		// Populate the fileExists cache so other callers benefit.
		// When truncated, only cache files that were found (true). Files
		// absent from a truncated tree may still exist — do not cache false.
		if c.cache != nil {
			for _, ciFile := range ExtendedCIConfigFiles() {
				if paths[ciFile.Path] || !treeResp.Truncated {
					cacheKey := owner + "/" + repo + "/" + ciFile.Path
					c.cache.setFileExists(cacheKey, paths[ciFile.Path])
				}
			}
		}

		return paths, treeResp.Truncated, true
	}

	return nil, false, false
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
// Uses bare git clone data when available, falling back to API.
func (c *GitHubClient) GetCommitActivity(repoURL string, since time.Time) ([]GitHubCommit, error) {
	owner, repo, err := parseGitHubURL(repoURL)
	if err != nil {
		return nil, err
	}

	// Clone-first path: use cached clone data if available (no API call needed)
	if commits, ok := c.getCommitActivityFromClone(owner, repo, since); ok {
		return commits, nil
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

	resp, err := c.doRequest(req)
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
// When direct lookups fail, falls back to paginated tag search to handle repos
// with non-standard tag naming (e.g. "jackson-modules-java8-2.15.3").
// Returns true if the tag exists, along with the tag URL.
func (c *GitHubClient) CheckGitTag(repoURL, version string) (bool, string, error) {
	owner, repo, err := parseGitHubURL(repoURL)
	if err != nil {
		return false, "", err
	}

	// Try common version tag formats: v1.2.3, 1.2.3, release-1.2.3, repo-1.2.3.
	// The repo-prefixed variants handle projects like Jackson that use
	// "jackson-modules-java8-2.15.3" style tags.
	tagVariants := []string{
		version,
		"v" + version,
		"V" + version,
		"release-" + version,
		"Release-" + version,
		repo + "-" + version,
		repo + "-v" + version,
	}

	// Scraping-first path: check the GitHub web page for each tag variant,
	// then try scraping the tags listing page for non-standard naming.
	// HEAD requests to github.com are served by the web frontend, not the API,
	// and are not subject to API rate limits.
	if c.shouldPreferScraping() {
		for _, tag := range tagVariants {
			tagURL := fmt.Sprintf("https://github.com/%s/%s/releases/tag/%s", owner, repo, tag)
			if c.checkTagViaWeb(tagURL) {
				return true, tagURL, nil
			}
		}
		// Direct tag lookups didn't find a release page — the tag may exist
		// as a lightweight tag or use non-standard naming. Search the tags
		// listing page (scraped, not API) before falling through to API.
		if found, tagURL := c.searchTagsPaginated(owner, repo, version); found {
			return true, tagURL, nil
		}
		// Scraping exhausted — fall through to API as last resort.
	}

	// API path: fallback when scraping didn't find the tag.
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

		resp, err := c.doRequest(req)
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
		// Also try the scraping-based tag search for non-standard naming.
		if found, tagURL := c.searchTagsPaginated(owner, repo, version); found {
			return true, tagURL, nil
		}
	}

	// Paginated fallback: when direct lookups fail (non-standard tag naming),
	// search through the tags listing. searchTagsPaginated uses scraping when
	// shouldPreferScraping() and API otherwise, with scraping fallback on rate limit.
	if !rateLimited && !c.shouldPreferScraping() {
		if found, tagURL := c.searchTagsPaginated(owner, repo, version); found {
			return true, tagURL, nil
		}
	}

	// Graceful degradation: when rate-limited and scraping didn't find the tag,
	// return (false, "", nil) — "could not confirm tag" — rather than an error.
	// The caller treats nil error + false as "tag not found" which is the safest
	// interpretation: the provenance scorer already handles missing tags.
	return false, "", nil
}

// maxTagSearchPages is the upper bound on pages fetched during paginated tag
// search. At 100 tags per page, this covers repos with up to 300 tags while
// keeping API overhead bounded. Most repos have matching tags within the first
// few hundred entries; 3 pages strikes a good balance between coverage and cost.
const maxTagSearchPages = 3

// fetchTagNamesViaGitLsRemote retrieves ALL tag names from a GitHub repository
// using `git ls-remote --tags`. This uses the git smart HTTP protocol which is
// NOT subject to GitHub API rate limits. A single HTTPS round-trip returns all
// tags regardless of count, solving the pagination limit problem for repos with
// 1000+ tags (e.g. FasterXML/jackson-*).
// Results are cached per owner/repo for subsequent calls.
func (c *GitHubClient) fetchTagNamesViaGitLsRemote(owner, repo string) ([]string, error) {
	cacheKey := owner + "/" + repo
	if c.cache != nil {
		if cached, ok := c.cache.getTagNames(cacheKey); ok {
			return cached, nil
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	repoURL := fmt.Sprintf("https://github.com/%s/%s.git", owner, repo)
	cmd := exec.CommandContext(ctx, "git", "ls-remote", "--tags", "--refs", repoURL)
	// Suppress git credential prompts — if the repo doesn't exist or is
	// private, we want a fast failure rather than a blocking prompt.
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git ls-remote failed: %w", err)
	}

	tagNames := parseGitLsRemoteOutput(output)

	if c.cache != nil {
		c.cache.setTagNames(cacheKey, tagNames)
	}

	return tagNames, nil
}

// parseGitLsRemoteOutput parses the output of `git ls-remote --tags --refs`
// and returns a list of tag names (without the refs/tags/ prefix).
// Each line has the format: "<sha>\trefs/tags/<tagname>"
func parseGitLsRemoteOutput(output []byte) []string {
	var tagNames []string
	for _, line := range strings.Split(string(output), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "\t", 2)
		if len(parts) != 2 {
			continue
		}
		ref := parts[1]
		if !strings.HasPrefix(ref, "refs/tags/") {
			continue
		}
		tagName := strings.TrimPrefix(ref, "refs/tags/")
		if tagName != "" {
			tagNames = append(tagNames, tagName)
		}
	}
	return tagNames
}

// searchTagsPaginated searches through GitHub tags for any tag ending with the
// target version string. This handles repos with non-standard tag naming where
// the version appears as a suffix (e.g. "module-name-2.15.3").
// Tries methods in order of preference:
//  1. git ls-remote --tags (single HTTPS call, ALL tags, 0 API quota)
//  2. Web scraping the tags page (no API quota, but limited by pagination)
//  3. GitHub Tags API (uses API quota, limited by pagination)
//
// Results are cached per owner/repo so that multiple dependencies from the same
// repository resolve instantly without repeating network calls.
func (c *GitHubClient) searchTagsPaginated(owner, repo, version string) (bool, string) {
	// Build version suffixes to match against — a tag like "foo-2.15.3" or "foo-v2.15.3"
	versionSuffixes := []string{
		"-" + version,
		"-v" + version,
		"_" + version,
		"_v" + version,
		"/" + version,
		"/v" + version,
	}

	cacheKey := owner + "/" + repo

	// Check cache first — a previous CheckGitTag call for the same repo may
	// have already fetched and stored all discovered tag names.
	if c.cache != nil {
		if cached, ok := c.cache.getTagNames(cacheKey); ok {
			return matchTagVersion(cached, versionSuffixes, owner, repo)
		}
	}

	// git ls-remote path: single HTTPS call returns ALL tags using the git
	// smart HTTP protocol. Not subject to GitHub API rate limits and has no
	// pagination limits, so it handles repos with 1000+ tags (e.g. FasterXML).
	// Only used for real GitHub — test servers use custom base URLs.
	if c.baseURL == "https://api.github.com" {
		if tags, err := c.fetchTagNamesViaGitLsRemote(owner, repo); err == nil && len(tags) > 0 {
			return matchTagVersion(tags, versionSuffixes, owner, repo)
		}
		// git ls-remote failed (git not installed, network error, etc.) —
		// fall through to scraping/API.
	}

	// Scraping-first path: scrape the tags page to avoid API rate limits.
	if c.shouldPreferScraping() {
		if scraped, err := c.scrapeTagNames(owner, repo); err == nil {
			return matchTagVersion(scraped, versionSuffixes, owner, repo)
		}
		// Scraping failed — fall through to try the API
	}

	// API path: fallback when scraping fails.
	allTagNames := c.fetchTagNamesViaAPI(owner, repo)

	// If API returned nothing (rate limited or error) and we haven't scraped yet, try scraping.
	if len(allTagNames) == 0 && !c.shouldPreferScraping() {
		if scraped, err := c.scrapeTagNames(owner, repo); err == nil && len(scraped) > 0 {
			return matchTagVersion(scraped, versionSuffixes, owner, repo)
		}
	}

	// Cache all discovered tags so subsequent calls for the same repo skip API/scraping.
	if c.cache != nil {
		c.cache.setTagNames(cacheKey, allTagNames)
	}

	return matchTagVersion(allTagNames, versionSuffixes, owner, repo)
}

// matchTagVersion searches a list of tag names for any matching the version suffixes.
func matchTagVersion(tagNames, versionSuffixes []string, owner, repo string) (bool, string) {
	for _, name := range tagNames {
		for _, suffix := range versionSuffixes {
			if strings.HasSuffix(name, suffix) {
				tagURL := fmt.Sprintf("https://github.com/%s/%s/releases/tag/%s", owner, repo, name)
				return true, tagURL
			}
		}
	}
	return false, ""
}

// fetchTagNamesViaAPI paginates through the GitHub tags API collecting tag names.
// Returns the collected names (may be empty on rate limit or error).
func (c *GitHubClient) fetchTagNamesViaAPI(owner, repo string) []string {
	var allTagNames []string
	nextURL := fmt.Sprintf("%s/repos/%s/%s/tags?per_page=100", c.baseURL, owner, repo)

	for page := 0; page < maxTagSearchPages && nextURL != ""; page++ {
		req, err := http.NewRequest("GET", nextURL, nil)
		if err != nil {
			break
		}

		if c.token != "" {
			req.Header.Set("Authorization", "Bearer "+c.token)
		}
		req.Header.Set("Accept", "application/vnd.github.v3+json")

		resp, err := c.doRequest(req)
		if err != nil {
			break
		}

		if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests {
			_ = resp.Body.Close()
			break // Rate limited — stop searching.
		}

		if resp.StatusCode != http.StatusOK {
			_ = resp.Body.Close()
			break
		}

		var tags []struct {
			Name string `json:"name"`
		}
		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			break
		}
		if err := json.Unmarshal(body, &tags); err != nil {
			break
		}

		for _, tag := range tags {
			allTagNames = append(allTagNames, tag.Name)
		}

		if len(tags) == 0 {
			break
		}

		nextURL = parseLinkHeaderNextURL(resp.Header.Get("Link"))
	}

	// Cache all discovered tags.
	cacheKey := owner + "/" + repo
	if c.cache != nil {
		c.cache.setTagNames(cacheKey, allTagNames)
	}

	return allTagNames
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

// scrapeTagNames scrapes tag names from the GitHub tags page. This avoids
// the paginated tags API (up to 3 API calls per repo) by fetching tag names
// from the web frontend, which is not subject to API rate limits.
// Results are cached per owner/repo so subsequent CheckGitTag calls for
// different versions of the same repo resolve without network calls.
func (c *GitHubClient) scrapeTagNames(owner, repo string) ([]string, error) {
	cacheKey := owner + "/" + repo

	// Return cached tags if available.
	if c.cache != nil {
		if cached, ok := c.cache.getTagNames(cacheKey); ok {
			return cached, nil
		}
	}

	var allTags []string
	nextPageURL := fmt.Sprintf("https://github.com/%s/%s/tags", owner, repo)
	tagPrefix := fmt.Sprintf("/%s/%s/releases/tag/", owner, repo)

	for page := 0; page < maxTagSearchPages && nextPageURL != ""; page++ {
		doc, err := scrapeWithUserAgent(nextPageURL)
		if err != nil {
			if page == 0 {
				return nil, fmt.Errorf("scraping tags page failed: %w", err)
			}
			break // Return what we have so far
		}

		pageHadTags := false

		// GitHub tags page lists each tag as a link to /releases/tag/{name}.
		doc.Find("a[href*='/releases/tag/']").Each(func(_ int, a *goquery.Selection) {
			href, exists := a.Attr("href")
			if !exists {
				return
			}
			// Extract tag name from href like /{owner}/{repo}/releases/tag/{tagname}
			idx := strings.Index(href, tagPrefix)
			if idx < 0 {
				return
			}
			tagName := href[idx+len(tagPrefix):]
			if tagName != "" {
				allTags = append(allTags, tagName)
				pageHadTags = true
			}
		})

		// Look for the "Next" pagination link
		nextPageURL = ""
		doc.Find("a.next_page, a[rel='next']").Each(func(_ int, a *goquery.Selection) {
			if href, exists := a.Attr("href"); exists && href != "" {
				if strings.HasPrefix(href, "/") {
					nextPageURL = "https://github.com" + href
				} else if strings.HasPrefix(href, "http") {
					nextPageURL = href
				}
			}
		})

		if !pageHadTags {
			break
		}
	}

	// Cache all discovered tags.
	if c.cache != nil {
		c.cache.setTagNames(cacheKey, allTags)
	}

	return allTags, nil
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

	// Clone-first path: use cached clone file tree if available (no network call)
	if exists, ok := c.fileExistsInClone(owner, repo, path); ok {
		if c.cache != nil {
			c.cache.setFileExists(cacheKey, exists)
		}
		return exists
	}

	// Raw-URL-first path: always try raw.githubusercontent.com first (CDN,
	// not subject to API rate limits). This avoids burning API calls for
	// simple file existence checks on public repos.
	if c.checkFileViaRawURL(owner, repo, path) {
		if c.cache != nil {
			c.cache.setFileExists(cacheKey, true)
		}
		return true
	}

	// API fallback: raw URL didn't confirm the file. Try the API which is
	// more reliable (handles private repos, correct branch resolution).
	url := fmt.Sprintf("%s/repos/%s/%s/contents/%s", c.baseURL, owner, repo, path)
	req, err := http.NewRequest("HEAD", url, nil)
	if err != nil {
		return false
	}

	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.doRequest(req)
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

	// Rate-limited: do NOT cache false — the file may exist but the API
	// refused to answer. A cached false here would poison subsequent checks.
	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests {
		return false
	}

	// File genuinely not found (404) or other client error — safe to cache.
	if c.cache != nil {
		c.cache.setFileExists(cacheKey, false)
	}
	return false
}

// checkFileViaRawURL checks if a file exists by issuing a HEAD request to
// raw.githubusercontent.com, which is served by a CDN and is not subject to
// the GitHub API rate limit. This is the primary file existence check;
// the API is used as a fallback when this returns false.
//
// When GetRepositoryInfo has already been called (which caches DefaultBranch),
// we use the known branch name to avoid a redundant HEAD request.
func (c *GitHubClient) checkFileViaRawURL(owner, repo, path string) bool {
	branches := c.defaultBranchCandidates(owner, repo)
	for _, branch := range branches {
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

// defaultBranchCandidates returns the branch names to try for raw URL checks.
// If we already have the default branch cached from GetRepositoryInfo, return
// just that branch (saving a redundant HEAD request). Otherwise fall back to
// trying both "main" and "master".
func (c *GitHubClient) defaultBranchCandidates(owner, repo string) []string {
	if c.cache != nil {
		cacheKey := owner + "/" + repo
		if info, ok := c.cache.getRepoInfo(cacheKey); ok && info.DefaultBranch != "" {
			return []string{info.DefaultBranch}
		}
	}
	return []string{"main", "master"}
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
// Web scraping is always tried first. The API is used as a fallback when
// scraping fails, providing richer release data (assets, draft status).
func (c *GitHubClient) getReleases(owner, repo string) ([]GitHubRelease, error) {
	// Cache releases — called from provenance checks (checkSignedReleases).
	// A cache hit eliminates redundant network calls.
	cacheKey := owner + "/" + repo
	if c.cache != nil {
		if cached, ok := c.cache.getCachedReleases(cacheKey); ok {
			return cached, nil
		}
	}

	// Scraping-first path: always try scraping the releases page first.
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

	// API path: fallback when scraping fails.
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

		resp, err := c.doRequest(req)
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
// This is the primary release data source for all GitHub requests.
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
// Uses bare git clone data when available (fastest, no network call).
// Falls back to raw.githubusercontent.com (CDN), then the API.
func (c *GitHubClient) GetFileContent(repoURL, filePath string) (string, error) {
	owner, repo, err := parseGitHubURL(repoURL)
	if err != nil {
		return "", err
	}

	// Clone-first path: use cached clone data if available (no network call)
	if content, cloneErr := c.GetCloneFileContent(owner, repo, filePath); cloneErr == nil {
		return content, nil
	}

	// Raw-URL-first path: always use CDN (not subject to API rate limits).
	if c.shouldPreferScraping() {
		content, rawErr := c.getFileContentViaRawURL(owner, repo, filePath)
		if rawErr == nil {
			return content, nil
		}
		// Raw URL failed — fall through to try the API
	}

	// API path: fallback when raw URL fails.
	url := fmt.Sprintf("%s/repos/%s/%s/contents/%s", c.baseURL, owner, repo, filePath)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}

	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	req.Header.Set("Accept", "application/vnd.github.v3.raw")

	resp, err := c.doRequest(req)
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
// Uses the cached default branch when available, otherwise tries main and master.
func (c *GitHubClient) getFileContentViaRawURL(owner, repo, path string) (string, error) {
	for _, branch := range c.defaultBranchCandidates(owner, repo) {
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

// GetCommitAuthors analyzes commit authorship patterns for ownership change detection.
// Results are cached per owner/repo so multiple packages from the same repository
// share a single set of API calls (up to 3 pages of commits).
func (c *GitHubClient) GetCommitAuthors(repoURL string) (*CommitAuthorStats, error) {
	owner, repo, err := parseGitHubURL(repoURL)
	if err != nil {
		return nil, err
	}

	cacheKey := owner + "/" + repo
	if c.cache != nil {
		if cached, ok := c.cache.getCommitAuthors(cacheKey); ok {
			return cached, nil
		}
	}

	// Clone-first path: use cached clone data if available (no API call needed)
	if authors, ok := c.getCommitAuthorsFromClone(owner, repo); ok {
		if c.cache != nil {
			c.cache.setCommitAuthors(cacheKey, authors)
		}
		return authors, nil
	}

	// Scraping-first path: always try scraping contributor data first to
	// minimize API usage.
	if c.shouldPreferScraping() {
		stats, scrapeErr := c.scrapeCommitAuthors(owner, repo)
		if scrapeErr == nil {
			if c.cache != nil {
				c.cache.setCommitAuthors(cacheKey, stats)
			}
			return stats, nil
		}
		// Scraping failed — fall through to try the API
	}

	// Fetch recent commits (up to 300) to determine contributor diversity
	url := fmt.Sprintf("%s/repos/%s/%s/commits?per_page=100", c.baseURL, owner, repo)

	stats := &CommitAuthorStats{
		AuthorCommitCounts: make(map[string]int),
		AuthorFirstCommit:  make(map[string]time.Time),
		AuthorLastCommit:   make(map[string]time.Time),
		RecentAuthors:      []string{},
		HistoricalAuthors:  []string{},
	}

	// Fetch up to 3 pages (300 commits) — sufficient for bus factor / unique committer count
	for page := 1; page <= 3; page++ {
		pageURL := fmt.Sprintf("%s&page=%d", url, page)
		req, err := http.NewRequest("GET", pageURL, nil)
		if err != nil {
			return nil, err
		}

		if c.token != "" {
			req.Header.Set("Authorization", "Bearer "+c.token)
		}
		req.Header.Set("Accept", "application/vnd.github.v3+json")

		resp, err := c.doRequest(req)
		if err != nil {
			if page == 1 {
				// Network error on first page — try scraping if we haven't already
				if !c.shouldPreferScraping() {
					if scraped, scrapeErr := c.scrapeCommitAuthors(owner, repo); scrapeErr == nil {
						if c.cache != nil {
							c.cache.setCommitAuthors(cacheKey, scraped)
						}
						return scraped, nil
					}
				}
				return nil, err
			}
			break
		}

		if resp.StatusCode != http.StatusOK {
			_ = resp.Body.Close()
			if page == 1 {
				// Rate limit on first page — try scraping fallback
				if shouldFallbackToScraping(nil, resp.StatusCode) && !c.shouldPreferScraping() {
					if scraped, scrapeErr := c.scrapeCommitAuthors(owner, repo); scrapeErr == nil {
						if c.cache != nil {
							c.cache.setCommitAuthors(cacheKey, scraped)
						}
						return scraped, nil
					}
					return nil, fmt.Errorf("%w: GitHub API returned %d for commit authors", ErrRateLimited, resp.StatusCode)
				}
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

	if c.cache != nil {
		c.cache.setCommitAuthors(cacheKey, stats)
	}
	return stats, nil
}

// scrapeCommitAuthors scrapes the contributors page to build approximate
// CommitAuthorStats when the API is rate-limited. The scraped data includes
// contributor usernames from the repo page sidebar and an approximate total
// contributor count. This provides enough data to calculate bus factor and
// detect single-maintainer packages, though without exact commit timestamps
// (all authors are treated as "historical" since we can't determine recency).
func (c *GitHubClient) scrapeCommitAuthors(owner, repo string) (*CommitAuthorStats, error) {
	pageURL := fmt.Sprintf("https://github.com/%s/%s", owner, repo)
	doc, err := scrapeWithUserAgent(pageURL)
	if err != nil {
		return nil, fmt.Errorf("scraping commit authors fallback failed: %w", err)
	}

	stats := &CommitAuthorStats{
		AuthorCommitCounts: make(map[string]int),
		AuthorFirstCommit:  make(map[string]time.Time),
		AuthorLastCommit:   make(map[string]time.Time),
		RecentAuthors:      []string{},
		HistoricalAuthors:  []string{},
	}

	// Extract individual contributor usernames from the sidebar
	doc.Find("a[data-hovercard-type='user']").Each(func(i int, s *goquery.Selection) {
		if href, exists := s.Attr("href"); exists {
			username := strings.TrimPrefix(href, "/")
			if username != "" && !strings.Contains(username, "/") {
				if _, seen := stats.AuthorCommitCounts[username]; !seen {
					stats.AuthorCommitCounts[username] = 1
					stats.UniqueAuthors = append(stats.UniqueAuthors, username)
					// Without API data, we can't determine recency — treat all as historical
					stats.HistoricalAuthors = append(stats.HistoricalAuthors, username)
				}
			}
		}
	})

	// Extract total contributor count from the contributors link
	totalContributors := 0
	doc.Find("a[href*='/graphs/contributors'] span, a[href*='/contributors'] span").Each(func(i int, s *goquery.Selection) {
		text := strings.TrimSpace(s.Text())
		num := extractNumber(text)
		if num > 0 {
			totalContributors = num
		}
	})

	// If total contributor count exceeds visible sidebar avatars, pad with
	// synthetic authors to preserve accurate bus factor calculation.
	if totalContributors > len(stats.AuthorCommitCounts) {
		for i := len(stats.AuthorCommitCounts); i < totalContributors; i++ {
			authorID := fmt.Sprintf("contributor-%d", i)
			stats.AuthorCommitCounts[authorID] = 1
			stats.UniqueAuthors = append(stats.UniqueAuthors, authorID)
			stats.HistoricalAuthors = append(stats.HistoricalAuthors, authorID)
		}
	}

	for _, count := range stats.AuthorCommitCounts {
		stats.TotalCommits += count
	}

	return stats, nil
}

// CheckSignedCommits checks if recent commits in the repository are GPG signed.
// Returns (false, 0, nil) when rate-limited — cannot verify signatures without API.
// Results are cached per owner/repo so multiple packages from the same repository
// share a single API call.
func (c *GitHubClient) CheckSignedCommits(repoURL string) (bool, int, error) {
	owner, repo, err := parseGitHubURL(repoURL)
	if err != nil {
		return false, 0, err
	}

	cacheKey := owner + "/" + repo
	if c.cache != nil {
		if cached, ok := c.cache.getSignedCommits(cacheKey); ok {
			return cached.hasSigning, cached.verifiedCount, nil
		}
	}

	// Clone-first path: use cached clone data if available (no API call needed)
	if hasSigning, verifiedCount, ok := c.getSignedCommitsFromClone(owner, repo); ok {
		if c.cache != nil {
			c.cache.setSignedCommits(cacheKey, &cachedSignedCommits{
				hasSigning:    hasSigning,
				verifiedCount: verifiedCount,
			})
		}
		return hasSigning, verifiedCount, nil
	}

	// Get recent commits (last 100)
	url := fmt.Sprintf("%s/repos/%s/%s/commits?per_page=100", c.baseURL, owner, repo)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return false, 0, err
	}

	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := c.doRequest(req)
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

	if c.cache != nil {
		c.cache.setSignedCommits(cacheKey, &cachedSignedCommits{
			hasSigning:    hasSigning,
			verifiedCount: verifiedCount,
		})
	}
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
	TotalPRs       int
	MergedPRs      int
	PRsWithReviews int
	CodeReviewRate float64 // Percentage of PRs with reviews
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
// Web scraping is always tried first. The API provides per-commit author data
// for more accurate analysis and is used as a fallback when scraping fails.
// Results are cached per owner/repo so multiple packages from the same repository
// share a single set of API calls.
func (c *GitHubClient) GetCommitStats(repoURL string) (*CommitStats, error) {
	owner, repo, err := parseGitHubURL(repoURL)
	if err != nil {
		return nil, err
	}

	cacheKey := owner + "/" + repo
	if c.cache != nil {
		if cached, ok := c.cache.getCommitStats(cacheKey); ok {
			return cached, nil
		}
	}

	// Clone-first path: derive CommitStats from clone commit author data (no API call needed)
	if stats, ok := c.getCommitStatsFromClone(owner, repo); ok {
		if c.cache != nil {
			c.cache.setCommitStats(cacheKey, stats)
		}
		return stats, nil
	}

	// Scraping-first path: always try scraping contributor data first.
	if c.shouldPreferScraping() {
		stats, scrapeErr := c.scrapeCommitStats(owner, repo)
		if scrapeErr == nil {
			if c.cache != nil {
				c.cache.setCommitStats(cacheKey, stats)
			}
			return stats, nil
		}
		// Scraping failed — fall through to try the API
	}

	// API path: fallback when scraping fails.
	url := fmt.Sprintf("%s/repos/%s/%s/commits?per_page=100", c.baseURL, owner, repo)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := c.doRequest(req)
	if err != nil {
		// Network error — try scraping if we haven't already
		if !c.shouldPreferScraping() {
			stats, scrapeErr := c.scrapeCommitStats(owner, repo)
			if scrapeErr == nil && c.cache != nil {
				c.cache.setCommitStats(cacheKey, stats)
			}
			return stats, scrapeErr
		}
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		// Rate limit or auth errors — try scraping if we haven't already
		if !c.shouldPreferScraping() && shouldFallbackToScraping(nil, resp.StatusCode) {
			stats, scrapeErr := c.scrapeCommitStats(owner, repo)
			if scrapeErr == nil && c.cache != nil {
				c.cache.setCommitStats(cacheKey, stats)
			}
			return stats, scrapeErr
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

	stats := &CommitStats{
		TotalCommits:      totalCommits,
		AuthorCommits:     authorCommits,
		BusFactor:         busFactor,
		TopContributorPct: topContributorPct,
	}
	if c.cache != nil {
		c.cache.setCommitStats(cacheKey, stats)
	}
	return stats, nil
}

// scrapeCommitStats scrapes contributor data from the GitHub repository page.
// This is the primary contributor data source for all GitHub requests.
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

// GetPullRequestStats analyzes PR statistics for code review verification.
// Results are cached per owner/repo so multiple packages from the same repository
// share a single set of API calls (up to 21 calls for PR list + review checks).
func (c *GitHubClient) GetPullRequestStats(repoURL string) (*PRStats, error) {
	owner, repo, err := parseGitHubURL(repoURL)
	if err != nil {
		return nil, err
	}

	cacheKey := owner + "/" + repo
	if c.cache != nil {
		if cached, ok := c.cache.getPRStats(cacheKey); ok {
			return cached, nil
		}
	}

	// Scraping-first path: always try scraping PR data first to minimize API usage.
	if c.shouldPreferScraping() {
		stats, scrapeErr := c.scrapePullRequestStats(owner, repo)
		if scrapeErr == nil {
			if c.cache != nil {
				c.cache.setPRStats(cacheKey, stats)
			}
			return stats, nil
		}
		// Scraping failed — fall through to try the API
	}

	stats := &PRStats{}

	// Fetch recent closed PRs. We request 100 (one API call) to get a sufficient pool
	// of merged PRs. We only check reviews on up to 20 merged PRs – enough to estimate
	// the project's code review rate without making 100+ API calls.
	const maxReviewChecks = 20
	url := fmt.Sprintf("%s/repos/%s/%s/pulls?state=closed&per_page=100", c.baseURL, owner, repo)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := c.doRequest(req)
	if err != nil {
		// Network error — try scraping if we haven't already
		if !c.shouldPreferScraping() {
			if scraped, scrapeErr := c.scrapePullRequestStats(owner, repo); scrapeErr == nil {
				if c.cache != nil {
					c.cache.setPRStats(cacheKey, scraped)
				}
				return scraped, nil
			}
		}
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		// Rate limit or auth errors — try scraping if we haven't already
		if !c.shouldPreferScraping() && shouldFallbackToScraping(nil, resp.StatusCode) {
			if scraped, scrapeErr := c.scrapePullRequestStats(owner, repo); scrapeErr == nil {
				if c.cache != nil {
					c.cache.setPRStats(cacheKey, scraped)
				}
				return scraped, nil
			}
		}
		return stats, nil // Return empty stats if we can't fetch PRs
	}

	var prs []GitHubPullRequest
	if err := json.NewDecoder(resp.Body).Decode(&prs); err != nil {
		return stats, nil
	}

	// Collect merged PR numbers for batch review checking
	var mergedPRNumbers []int
	for _, pr := range prs {
		if pr.MergedAt != nil {
			stats.TotalPRs++
			stats.MergedPRs++
			if len(mergedPRNumbers) < maxReviewChecks {
				mergedPRNumbers = append(mergedPRNumbers, pr.Number)
			}
		}
	}

	// Batch-fetch review status: 1 GraphQL call (with token) instead of up to
	// 20 individual REST calls. Falls back to REST with rate limit awareness.
	reviewMap := c.batchCheckPRReviews(owner, repo, mergedPRNumbers)
	for _, prNum := range mergedPRNumbers {
		if reviewMap[prNum] {
			stats.PRsWithReviews++
		}
	}

	// Calculate code review rate based on the sampled PRs only
	sampledPRs := stats.MergedPRs
	if sampledPRs > maxReviewChecks {
		sampledPRs = maxReviewChecks
	}
	if sampledPRs > 0 {
		stats.CodeReviewRate = float64(stats.PRsWithReviews) / float64(sampledPRs) * 100
	}

	if c.cache != nil {
		c.cache.setPRStats(cacheKey, stats)
	}
	return stats, nil
}

// scrapePullRequestStats scrapes the pull requests page to build approximate
// PRStats when the API is rate-limited. This provides a rough merged PR count
// by scraping the closed PRs tab, though it cannot determine code review rates
// (which require per-PR API calls).
func (c *GitHubClient) scrapePullRequestStats(owner, repo string) (*PRStats, error) {
	pageURL := fmt.Sprintf("https://github.com/%s/%s/pulls?q=is%%3Apr+is%%3Aclosed", owner, repo)
	doc, err := scrapeWithUserAgent(pageURL)
	if err != nil {
		return nil, fmt.Errorf("scraping PR stats fallback failed: %w", err)
	}

	stats := &PRStats{}

	// Extract closed PR count from the "closed" link/counter on the page.
	// GitHub's PR page shows "N closed" as a counter.
	doc.Find("a[href*='is%3Aclosed'] .State--closed, a[href*='is%3Aclosed']").Each(func(i int, s *goquery.Selection) {
		text := strings.TrimSpace(s.Text())
		num := extractNumber(text)
		if num > 0 && num > stats.TotalPRs {
			stats.TotalPRs = num
			stats.MergedPRs = num // approximate: most closed PRs are merged
		}
	})

	// Also try extracting from issue-like counters
	if stats.TotalPRs == 0 {
		doc.Find("a.btn-link").Each(func(i int, s *goquery.Selection) {
			text := strings.TrimSpace(s.Text())
			if strings.Contains(strings.ToLower(text), "closed") {
				num := extractNumber(text)
				if num > 0 {
					stats.TotalPRs = num
					stats.MergedPRs = num
				}
			}
		})
	}

	return stats, nil
}

// prHasReviews checks if a PR has any reviews (single REST call).
// Prefer batchCheckPRReviews for checking multiple PRs.
func (c *GitHubClient) prHasReviews(owner, repo string, prNumber int) bool {
	url := fmt.Sprintf("%s/repos/%s/%s/pulls/%d/reviews", c.baseURL, owner, repo, prNumber)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return false
	}

	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.doRequest(req)
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

// batchCheckPRReviews checks review status for multiple PRs efficiently.
// Uses a single GraphQL query when a token is available (1 API call instead of N).
// Falls back to individual REST calls with rate limit awareness when GraphQL is
// unavailable.
func (c *GitHubClient) batchCheckPRReviews(owner, repo string, prNumbers []int) map[int]bool {
	if len(prNumbers) == 0 {
		return make(map[int]bool)
	}

	// Try GraphQL batch first — requires a token but replaces N REST calls with 1
	if c.token != "" {
		if result := c.batchCheckPRReviewsGraphQL(owner, repo, prNumbers); result != nil {
			return result
		}
		// GraphQL failed — fall through to individual REST calls
	}

	// Fallback: individual REST calls with rate limit awareness.
	// Stop early when API quota drops to preserve calls for critical checks.
	result := make(map[int]bool)
	for _, prNum := range prNumbers {
		if c.rateLimiter != nil && c.rateLimiter.ShouldPreferScraping() {
			break
		}
		result[prNum] = c.prHasReviews(owner, repo, prNum)
	}
	return result
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
// Web scraping is always tried first. Falls back to the API when scraping
// fails. Returns empty list (not error) when all methods fail so CI detection
// degrades gracefully. Results are cached per owner/repo to avoid redundant calls.
func (c *GitHubClient) getWorkflowFiles(owner, repo string) ([]string, error) {
	cacheKey := owner + "/" + repo
	if c.cache != nil {
		if cached, ok := c.cache.getWorkflowFiles(cacheKey); ok {
			return cached, nil
		}
	}

	// Scraping-first path: always try scraping the GitHub tree page first.
	if c.shouldPreferScraping() {
		workflows, scrapeErr := c.scrapeWorkflowFiles(owner, repo)
		if scrapeErr == nil {
			if c.cache != nil {
				c.cache.setWorkflowFiles(cacheKey, workflows)
			}
			return workflows, nil
		}
		// Scraping failed — fall through to try the API
	}

	// API path: fallback when scraping fails.
	url := fmt.Sprintf("%s/repos/%s/%s/contents/.github/workflows", c.baseURL, owner, repo)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := c.doRequest(req)
	if err != nil {
		// Network error — try scraping if we haven't already
		if !c.shouldPreferScraping() {
			workflows, scrapeErr := c.scrapeWorkflowFiles(owner, repo)
			if scrapeErr == nil {
				if c.cache != nil {
					c.cache.setWorkflowFiles(cacheKey, workflows)
				}
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
				if c.cache != nil {
					c.cache.setWorkflowFiles(cacheKey, workflows)
				}
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

	if c.cache != nil {
		c.cache.setWorkflowFiles(cacheKey, workflows)
	}
	return workflows, nil
}

// scrapeWorkflowFiles scrapes workflow filenames from the GitHub repository tree page.
// This is the primary method for all GitHub requests, avoiding API rate limits.
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

type GitHubContent struct {
	Name string `json:"name"`
	Path string `json:"path"`
	Type string `json:"type"`
}

// GetAverageIssueResponseTime calculates the average time to first response on issues.
// This helps assess maintainer responsiveness and governance quality.
// Results are cached per owner/repo so multiple packages from the same repository
// share the expensive per-issue comment fetching (up to 31 API calls).
func (c *GitHubClient) GetAverageIssueResponseTime(repoURL string) (float64, error) {
	owner, repo, err := parseGitHubURL(repoURL)
	if err != nil {
		return 0, err
	}

	cacheKey := owner + "/" + repo
	if c.cache != nil {
		if cached, ok := c.cache.getIssueResponseTime(cacheKey); ok {
			if !cached.hasData {
				return 0, fmt.Errorf("no issues with responses found")
			}
			return cached.avgDays, nil
		}
	}

	// Skip API call when quota is low — issue response time requires up to
	// 31 API calls (1 for issue list + 10 for per-issue comments) and has no
	// scraping alternative. Return 0 with nil error so callers degrade
	// gracefully rather than wasting precious API quota.
	if c.shouldPreferScraping() {
		return 0, nil
	}

	// Also skip when actual API quota is low — this covers enterprise/custom
	// base URL setups where shouldPreferScraping() returns false but the rate
	// limit is nearly exhausted.
	if c.rateLimiter != nil && c.rateLimiter.ShouldPreferScraping() {
		return 0, nil
	}

	// Fetch recent closed issues (one API call with per_page=100 for max data)
	url := fmt.Sprintf("%s/repos/%s/%s/issues?state=closed&per_page=100&sort=updated&direction=desc", c.baseURL, owner, repo)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return 0, err
	}

	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := c.doRequest(req)
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
		if c.cache != nil {
			c.cache.setIssueResponseTime(cacheKey, &cachedIssueResponseTime{hasData: false})
		}
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

		commentsResp, err := c.doRequest(commentsReq)
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
		if c.cache != nil {
			c.cache.setIssueResponseTime(cacheKey, &cachedIssueResponseTime{hasData: false})
		}
		return 0, fmt.Errorf("no issues with responses found")
	}

	avgDays := totalResponseTime / float64(issuesWithResponse)
	if c.cache != nil {
		c.cache.setIssueResponseTime(cacheKey, &cachedIssueResponseTime{
			avgDays: avgDays,
			hasData: true,
		})
	}
	return avgDays, nil
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
	id := c.fetchIdentity(owner)
	if id == nil {
		return false, ""
	}
	return id.isOrg, id.name
}

// fetchIdentity fetches and caches user/org identity information.
// Web scraping is always tried first. The API provides richer data (exact
// creation date, type field) and is used as a fallback when scraping fails.
// Called by CheckIfOrganization and GetUserAccountCreatedDate to avoid
// duplicate network calls for the same owner within a scan.
func (c *GitHubClient) fetchIdentity(owner string) *cachedIdentity {
	if c.orgCache != nil {
		if cached, ok := c.orgCache.getIdentity(owner); ok {
			return cached
		}
	}

	// Scraping-first path: always try scraping the profile page first.
	if c.shouldPreferScraping() {
		if id := c.scrapeIdentity(owner); id != nil && id.name != "" {
			if c.orgCache != nil {
				c.orgCache.setIdentity(owner, id)
			}
			return id
		}
		// Scraping failed — fall through to try the API
	}

	url := fmt.Sprintf("%s/users/%s", c.baseURL, owner)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil
	}

	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := c.doRequest(req)
	if err != nil {
		// Network error — try scraping if we haven't already
		if !c.shouldPreferScraping() {
			if id := c.scrapeIdentity(owner); id != nil && id.name != "" {
				if c.orgCache != nil {
					c.orgCache.setIdentity(owner, id)
				}
				return id
			}
		}
		return nil
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		// Rate limit or auth error — try scraping if we haven't already
		if !c.shouldPreferScraping() && shouldFallbackToScraping(nil, resp.StatusCode) {
			if id := c.scrapeIdentity(owner); id != nil && id.name != "" {
				if c.orgCache != nil {
					c.orgCache.setIdentity(owner, id)
				}
				return id
			}
		}
		return nil
	}

	var user struct {
		Login     string    `json:"login"`
		Type      string    `json:"type"` // "User" or "Organization"
		Name      string    `json:"name"`
		CreatedAt time.Time `json:"created_at"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return nil
	}

	name := user.Name
	if name == "" {
		name = user.Login
	}

	id := &cachedIdentity{
		isOrg:     user.Type == "Organization",
		name:      name,
		createdAt: user.CreatedAt,
	}
	if c.orgCache != nil {
		c.orgCache.setIdentity(owner, id)
	}
	return id
}

// scrapeIdentity scrapes the GitHub profile page to determine if an owner is
// an organization and to extract the display name and account creation date.
// GitHub uses different page structures for orgs and users (orgs show "People"
// tab, users show "Repositories" tab). The creation date is extracted from the
// <relative-time> element in the "Joined" section of the sidebar.
func (c *GitHubClient) scrapeIdentity(owner string) *cachedIdentity {
	pageURL := fmt.Sprintf("https://github.com/%s", owner)
	doc, err := scrapeWithUserAgent(pageURL)
	if err != nil {
		return nil
	}

	// GitHub org pages have a "People" tab in the navigation.
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

	// Extract "Joined" date from the sidebar's <relative-time> element.
	// User profiles show: <relative-time datetime="2020-03-15T12:00:00Z">
	var createdAt time.Time
	doc.Find("relative-time").Each(func(_ int, rt *goquery.Selection) {
		if datetime, exists := rt.Attr("datetime"); exists && createdAt.IsZero() {
			if t, parseErr := time.Parse(time.RFC3339, datetime); parseErr == nil {
				createdAt = t
			}
		}
	})

	return &cachedIdentity{isOrg: isOrg, name: name, createdAt: createdAt}
}

// fetchOrgInfo fetches and caches the result of GET /orgs/{owner}.
// Both CheckVerifiedOrganization and CheckOrgMFARequired share this single
// request, saving one API call per org per scan.
func (c *GitHubClient) fetchOrgInfo(owner string) *cachedOrgInfo {
	if c.orgCache != nil {
		if cached, ok := c.orgCache.getOrgInfo(owner); ok {
			return cached
		}
	}

	// Scraping-first path: always try scraping the org page first to detect
	// verified badge. MFA requirement cannot be determined via scraping.
	if c.shouldPreferScraping() {
		info := c.scrapeOrgInfo(owner)
		if info != nil {
			if c.orgCache != nil {
				c.orgCache.setOrgInfo(owner, info)
			}
			return info
		}
		// Scraping failed — fall through to try the API
	}

	apiURL := fmt.Sprintf("%s/orgs/%s", c.baseURL, owner)
	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return nil
	}

	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := c.doRequest(req)
	if err != nil {
		// Network error — try scraping if we haven't already
		if !c.shouldPreferScraping() {
			if info := c.scrapeOrgInfo(owner); info != nil {
				if c.orgCache != nil {
					c.orgCache.setOrgInfo(owner, info)
				}
				return info
			}
		}
		return nil
	}
	defer func() { _ = resp.Body.Close() }()

	// 404 = owner is a user, not an org; other non-200 = API unavailable
	if resp.StatusCode != http.StatusOK {
		// Rate limit — try scraping if we haven't already
		if !c.shouldPreferScraping() && shouldFallbackToScraping(nil, resp.StatusCode) {
			if info := c.scrapeOrgInfo(owner); info != nil {
				if c.orgCache != nil {
					c.orgCache.setOrgInfo(owner, info)
				}
				return info
			}
		}
		info := &cachedOrgInfo{found: false}
		if c.orgCache != nil {
			c.orgCache.setOrgInfo(owner, info)
		}
		return info
	}

	var org struct {
		IsVerified                  bool `json:"is_verified"`
		TwoFactorRequirementEnabled bool `json:"two_factor_requirement_enabled"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&org); err != nil {
		return nil
	}

	info := &cachedOrgInfo{
		isVerified:  org.IsVerified,
		mfaRequired: org.TwoFactorRequirementEnabled,
		found:       true,
	}
	if c.orgCache != nil {
		c.orgCache.setOrgInfo(owner, info)
	}
	return info
}

// scrapeOrgInfo scrapes the organization profile page to detect verified status.
// MFA requirement cannot be determined via scraping (API-only field), so
// mfaRequired is always false when scraped. Returns nil if the owner doesn't
// appear to be an organization.
func (c *GitHubClient) scrapeOrgInfo(owner string) *cachedOrgInfo {
	// First check if this is actually an org via the cached identity
	id := c.fetchIdentity(owner)
	if id == nil || !id.isOrg {
		return &cachedOrgInfo{found: false}
	}

	// Scrape the org page to check for verified badge
	pageURL := fmt.Sprintf("https://github.com/%s", owner)
	doc, err := scrapeWithUserAgent(pageURL)
	if err != nil {
		return nil
	}

	isVerified := false
	// GitHub shows a "Verified" badge/tooltip on verified org pages
	doc.Find(".octicon-verified, [aria-label*='erified'], .Label--success").Each(func(i int, s *goquery.Selection) {
		text := strings.TrimSpace(s.Text())
		ariaLabel, _ := s.Attr("aria-label")
		if strings.Contains(strings.ToLower(text), "verified") || strings.Contains(strings.ToLower(ariaLabel), "verified") {
			isVerified = true
		}
	})

	return &cachedOrgInfo{
		isVerified:  isVerified,
		mfaRequired: false, // cannot be determined via scraping
		found:       true,
	}
}

// CheckVerifiedOrganization checks if a GitHub organization has verified status
//
// Methodology:
// - Query GitHub API: GET /orgs/{org} (cached, shared with CheckOrgMFARequired)
// - Check for "is_verified" field (requires authentication)
//
// Note: GitHub's verified organization badge requires specific API permissions
// If unavailable, this returns false (conservative approach)
func (c *GitHubClient) CheckVerifiedOrganization(owner string) bool {
	info := c.fetchOrgInfo(owner)
	if info == nil || !info.found {
		return false
	}
	return info.isVerified
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
//              Cached: shared with CheckVerifiedOrganization (single API call).
//              Returns (false, false) if the owner is a user (not an org) or API unavailable.
// Result: (true, true) = MFA enforced; (false, true) = MFA not enforced; (false, false) = unknown
func (c *GitHubClient) CheckOrgMFARequired(owner string) (required bool, available bool) {
	info := c.fetchOrgInfo(owner)
	if info == nil || !info.found {
		return false, false
	}
	return info.mfaRequired, true
}

// GetUserAccountCreatedDate fetches the account creation date for a GitHub user
//
// Methodology:
// - Query GitHub API: GET /users/{username} (cached, shared with CheckIfOrganization)
// - Extract "created_at" field
//
// Returns account creation timestamp
// Used to detect new accounts (< 6 months = suspicious, < 1 month = red flag)
func (c *GitHubClient) GetUserAccountCreatedDate(username string) (time.Time, error) {
	id := c.fetchIdentity(username)
	if id == nil {
		return time.Time{}, fmt.Errorf("unable to fetch user info for %s", username)
	}
	return id.createdAt, nil
}
