package fetcher

import (
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/metalstormbass/snyft/pkg/models"
)

// PyPIClient handles interactions with PyPI API
type PyPIClient struct {
	httpClient *http.Client
	baseURL    string
}

// PyPIPackage represents package information from PyPI
type PyPIPackage struct {
	Name           string
	Version        string
	LatestVersion  string
	RepositoryURL  string
	Homepage       string
	License        string
	Downloads      int64
	PublishedAt    time.Time
	Maintainers    []string
	DirectDepCount int // Number of direct dependencies from requires_dist
}

// NewPyPIClient creates a new PyPI client
func NewPyPIClient() *PyPIClient {
	return &PyPIClient{
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		baseURL: "https://pypi.org/pypi",
	}
}

// GetPackageInfo fetches package information from PyPI
func (c *PyPIClient) GetPackageInfo(packageName string) (*PyPIPackage, error) {
	url := fmt.Sprintf("%s/%s/json", c.baseURL, packageName)

	resp, err := c.httpClient.Get(url)
	if err != nil {
		// Network error (timeout, DNS, connection refused) — try scraping fallback
		return c.scrapePyPIPackageInfo(packageName)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("%w: %s", ErrPackageNotFound, packageName)
	}

	if resp.StatusCode != http.StatusOK {
		// Try scraping fallback on rate limit or auth errors
		if shouldFallbackToScraping(nil, resp.StatusCode) {
			return c.scrapePyPIPackageInfo(packageName)
		}
		return nil, fmt.Errorf("PyPI API returned status %d", resp.StatusCode)
	}

	var pypiResp PyPIResponse
	if err := json.NewDecoder(resp.Body).Decode(&pypiResp); err != nil {
		return nil, fmt.Errorf("failed to decode PyPI response: %w", err)
	}

	pkg := &PyPIPackage{
		Name:          pypiResp.Info.Name,
		LatestVersion: pypiResp.Info.Version,
		License:       pypiResp.Info.License,
		Homepage:      pypiResp.Info.HomePage,
	}

	// Extract repository URL from project_urls dict, checked in priority order.
	// Source: PyPI JSON API — project_urls is an arbitrary string→URL map.
	pkg.RepositoryURL = extractPyPIRepoURL(pypiResp.Info)

	// Extract maintainers from all available PyPI metadata fields.
	// Modern packages using pyproject.toml populate author_email instead of author.
	// The maintainer/maintainer_email fields are used when a separate maintainer
	// is designated. We check all fields to avoid missing maintainer data.
	// Source: PyPI JSON API docs — info.author, info.author_email, info.maintainer,
	//         info.maintainer_email fields
	pkg.Maintainers = extractPyPIMaintainers(pypiResp.Info)

	// PyPI doesn't provide download counts in the JSON API directly
	pkg.Downloads = 0

	// Count direct dependencies from requires_dist, excluding extras-only deps.
	// requires_dist entries with "; extra ==" are optional extras, not required deps.
	pkg.DirectDepCount = countRequiresDist(pypiResp.Info.RequiresDist)

	return pkg, nil
}

// PyPIResponse represents the PyPI JSON API response
type PyPIResponse struct {
	Info    PyPIInfo              `json:"info"`
	Urls    []PyPIURL             `json:"urls"`
	Releases map[string][]PyPIURL `json:"releases,omitempty"`
}

type PyPIURL struct {
	Filename      string            `json:"filename"`
	URL           string            `json:"url"`
	HasSignature  bool              `json:"has_sig"`          // Deprecated: always false since May 2023
	Digests       map[string]string `json:"digests"`
	PGPSignature  string            `json:"pgp_signature,omitempty"` // Deprecated: always empty since May 2023
	Provenance    string            `json:"provenance,omitempty"`    // PEP 740 attestation provenance URL
}

type PyPIInfo struct {
	Name            string            `json:"name"`
	Version         string            `json:"version"`
	Author          string            `json:"author"`
	AuthorEmail     string            `json:"author_email"`
	Maintainer      string            `json:"maintainer"`
	MaintainerEmail string            `json:"maintainer_email"`
	License         string            `json:"license"`
	HomePage        string            `json:"home_page"`
	ProjectURL      string            `json:"project_url"`
	ProjectURLs     map[string]string `json:"project_urls"`
	RequiresDist    []string          `json:"requires_dist"`
}

// extractPyPIRepoURL extracts the best available source-code repository URL from
// PyPI package metadata. It checks project_urls keys in priority order and then
// falls back to project_url and home_page fields, filtering the latter two for
// known source-hosting domains so that marketing homepages are skipped.
//
// Priority order for project_urls keys (case-insensitive):
//  1. "Source Code"
//  2. "Source"
//  3. "Repository"
//  4. "Code"
//  5. "Homepage" — only if the URL contains a known source-hosting domain
//
// Final fallbacks (domain-filtered): project_url, home_page
func extractPyPIRepoURL(info PyPIInfo) string {
	// Build a lowercase key → original URL map for case-insensitive lookup.
	// PyPI project_urls keys have no enforced casing convention; packages use
	// "Source Code", "source code", "Source code", "repository", etc.
	lowerURLs := make(map[string]string, len(info.ProjectURLs))
	for k, v := range info.ProjectURLs {
		lowerURLs[strings.ToLower(k)] = v
	}

	priority := []string{"source code", "source", "repository", "code"}
	for _, key := range priority {
		if url, ok := lowerURLs[key]; ok && url != "" {
			return url
		}
	}

	// "Homepage" is only accepted when it points at a source-hosting service
	if url, ok := lowerURLs["homepage"]; ok && url != "" {
		if isSourceRepoHost(url) {
			return url
		}
	}

	// Final fallbacks — also filtered for source-hosting domains
	if info.ProjectURL != "" && isSourceRepoHost(info.ProjectURL) {
		return info.ProjectURL
	}
	if info.HomePage != "" && isSourceRepoHost(info.HomePage) {
		return info.HomePage
	}

	return ""
}

// extractPyPIMaintainers extracts maintainer names from all available PyPI info fields.
// Modern Python packages using pyproject.toml populate author_email (e.g.
// "Name <email>, Name2 <email2>") while leaving the author field empty.
// We check author, author_email, maintainer, and maintainer_email fields,
// deduplicating by name to produce an accurate maintainer count.
//
// Justification: Accurate maintainer count is critical for single-maintainer
// detection — the #1 supply chain compromise risk signal.
// Source: PyPI JSON API docs, PEP 621 (pyproject.toml metadata)
func extractPyPIMaintainers(info PyPIInfo) []string {
	seen := make(map[string]bool)
	var maintainers []string

	addName := func(name string) {
		name = strings.TrimSpace(name)
		if name == "" {
			return
		}
		// For dedup, use only the name part (before "<") so that
		// "Tom Christie" and "Tom Christie <tom@example.com>" are recognized
		// as the same person. The entry with the email is preferred for
		// downstream email domain analysis.
		dedupKey := strings.ToLower(name)
		if idx := strings.Index(dedupKey, "<"); idx > 0 {
			dedupKey = strings.TrimSpace(dedupKey[:idx])
		}
		if seen[dedupKey] {
			return
		}
		seen[dedupKey] = true
		maintainers = append(maintainers, name)
	}

	// Parse a "Name <email>, Name2 <email2>" formatted string into individual entries.
	// This format is used by pyproject.toml's authors/maintainers lists when serialized
	// to the author_email/maintainer_email fields.
	parseEmailList := func(emailList string) {
		if emailList == "" {
			return
		}
		// Split on commas that are NOT inside angle brackets.
		// e.g. "Sam <s@x.com>, Eric <e@x.com>" → ["Sam <s@x.com>", "Eric <e@x.com>"]
		entries := splitEmailList(emailList)
		for _, entry := range entries {
			entry = strings.TrimSpace(entry)
			if entry == "" {
				continue
			}
			// Extract name from "Name <email>" format
			if idx := strings.Index(entry, "<"); idx > 0 {
				name := strings.TrimSpace(entry[:idx])
				if name != "" {
					email := ""
					if end := strings.Index(entry, ">"); end > idx {
						email = entry[idx+1 : end]
					}
					if email != "" {
						addName(name + " <" + email + ">")
					} else {
						addName(name)
					}
					continue
				}
			}
			// Bare email or name without angle brackets
			addName(entry)
		}
	}

	// Priority 1: maintainer/maintainer_email (explicitly designated maintainer)
	if info.Maintainer != "" {
		addName(info.Maintainer)
	}
	parseEmailList(info.MaintainerEmail)

	// Priority 2: author/author_email (package author)
	if info.Author != "" {
		addName(info.Author)
	}
	parseEmailList(info.AuthorEmail)

	return maintainers
}

// splitEmailList splits a comma-separated email list like
// "Name1 <a@b.com>, Name2 <c@d.com>" into individual entries,
// correctly handling commas inside angle brackets (which shouldn't occur
// in practice but we handle defensively).
func splitEmailList(s string) []string {
	var entries []string
	var current strings.Builder
	depth := 0
	for _, ch := range s {
		switch ch {
		case '<':
			depth++
			current.WriteRune(ch)
		case '>':
			if depth > 0 {
				depth--
			}
			current.WriteRune(ch)
		case ',':
			if depth == 0 {
				entries = append(entries, current.String())
				current.Reset()
			} else {
				current.WriteRune(ch)
			}
		default:
			current.WriteRune(ch)
		}
	}
	if current.Len() > 0 {
		entries = append(entries, current.String())
	}
	return entries
}

// countRequiresDist counts required (non-extra) dependencies from requires_dist.
// Entries with "; extra ==" are optional extras and are excluded because they
// only apply when the consumer explicitly requests them.
func countRequiresDist(requiresDist []string) int {
	count := 0
	for _, req := range requiresDist {
		if !strings.Contains(req, "extra ==") {
			count++
		}
	}
	return count
}

// VerifySourceAvailability verifies that source code exists for the exact version
// Checks: 1) sdist (source distribution) is available, 2) matching git tag exists
func (c *PyPIClient) VerifySourceAvailability(packageName, version string, repoURL string, gitClient GitPlatformClient) *models.SourceVerification {
	result := &models.SourceVerification{
		Verified:           false,
		HasSourcePackage:   false,
		HasMatchingGitTag:  false,
		VerificationErrors: []string{},
	}

	// Fetch package version metadata from PyPI
	url := fmt.Sprintf("%s/%s/%s/json", c.baseURL, packageName, version)
	resp, err := c.httpClient.Get(url)
	if err != nil {
		result.VerificationErrors = append(result.VerificationErrors, fmt.Sprintf("Failed to fetch package version: %v", err))
		result.Details = "Failed to fetch package metadata from PyPI"
		return result
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		result.VerificationErrors = append(result.VerificationErrors, "Package version not found in PyPI")
		result.Details = fmt.Sprintf("Version %s not found in registry", version)
		return result
	}

	if resp.StatusCode != http.StatusOK {
		result.VerificationErrors = append(result.VerificationErrors, fmt.Sprintf("PyPI returned status %d", resp.StatusCode))
		result.Details = "Failed to access PyPI"
		return result
	}

	var pypiResp struct {
		URLs []struct {
			PackageType string `json:"packagetype"`
			URL         string `json:"url"`
			Filename    string `json:"filename"`
		} `json:"urls"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&pypiResp); err != nil {
		result.VerificationErrors = append(result.VerificationErrors, fmt.Sprintf("Failed to parse package metadata: %v", err))
		result.Details = "Invalid package metadata from PyPI"
		return result
	}

	// Check for sdist (source distribution)
	hasSdist := false
	hasOnlyWheel := true
	var sdistURL string

	for _, file := range pypiResp.URLs {
		if file.PackageType == "sdist" {
			hasSdist = true
			hasOnlyWheel = false
			sdistURL = file.URL
			break
		}
		if file.PackageType != "bdist_wheel" {
			hasOnlyWheel = false
		}
	}

	if hasSdist {
		result.HasSourcePackage = true
		result.SourcePackageURL = sdistURL
	} else if hasOnlyWheel {
		result.VerificationErrors = append(result.VerificationErrors, "Package only provides wheel distribution, no source distribution (sdist)")
		result.Details = "No source distribution available, only compiled wheels"
	} else {
		result.VerificationErrors = append(result.VerificationErrors, "No source distribution found")
		result.Details = "Package lacks source distribution"
	}

	// Check for matching git tag in repository
	// Note: gitClient is an interface, so we need to check if the underlying value is nil
	if repoURL != "" && gitClient != nil && !reflect.ValueOf(gitClient).IsNil() {
		tagExists, tagURL, err := gitClient.CheckGitTag(repoURL, version)
		if err != nil {
			result.VerificationErrors = append(result.VerificationErrors, fmt.Sprintf("Failed to check git tag: %v", err))
		} else if tagExists {
			result.HasMatchingGitTag = true
			result.GitTagURL = tagURL
		} else {
			result.VerificationErrors = append(result.VerificationErrors, fmt.Sprintf("No git tag found for version %s", version))
		}
	}

	// Overall verification passes if both checks pass
	result.Verified = result.HasSourcePackage && result.HasMatchingGitTag

	if result.Verified {
		result.Details = fmt.Sprintf("Source code verified for v%s: sdist available, git tag exists", version)
	} else if result.HasSourcePackage && !result.HasMatchingGitTag {
		result.Details = fmt.Sprintf("Partial verification: sdist available but no matching git tag for v%s", version)
	} else if !result.HasSourcePackage && result.HasMatchingGitTag {
		result.Details = fmt.Sprintf("Partial verification: git tag exists but no sdist for v%s", version)
	} else {
		result.Details = fmt.Sprintf("Source verification failed for v%s", version)
	}

	return result
}

// scrapePyPIPackageInfo scrapes package information from pypi.org web page
// Used as a fallback when the PyPI API fails
func (c *PyPIClient) scrapePyPIPackageInfo(packageName string) (*PyPIPackage, error) {
	pageURL := fmt.Sprintf("https://pypi.org/project/%s/", packageName)
	doc, err := scrapeWithUserAgent(pageURL)
	if err != nil {
		return nil, fmt.Errorf("scraping fallback failed: %w", err)
	}

	pkg := &PyPIPackage{
		Name:        packageName,
		Maintainers: []string{},
	}

	// Extract version
	doc.Find("h1.package-header__name").Each(func(i int, s *goquery.Selection) {
		text := strings.TrimSpace(s.Text())
		// Version is typically after the package name
		parts := strings.Fields(text)
		if len(parts) > 1 {
			pkg.LatestVersion = parts[len(parts)-1]
		}
	})

	// Extract maintainers/authors
	doc.Find("span.sidebar-section__maintainer a").Each(func(i int, s *goquery.Selection) {
		maintainer := strings.TrimSpace(s.Text())
		if maintainer != "" {
			pkg.Maintainers = append(pkg.Maintainers, maintainer)
		}
	})

	// Extract license
	doc.Find("p:contains('License:')").Each(func(i int, s *goquery.Selection) {
		text := strings.TrimSpace(s.Text())
		// Remove "License: " prefix
		pkg.License = strings.TrimPrefix(text, "License:")
		pkg.License = strings.TrimSpace(pkg.License)
	})

	// Extract repository URL from project links
	doc.Find("a.vertical-tabs__tab[href*='github.com']").Each(func(i int, s *goquery.Selection) {
		if href, exists := s.Attr("href"); exists {
			pkg.RepositoryURL = href
		}
	})

	// Extract download stats if available
	doc.Find("p:contains('downloads')").Each(func(i int, s *goquery.Selection) {
		text := strings.TrimSpace(s.Text())
		// Try to extract download number
		parts := strings.Fields(text)
		for _, part := range parts {
			if num, err := strconv.ParseInt(strings.ReplaceAll(part, ",", ""), 10, 64); err == nil && num > 0 {
				pkg.Downloads = num
				break
			}
		}
	})

	return pkg, nil
}


// GetVersionHistory fetches version publish timestamps from the PyPI registry.
// The PyPI JSON API includes a "releases" map where each version key maps to an
// array of release files, each with an upload_time_iso_8601 timestamp.
// Returns all versions sorted by publish date (newest first).
//
// Justification: When a package has no GitHub releases/tags, this data provides
// temporal release patterns needed for dormancy reactivation detection and
// cadence regularity analysis.
// Source: PyPI JSON API — the "releases" field on /pypi/{package}/json responses
func (c *PyPIClient) GetVersionHistory(packageName string) ([]RegistryRelease, error) {
	apiURL := fmt.Sprintf("%s/%s/json", c.baseURL, packageName)

	resp, err := c.httpClient.Get(apiURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch PyPI package: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("PyPI API returned status %d", resp.StatusCode)
	}

	var pypiResp PyPIFullResponse
	if err := json.NewDecoder(resp.Body).Decode(&pypiResp); err != nil {
		return nil, fmt.Errorf("failed to decode PyPI response: %w", err)
	}

	releases := make([]RegistryRelease, 0, len(pypiResp.Releases))
	for version, files := range pypiResp.Releases {
		if len(files) == 0 {
			continue
		}
		// Use the earliest file upload time as the release time
		earliest := files[0].UploadTime
		for _, f := range files[1:] {
			if !f.UploadTime.IsZero() && f.UploadTime.Before(earliest) {
				earliest = f.UploadTime
			}
		}
		if earliest.IsZero() {
			continue
		}
		// Detect prerelease versions (PEP 440 convention: contains a/b/rc/dev)
		isPrerelease := strings.ContainsAny(version, "abrc") &&
			(strings.Contains(version, "a") || strings.Contains(version, "b") ||
				strings.Contains(version, "rc") || strings.Contains(version, "dev"))
		releases = append(releases, RegistryRelease{
			Version:      version,
			PublishedAt:  earliest,
			IsPrerelease: isPrerelease,
		})
	}

	// Sort newest first (matching GitHub release ordering)
	sort.Slice(releases, func(i, j int) bool {
		return releases[i].PublishedAt.After(releases[j].PublishedAt)
	})

	return releases, nil
}

// PyPIOwnershipHistory represents ownership/maintainer changes over time
type PyPIOwnershipHistory struct {
	CurrentAuthor     string
	HistoricalAuthors []string
	AuthorChanges     int
	RecentTransfer    bool
	TransferDate      time.Time
}

// GetOwnershipHistory analyzes package owner/author changes over time.
// Falls back to scraping the PyPI page when the API is rate-limited.
func (c *PyPIClient) GetOwnershipHistory(packageName string) (*PyPIOwnershipHistory, error) {
	url := fmt.Sprintf("%s/%s/json", c.baseURL, packageName)

	resp, err := c.httpClient.Get(url)
	if err != nil {
		// Network error — try scraping fallback for basic maintainer info
		return c.scrapePyPIOwnershipHistory(packageName)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		// Rate limit or auth errors — try scraping fallback
		if shouldFallbackToScraping(nil, resp.StatusCode) {
			return c.scrapePyPIOwnershipHistory(packageName)
		}
		return nil, fmt.Errorf("PyPI API returned status %d", resp.StatusCode)
	}

	var pypiResp PyPIFullResponse
	if err := json.NewDecoder(resp.Body).Decode(&pypiResp); err != nil {
		return nil, fmt.Errorf("failed to decode PyPI response: %w", err)
	}

	// Use the full maintainer extraction to get current author, falling back
	// to just the author field for backward compatibility.
	currentAuthor := pypiResp.Info.Author
	if currentAuthor == "" {
		// Try author_email, maintainer, maintainer_email
		maintainers := extractPyPIMaintainers(pypiResp.Info)
		if len(maintainers) > 0 {
			currentAuthor = maintainers[0]
		}
	}

	history := &PyPIOwnershipHistory{
		CurrentAuthor:     currentAuthor,
		HistoricalAuthors: []string{},
		AuthorChanges:     0,
		RecentTransfer:    false,
	}

	allAuthors := make(map[string]bool)
	if currentAuthor != "" {
		allAuthors[currentAuthor] = true
	}

	// Analyze releases for author changes
	type releaseInfo struct {
		author string
		date   time.Time
	}

	releases := []releaseInfo{}

	// Parse releases (PyPI provides releases as map[version][]ReleaseFile).
	// Note: PyPI's public JSON API does not expose a per-file "uploader" field in
	// practice - it is always "". We use file.Uploader when available (non-empty),
	// and fall back to info.Author so that at minimum the current author is recorded
	// for each release, enabling release timestamp tracking even when per-release
	// uploader history is unavailable via the public API.
	for _, releaseFiles := range pypiResp.Releases {
		if len(releaseFiles) > 0 {
			file := releaseFiles[0]
			// Prefer per-file uploader when present; fall back to info-level author.
			author := file.Uploader
			if author == "" {
				author = pypiResp.Info.Author
			}
			if author != "" {
				allAuthors[author] = true
				releases = append(releases, releaseInfo{
					author: author,
					date:   file.UploadTime,
				})
			}
		}
	}

	// Sort releases by date (oldest first)
	sort.Slice(releases, func(i, j int) bool {
		return releases[i].date.Before(releases[j].date)
	})

	if len(releases) > 1 {
		previousAuthor := releases[0].author
		for i := 1; i < len(releases); i++ {
			if releases[i].author != previousAuthor && releases[i].author != "" {
				history.AuthorChanges++

				// Check if recent (within 6 months)
				sixMonthsAgo := time.Now().AddDate(0, -6, 0)
				if releases[i].date.After(sixMonthsAgo) {
					history.RecentTransfer = true
					history.TransferDate = releases[i].date
				}

				previousAuthor = releases[i].author
			}
		}
	}

	// Build historical authors list
	for author := range allAuthors {
		if author != history.CurrentAuthor && author != "" {
			history.HistoricalAuthors = append(history.HistoricalAuthors, author)
		}
	}

	return history, nil
}

// scrapePyPIOwnershipHistory scrapes basic maintainer info from the PyPI package page.
// Used as a fallback when the API is rate-limited. Provides current author/maintainers
// but cannot detect historical author changes (requires release-level API data).
func (c *PyPIClient) scrapePyPIOwnershipHistory(packageName string) (*PyPIOwnershipHistory, error) {
	pkg, err := c.scrapePyPIPackageInfo(packageName)
	if err != nil {
		return nil, fmt.Errorf("scraping ownership history fallback failed: %w", err)
	}

	author := ""
	if len(pkg.Maintainers) > 0 {
		author = pkg.Maintainers[0]
	}

	return &PyPIOwnershipHistory{
		CurrentAuthor:     author,
		HistoricalAuthors: []string{},
		AuthorChanges:     0,
		RecentTransfer:    false,
	}, nil
}

// PyPIFullResponse includes releases data
type PyPIFullResponse struct {
	Info     PyPIInfo                               `json:"info"`
	Releases map[string][]PyPIReleaseFile           `json:"releases"`
}

type PyPIReleaseFile struct {
	Filename   string    `json:"filename"`
	// upload_time_iso_8601 is preferred over upload_time because it includes a timezone
	// indicator (e.g. "2010-04-16T14:29:37.458396Z") that Go's time.Time can unmarshal.
	// The plain upload_time field ("2010-04-16T14:29:37") lacks a timezone suffix and
	// causes json.Unmarshal to fail with RFC3339 parse errors on historical PyPI data.
	UploadTime time.Time `json:"upload_time_iso_8601"`
	Uploader   string    `json:"uploader"`
}
