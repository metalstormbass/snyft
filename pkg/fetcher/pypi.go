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
	Name          string
	Version       string
	LatestVersion string
	RepositoryURL string
	Homepage      string
	License       string
	Downloads     int64
	PublishedAt   time.Time
	Maintainers   []string
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
		return nil, fmt.Errorf("failed to fetch PyPI package: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("package not found: %s", packageName)
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

	// Extract repository URL from project URLs
	if pypiResp.Info.ProjectURLs.Source != "" {
		pkg.RepositoryURL = pypiResp.Info.ProjectURLs.Source
	} else if pypiResp.Info.ProjectURLs.Repository != "" {
		pkg.RepositoryURL = pypiResp.Info.ProjectURLs.Repository
	} else if pypiResp.Info.ProjectURLs.Homepage != "" {
		pkg.RepositoryURL = pypiResp.Info.ProjectURLs.Homepage
	}

	// Get author as maintainer
	if pypiResp.Info.Author != "" {
		pkg.Maintainers = []string{pypiResp.Info.Author}
	}

	// PyPI doesn't provide download counts in the JSON API directly
	pkg.Downloads = 0

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
	HasSignature  bool              `json:"has_sig"`
	Digests       map[string]string `json:"digests"`
	PGPSignature  string            `json:"pgp_signature,omitempty"`
}

type PyPIInfo struct {
	Name        string        `json:"name"`
	Version     string        `json:"version"`
	Author      string        `json:"author"`
	License     string        `json:"license"`
	HomePage    string        `json:"home_page"`
	ProjectURLs PyPIProjectURLs `json:"project_urls"`
}

type PyPIProjectURLs struct {
	Homepage   string `json:"Homepage"`
	Source     string `json:"Source"`
	Repository string `json:"Repository"`
}

// CheckPyPISignatures checks if a package has cryptographic signatures
func (c *PyPIClient) CheckPyPISignatures(packageName string) (hasSignatures bool, signedCount, totalCount int, err error) {
	url := fmt.Sprintf("%s/%s/json", c.baseURL, packageName)

	resp, err := c.httpClient.Get(url)
	if err != nil {
		return false, 0, 0, fmt.Errorf("failed to fetch PyPI package: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return false, 0, 0, fmt.Errorf("PyPI API returned status %d", resp.StatusCode)
	}

	var pypiResp PyPIResponse
	if err := json.NewDecoder(resp.Body).Decode(&pypiResp); err != nil {
		return false, 0, 0, fmt.Errorf("failed to decode PyPI response: %w", err)
	}

	// Check the latest release URLs for signatures
	totalCount = len(pypiResp.Urls)
	signedCount = 0

	for _, url := range pypiResp.Urls {
		// PyPI packages can have PGP signatures or use has_sig field
		if url.HasSignature || url.PGPSignature != "" {
			signedCount++
		}
	}

	hasSignatures = signedCount > 0

	return hasSignatures, signedCount, totalCount, nil
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


// PyPIOwnershipHistory represents ownership/maintainer changes over time
type PyPIOwnershipHistory struct {
	CurrentAuthor     string
	HistoricalAuthors []string
	AuthorChanges     int
	RecentTransfer    bool
	TransferDate      time.Time
}

// GetOwnershipHistory analyzes package owner/author changes over time
func (c *PyPIClient) GetOwnershipHistory(packageName string) (*PyPIOwnershipHistory, error) {
	url := fmt.Sprintf("%s/%s/json", c.baseURL, packageName)

	resp, err := c.httpClient.Get(url)
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

	history := &PyPIOwnershipHistory{
		CurrentAuthor:     pypiResp.Info.Author,
		HistoricalAuthors: []string{},
		AuthorChanges:     0,
		RecentTransfer:    false,
	}

	allAuthors := make(map[string]bool)
	allAuthors[pypiResp.Info.Author] = true

	// Analyze releases for author changes
	type releaseInfo struct {
		author string
		date   time.Time
	}

	releases := []releaseInfo{}

	// Parse releases (PyPI provides releases as map[version][]ReleaseFile)
	for _, releaseFiles := range pypiResp.Releases {
		if len(releaseFiles) > 0 {
			// Use upload time and uploader from first file
			file := releaseFiles[0]
			author := file.Uploader
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

// PyPIFullResponse includes releases data
type PyPIFullResponse struct {
	Info     PyPIInfo                               `json:"info"`
	Releases map[string][]PyPIReleaseFile           `json:"releases"`
}

type PyPIReleaseFile struct {
	Filename   string    `json:"filename"`
	UploadTime time.Time `json:"upload_time"`
	Uploader   string    `json:"uploader"`
}
