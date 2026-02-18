package fetcher

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/metalstormbass/snyft/pkg/models"
)

// NPMClient handles interactions with npm registry API
type NPMClient struct {
	httpClient *http.Client
	baseURL    string
}

// NPMPackage represents package information from npm
type NPMPackage struct {
	Name           string
	Version        string
	LatestVersion  string
	RepositoryURL  string
	Homepage       string
	License        string
	Downloads      int64
	PublishedAt    time.Time
	Maintainers    []string
	Scripts        map[string]string // Install-time scripts (postinstall, preinstall, etc.)
	DirectDepCount int               // Number of direct dependencies declared in the published version
}

// NewNPMClient creates a new npm registry client
func NewNPMClient() *NPMClient {
	return &NPMClient{
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		baseURL: "https://registry.npmjs.org",
	}
}

// GetPackageInfo fetches package information from npm
func (c *NPMClient) GetPackageInfo(packageName string) (*NPMPackage, error) {
	url := fmt.Sprintf("%s/%s", c.baseURL, packageName)

	resp, err := c.httpClient.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch npm package: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("package not found: %s", packageName)
	}

	if resp.StatusCode != http.StatusOK {
		// Try scraping fallback on rate limit or auth errors
		if shouldFallbackToScraping(nil, resp.StatusCode) {
			return c.scrapeNPMPackageInfo(packageName)
		}
		return nil, fmt.Errorf("npm registry returned status %d", resp.StatusCode)
	}

	var npmResp NPMRegistryResponse
	if err := json.NewDecoder(resp.Body).Decode(&npmResp); err != nil {
		return nil, fmt.Errorf("failed to decode npm response: %w", err)
	}

	pkg := &NPMPackage{
		Name:          npmResp.Name,
		LatestVersion: npmResp.DistTags.Latest,
		License:       npmResp.License,
		Homepage:      npmResp.Homepage,
		Maintainers:   extractMaintainers(npmResp.Maintainers),
		Scripts:       make(map[string]string),
	}

	// Extract repository URL — npm registry `repository` field comes in many forms;
	// normalizeNPMRepoURL handles all of them.
	if npmResp.Repository.URL != "" {
		pkg.RepositoryURL = normalizeNPMRepoURL(npmResp.Repository.URL)
	} else if npmResp.Repository.TypeString != "" {
		pkg.RepositoryURL = normalizeNPMRepoURL(npmResp.Repository.TypeString)
	}

	// Get latest version info and scripts
	if latest, ok := npmResp.Versions[npmResp.DistTags.Latest]; ok {
		pkg.Version = latest.Version
		// Convert RawMessage script values to plain strings.
		// Values that are JSON objects (not strings) are kept as their raw JSON
		// representation so they remain inspectable without crashing the decoder.
		pkg.Scripts = make(map[string]string, len(latest.Scripts))
		for k, raw := range latest.Scripts {
			var s string
			if err := json.Unmarshal(raw, &s); err == nil {
				pkg.Scripts[k] = s
			} else {
				pkg.Scripts[k] = string(raw)
			}
		}
		pkg.DirectDepCount = len(latest.Dependencies) + len(latest.PeerDependencies)
	}

	// Get published time for the latest version
	if timeStr, ok := npmResp.Time[npmResp.DistTags.Latest]; ok {
		if t, err := time.Parse(time.RFC3339, timeStr); err == nil {
			pkg.PublishedAt = t
		}
	}

	// Fetch download count from the npm downloads API.
	// Errors are handled gracefully: if the request fails, Downloads stays 0.
	pkg.Downloads = c.fetchDownloadCount(packageName)

	return pkg, nil
}

// fetchDownloadCount fetches the last-month download count for a package from
// the npm downloads API: GET https://api.npmjs.org/downloads/point/last-month/{name}
// Returns 0 on any error so callers can treat it as a best-effort enrichment.
func (c *NPMClient) fetchDownloadCount(packageName string) int64 {
	url := fmt.Sprintf("https://api.npmjs.org/downloads/point/last-month/%s", packageName)

	resp, err := c.httpClient.Get(url)
	if err != nil {
		return 0
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return 0
	}

	var dlResp struct {
		Downloads int64  `json:"downloads"`
		Package   string `json:"package"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&dlResp); err != nil {
		return 0
	}

	return dlResp.Downloads
}

// NPMRegistryResponse represents the npm registry API response
type NPMRegistryResponse struct {
	Name        string                       `json:"name"`
	Version     string                       `json:"version"`
	Description string                       `json:"description"`
	License     string                       `json:"license"`
	Homepage    string                       `json:"homepage"`
	Repository  NPMRepository                `json:"repository"`
	Maintainers []NPMMaintainer              `json:"maintainers"`
	DistTags    NPMDistTags                  `json:"dist-tags"`
	Versions    map[string]NPMVersionDetails `json:"versions"`
	Time        map[string]string            `json:"time"`
}

type NPMRepository struct {
	Type       string `json:"type"`
	URL        string `json:"url"`
	TypeString string `json:"repository"` // Sometimes it's just a string
}

type NPMMaintainer struct {
	Name  string `json:"name"`
	Email string `json:"email"`
}

type NPMDistTags struct {
	Latest string `json:"latest"`
}

type NPMVersionDetails struct {
	Version string `json:"version"`
	// Scripts values can be strings OR nested objects (e.g. in old joi versions).
	// Using json.RawMessage avoids an unmarshal failure on non-string values.
	Scripts          map[string]json.RawMessage `json:"scripts"`
	Dist             NPMDist                    `json:"dist"`
	Maintainers      []NPMMaintainer            `json:"maintainers"`
	Dependencies     map[string]string          `json:"dependencies"`
	PeerDependencies map[string]string          `json:"peerDependencies"`
}

type NPMDist struct {
	Tarball      string        `json:"tarball"`
	Shasum       string        `json:"shasum"`
	Integrity    string        `json:"integrity"`
	Attestations *NPMAttestation `json:"attestations,omitempty"`
}

type NPMAttestation struct {
	URL           string `json:"url"`
	ProvenanceURL string `json:"provenance_url"`
}

type NPMOwnershipHistory struct {
	CurrentMaintainers    []string
	HistoricalMaintainers []string
	MaintainerChanges     int
	RecentTransfer        bool
	TransferDate          time.Time
}

func extractMaintainers(maintainers []NPMMaintainer) []string {
	var names []string
	for _, m := range maintainers {
		if m.Name == "" {
			continue
		}
		if m.Email != "" {
			// Include email so downstream email domain analysis can classify the domain.
			// Format: "username <email@domain.com>" which extractUsernameFromEmail handles.
			names = append(names, fmt.Sprintf("%s <%s>", m.Name, m.Email))
		} else {
			names = append(names, m.Name)
		}
	}
	return names
}

// CheckNPMProvenance checks if a package has npm provenance attestations
func (c *NPMClient) CheckNPMProvenance(packageName string) (bool, string, error) {
	url := fmt.Sprintf("%s/%s", c.baseURL, packageName)

	resp, err := c.httpClient.Get(url)
	if err != nil {
		return false, "", fmt.Errorf("failed to fetch npm package: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return false, "", fmt.Errorf("npm registry returned status %d", resp.StatusCode)
	}

	var npmResp NPMRegistryResponse
	if err := json.NewDecoder(resp.Body).Decode(&npmResp); err != nil {
		return false, "", fmt.Errorf("failed to decode npm response: %w", err)
	}

	// Check the latest version for provenance
	if latest, ok := npmResp.Versions[npmResp.DistTags.Latest]; ok {
		if latest.Dist.Attestations != nil && latest.Dist.Attestations.ProvenanceURL != "" {
			return true, latest.Dist.Attestations.ProvenanceURL, nil
		}
	}

	return false, "", nil
}

// VerifySourceAvailability verifies that source code exists for the exact version
// Checks: 1) tarball contains source files (not just minified), 2) matching git tag exists
func (c *NPMClient) VerifySourceAvailability(packageName, version string, repoURL string, gitClient GitPlatformClient) *models.SourceVerification {
	result := &models.SourceVerification{
		Verified:           false,
		HasSourcePackage:   false,
		HasMatchingGitTag:  false,
		VerificationErrors: []string{},
	}

	// Fetch package version metadata
	pkgURL := fmt.Sprintf("%s/%s/%s", c.baseURL, packageName, version)
	resp, err := c.httpClient.Get(pkgURL)
	if err != nil {
		result.VerificationErrors = append(result.VerificationErrors, fmt.Sprintf("Failed to fetch package version: %v", err))
		result.Details = "Failed to fetch package metadata from npm registry"
		return result
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		result.VerificationErrors = append(result.VerificationErrors, "Package version not found in npm registry")
		result.Details = fmt.Sprintf("Version %s not found in registry", version)
		return result
	}

	if resp.StatusCode != http.StatusOK {
		result.VerificationErrors = append(result.VerificationErrors, fmt.Sprintf("npm registry returned status %d", resp.StatusCode))
		result.Details = "Failed to access npm registry"
		return result
	}

	var versionData struct {
		Dist struct {
			Tarball string `json:"tarball"`
		} `json:"dist"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&versionData); err != nil {
		result.VerificationErrors = append(result.VerificationErrors, fmt.Sprintf("Failed to parse package metadata: %v", err))
		result.Details = "Invalid package metadata from registry"
		return result
	}

	if versionData.Dist.Tarball == "" {
		result.VerificationErrors = append(result.VerificationErrors, "No tarball URL found for package version")
		result.Details = "Package has no downloadable tarball"
		return result
	}

	result.SourcePackageURL = versionData.Dist.Tarball

	// Check if tarball contains source files
	hasSource, err := c.checkTarballHasSource(versionData.Dist.Tarball)
	if err != nil {
		result.VerificationErrors = append(result.VerificationErrors, fmt.Sprintf("Failed to analyze tarball: %v", err))
		result.Details = "Could not verify tarball contents"
	} else if hasSource {
		result.HasSourcePackage = true
	} else {
		result.VerificationErrors = append(result.VerificationErrors, "Tarball contains only minified/dist files, no source code")
		result.Details = "Package distribution lacks source code"
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
		result.Details = fmt.Sprintf("Source code verified for v%s: tarball contains source, git tag exists", version)
	} else if result.HasSourcePackage && !result.HasMatchingGitTag {
		result.Details = fmt.Sprintf("Partial verification: tarball has source but no matching git tag for v%s", version)
	} else if !result.HasSourcePackage && result.HasMatchingGitTag {
		result.Details = fmt.Sprintf("Partial verification: git tag exists but tarball lacks source for v%s", version)
	} else {
		result.Details = fmt.Sprintf("Source verification failed for v%s", version)
	}

	return result
}

// checkTarballHasSource downloads and inspects the tarball to verify it contains source files
func (c *NPMClient) checkTarballHasSource(tarballURL string) (bool, error) {
	resp, err := c.httpClient.Get(tarballURL)
	if err != nil {
		return false, fmt.Errorf("failed to download tarball: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("tarball download returned status %d", resp.StatusCode)
	}

	// Decompress gzip
	gzr, err := gzip.NewReader(resp.Body)
	if err != nil {
		return false, fmt.Errorf("failed to decompress gzip: %w", err)
	}
	defer func() { _ = gzr.Close() }()

	// Read tar archive
	tr := tar.NewReader(gzr)

	hasSourceFile := false
	hasOnlyMinified := true
	fileCount := 0
	maxFilesToCheck := 100 // Limit to avoid processing huge packages

	for fileCount < maxFilesToCheck {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return false, fmt.Errorf("failed to read tar: %w", err)
		}

		if header.Typeflag != tar.TypeReg {
			continue
		}

		fileCount++
		filename := strings.ToLower(header.Name)

		// Skip package.json and other metadata
		if strings.HasSuffix(filename, "package.json") || strings.HasSuffix(filename, ".md") {
			continue
		}

		// Look for source files (not minified, not in dist/build directories)
		isSourceFile := (strings.HasSuffix(filename, ".js") ||
			strings.HasSuffix(filename, ".ts") ||
			strings.HasSuffix(filename, ".jsx") ||
			strings.HasSuffix(filename, ".tsx") ||
			strings.HasSuffix(filename, ".mjs"))

		isInSourceDir := strings.Contains(filename, "/src/") ||
			strings.Contains(filename, "/lib/") && !strings.Contains(filename, "/dist/") && !strings.Contains(filename, "/build/")

		isMinified := strings.Contains(filename, ".min.") ||
			strings.Contains(filename, "/dist/") ||
			strings.Contains(filename, "/build/") ||
			strings.Contains(filename, "/bundle")

		if isSourceFile && isInSourceDir {
			hasSourceFile = true
			hasOnlyMinified = false
		}

		if isSourceFile && !isMinified {
			hasOnlyMinified = false
		}
	}

	// If we found source files in typical source directories, verification passes
	if hasSourceFile {
		return true, nil
	}

	// If all JS files are minified/in dist folders, verification fails
	if hasOnlyMinified && fileCount > 0 {
		return false, nil
	}

	// If we found non-minified JS files (even not in src/), give benefit of doubt
	return !hasOnlyMinified, nil
}

// scrapeNPMPackageInfo scrapes package information from npmjs.com web page
// Used as a fallback when the npm registry API fails
func (c *NPMClient) scrapeNPMPackageInfo(packageName string) (*NPMPackage, error) {
	pageURL := fmt.Sprintf("https://www.npmjs.com/package/%s", packageName)
	doc, err := scrapeWithUserAgent(pageURL)
	if err != nil {
		return nil, fmt.Errorf("scraping fallback failed: %w", err)
	}

	pkg := &NPMPackage{
		Name:        packageName,
		Maintainers: []string{},
		Scripts:     make(map[string]string),
	}

	// Extract version
	doc.Find("h3:contains('Version')").Parent().Find("p").Each(func(i int, s *goquery.Selection) {
		if i == 0 {
			pkg.LatestVersion = strings.TrimSpace(s.Text())
		}
	})

	// Extract download count from stats
	doc.Find("div._9ba9a726").Each(func(i int, s *goquery.Selection) {
		text := strings.TrimSpace(s.Text())
		if strings.Contains(strings.ToLower(text), "weekly downloads") {
			// Extract number from text
			re := regexp.MustCompile(`[\d,]+`)
			match := re.FindString(text)
			if match != "" {
				downloads, _ := strconv.ParseInt(strings.ReplaceAll(match, ",", ""), 10, 64)
				pkg.Downloads = downloads
			}
		}
	})

	// Extract maintainers
	doc.Find("a[href^='/~']").Each(func(i int, s *goquery.Selection) {
		maintainer := strings.TrimPrefix(s.Text(), "~")
		if maintainer != "" && !contains(pkg.Maintainers, maintainer) {
			pkg.Maintainers = append(pkg.Maintainers, maintainer)
		}
	})

	// Extract repository URL
	doc.Find("a[href*='github.com']").Each(func(i int, s *goquery.Selection) {
		if href, exists := s.Attr("href"); exists && strings.Contains(href, "github.com") {
			pkg.RepositoryURL = href
		}
	})

	// Extract license
	doc.Find("h3:contains('License')").Parent().Find("p a").Each(func(i int, s *goquery.Selection) {
		if i == 0 {
			pkg.License = strings.TrimSpace(s.Text())
		}
	})

	return pkg, nil
}

// contains checks if a string slice contains a string
func contains(slice []string, str string) bool {
	for _, s := range slice {
		if s == str {
			return true
		}
	}
	return false
}


func (c *NPMClient) GetOwnershipHistory(packageName string) (*NPMOwnershipHistory, error) {
	url := fmt.Sprintf("%s/%s", c.baseURL, packageName)

	resp, err := c.httpClient.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch npm package: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("npm registry returned status %d", resp.StatusCode)
	}

	var npmResp NPMRegistryResponse
	if err := json.NewDecoder(resp.Body).Decode(&npmResp); err != nil {
		return nil, fmt.Errorf("failed to decode npm response: %w", err)
	}

	history := &NPMOwnershipHistory{
		CurrentMaintainers:    extractMaintainers(npmResp.Maintainers),
		HistoricalMaintainers: []string{},
		MaintainerChanges:     0,
		RecentTransfer:        false,
	}

	// Track unique maintainers across all versions
	allMaintainers := make(map[string]bool)
	for _, m := range npmResp.Maintainers {
		if m.Name != "" {
			allMaintainers[m.Name] = true
		}
	}

	// Analyze maintainer changes across versions (sample recent versions)
	versionTimes := make(map[string]time.Time)
	for version, timeStr := range npmResp.Time {
		if version == "created" || version == "modified" {
			continue
		}
		if t, err := time.Parse(time.RFC3339, timeStr); err == nil {
			versionTimes[version] = t
		}
	}

	// Sort versions by time (oldest first) to detect changes chronologically
	type versionEntry struct {
		version string
		time    time.Time
	}
	sortedVersions := make([]versionEntry, 0, len(versionTimes))
	for version, vTime := range versionTimes {
		if _, exists := npmResp.Versions[version]; exists {
			sortedVersions = append(sortedVersions, versionEntry{version: version, time: vTime})
		}
	}
	sort.Slice(sortedVersions, func(i, j int) bool {
		return sortedVersions[i].time.Before(sortedVersions[j].time)
	})

	// Check versions for maintainer changes
	// Sample up to 10 most recent versions to detect changes
	checkedVersions := 0
	previousMaintainers := make(map[string]bool)

	for _, entry := range sortedVersions {
		if checkedVersions >= 10 {
			break
		}

		version := entry.version
		versionInfo := npmResp.Versions[version]
		versionMaintainers := extractMaintainers(versionInfo.Maintainers)
		currentSet := make(map[string]bool)

		for _, m := range versionMaintainers {
			allMaintainers[m] = true
			currentSet[m] = true
		}

		// Detect changes from previous version
		if checkedVersions > 0 {
			// Check if maintainers are completely different
			overlap := 0
			for m := range currentSet {
				if previousMaintainers[m] {
					overlap++
				}
			}

			// If there's no overlap and both have maintainers, it's a transfer
			if overlap == 0 && len(currentSet) > 0 && len(previousMaintainers) > 0 {
				history.MaintainerChanges++

				// Check if this is a recent transfer (within last 6 months)
				sixMonthsAgo := time.Now().AddDate(0, -6, 0)
				if entry.time.After(sixMonthsAgo) {
					history.RecentTransfer = true
					history.TransferDate = entry.time
				}
			}
		}

		previousMaintainers = currentSet
		checkedVersions++
	}

	// Build historical maintainers list (all maintainers not in current list)
	currentSet := make(map[string]bool)
	for _, m := range history.CurrentMaintainers {
		currentSet[m] = true
	}

	for m := range allMaintainers {
		if !currentSet[m] {
			history.HistoricalMaintainers = append(history.HistoricalMaintainers, m)
		}
	}

	return history, nil
}

// GetMaintainerPackageCount fetches the number of packages maintained by a specific user
//
// Methodology:
// - Search npm registry for packages by maintainer
// - npm API: GET https://registry.npmjs.org/-/v1/search?text=maintainer:{username}
// - Count total packages returned
//
// Note: This requires authentication for accurate results. Without auth, npm limits results.
//
// Risk Assessment:
// - 1-5 packages: LOW RISK (normal maintainer)
// - 6-49 packages: MEDIUM RISK (active contributor)
// - 50+ packages: HIGH RISK (high-value target, compromise = widespread impact)
//
// Justification:
// Maintainers with many packages are high-value targets. Compromising one account
// gives attackers control over entire package ecosystems.
//
// Real-world examples:
// - event-stream attack (2018): Maintainer handed over popular package to attacker
// - left-pad incident (2016): One maintainer controlled critical infrastructure packages
//
// Source: "Small World with High Risks" (Zimmermann et al., 2019)
// Finding: Top 500 npm maintainers collectively control 30% of the ecosystem
func (c *NPMClient) GetMaintainerPackageCount(username string) (int, error) {
	// Try to search for packages by this maintainer
	// npm search API: https://registry.npmjs.org/-/v1/search
	searchURL := fmt.Sprintf("https://registry.npmjs.org/-/v1/search?text=maintainer:%s&size=250", username)

	resp, err := c.httpClient.Get(searchURL)
	if err != nil {
		// Fallback: try alternative approach - search by author
		return c.searchByAuthor(username)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		// Fallback to author search
		return c.searchByAuthor(username)
	}

	var searchResp struct {
		Total   int `json:"total"`
		Objects []struct {
			Package struct {
				Name        string   `json:"name"`
				Maintainers []struct {
					Username string `json:"username"`
				} `json:"maintainers"`
			} `json:"package"`
		} `json:"objects"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&searchResp); err != nil {
		return 0, err
	}

	// Filter to only count packages where this user is actually a maintainer
	count := 0
	for _, obj := range searchResp.Objects {
		for _, maintainer := range obj.Package.Maintainers {
			if maintainer.Username == username {
				count++
				break
			}
		}
	}

	// If we hit the size limit (250), the actual count might be higher
	// Return the total from the API response if available
	if searchResp.Total > count {
		return searchResp.Total, nil
	}

	return count, nil
}

// searchByAuthor is a fallback method to search packages by author field
func (c *NPMClient) searchByAuthor(username string) (int, error) {
	searchURL := fmt.Sprintf("https://registry.npmjs.org/-/v1/search?text=author:%s&size=250", username)

	resp, err := c.httpClient.Get(searchURL)
	if err != nil {
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		// Unable to get count - return 0 as conservative estimate
		return 0, fmt.Errorf("npm search returned %d", resp.StatusCode)
	}

	var searchResp struct {
		Total int `json:"total"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&searchResp); err != nil {
		return 0, err
	}

	return searchResp.Total, nil
}
