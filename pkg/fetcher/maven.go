package fetcher

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/metalstormbass/snyft/pkg/models"
)

// MavenClient handles interactions with Maven Central
type MavenClient struct {
	httpClient *http.Client
	baseURL    string
	searchURL  string
	depsDevURL string // base URL for deps.dev API (default: https://api.deps.dev)
}

// MavenPackage represents package information from Maven Central
type MavenPackage struct {
	GroupID         string
	ArtifactID      string
	LatestVersion   string
	RepositoryURL   string
	License         string
	PublishedAt     time.Time // First version publish date (from Solr API)
	LastPublishedAt time.Time // Latest version publish date (from Solr API)
	Developers      []MavenDeveloper // From POM <developers> section
	VersionCount    int              // Number of versions published (from maven-metadata.xml)
	DirectDepCount  int              // Direct non-test dependencies from POM
	HasGPGSignature bool             // Whether .asc GPG signature file exists
}

// NewMavenClient creates a new Maven Central client
func NewMavenClient() *MavenClient {
	return &MavenClient{
		httpClient: &http.Client{
			// Reduced timeout - individual requests should be fast
			// Maven Central's APIs typically respond in < 1 second
			Timeout: 10 * time.Second,
		},
		baseURL:    "https://repo1.maven.org/maven2",
		searchURL:  "https://search.maven.org/solrsearch/select",
		depsDevURL: "https://api.deps.dev",
	}
}

// GetPackageInfo fetches package information from Maven Central
func (c *MavenClient) GetPackageInfo(packageName string) (*MavenPackage, error) {
	// Package name format: groupId:artifactId
	parts := strings.Split(packageName, ":")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid Maven package name format: %s (expected groupId:artifactId)", packageName)
	}

	groupID := parts[0]
	artifactID := parts[1]

	var pkg *MavenPackage

	// PRIMARY: Try direct maven-metadata.xml access (faster and more reliable)
	var err error
	pkg, err = c.getPackageInfoDirect(groupID, artifactID)
	if err != nil {
		// FALLBACK 1: Try Solr search API
		pkg, err = c.getPackageInfoViaSearch(groupID, artifactID)
	}
	if err != nil {
		// FALLBACK 2: Try scraping mvnrepository.com
		var scrapeErr error
		pkg, scrapeErr = c.scrapeMavenPackageInfo(packageName)
		if scrapeErr != nil {
			return nil, fmt.Errorf("failed to fetch package info: %w", err)
		}
	}

	// If no repository URL was found via POM-based strategies, try deps.dev
	// as a cross-ecosystem fallback.  The deps.dev API is free and unauthenticated.
	// Source: https://docs.deps.dev/api/v3/
	if pkg.RepositoryURL == "" {
		_ = c.enrichFromDepsDev(pkg)
	}

	// Enrich with publish date timestamps from Solr API.
	// This provides first publish date (for package maturity/age) and latest
	// publish date (for staleness detection when no git repo is available).
	_ = c.enrichWithPublishDates(pkg)

	// Check for GPG signature on the main artifact.
	// Maven Central has required GPG signatures since 2010, but verifying their
	// presence indicates the publisher followed proper release procedures.
	// Source: https://central.sonatype.org/publish/requirements/gpg/
	if pkg.LatestVersion != "" {
		pkg.HasGPGSignature = c.CheckGPGSignature(pkg.GroupID, pkg.ArtifactID, pkg.LatestVersion)
	}

	return pkg, nil
}

// getPackageInfoDirect fetches package info using direct maven-metadata.xml access
// This is faster and more reliable than the search API
func (c *MavenClient) getPackageInfoDirect(groupID, artifactID string) (*MavenPackage, error) {
	// Convert groupId to path (com.example -> com/example)
	groupPath := strings.ReplaceAll(groupID, ".", "/")

	// Fetch maven-metadata.xml
	metadataURL := fmt.Sprintf("%s/%s/%s/maven-metadata.xml",
		c.baseURL, groupPath, artifactID)

	resp, err := c.httpClient.Get(metadataURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch maven-metadata.xml: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("%w in Maven Central", ErrPackageNotFound)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("maven Central returned status %d", resp.StatusCode)
	}

	// Parse maven-metadata.xml
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read maven-metadata.xml: %w", err)
	}

	var metadata MavenMetadataXML
	if err := xml.Unmarshal(body, &metadata); err != nil {
		return nil, fmt.Errorf("failed to parse maven-metadata.xml: %w", err)
	}

	// Use release version, fallback to latest
	version := metadata.Versioning.Release
	if version == "" {
		version = metadata.Versioning.Latest
	}
	if version == "" && len(metadata.Versioning.Versions) > 0 {
		// Use last version in list
		version = metadata.Versioning.Versions[len(metadata.Versioning.Versions)-1]
	}

	if version == "" {
		return nil, fmt.Errorf("no version found in maven-metadata.xml")
	}

	pkg := &MavenPackage{
		GroupID:       groupID,
		ArtifactID:    artifactID,
		LatestVersion: version,
		VersionCount:  len(metadata.Versioning.Versions),
	}

	// Try to fetch POM to get more metadata (ignore errors and continue with basic info)
	_ = c.enrichFromPOM(pkg, groupID, artifactID, version)

	return pkg, nil
}

// getPackageInfoViaSearch fetches package info using the Solr search API (fallback method)
func (c *MavenClient) getPackageInfoViaSearch(groupID, artifactID string) (*MavenPackage, error) {
	searchURL := fmt.Sprintf("%s?q=g:%s+AND+a:%s&rows=1&wt=json",
		c.searchURL, groupID, artifactID)

	resp, err := c.httpClient.Get(searchURL)
	if err != nil {
		return nil, fmt.Errorf("failed to search Maven Central: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("maven Central search returned status %d", resp.StatusCode)
	}

	var searchResp MavenSearchResponse
	if err := json.NewDecoder(resp.Body).Decode(&searchResp); err != nil {
		return nil, fmt.Errorf("failed to decode Maven search response: %w", err)
	}

	if len(searchResp.Response.Docs) == 0 {
		return nil, ErrPackageNotFound
	}

	doc := searchResp.Response.Docs[0]

	pkg := &MavenPackage{
		GroupID:       doc.G,
		ArtifactID:    doc.A,
		LatestVersion: doc.LatestVersion,
	}

	// Try to fetch POM to get more metadata (ignore errors and continue with basic info)
	_ = c.enrichFromPOM(pkg, groupID, artifactID, doc.LatestVersion)

	return pkg, nil
}

func (c *MavenClient) enrichFromPOM(pkg *MavenPackage, groupID, artifactID, version string) error {
	// Construct POM URL
	groupPath := strings.ReplaceAll(groupID, ".", "/")
	pomURL := fmt.Sprintf("%s/%s/%s/%s/%s-%s.pom",
		c.baseURL, groupPath, artifactID, version, artifactID, version)

	resp, err := c.httpClient.Get(pomURL)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("POM not found")
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	var pom MavenPOM
	if err := xml.Unmarshal(body, &pom); err != nil {
		return err
	}

	// Repository URL resolution — cascading fallback chain.
	// Each strategy is tried only when all previous strategies failed.
	// The order reflects confidence: SCM > POM <url> > issueManagement >
	// parent POM > groupId heuristic > Apache/Eclipse platform fallbacks.

	// 1. SCM URL (highest confidence — explicitly declared source control)
	if pom.SCM.URL != "" {
		pkg.RepositoryURL = normalizeSCMURL(pom.SCM.URL)
	} else if pom.SCM.Connection != "" {
		// Parse scm:git: prefix
		raw := strings.TrimPrefix(pom.SCM.Connection, "scm:git:")
		pkg.RepositoryURL = normalizeSCMURL(raw)
	}

	// 2. POM <url> element — many projects set this to their GitHub page
	//    even when <scm> is missing or malformed.  Only accept URLs that
	//    point to a recognised git hosting provider.
	if pkg.RepositoryURL == "" && pom.URL != "" && isSourceRepoHost(pom.URL) {
		pkg.RepositoryURL = normalizeSCMURL(pom.URL)
	}

	// 3. Issue tracker URL — strip /issues suffix to derive repo URL.
	if pkg.RepositoryURL == "" {
		if derived := repoFromIssueURL(pom.IssueManagement.URL); derived != "" {
			pkg.RepositoryURL = derived
		}
	}

	// 4. Parent POM — multi-module Maven projects often store SCM only
	//    in the root/parent POM.
	//    Source: Maven POM reference — <scm> is inherited from parent.
	if pkg.RepositoryURL == "" &&
		pom.Parent.GroupID != "" &&
		pom.Parent.ArtifactID != "" &&
		pom.Parent.Version != "" {
		_ = c.enrichFromParentPOM(pkg, pom.Parent.GroupID, pom.Parent.ArtifactID, pom.Parent.Version)
	}

	// 5. GroupId-to-repository heuristic — io.github.*, com.github.*, etc.
	//    Includes Sonatype-verified prefixes and well-known Java foundations.
	//    Source: https://central.sonatype.org/publish/requirements/coordinates/
	if pkg.RepositoryURL == "" {
		if derived := deriveRepoFromGroupID(pkg.GroupID, pkg.ArtifactID); derived != "" {
			pkg.RepositoryURL = derived
		}
	}

	// Extract license
	if len(pom.Licenses) > 0 {
		pkg.License = pom.Licenses[0].Name
	}

	// Extract developers as proxy for maintainer/publisher data.
	// Maven Central does not expose a maintainer list via its API, but POM files
	// include a <developers> section listing the people who maintain the project.
	// Source: Maven POM reference — https://maven.apache.org/pom.html#developers
	if len(pom.Developers) > 0 {
		pkg.Developers = pom.Developers
	}

	// Count direct non-test dependencies from POM.
	// This provides a dependency sprawl signal even when no local pom.xml is available.
	directCount := 0
	for _, dep := range pom.Dependencies {
		if dep.Scope != "test" {
			directCount++
		}
	}
	pkg.DirectDepCount = directCount

	return nil
}

// enrichFromParentPOM fetches the parent POM and extracts SCM URL from it.
// Called when the artifact's own POM has no SCM element — common in multi-module
// projects (e.g. guava, jjwt, springdoc) where the root/parent POM holds SCM.
func (c *MavenClient) enrichFromParentPOM(pkg *MavenPackage, groupID, artifactID, version string) error {
	groupPath := strings.ReplaceAll(groupID, ".", "/")
	pomURL := fmt.Sprintf("%s/%s/%s/%s/%s-%s.pom",
		c.baseURL, groupPath, artifactID, version, artifactID, version)

	resp, err := c.httpClient.Get(pomURL)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("parent POM returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	var pom MavenPOM
	if err := xml.Unmarshal(body, &pom); err != nil {
		return err
	}

	if pom.SCM.URL != "" {
		pkg.RepositoryURL = normalizeSCMURL(pom.SCM.URL)
	} else if pom.SCM.Connection != "" {
		raw := strings.TrimPrefix(pom.SCM.Connection, "scm:git:")
		pkg.RepositoryURL = normalizeSCMURL(raw)
	}

	return nil
}

// enrichWithPublishDates queries the Maven Central Solr API to get the first
// and latest publish timestamps for a package.
//
// First publish date feeds into Package Maturity (Category 10) age assessment.
// Latest publish date provides a staleness fallback when no git repo is available.
//
// Source: Maven Central Solr search API — timestamp field on version documents
func (c *MavenClient) enrichWithPublishDates(pkg *MavenPackage) error {
	groupID := pkg.GroupID
	artifactID := pkg.ArtifactID

	// Get first publish date (oldest version)
	oldestURL := fmt.Sprintf("%s?q=g:%s+AND+a:%s&rows=1&wt=json&core=gav&sort=timestamp+asc",
		c.searchURL, url.QueryEscape(groupID), url.QueryEscape(artifactID))

	resp, err := c.httpClient.Get(oldestURL)
	if err != nil {
		return fmt.Errorf("failed to fetch oldest version: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("maven Central returned status %d for oldest version query", resp.StatusCode)
	}

	var searchResp struct {
		Response struct {
			Docs []struct {
				Timestamp int64 `json:"timestamp"`
			} `json:"docs"`
		} `json:"response"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&searchResp); err != nil {
		return fmt.Errorf("failed to decode oldest version response: %w", err)
	}

	if len(searchResp.Response.Docs) > 0 && searchResp.Response.Docs[0].Timestamp > 0 {
		pkg.PublishedAt = time.Unix(searchResp.Response.Docs[0].Timestamp/1000, 0)
	}

	// Get latest publish date (newest version)
	newestURL := fmt.Sprintf("%s?q=g:%s+AND+a:%s&rows=1&wt=json&core=gav&sort=timestamp+desc",
		c.searchURL, url.QueryEscape(groupID), url.QueryEscape(artifactID))

	resp2, err := c.httpClient.Get(newestURL)
	if err != nil {
		return fmt.Errorf("failed to fetch newest version: %w", err)
	}
	defer func() { _ = resp2.Body.Close() }()

	if resp2.StatusCode != http.StatusOK {
		return fmt.Errorf("maven Central returned status %d for newest version query", resp2.StatusCode)
	}

	var searchResp2 struct {
		Response struct {
			Docs []struct {
				Timestamp int64 `json:"timestamp"`
			} `json:"docs"`
		} `json:"response"`
	}
	if err := json.NewDecoder(resp2.Body).Decode(&searchResp2); err != nil {
		return fmt.Errorf("failed to decode newest version response: %w", err)
	}

	if len(searchResp2.Response.Docs) > 0 && searchResp2.Response.Docs[0].Timestamp > 0 {
		pkg.LastPublishedAt = time.Unix(searchResp2.Response.Docs[0].Timestamp/1000, 0)
	}

	return nil
}

// CheckGPGSignature checks whether a GPG signature (.asc file) exists for a
// Maven artifact in Maven Central.
//
// Maven Central has required GPG signing for artifact uploads since 2010.
// The presence of a .asc file indicates the publisher used proper release procedures
// and their identity can be verified against public keyservers.
//
// Source: https://central.sonatype.org/publish/requirements/gpg/
func (c *MavenClient) CheckGPGSignature(groupID, artifactID, version string) bool {
	groupPath := strings.ReplaceAll(groupID, ".", "/")
	ascURL := fmt.Sprintf("%s/%s/%s/%s/%s-%s.jar.asc",
		c.baseURL, groupPath, artifactID, version, artifactID, version)

	resp, err := c.httpClient.Head(ascURL)
	if err != nil {
		return false
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode == http.StatusOK
}

// Maven API response structures
type MavenSearchResponse struct {
	Response MavenSearchResponseBody `json:"response"`
}

type MavenSearchResponseBody struct {
	NumFound int              `json:"numFound"`
	Docs     []MavenSearchDoc `json:"docs"`
}

type MavenSearchDoc struct {
	ID            string `json:"id"`
	G             string `json:"g"`
	A             string `json:"a"`
	LatestVersion string `json:"latestVersion"`
	RepositoryID  string `json:"repositoryId"`
	Timestamp     int64  `json:"timestamp"`
}

// MavenDeveloper represents a developer entry from the POM <developers> section.
// POM developers serve as proxy for maintainer/publisher data, which Maven Central
// does not expose via its API.
// Source: Maven POM reference — https://maven.apache.org/pom.html#developers
type MavenDeveloper struct {
	ID           string `xml:"id"`
	Name         string `xml:"name"`
	Email        string `xml:"email"`
	Organization string `xml:"organization"`
}

// MavenPOMDependency represents a dependency entry from the POM <dependencies> section.
type MavenPOMDependency struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Version    string `xml:"version"`
	Scope      string `xml:"scope"`
}

// Maven POM structure — includes dependencyManagement and properties
// for version resolution from parent BOMs, plus developers and dependencies
// for enrichment.
type MavenPOM struct {
	XMLName              xml.Name                     `xml:"project"`
	GroupID              string                       `xml:"groupId"`
	ArtifactID           string                       `xml:"artifactId"`
	Version              string                       `xml:"version"`
	Parent               MavenParent                  `xml:"parent"`
	URL                  string                       `xml:"url"`
	SCM                  MavenSCM                     `xml:"scm"`
	IssueManagement      MavenIssueManagement         `xml:"issueManagement"`
	Licenses             []MavenLicense               `xml:"licenses>license"`
	Developers           []MavenDeveloper             `xml:"developers>developer"`
	Dependencies         []MavenPOMDependency         `xml:"dependencies>dependency"`
	Properties           MavenPOMProperties           `xml:"properties"`
	DependencyManagement MavenPOMDependencyManagement `xml:"dependencyManagement"`
}

// MavenPOMProperties represents the <properties> section of a Maven POM.
// Uses a custom XML unmarshaler since property names are dynamic element names.
type MavenPOMProperties struct {
	Entries map[string]string
}

// UnmarshalXML implements custom XML unmarshaling for dynamic property elements.
func (p *MavenPOMProperties) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	p.Entries = make(map[string]string)
	for {
		tok, err := d.Token()
		if err != nil {
			return err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			var value string
			if err := d.DecodeElement(&value, &t); err != nil {
				return err
			}
			p.Entries[t.Name.Local] = value
		case xml.EndElement:
			return nil
		}
	}
}

// MavenPOMDependencyManagement represents the <dependencyManagement> section.
type MavenPOMDependencyManagement struct {
	Dependencies []MavenPOMManagedDep `xml:"dependencies>dependency"`
}

// MavenPOMManagedDep represents a dependency entry in dependencyManagement.
type MavenPOMManagedDep struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Version    string `xml:"version"`
	Scope      string `xml:"scope"`
	Type       string `xml:"type"`
}

type MavenIssueManagement struct {
	URL string `xml:"url"`
}

type MavenParent struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Version    string `xml:"version"`
}

type MavenSCM struct {
	Connection    string `xml:"connection"`
	DevConnection string `xml:"developerConnection"`
	URL           string `xml:"url"`
}

type MavenLicense struct {
	Name string `xml:"name"`
	URL  string `xml:"url"`
}

// MavenMetadataXML represents the maven-metadata.xml structure
type MavenMetadataXML struct {
	XMLName    xml.Name              `xml:"metadata"`
	GroupID    string                `xml:"groupId"`
	ArtifactID string                `xml:"artifactId"`
	Versioning MavenMetadataVersioning `xml:"versioning"`
}

type MavenMetadataVersioning struct {
	Latest      string   `xml:"latest"`
	Release     string   `xml:"release"`
	Versions    []string `xml:"versions>version"`
	LastUpdated string   `xml:"lastUpdated"` // Format: yyyyMMddHHmmss
}

// GetVersionHistory fetches version publish timestamps from Maven Central.
// Uses the Solr search API to query all versions of an artifact with their
// timestamps, paginating through results with the start parameter.
// Falls back to maven-metadata.xml version list without timestamps
// when the search API is unavailable.
//
// Justification: When a package has no GitHub releases/tags, this data provides
// temporal release patterns needed for dormancy reactivation detection and
// cadence regularity analysis.
// Source: Maven Central Solr search API — timestamp field on version documents
func (c *MavenClient) GetVersionHistory(packageName string) ([]RegistryRelease, error) {
	parts := strings.Split(packageName, ":")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid Maven package name: %s (expected groupId:artifactId)", packageName)
	}
	groupID := parts[0]
	artifactID := parts[1]

	const rowsPerPage = 200
	var allReleases []RegistryRelease

	for page := 0; page < maxPaginationPages; page++ {
		startOffset := page * rowsPerPage
		searchURL := fmt.Sprintf("%s?q=g:%s+AND+a:%s&rows=%d&start=%d&wt=json&core=gav",
			c.searchURL, url.QueryEscape(groupID), url.QueryEscape(artifactID),
			rowsPerPage, startOffset)

		resp, err := c.httpClient.Get(searchURL)
		if err != nil {
			if page == 0 {
				return nil, fmt.Errorf("failed to search Maven Central: %w", err)
			}
			break
		}

		if resp.StatusCode != http.StatusOK {
			_ = resp.Body.Close()
			if page == 0 {
				return nil, fmt.Errorf("maven Central search returned status %d", resp.StatusCode)
			}
			break
		}

		var searchResp struct {
			Response struct {
				NumFound int `json:"numFound"`
				Docs     []struct {
					V         string `json:"v"`
					Timestamp int64  `json:"timestamp"`
				} `json:"docs"`
			} `json:"response"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&searchResp); err != nil {
			_ = resp.Body.Close()
			if page == 0 {
				return nil, fmt.Errorf("failed to decode Maven search response: %w", err)
			}
			break
		}
		_ = resp.Body.Close()

		for _, doc := range searchResp.Response.Docs {
			if doc.V == "" || doc.Timestamp == 0 {
				continue
			}
			publishedAt := time.Unix(doc.Timestamp/1000, 0)
			// Detect prerelease versions (Maven convention: SNAPSHOT, RC, alpha, beta)
			isPrerelease := strings.Contains(strings.ToLower(doc.V), "snapshot") ||
				strings.Contains(strings.ToLower(doc.V), "-rc") ||
				strings.Contains(strings.ToLower(doc.V), "-alpha") ||
				strings.Contains(strings.ToLower(doc.V), "-beta")
			allReleases = append(allReleases, RegistryRelease{
				Version:      doc.V,
				PublishedAt:  publishedAt,
				IsPrerelease: isPrerelease,
			})
		}

		// Stop when we've fetched all results or got an empty page
		if len(searchResp.Response.Docs) == 0 ||
			startOffset+len(searchResp.Response.Docs) >= searchResp.Response.NumFound {
			break
		}
	}

	// Sort newest first (matching GitHub release ordering)
	sort.Slice(allReleases, func(i, j int) bool {
		return allReleases[i].PublishedAt.After(allReleases[j].PublishedAt)
	})

	return allReleases, nil
}

// VerifySourceAvailability verifies that source code exists for the exact version
// Checks: 1) sources.jar exists in Maven Central, 2) matching git tag exists
func (c *MavenClient) VerifySourceAvailability(packageName, version string, repoURL string, gitClient GitPlatformClient) *models.SourceVerification {
	result := &models.SourceVerification{
		Verified:           false,
		HasSourcePackage:   false,
		HasMatchingGitTag:  false,
		VerificationErrors: []string{},
	}

	// Parse package name (format: groupId:artifactId)
	parts := strings.Split(packageName, ":")
	if len(parts) != 2 {
		result.VerificationErrors = append(result.VerificationErrors, "Invalid Maven package name format")
		result.Details = "Expected format: groupId:artifactId"
		return result
	}

	groupID := parts[0]
	artifactID := parts[1]

	// Construct sources.jar URL
	groupPath := strings.ReplaceAll(groupID, ".", "/")
	sourcesURL := fmt.Sprintf("%s/%s/%s/%s/%s-%s-sources.jar",
		c.baseURL, groupPath, artifactID, version, artifactID, version)

	result.SourcePackageURL = sourcesURL

	// Check if sources.jar exists
	resp, err := c.httpClient.Head(sourcesURL)
	if err != nil {
		result.VerificationErrors = append(result.VerificationErrors, fmt.Sprintf("Failed to check sources.jar: %v", err))
		result.Details = "Could not verify sources.jar availability"
	} else {
		defer func() { _ = resp.Body.Close() }()
		switch resp.StatusCode {
		case http.StatusOK:
			result.HasSourcePackage = true
		case http.StatusNotFound:
			result.VerificationErrors = append(result.VerificationErrors, "sources.jar not found in Maven Central")
			result.Details = "Package does not publish sources.jar"
		default:
			result.VerificationErrors = append(result.VerificationErrors, fmt.Sprintf("Maven Central returned status %d for sources.jar", resp.StatusCode))
			result.Details = "Could not verify sources.jar"
		}
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
		result.Details = fmt.Sprintf("Source code verified for v%s: sources.jar exists, git tag exists", version)
	} else if result.HasSourcePackage && !result.HasMatchingGitTag {
		result.Details = fmt.Sprintf("Partial verification: sources.jar exists but no matching git tag for v%s", version)
	} else if !result.HasSourcePackage && result.HasMatchingGitTag {
		result.Details = fmt.Sprintf("Partial verification: git tag exists but no sources.jar for v%s", version)
	} else {
		result.Details = fmt.Sprintf("Source verification failed for v%s", version)
	}

	return result
}

// repoFromIssueURL tries to derive a repository URL from an issue tracker
// URL by stripping common suffixes like "/issues", "/-/issues", "/jira", etc.
func repoFromIssueURL(issueURL string) string {
	if issueURL == "" || !isSourceRepoHost(issueURL) {
		return ""
	}
	trimmed := strings.TrimRight(issueURL, "/")
	for _, suffix := range []string{"/issues", "/-/issues"} {
		if strings.HasSuffix(trimmed, suffix) {
			return normalizeSCMURL(strings.TrimSuffix(trimmed, suffix))
		}
	}
	return ""
}

// deriveRepoFromGroupID infers a repository URL from well-known groupId
// patterns.  Sonatype's Central Repository requires domain ownership
// verification for io.github.*, com.github.*, io.gitlab.*, io.bitbucket.*
// prefixes, so these heuristics are high-confidence.
// Source: https://central.sonatype.org/publish/requirements/coordinates/
func deriveRepoFromGroupID(groupID, artifactID string) string {
	parts := strings.Split(groupID, ".")

	type mapping struct {
		prefix   []string
		template string // %s = username, %s = artifactID
	}
	mappings := []mapping{
		{[]string{"io", "github"}, "https://github.com/%s/%s"},
		{[]string{"com", "github"}, "https://github.com/%s/%s"},
		{[]string{"io", "gitlab"}, "https://gitlab.com/%s/%s"},
		{[]string{"io", "bitbucket"}, "https://bitbucket.org/%s/%s"},
	}

	for _, m := range mappings {
		if len(parts) > len(m.prefix) {
			match := true
			for i, p := range m.prefix {
				if parts[i] != p {
					match = false
					break
				}
			}
			if match {
				username := parts[len(m.prefix)]
				return fmt.Sprintf(m.template, username, artifactID)
			}
		}
	}

	// Eclipse Foundation projects are mirrored on GitHub.
	if len(parts) >= 2 && parts[0] == "org" && parts[1] == "eclipse" {
		return "https://github.com/eclipse/" + artifactID
	}

	// Well-known Java foundation and organization mappings.
	// These map groupId prefixes to GitHub organizations based on
	// verified, documented, official repository structures.
	//
	// Unlike io.github.*/com.github.* (Sonatype-enforced), these rely
	// on foundation/org governance ensuring stable URL patterns.
	// They are used as a heuristic fallback — if the repo doesn't exist,
	// the git client fails gracefully and risk checks use "unknown" scores.

	// Apache Software Foundation: all projects mirrored on GitHub.
	// Uses GitHub (not gitbox.apache.org) to enable full risk assessment
	// via the GitHub API (maintainers, releases, PRs, signed commits, etc.).
	// Source: https://infra.apache.org/github-actions-policy.html
	if len(parts) >= 2 && parts[0] == "org" && parts[1] == "apache" {
		return "https://github.com/apache/" + artifactID
	}

	// FasterXML (Jackson ecosystem): consistently named on GitHub.
	// FasterXML is one of the most widely used Java library publishers
	// (jackson-core, jackson-databind, jackson-annotations, woodstox, etc.)
	// Source: https://github.com/FasterXML — all repos match artifactId
	if len(parts) >= 2 && parts[0] == "com" && parts[1] == "fasterxml" {
		return "https://github.com/FasterXML/" + artifactID
	}

	// Square (OkHttp, Retrofit, Moshi, Wire): consistently named on GitHub.
	// Square's open source libraries use "square" as the GitHub org.
	// Source: https://github.com/square — repos match artifactId
	if len(parts) >= 2 && parts[0] == "com" && parts[1] == "squareup" {
		return "https://github.com/square/" + artifactID
	}

	return ""
}

// apacheGitboxToGitHub converts Apache gitbox.apache.org (and git.apache.org)
// URLs to their GitHub mirror equivalents.  All Apache Software Foundation
// projects are mirrored on GitHub under the "apache" organisation.  Using the
// GitHub mirror enables full risk assessment via the GitHub API (maintainers,
// releases, PRs, signed commits, etc.) instead of the limited GenericGitClient.
//
// Handles two URL styles found in the wild:
//
//	Path-based:  https://gitbox.apache.org/repos/asf/commons-io.git
//	Query-param: https://gitbox.apache.org/repos/asf?p=commons-io.git
//
// Source: https://infra.apache.org/github-actions-policy.html
func apacheGitboxToGitHub(rawURL string) string {
	lower := strings.ToLower(rawURL)
	if !strings.Contains(lower, "gitbox.apache.org") &&
		!strings.Contains(lower, "git.apache.org") {
		return ""
	}

	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}

	// Query-param style: ?p=commons-io or ?p=commons-io.git
	if p := u.Query().Get("p"); p != "" {
		repoName := strings.TrimSuffix(p, ".git")
		return "https://github.com/apache/" + repoName
	}

	// Path-based style: /repos/asf/commons-io.git
	segments := strings.Split(strings.Trim(u.Path, "/"), "/")
	// Expected layout: repos/asf/<repo-name>
	if len(segments) >= 3 && segments[0] == "repos" && segments[1] == "asf" {
		repoName := strings.TrimSuffix(segments[2], ".git")
		return "https://github.com/apache/" + repoName
	}

	return ""
}

// normalizeSCMURL trims SCM URLs to the canonical repository root.
// Some POM files contain extra path segments after the owner/repo portion
// (e.g. "https://github.com/mapstruct/mapstruct/mapstruct/"). Keeping these
// extra segments causes GitHub and other platform parsers to reject the URL.
func normalizeSCMURL(rawURL string) string {
	if rawURL == "" {
		return ""
	}

	// Convert Apache gitbox/git URLs to GitHub mirrors before any other
	// processing.  This ensures that wherever a gitbox URL appears (SCM,
	// POM <url>, issue tracker) it is resolved to the GitHub mirror.
	if gh := apacheGitboxToGitHub(rawURL); gh != "" {
		return gh
	}

	// Strip trailing .git for uniform handling, restore later if needed
	clean := strings.TrimSuffix(strings.TrimRight(rawURL, "/"), ".git")

	// Detect known hosting prefixes and truncate to owner/repo
	for _, prefix := range []string{
		"https://github.com/",
		"http://github.com/",
		"https://gitlab.com/",
		"http://gitlab.com/",
		"https://bitbucket.org/",
		"http://bitbucket.org/",
	} {
		if strings.HasPrefix(clean, prefix) {
			rest := strings.TrimPrefix(clean, prefix)
			parts := strings.SplitN(rest, "/", 3)
			if len(parts) >= 2 && parts[0] != "" && parts[1] != "" {
				return prefix + parts[0] + "/" + parts[1]
			}
		}
	}

	return rawURL
}

// scrapeMavenPackageInfo scrapes package information from mvnrepository.com
// Used as a fallback when Maven Central search API fails
func (c *MavenClient) scrapeMavenPackageInfo(packageName string) (*MavenPackage, error) {
	// Parse package name (format: groupId:artifactId)
	parts := strings.Split(packageName, ":")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid Maven package name format: %s (expected groupId:artifactId)", packageName)
	}

	groupID := parts[0]
	artifactID := parts[1]

	// Build mvnrepository.com URL
	pageURL := fmt.Sprintf("https://mvnrepository.com/artifact/%s/%s", groupID, artifactID)

	doc, err := scrapeWithUserAgent(pageURL)
	if err != nil {
		return nil, fmt.Errorf("scraping fallback failed: %w", err)
	}

	pkg := &MavenPackage{
		GroupID:    groupID,
		ArtifactID: artifactID,
	}

	// Extract latest version
	doc.Find("a.vbtn.release").First().Each(func(i int, s *goquery.Selection) {
		pkg.LatestVersion = strings.TrimSpace(s.Text())
	})

	// Extract license from the page
	doc.Find("span.b.lic").Each(func(i int, s *goquery.Selection) {
		if i == 0 {
			pkg.License = strings.TrimSpace(s.Text())
		}
	})

	// Extract repository URL — check all known git hosting providers,
	// not just GitHub.
	doc.Find("a[href]").Each(func(i int, s *goquery.Selection) {
		if pkg.RepositoryURL != "" {
			return
		}
		if href, exists := s.Attr("href"); exists && isSourceRepoHost(href) {
			pkg.RepositoryURL = normalizeSCMURL(href)
		}
	})

	// Extract usage stats if available (number of usages shown on mvnrepository)
	doc.Find("td:contains('Usages')").Next().Each(func(i int, s *goquery.Selection) {
		text := strings.TrimSpace(s.Text())
		// Extract number from text
		numStr := strings.ReplaceAll(text, ",", "")
		// Parse usage count (not currently stored in MavenPackage struct)
		_, _ = strconv.Atoi(numStr)
	})

	return pkg, nil
}

// enrichFromDepsDev queries Google's deps.dev API for the source repository
// URL.  deps.dev aggregates metadata from Maven Central and normalises POM
// fields, so it often succeeds even when our own POM parsing finds nothing.
// The API is free, unauthenticated, and globally replicated on Google Cloud.
// Source: https://docs.deps.dev/api/v3/
func (c *MavenClient) enrichFromDepsDev(pkg *MavenPackage) error {
	version := pkg.LatestVersion
	if version == "" {
		return fmt.Errorf("no version available for deps.dev lookup")
	}

	// deps.dev expects the package name URL-encoded (colons → %3A, dots → %2E, etc.)
	pkgEncoded := url.PathEscape(pkg.GroupID + ":" + pkg.ArtifactID)
	versionEncoded := url.PathEscape(version)

	depsDevBase := c.depsDevURL
	if depsDevBase == "" {
		depsDevBase = "https://api.deps.dev"
	}

	apiURL := fmt.Sprintf("%s/v3/systems/maven/packages/%s/versions/%s",
		depsDevBase, pkgEncoded, versionEncoded)

	resp, err := c.httpClient.Get(apiURL)
	if err != nil {
		return fmt.Errorf("deps.dev request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("deps.dev returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read deps.dev response: %w", err)
	}

	var depsResp depsDevVersionResponse
	if err := json.Unmarshal(body, &depsResp); err != nil {
		return fmt.Errorf("failed to parse deps.dev response: %w", err)
	}

	// First try links with label "SOURCE_REPO" — these are raw URLs.
	for _, link := range depsResp.Links {
		if link.Label == "SOURCE_REPO" && link.URL != "" {
			pkg.RepositoryURL = normalizeSCMURL(link.URL)
			return nil
		}
	}

	// Fall back to relatedProjects with relationType "SOURCE_REPO" —
	// these use a normalised project key like "github.com/owner/repo".
	for _, rp := range depsResp.RelatedProjects {
		if rp.RelationType == "SOURCE_REPO" && rp.ProjectKey.ID != "" {
			// Project key is in format "github.com/owner/repo" — add https://
			repoURL := "https://" + rp.ProjectKey.ID
			if isSourceRepoHost(repoURL) {
				pkg.RepositoryURL = normalizeSCMURL(repoURL)
				return nil
			}
		}
	}

	return fmt.Errorf("no SOURCE_REPO found in deps.dev response")
}

// deps.dev API response types (only the fields we need)
type depsDevVersionResponse struct {
	Links           []depsDevLink           `json:"links"`
	RelatedProjects []depsDevRelatedProject `json:"relatedProjects"`
}

type depsDevLink struct {
	Label string `json:"label"`
	URL   string `json:"url"`
}

type depsDevRelatedProject struct {
	ProjectKey         depsDevProjectKey `json:"projectKey"`
	RelationType       string            `json:"relationType"`
	RelationProvenance string            `json:"relationProvenance"`
}

type depsDevProjectKey struct {
	ID string `json:"id"`
}

// BOMImport represents an imported BOM reference (scope=import, type=pom)
// from a local POM's dependencyManagement section.
type BOMImport struct {
	GroupID    string
	ArtifactID string
	Version    string
}

// ResolveBOMVersions resolves "unknown" versions in Maven dependencies by
// fetching the parent POM chain and imported BOMs from Maven Central,
// looking up versions in <dependencyManagement> sections and <properties>.
//
// This follows Maven's version resolution model:
// 1. Properties from the parent chain (child values take precedence)
// 2. dependencyManagement entries from the parent chain (nearest definition wins)
// 3. Imported BOMs (scope=import, type=pom) are followed recursively
// 4. Property references within dependencyManagement versions are resolved
// 5. Unresolved property refs from the local POM are resolved using parent properties
//
// bomImports: imported BOMs from the local POM's dependencyManagement
// unresolvedRefs: map of depName → original ${property} ref for locally-unresolved deps
//
// Justification: Accurate version identification is critical for source
// verification — if version is "unknown", we cannot verify sources.jar
// existence or git tag matches, leading to false risk inflation.
// Source: Maven POM reference — dependency management inheritance
func (c *MavenClient) ResolveBOMVersions(deps []models.Dependency, parentGroupID, parentArtifactID, parentVersion string, bomImports []BOMImport, unresolvedRefs map[string]string) []models.Dependency {
	hasParent := parentGroupID != "" && parentArtifactID != "" && parentVersion != ""
	hasBOMImports := len(bomImports) > 0
	hasUnresolved := len(unresolvedRefs) > 0

	if !hasParent && !hasBOMImports && !hasUnresolved {
		return deps
	}

	// Collect properties and dependencyManagement entries from the parent chain
	properties := make(map[string]string)
	depMgmt := make(map[string]string)

	if hasParent {
		c.fetchParentChain(parentGroupID, parentArtifactID, parentVersion, properties, depMgmt, 0)
	}

	// Follow locally-declared BOM imports
	for _, bom := range bomImports {
		c.fetchBOMImport(bom.GroupID, bom.ArtifactID, bom.Version, properties, depMgmt, 0)
	}

	if len(properties) == 0 && len(depMgmt) == 0 {
		return deps
	}

	// Resolve property references within property values (iterative)
	for i := 0; i < 5; i++ {
		changed := false
		for k, v := range properties {
			if strings.Contains(v, "${") {
				resolved := resolveMavenPropertyRefs(v, properties)
				if resolved != v {
					properties[k] = resolved
					changed = true
				}
			}
		}
		if !changed {
			break
		}
	}

	// Resolve property references within dependencyManagement versions
	for k, v := range depMgmt {
		if strings.Contains(v, "${") {
			depMgmt[k] = resolveMavenPropertyRefs(v, properties)
		}
	}

	// Resolve unknown versions in dependencies
	resolved := make([]models.Dependency, len(deps))
	copy(resolved, deps)

	for i, dep := range resolved {
		if dep.Ecosystem != models.EcosystemMaven {
			continue
		}

		if dep.Version == "unknown" {
			// Try resolving unresolved property refs using parent properties
			if ref, ok := unresolvedRefs[dep.Name]; ok {
				propResolved := resolveMavenPropertyRefs(ref, properties)
				if !strings.Contains(propResolved, "${") && propResolved != "" {
					resolved[i].Version = propResolved
					continue
				}
			}

			// Fall back to dependencyManagement lookup
			if version, ok := depMgmt[dep.Name]; ok {
				if version != "" && !strings.Contains(version, "${") {
					resolved[i].Version = version
				}
			}
		}
	}

	return resolved
}

// fetchParentChain recursively fetches parent POMs from Maven Central,
// collecting properties and dependencyManagement entries.
// Follows Maven's "nearest definition wins" rule: child values are not
// overwritten by parent values.
// Also follows imported BOMs (scope=import, type=pom) in dependencyManagement.
// Maximum recursion depth of 5 prevents infinite loops.
func (c *MavenClient) fetchParentChain(groupID, artifactID, version string, properties map[string]string, depMgmt map[string]string, depth int) {
	if depth > 5 {
		return
	}

	pom, err := c.fetchBOMPOM(groupID, artifactID, version)
	if err != nil {
		return // graceful degradation
	}

	// Add properties (child values take precedence — don't overwrite)
	if pom.Properties.Entries != nil {
		for k, v := range pom.Properties.Entries {
			if _, exists := properties[k]; !exists {
				properties[k] = v
			}
		}
	}

	// Add built-in properties for this POM
	pomVersion := pom.Version
	if pomVersion == "" && pom.Parent.Version != "" {
		pomVersion = pom.Parent.Version
	}
	if pomVersion != "" {
		if _, exists := properties["project.parent.version"]; !exists {
			properties["project.parent.version"] = pomVersion
		}
	}

	// Process dependencyManagement entries:
	// - Regular entries: add to depMgmt (nearest definition wins)
	// - BOM imports (scope=import, type=pom): follow recursively
	for _, dep := range pom.DependencyManagement.Dependencies {
		if strings.EqualFold(dep.Scope, "import") && strings.EqualFold(dep.Type, "pom") {
			// Resolve property refs in BOM version before following
			bomVersion := dep.Version
			if strings.Contains(bomVersion, "${") {
				bomVersion = resolveMavenPropertyRefs(bomVersion, properties)
				if strings.Contains(bomVersion, "${") {
					continue // can't resolve BOM version
				}
			}
			c.fetchBOMImport(dep.GroupID, dep.ArtifactID, bomVersion, properties, depMgmt, depth+1)
			continue
		}

		key := dep.GroupID + ":" + dep.ArtifactID
		if _, exists := depMgmt[key]; !exists {
			depMgmt[key] = dep.Version
		}
	}

	// Follow parent chain
	if pom.Parent.GroupID != "" && pom.Parent.ArtifactID != "" && pom.Parent.Version != "" {
		c.fetchParentChain(pom.Parent.GroupID, pom.Parent.ArtifactID, pom.Parent.Version, properties, depMgmt, depth+1)
	}
}

// fetchBOMImport fetches an imported BOM POM (scope=import, type=pom) and
// merges its dependencyManagement entries and properties.
// Follows the same "nearest definition wins" rule as fetchParentChain.
// Also follows nested BOM imports and parent chains within the imported BOM.
func (c *MavenClient) fetchBOMImport(groupID, artifactID, version string, properties map[string]string, depMgmt map[string]string, depth int) {
	if depth > 5 {
		return
	}

	pom, err := c.fetchBOMPOM(groupID, artifactID, version)
	if err != nil {
		return // graceful degradation
	}

	// Add properties from imported BOM (nearest wins)
	if pom.Properties.Entries != nil {
		for k, v := range pom.Properties.Entries {
			if _, exists := properties[k]; !exists {
				properties[k] = v
			}
		}
	}

	// Process dependencyManagement entries from imported BOM
	for _, dep := range pom.DependencyManagement.Dependencies {
		if strings.EqualFold(dep.Scope, "import") && strings.EqualFold(dep.Type, "pom") {
			bomVersion := dep.Version
			if strings.Contains(bomVersion, "${") {
				bomVersion = resolveMavenPropertyRefs(bomVersion, properties)
				if strings.Contains(bomVersion, "${") {
					continue
				}
			}
			c.fetchBOMImport(dep.GroupID, dep.ArtifactID, bomVersion, properties, depMgmt, depth+1)
			continue
		}

		key := dep.GroupID + ":" + dep.ArtifactID
		if _, exists := depMgmt[key]; !exists {
			depMgmt[key] = dep.Version
		}
	}

	// Follow imported BOM's own parent chain
	if pom.Parent.GroupID != "" && pom.Parent.ArtifactID != "" && pom.Parent.Version != "" {
		c.fetchParentChain(pom.Parent.GroupID, pom.Parent.ArtifactID, pom.Parent.Version, properties, depMgmt, depth+1)
	}
}

// fetchBOMPOM fetches and parses a POM file from Maven Central for BOM resolution.
func (c *MavenClient) fetchBOMPOM(groupID, artifactID, version string) (*MavenPOM, error) {
	groupPath := strings.ReplaceAll(groupID, ".", "/")
	pomURL := fmt.Sprintf("%s/%s/%s/%s/%s-%s.pom",
		c.baseURL, groupPath, artifactID, version, artifactID, version)

	resp, err := c.httpClient.Get(pomURL)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("POM returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var pom MavenPOM
	if err := xml.Unmarshal(body, &pom); err != nil {
		return nil, err
	}

	return &pom, nil
}

// mavenPropertyRefRegex matches Maven property references like ${spring.version}
var mavenPropertyRefRegex = regexp.MustCompile(`\$\{([^}]+)\}`)

// resolveMavenPropertyRefs replaces all ${property.name} references in a string
// with their values from the properties map.
func resolveMavenPropertyRefs(value string, properties map[string]string) string {
	return mavenPropertyRefRegex.ReplaceAllStringFunc(value, func(match string) string {
		propName := match[2 : len(match)-1]
		if resolved, ok := properties[propName]; ok {
			return resolved
		}
		return match
	})
}

