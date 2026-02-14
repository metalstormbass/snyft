package fetcher

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
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
}

// MavenPackage represents package information from Maven Central
type MavenPackage struct {
	GroupID       string
	ArtifactID    string
	LatestVersion string
	RepositoryURL string
	License       string
	PublishedAt   time.Time
}

// NewMavenClient creates a new Maven Central client
func NewMavenClient() *MavenClient {
	return &MavenClient{
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		baseURL:   "https://repo1.maven.org/maven2",
		searchURL: "https://search.maven.org/solrsearch/select",
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

	// Search for the package
	searchURL := fmt.Sprintf("%s?q=g:%s+AND+a:%s&rows=1&wt=json",
		c.searchURL, groupID, artifactID)

	resp, err := c.httpClient.Get(searchURL)
	if err != nil {
		return nil, fmt.Errorf("failed to search Maven Central: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		// Try scraping fallback on rate limit or auth errors
		if shouldFallbackToScraping(nil, resp.StatusCode) {
			return c.scrapeMavenPackageInfo(packageName)
		}
		return nil, fmt.Errorf("maven Central returned status %d", resp.StatusCode)
	}

	var searchResp MavenSearchResponse
	if err := json.NewDecoder(resp.Body).Decode(&searchResp); err != nil {
		return nil, fmt.Errorf("failed to decode Maven search response: %w", err)
	}

	if len(searchResp.Response.Docs) == 0 {
		return nil, fmt.Errorf("package not found: %s", packageName)
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

	// Extract SCM URL
	if pom.SCM.URL != "" {
		pkg.RepositoryURL = pom.SCM.URL
	} else if pom.SCM.Connection != "" {
		// Parse scm:git: prefix
		pkg.RepositoryURL = strings.TrimPrefix(pom.SCM.Connection, "scm:git:")
	}

	// Extract license
	if len(pom.Licenses) > 0 {
		pkg.License = pom.Licenses[0].Name
	}

	return nil
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

// Maven POM structure (simplified)
type MavenPOM struct {
	XMLName  xml.Name      `xml:"project"`
	SCM      MavenSCM      `xml:"scm"`
	Licenses []MavenLicense `xml:"licenses>license"`
}

type MavenSCM struct {
	Connection string `xml:"connection"`
	DevConnection string `xml:"developerConnection"`
	URL        string `xml:"url"`
}

type MavenLicense struct {
	Name string `xml:"name"`
	URL  string `xml:"url"`
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
	if repoURL != "" && gitClient != nil {
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

	// Extract repository URL (often shows GitHub link)
	doc.Find("a[href*='github.com']").Each(func(i int, s *goquery.Selection) {
		if href, exists := s.Attr("href"); exists && pkg.RepositoryURL == "" {
			pkg.RepositoryURL = href
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

