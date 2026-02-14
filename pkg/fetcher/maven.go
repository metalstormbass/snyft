package fetcher

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
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
