package fetcher

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// NPMClient handles interactions with npm registry API
type NPMClient struct {
	httpClient *http.Client
	baseURL    string
}

// NPMPackage represents package information from npm
type NPMPackage struct {
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
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("package not found: %s", packageName)
	}

	if resp.StatusCode != http.StatusOK {
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
	}

	// Extract repository URL
	if npmResp.Repository.URL != "" {
		pkg.RepositoryURL = cleanRepositoryURL(npmResp.Repository.URL)
	} else if npmResp.Repository.TypeString != "" {
		pkg.RepositoryURL = cleanRepositoryURL(npmResp.Repository.TypeString)
	}

	// Get latest version info
	if latest, ok := npmResp.Versions[npmResp.DistTags.Latest]; ok {
		pkg.Version = latest.Version
		if t, err := time.Parse(time.RFC3339, latest.Time); err == nil {
			pkg.PublishedAt = t
		}
	}

	// Get download count (would need to query npm download stats API)
	// This is a simplified version - full implementation would make additional API call
	pkg.Downloads = 0

	return pkg, nil
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
	Time    string `json:"_npmUser"`
}

func extractMaintainers(maintainers []NPMMaintainer) []string {
	var names []string
	for _, m := range maintainers {
		if m.Name != "" {
			names = append(names, m.Name)
		}
	}
	return names
}
