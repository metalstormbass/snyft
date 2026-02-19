package fetcher

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"
)

// LibrariesIOClient handles interactions with the Libraries.io API.
// Used to enrich package metadata with ecosystem-wide adoption data
// (dependents count, contribution activity) that helps AI assess blast radius.
//
// Justification: A package with 10,000 dependents is a higher-value target for
// supply chain attackers than one with 10 dependents. This data is unavailable
// from registry APIs alone.
//
// Source: "Small World with High Risks" (Zimmermann et al., 2019) — dependency
// network analysis showing compromise propagation scales with dependents.
type LibrariesIOClient struct {
	httpClient *http.Client
	baseURL    string
	apiKey     string
}

// LibrariesIOPackageInfo contains package information from Libraries.io
type LibrariesIOPackageInfo struct {
	DependentsCount     int    `json:"dependents_count"`
	DependentReposCount int    `json:"dependent_repos_count"`
	ContributionsCount  int    `json:"contributions_count"`
	Rank                int    `json:"rank"`
	SecurityPolicyURL   string `json:"security_policy_url,omitempty"`
	LatestStableRelease string `json:"latest_stable_release_number"`
}

// NewLibrariesIOClient creates a new Libraries.io API client.
// The API key is read from the LIBRARIES_IO_API_KEY environment variable.
// If no key is set, the client will be non-functional (IsAvailable() returns false).
func NewLibrariesIOClient() *LibrariesIOClient {
	return &LibrariesIOClient{
		httpClient: &http.Client{Timeout: 15 * time.Second},
		baseURL:    "https://libraries.io/api",
		apiKey:     os.Getenv("LIBRARIES_IO_API_KEY"),
	}
}

// IsAvailable returns true if the Libraries.io API key is configured.
func (c *LibrariesIOClient) IsAvailable() bool {
	return c.apiKey != ""
}

// ecosystemPlatform maps our internal ecosystem names to Libraries.io platform names.
func ecosystemPlatform(ecosystem string) string {
	switch ecosystem {
	case "npm":
		return "npm"
	case "pypi":
		return "pypi"
	case "maven":
		return "maven"
	default:
		return ecosystem
	}
}

// GetPackageInfo fetches package information from the Libraries.io API.
// Returns nil on any error (graceful degradation — this is optional enrichment).
func (c *LibrariesIOClient) GetPackageInfo(ecosystem, name string) *LibrariesIOPackageInfo {
	if !c.IsAvailable() {
		return nil
	}

	platform := ecosystemPlatform(ecosystem)
	url := fmt.Sprintf("%s/%s/%s?api_key=%s", c.baseURL, platform, name, c.apiKey)

	resp, err := c.httpClient.Get(url)
	if err != nil {
		return nil
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	var info LibrariesIOPackageInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil
	}

	return &info
}
