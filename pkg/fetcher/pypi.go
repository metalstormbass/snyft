package fetcher

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
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
