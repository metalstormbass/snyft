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
	Scripts       map[string]string // Install-time scripts (postinstall, preinstall, etc.)
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

	// Extract repository URL
	if npmResp.Repository.URL != "" {
		pkg.RepositoryURL = cleanRepositoryURL(npmResp.Repository.URL)
	} else if npmResp.Repository.TypeString != "" {
		pkg.RepositoryURL = cleanRepositoryURL(npmResp.Repository.TypeString)
	}

	// Get latest version info and scripts
	if latest, ok := npmResp.Versions[npmResp.DistTags.Latest]; ok {
		pkg.Version = latest.Version
		pkg.Scripts = latest.Scripts
	}

	// Get published time for the latest version
	if timeStr, ok := npmResp.Time[npmResp.DistTags.Latest]; ok {
		if t, err := time.Parse(time.RFC3339, timeStr); err == nil {
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
	Version     string            `json:"version"`
	Scripts     map[string]string `json:"scripts"`
	Maintainers []NPMMaintainer   `json:"maintainers"`
	Dist        NPMDist           `json:"dist"`
}

type NPMDist struct {
	Tarball      string          `json:"tarball"`
	Shasum       string          `json:"shasum"`
	Integrity    string          `json:"integrity"`
	Attestations *NPMAttestation `json:"attestations,omitempty"`
}

type NPMAttestation struct {
	URL           string `json:"url"`
	ProvenanceURL string `json:"provenance_url"`
}

// NPMOwnershipHistory represents ownership/maintainer changes over time
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
		if m.Name != "" {
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

// GetOwnershipHistory analyzes maintainer changes across package versions
func (c *NPMClient) GetOwnershipHistory(packageName string) (*NPMOwnershipHistory, error) {
	url := fmt.Sprintf("%s/%s", c.baseURL, packageName)

	resp, err := c.httpClient.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch npm package: %w", err)
	}
	defer resp.Body.Close()

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

	// Check versions for maintainer changes
	// Sample up to 10 most recent versions to detect changes
	checkedVersions := 0
	previousMaintainers := make(map[string]bool)

	for version, versionInfo := range npmResp.Versions {
		if checkedVersions >= 10 {
			break
		}

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
				if versionTime, exists := versionTimes[version]; exists {
					sixMonthsAgo := time.Now().AddDate(0, -6, 0)
					if versionTime.After(sixMonthsAgo) {
						history.RecentTransfer = true
						history.TransferDate = versionTime
					}
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
