package models

import "time"

// Ecosystem represents the package ecosystem (npm, pypi, maven, etc.)
type Ecosystem string

const (
	EcosystemNPM   Ecosystem = "npm"
	EcosystemPyPI  Ecosystem = "pypi"
	EcosystemMaven Ecosystem = "maven"
)

// Dependency represents a single dependency from a manifest file
type Dependency struct {
	Name      string    `json:"name"`
	Version   string    `json:"version"`
	Ecosystem Ecosystem `json:"ecosystem"`
	Source    string    `json:"source"` // The manifest file it came from
}

// AnalysisResult contains the supply chain security analysis for a dependency
type AnalysisResult struct {
	Dependency          Dependency      `json:"dependency"`
	Timestamp           time.Time       `json:"timestamp"`
	RiskLevel           string          `json:"risk_level"` // HIGH, MEDIUM, LOW
	RiskScore           int             `json:"risk_score"` // 0-100
	RiskFactors         []string        `json:"risk_factors"`
	RepositoryURL       string          `json:"repository_url"`
	SourceCodeAvailable bool            `json:"source_code_available"`
	BuildInfrastructure string          `json:"build_infrastructure"`
	Findings            []Finding       `json:"findings"`
	Metadata            PackageMetadata `json:"metadata"`
}

// Finding represents a specific security finding
type Finding struct {
	Severity    string `json:"severity"`
	Category    string `json:"category"`
	Description string `json:"description"`
	Evidence    string `json:"evidence,omitempty"`
}

// PackageMetadata contains metadata about the package
type PackageMetadata struct {
	// Repository information
	RepoOwner        string    `json:"repo_owner"`
	RepoName         string    `json:"repo_name"`
	RepoStars        int       `json:"repo_stars"`
	RepoForks        int       `json:"repo_forks"`
	RepoWatchers     int       `json:"repo_watchers"`
	RepoOpenIssues   int       `json:"repo_open_issues"`
	RepoLastCommit   time.Time `json:"repo_last_commit"`
	RepoCreatedAt    time.Time `json:"repo_created_at"`
	RepoUpdatedAt    time.Time `json:"repo_updated_at"`
	RepoDefaultBranch string   `json:"repo_default_branch"`
	RepoArchived     bool      `json:"repo_archived"`

	// Package registry information
	DownloadCount    int64     `json:"download_count"`
	PublishedAt      time.Time `json:"published_at"`
	LatestVersion    string    `json:"latest_version"`
	Maintainers      []string  `json:"maintainers"`
	License          string    `json:"license"`
	Homepage         string    `json:"homepage"`

	// Build & CI information
	HasCI            bool     `json:"has_ci"`
	CISystems        []string `json:"ci_systems"`
	HasReleaseProcess bool    `json:"has_release_process"`
	SignedReleases   bool     `json:"signed_releases"`

	// OpenSSF Scorecard
	OSSFScore        float64  `json:"ossf_score"`
	OSSFChecks       map[string]int `json:"ossf_checks"`
}

// RepositoryInfo contains information about a Git repository
type RepositoryInfo struct {
	URL           string
	Owner         string
	Name          string
	Description   string
	Stars         int
	Forks         int
	Watchers      int
	OpenIssues    int
	DefaultBranch string
	Archived      bool
	CreatedAt     time.Time
	UpdatedAt     time.Time
	PushedAt      time.Time
	License       string
	Topics        []string
}

// ReleaseInfo contains information about a package release
type ReleaseInfo struct {
	Version     string
	PublishedAt time.Time
	Author      string
	Assets      []string
	Checksum    string
	Signature   string
}
