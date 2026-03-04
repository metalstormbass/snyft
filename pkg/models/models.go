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
	Name         string    `json:"name"`
	Version      string    `json:"version"`
	Ecosystem    Ecosystem `json:"ecosystem"`
	Source       string    `json:"source"`        // The manifest file it came from
	IsTransitive bool     `json:"is_transitive"` // True if this is a transitive (indirect) dependency

	// ResolvedRepoURL is populated during the pre-scan repo resolution phase.
	// When set, the analyzer skips redundant repo URL extraction from registry
	// metadata and uses this URL directly for repo-level analysis caching.
	ResolvedRepoURL string `json:"-"`
}

// IsVersionUnknown returns true when the dependency's version could not be
// determined by the parser (e.g. Maven BOM imports, unresolved property
// references). Version-dependent checks should be skipped for such packages.
func (d Dependency) IsVersionUnknown() bool {
	return d.Version == "" || d.Version == "unknown"
}

// DisplayVersion returns a human-readable version string. When the version
// is unknown/undetermined it returns "-" instead of the raw sentinel value.
func (d Dependency) DisplayVersion() string {
	if d.IsVersionUnknown() {
		return "-"
	}
	return d.Version
}

// SourceVerification contains detailed results of source code availability verification
type SourceVerification struct {
	Verified           bool     `json:"verified"`              // Overall verification status
	HasSourcePackage   bool     `json:"has_source_package"`    // npm: tarball has source, PyPI: sdist exists, Maven: sources.jar exists
	HasMatchingGitTag  bool     `json:"has_matching_git_tag"`  // Repository has git tag matching the version
	SourcePackageURL   string   `json:"source_package_url"`    // URL to source package
	GitTagURL          string   `json:"git_tag_url"`           // URL to git tag in repository
	VerificationErrors []string `json:"verification_errors"`   // Any errors during verification
	Details            string   `json:"details"`               // Human-readable details
}

// DataMode indicates how data was collected for an analysis result.
const (
	// DataModeFull means all data sources (API + scraping) were available.
	DataModeFull = ""
	// DataModeScrapingOnly means the GitHub API rate limit was exhausted and
	// only web scraping was used. Results have reduced fidelity — checks that
	// require API access (signed commits, GraphQL batch queries, branch
	// protection) will have missing or degraded data.
	DataModeScrapingOnly = "scraping-only"
)

// AnalysisResult contains the supply chain security analysis for a dependency
type AnalysisResult struct {
	Dependency            Dependency             `json:"dependency"`
	Timestamp             time.Time              `json:"timestamp"`
	RiskLevel             string                 `json:"risk_level"` // HIGH, MEDIUM, LOW
	RiskScore             int                    `json:"risk_score"` // 0-100
	RiskFactors           []string               `json:"risk_factors"`
	RepositoryURL         string                 `json:"repository_url"`
	ScorecardURL          string                 `json:"scorecard_url,omitempty"`
	SourceCodeAvailable   bool                   `json:"source_code_available"`
	SourceVerification    *SourceVerification    `json:"source_verification,omitempty"`
	BuildInfrastructure   string                 `json:"build_infrastructure"`
	Findings              []Finding              `json:"findings"`
	Metadata              PackageMetadata        `json:"metadata"`
	SupplyChainScore      *SupplyChainScore      `json:"supply_chain_score,omitempty"`
	DataMode              string                 `json:"data_mode,omitempty"` // "" (full) or "scraping-only"
}

// Finding represents a specific security finding
type Finding struct {
	Severity    string `json:"severity"`
	Category    string `json:"category"`
	Description string `json:"description"`
	Check       string `json:"check"`                      // The check that identified this risk
	Evidence    string `json:"evidence,omitempty"`
	Methodology string `json:"methodology,omitempty"`       // How this check was performed (data sources, APIs)
	SourceURL   string `json:"source_url,omitempty"`        // URL to the data source for verification
}

// InstallScriptAnalysis contains analysis of install-time scripts
type InstallScriptAnalysis struct {
	HasDangerousPatterns bool               `json:"has_dangerous_patterns"`
	DangerousPatterns    []DangerousPattern `json:"dangerous_patterns,omitempty"`
	RiskLevel            string             `json:"risk_level"` // HIGH, MEDIUM, LOW
	ScriptCount          int                `json:"script_count"`
}

// DangerousPattern represents a dangerous operation found in install scripts
type DangerousPattern struct {
	Pattern     string `json:"pattern"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	Match       string `json:"match,omitempty"`
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
	RepoDescription  string    `json:"repo_description,omitempty"`

	// Deprecation signals
	IsDeprecated      bool   `json:"is_deprecated"`                // Package has been explicitly deprecated or abandoned
	DeprecationNotice string `json:"deprecation_notice,omitempty"` // The deprecation signal found (keyword, archived, etc.)
	DeprecationSource string `json:"deprecation_source,omitempty"` // Where the signal was found: "readme", "description", "archived", "registry"

	// Package registry information
	DownloadCount    int64     `json:"download_count"`
	PublishedAt      time.Time `json:"published_at"`
	LatestVersion    string    `json:"latest_version"`
	Maintainers      []string  `json:"maintainers"`
	License          string    `json:"license"`
	Homepage         string    `json:"homepage"`

	// Build & CI information
	HasCI            bool              `json:"has_ci"`
	CISystems        []string          `json:"ci_systems"`
	BuildSystems     []BuildSystemInfo `json:"build_systems,omitempty"` // Structured build system info
	HasSelfHosted    bool              `json:"has_self_hosted"`          // Any self-hosted runners detected
	HasReleaseProcess bool             `json:"has_release_process"`
	CIWorkflowRisks  []CIWorkflowRisk `json:"ci_workflow_risks,omitempty"` // Parsed CI/CD workflow risk signals
	SignedReleases    bool              `json:"signed_releases"`
	TotalReleaseCount int               `json:"total_release_count"` // 0 means no GitHub releases to check

	// Provenance information
	HasNPMProvenance     bool  `json:"has_npm_provenance"`
	HasMavenGPGSignature bool  `json:"has_maven_gpg_signature"`       // Maven Central GPG .asc signature
	ProvenanceDetails    string `json:"provenance_details,omitempty"`  // Additional context

	// Health metrics (Category 7)
	BusFactor           int               `json:"bus_factor"`             // Number of contributors for 50% of commits
	CommitDistribution  map[string]int    `json:"commit_distribution"`    // Author -> commit count
	TopContributorPct   float64           `json:"top_contributor_pct"`    // Percentage by top contributor
	CodeReviewRate      float64           `json:"code_review_rate"`       // Percentage of PRs with reviews
	RequiredReviewers   int               `json:"required_reviewers"`     // Required reviewers from branch protection
	HasBranchProtection    bool           `json:"has_branch_protection"`     // Whether branch protection is enabled
	BranchProtectionDenied bool           `json:"branch_protection_denied"` // True when API returned 403/404 (admin access required)
	CIQualityScore      int               `json:"ci_quality_score"`       // 0-10 CI quality score

	// Install-time execution
	InstallScripts      map[string]string `json:"install_scripts,omitempty"`       // postinstall, preinstall, etc.
	HasInstallScripts   bool              `json:"has_install_scripts"`             // Whether package has install scripts
	InstallScriptAnalysis *InstallScriptAnalysis `json:"install_script_analysis,omitempty"` // Analysis of install scripts

	// Dependency metrics
	DependencyMetrics *DependencyMetrics `json:"dependency_metrics,omitempty"`

	// Libraries.io enrichment data (optional, requires LIBRARIES_IO_API_KEY)
	DependentsCount     int    `json:"dependents_count,omitempty"`      // Number of packages depending on this
	DependentReposCount int    `json:"dependent_repos_count,omitempty"` // Number of repos depending on this
	ContributionsCount  int    `json:"contributions_count,omitempty"`   // Contribution count from libraries.io
	SecurityPolicyURL   string `json:"security_policy_url,omitempty"`   // URL to SECURITY.md or similar

	// Release documentation signals
	ReleaseDocumentation *ReleaseDocumentation `json:"release_documentation,omitempty"`

	// OpenSSF Scorecard
	OSSFScore        float64  `json:"ossf_score"`
	OSSFChecks       map[string]int `json:"ossf_checks"`
}

// BuildSystemInfo contains information about a CI/CD build system detected in a repository
type BuildSystemInfo struct {
	Platform     string `json:"platform"`               // "GitHub Actions", "Jenkins", "CircleCI", etc.
	HostedBy     string `json:"hosted_by"`              // "GitHub", "GitLab", "Self-hosted", "CircleCI", etc.
	IsSelfHosted bool   `json:"is_self_hosted"`         // Key risk signal: self-hosted = uncontrolled environment
	RunnerDetails string `json:"runner_details,omitempty"` // e.g. "ubuntu-latest", "custom-runner"
	ConfigFile   string `json:"config_file,omitempty"`  // Config file that detected this system
}

// CIWorkflowRisk contains risk signals parsed from CI/CD configuration files.
//
// Check: CI/CD workflow security analysis
// Justification: Insecure CI/CD configurations are a direct supply chain attack vector.
//                Unpinned actions can be hijacked via tag mutation, excessive permissions
//                grant attackers wider blast radius, and dangerous triggers like
//                pull_request_target enable code execution from untrusted forks.
// Source: "Backstabber's Knife Collection" (Ohm et al., 2020)
//         SLSA Build Level Requirements (https://slsa.dev/spec/v1.0/levels)
//         GitHub Actions Security Hardening (https://docs.github.com/en/actions/security-guides)
// Methodology: Parse CI config files (GitHub Actions YAML, CircleCI config, GitLab CI, etc.)
//              and identify insecure patterns via string analysis
// Result: Risk signals feed into Release Security scoring (Category 9)
type CIWorkflowRisk struct {
	// UnpinnedActions lists actions/orbs/images referenced by mutable tag instead of SHA
	UnpinnedActions []string `json:"unpinned_actions,omitempty"`
	// HasExcessivePermissions is true when workflows request write-all or broad permissions
	HasExcessivePermissions bool `json:"has_excessive_permissions"`
	// DangerousTriggers lists risky event triggers (e.g., pull_request_target, workflow_dispatch)
	DangerousTriggers []string `json:"dangerous_triggers,omitempty"`
	// HasScriptInjection is true when workflow uses untrusted input in run: steps without sanitization
	HasScriptInjection bool `json:"has_script_injection"`
	// SecretsInLogs is true when echo/print of secret variables detected
	SecretsInLogs bool `json:"secrets_in_logs"`
	// MissingEnvironmentProtection is true when publish/deploy steps lack environment gates
	MissingEnvironmentProtection bool `json:"missing_environment_protection"`
	// Platform is the CI platform these risks were parsed from
	Platform string `json:"platform"`
	// RiskCount is the total number of risk signals found
	RiskCount int `json:"risk_count"`
	// Details contains human-readable descriptions of each risk found
	Details []string `json:"details,omitempty"`
}

// DependencyMetrics contains information about dependency sprawl
type DependencyMetrics struct {
	TransitiveCount int `json:"transitive_count"` // Total number of transitive dependencies
	DirectCount     int `json:"direct_count"`     // Number of direct dependencies (compile+runtime only for Maven)
	MaxDepth        int `json:"max_depth"`        // Maximum depth of dependency tree
	Verified        bool `json:"verified"`        // Whether metrics were computed from lock file

	// Maven scope breakdown — populated when dependency data comes from a Maven POM.
	// Only compile and runtime scoped dependencies count toward DirectCount (and thus
	// the sprawl score), since test/provided/system deps don't flow to consumers.
	MavenScopeBreakdown *MavenScopeBreakdown `json:"maven_scope_breakdown,omitempty"`
}

// MavenScopeBreakdown records the number of dependencies in each Maven scope.
// Maven defaults absent scope to "compile". Only compile and runtime scoped
// dependencies represent actual supply chain entry points for consumers.
//
// Source: Maven POM reference — https://maven.apache.org/guides/introduction/introduction-to-dependency-mechanism.html#Dependency_Scope
type MavenScopeBreakdown struct {
	Compile  int `json:"compile"`  // Default scope — available in all classpaths, transitive
	Runtime  int `json:"runtime"`  // Needed at runtime, not compile-time — transitive
	Test     int `json:"test"`     // Only for test compilation and execution — NOT transitive
	Provided int `json:"provided"` // Expected to be provided by JDK/container at runtime — NOT transitive
	System   int `json:"system"`   // Like provided but from explicit local path — NOT transitive
}

// ReleaseDocumentation contains signals parsed from contributing/release documentation files.
//
// Check: Release process documentation analysis
// Justification: Projects with documented release processes have formalized controls
//                that reduce the risk of a single compromised maintainer pushing
//                malicious code. Documented multi-approval requirements, release
//                checklists, and CI/CD automation create barriers an attacker must
//                bypass beyond just compromising one account.
// Source: SLSA Build Level Requirements (https://slsa.dev/spec/v1.0/levels)
//         OSSF Scorecard Specification (Security Policy, Branch-Protection checks)
//         "Backstabber's Knife Collection" (Ohm et al., 2020)
// Methodology: Fetch CONTRIBUTING.md, RELEASING.md, RELEASE.md, .github/CONTRIBUTING.md,
//              docs/RELEASING.md, docs/RELEASE.md from repository via web scraping.
//              Parse content for release process keywords and patterns.
// Result: Feeds into Governance (Category 8) and Release Security (Category 9) scoring
type ReleaseDocumentation struct {
	// Which files were found
	FilesFound []string `json:"files_found"`

	// Parsed signals
	HasDocumentedReleaseProcess bool `json:"has_documented_release_process"` // Any release docs exist
	HasMultiApprovalRequirement bool `json:"has_multi_approval_requirement"` // Requires multiple sign-offs
	HasReleaseChecklist         bool `json:"has_release_checklist"`          // Structured release checklist
	HasAutomatedReleaseProcess  bool `json:"has_automated_release_process"`  // CI/CD mentioned for releases
	HasReleaseManagerRole       bool `json:"has_release_manager_role"`       // Dedicated release manager

	// Raw evidence for debugging/display
	Evidence []string `json:"evidence,omitempty"`
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

// ProvenanceInfo contains detailed provenance and attestation information
type ProvenanceInfo struct {
	HasNPMProvenance     bool     `json:"has_npm_provenance"`
	NPMProvenanceURL     string   `json:"npm_provenance_url,omitempty"`
	SignedReleaseCount   int      `json:"signed_release_count"`
	TotalReleaseCount    int      `json:"total_release_count"`
	BuildSystem          string   `json:"build_system,omitempty"`
}

// SupplyChainScore represents a 0-20 point supply chain security scoring rubric
type SupplyChainScore struct {
	TotalScore         int            `json:"total_score"`                      // 0-20 points (or fewer when --check filters active)
	MaxScore           int            `json:"max_score"`                        // Maximum possible score (active_checks * 2)
	ActiveChecks       int            `json:"active_checks"`                    // Number of checks that were run (10 normally, fewer with --check)
	RiskLevel          string         `json:"risk_level"`                       // LOW (0-8), MEDIUM (9-12), HIGH (13+)
	CategoryScores     CategoryScores `json:"category_scores"`
}

// CategoryScores contains individual scores for each supply chain security category
type CategoryScores struct {
	PublisherControl   CategoryScore `json:"publisher_control"`    // 0-2 pts: 2FA/signing/multi-maintainer
	OwnershipChanges   CategoryScore `json:"ownership_changes"`    // 0-2 pts: ownership transfers
	ReleaseAnomalies   CategoryScore `json:"release_anomalies"`    // 0-2 pts: dormant→sudden activity
	InstallExecution   CategoryScore `json:"install_execution"`    // 0-2 pts: postinstall scripts
	DependencySprawl   CategoryScore `json:"dependency_sprawl"`    // 0-2 pts: transitive dependencies
	Provenance         CategoryScore `json:"provenance"`           // 0-2 pts: reproducible/signed builds
	Health             CategoryScore `json:"health"`               // 0-2 pts: bus factor/review/CI
	Governance         CategoryScore `json:"governance"`           // 0-2 pts: governance docs/responsiveness
	ReleaseSecurity    CategoryScore `json:"release_security"`     // 0-2 pts: CI publishing/branch protection/signed tags/CI workflow security
	PackageMaturity    CategoryScore `json:"package_maturity"`     // 0-2 pts: package age/update frequency/staleness
}

// CheckResult represents the outcome of an individual sub-check within a category.
// Each scoring category performs multiple sub-checks; this struct records whether
// each sub-check passed, failed, was skipped, or had unavailable data.
type CheckResult struct {
	Name   string `json:"name"`   // Sub-check name, e.g. "SLSA attestation", "SECURITY.md present"
	Status string `json:"status"` // PASS, FAIL, SKIPPED, UNAVAILABLE
	Detail string `json:"detail"` // Human-readable explanation of the result
}

// CategoryScore contains the score and details for a single category
type CategoryScore struct {
	Score           int                `json:"score"`                           // 0-2 points
	RiskPoints      int                `json:"risk_points"`                     // Points assigned (higher = more risk)
	Description     string             `json:"description"`                     // Human-readable description
	Evidence        string             `json:"evidence"`                        // Evidence for the score
	Verified        bool               `json:"verified"`                        // Whether data was available to verify
	DataAvailable   bool               `json:"data_available"`                  // True when sufficient data was available for assessment; false means score reflects uncertainty (unable to verify)
	Skipped         bool               `json:"skipped,omitempty"`              // True when check was excluded via --check flag
	Methodology     string             `json:"methodology,omitempty"`           // How this check was performed (data sources, APIs)
	ChecksPerformed []CheckResult      `json:"checks_performed,omitempty"`      // Individual sub-check outcomes
	SourceURL       string             `json:"source_url,omitempty"`            // URL to the data source for verification
}

// EcosystemCapabilities describes what data each package registry exposes.
// Scoring functions should check these before interpreting zero values.
// A zero value in a field that the ecosystem does not expose means "data unavailable",
// not "data is zero/bad".
//
// Justification: npm exposes multi-maintainer lists and download counts; PyPI exposes
// a singular author and no download counts; Maven exposes no ownership data at all.
// Scoring that treats zero as worst-case silently penalizes ecosystems with less data.
//
// Source: npm registry API docs, PyPI JSON API docs, Maven Central REST API docs
type EcosystemCapabilities struct {
	HasMaintainerList   bool // npm: yes, PyPI: partial (single author), Maven: no
	HasDownloadCounts   bool // npm: yes, PyPI: partial (via BigQuery, not real-time), Maven: no
	HasOwnershipHistory bool // npm: yes (via API), PyPI: no, Maven: no
}

// GetEcosystemCapabilities returns the data capabilities for a given ecosystem.
// Scoring functions use this to distinguish "zero means unavailable" from "zero means bad".
func GetEcosystemCapabilities(eco Ecosystem) EcosystemCapabilities {
	switch eco {
	case EcosystemNPM:
		return EcosystemCapabilities{
			HasMaintainerList:   true,
			HasDownloadCounts:   true,
			HasOwnershipHistory: true,
		}
	case EcosystemPyPI:
		return EcosystemCapabilities{
			HasMaintainerList:   true, // Partial: single author field, but populated
			HasDownloadCounts:   false, // PyPI JSON API does not expose real-time downloads
			HasOwnershipHistory: false,
		}
	case EcosystemMaven:
		return EcosystemCapabilities{
			HasMaintainerList:   true,  // Partial: POM <developers> section provides maintainer data
			HasDownloadCounts:   false, // Maven Central does not expose download counts
			HasOwnershipHistory: false,
		}
	default:
		return EcosystemCapabilities{}
	}
}
