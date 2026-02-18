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

// AIAnalysisResult contains AI-powered supply chain security analysis
type AIAnalysisResult struct {
	Timestamp         time.Time              `json:"timestamp"`
	ModelVersion      string                 `json:"model_version"`         // AI model used for analysis
	OverallConfidence float64                `json:"overall_confidence"`    // 0.0-1.0
	SemanticFindings  []SemanticFinding      `json:"semantic_findings,omitempty"`
	AttackPatterns    []AttackPatternMatch   `json:"attack_patterns,omitempty"`
	ExecutiveSummary  *ExecutiveExplanation  `json:"executive_summary,omitempty"`
	AnalysisNotes     string                 `json:"analysis_notes,omitempty"` // Additional context from AI
}

// SemanticFinding represents a code pattern or behavior identified through AI analysis
type SemanticFinding struct {
	Type            string  `json:"type"`              // e.g., "obfuscation", "suspicious_network_call", "credential_harvesting"
	Description     string  `json:"description"`       // What was found
	Confidence      float64 `json:"confidence"`        // 0.0-1.0
	Severity        string  `json:"severity"`          // HIGH, MEDIUM, LOW
	FilePath        string  `json:"file_path,omitempty"`
	LineNumber      int     `json:"line_number,omitempty"`
	CodeSnippet     string  `json:"code_snippet,omitempty"`
	Evidence        string  `json:"evidence"`          // Why this is concerning
	RiskExplanation string  `json:"risk_explanation"`  // Impact if exploited
}

// AttackPatternMatch represents a match to a known supply chain attack pattern
type AttackPatternMatch struct {
	PatternName      string   `json:"pattern_name"`      // e.g., "Dependency Confusion", "Typosquatting"
	Description      string   `json:"description"`       // Attack pattern description
	Confidence       float64  `json:"confidence"`        // 0.0-1.0
	Severity         string   `json:"severity"`          // HIGH, MEDIUM, LOW
	Evidence         []string `json:"evidence"`          // List of evidence points
	AcademicSource   string   `json:"academic_source,omitempty"`  // Citation for attack pattern
	Indicators       []string `json:"indicators"`        // Specific indicators found
	MitigationAdvice string   `json:"mitigation_advice,omitempty"`
}

// ExecutiveExplanation provides a business-friendly summary of AI findings
type ExecutiveExplanation struct {
	Summary           string    `json:"summary"`           // High-level summary for stakeholders
	KeyRisks          []string  `json:"key_risks"`         // Top 3-5 risks in plain language
	BusinessImpact    string    `json:"business_impact"`   // Potential business consequences
	RecommendedAction string    `json:"recommended_action"` // What should be done
	TechnicalDetails  string    `json:"technical_details,omitempty"` // Optional technical context
	Confidence        float64   `json:"confidence"`        // 0.0-1.0 confidence in assessment
	GeneratedAt       time.Time `json:"generated_at"`
}

// AnalysisResult contains the supply chain security analysis for a dependency
type AnalysisResult struct {
	Dependency            Dependency             `json:"dependency"`
	Timestamp             time.Time              `json:"timestamp"`
	RiskLevel             string                 `json:"risk_level"` // HIGH, MEDIUM, LOW
	RiskScore             int                    `json:"risk_score"` // 0-100
	RiskFactors           []string               `json:"risk_factors"`
	RepositoryURL         string                 `json:"repository_url"`
	SourceCodeAvailable   bool                   `json:"source_code_available"`
	SourceVerification    *SourceVerification    `json:"source_verification,omitempty"`
	BuildInfrastructure   string                 `json:"build_infrastructure"`
	Findings              []Finding              `json:"findings"`
	Metadata              PackageMetadata        `json:"metadata"`
	SupplyChainScore      *SupplyChainScore      `json:"supply_chain_score,omitempty"`
	AIAnalysis            *AIAnalysisResult      `json:"ai_analysis,omitempty"`
}

// Finding represents a specific security finding
type Finding struct {
	Severity    string `json:"severity"`
	Category    string `json:"category"`
	Description string `json:"description"`
	Check       string `json:"check"`           // The check that identified this risk
	Evidence    string `json:"evidence,omitempty"`
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
	SignedReleases   bool              `json:"signed_releases"`

	// Provenance information
	HasSLSAAttestation  bool   `json:"has_slsa_attestation"`
	SLSALevel           string `json:"slsa_level,omitempty"`           // e.g., "SLSA_LEVEL_3"
	HasSigstoreSignature bool  `json:"has_sigstore_signature"`
	HasNPMProvenance     bool  `json:"has_npm_provenance"`
	HasPyPISignatures    bool  `json:"has_pypi_signatures"`
	ReproducibleBuild    bool  `json:"reproducible_build"`
	ProvenanceDetails    string `json:"provenance_details,omitempty"`  // Additional context

	// Health metrics (Category 7)
	BusFactor           int               `json:"bus_factor"`             // Number of contributors for 50% of commits
	CommitDistribution  map[string]int    `json:"commit_distribution"`    // Author -> commit count
	TopContributorPct   float64           `json:"top_contributor_pct"`    // Percentage by top contributor
	CodeReviewRate      float64           `json:"code_review_rate"`       // Percentage of PRs with reviews
	RequiredReviewers   int               `json:"required_reviewers"`     // Required reviewers from branch protection
	HasBranchProtection bool              `json:"has_branch_protection"`  // Whether branch protection is enabled
	CIQualityScore      int               `json:"ci_quality_score"`       // 0-10 CI quality score
	CIHasTests          bool              `json:"ci_has_tests"`           // Whether CI runs tests

	// Install-time execution
	InstallScripts      map[string]string `json:"install_scripts,omitempty"`       // postinstall, preinstall, etc.
	HasInstallScripts   bool              `json:"has_install_scripts"`             // Whether package has install scripts
	InstallScriptAnalysis *InstallScriptAnalysis `json:"install_script_analysis,omitempty"` // Analysis of install scripts

	// Dependency metrics
	DependencyMetrics *DependencyMetrics `json:"dependency_metrics,omitempty"`

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

// DependencyMetrics contains information about dependency sprawl
type DependencyMetrics struct {
	TransitiveCount int `json:"transitive_count"` // Total number of transitive dependencies
	DirectCount     int `json:"direct_count"`     // Number of direct dependencies
	MaxDepth        int `json:"max_depth"`        // Maximum depth of dependency tree
	Verified        bool `json:"verified"`        // Whether metrics were computed from lock file
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
	HasSLSAAttestation   bool     `json:"has_slsa_attestation"`
	SLSALevel            string   `json:"slsa_level,omitempty"`
	SLSAAttestationURL   string   `json:"slsa_attestation_url,omitempty"`
	HasSigstoreSignature bool     `json:"has_sigstore_signature"`
	SigstoreBundle       string   `json:"sigstore_bundle,omitempty"`
	HasNPMProvenance     bool     `json:"has_npm_provenance"`
	NPMProvenanceURL     string   `json:"npm_provenance_url,omitempty"`
	HasPyPISignatures    bool     `json:"has_pypi_signatures"`
	SignedReleaseCount   int      `json:"signed_release_count"`
	TotalReleaseCount    int      `json:"total_release_count"`
	ReproducibleBuild    bool     `json:"reproducible_build"`
	BuildSystem          string   `json:"build_system,omitempty"`
}

// SupplyChainScore represents a 0-20 point supply chain security scoring rubric
type SupplyChainScore struct {
	TotalScore    int                   `json:"total_score"`    // 0-20 points
	RiskLevel     string                `json:"risk_level"`     // LOW (0-5), MEDIUM (6-14), HIGH (15+)
	CategoryScores CategoryScores       `json:"category_scores"`
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
	ReleaseSecurity    CategoryScore `json:"release_security"`     // 0-2 pts: CI publishing/branch protection/signed tags
	PackageMaturity    CategoryScore `json:"package_maturity"`     // 0-2 pts: package age/update frequency/staleness
}

// CategoryScore contains the score and details for a single category
type CategoryScore struct {
	Score       int    `json:"score"`       // 0-2 points
	RiskPoints  int    `json:"risk_points"` // Points assigned (higher = more risk)
	Description string `json:"description"` // Human-readable description
	Evidence    string `json:"evidence"`    // Evidence for the score
	Verified    bool   `json:"verified"`    // Whether data was available to verify
}
