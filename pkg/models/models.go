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
	DeepAnalysis      *DeepAnalysisResult    `json:"deep_analysis,omitempty"`
	AttackPatterns    []AttackPatternMatch   `json:"attack_patterns,omitempty"`
	ExecutiveSummary  *ExecutiveExplanation  `json:"executive_summary,omitempty"`
	AnalysisNotes     string                 `json:"analysis_notes,omitempty"` // Additional context from AI
}

// DeepAnalysisResult contains the AI's holistic cross-cutting analysis of a package.
// Unlike per-category analysis that re-examines what rules already found, deep analysis
// identifies compound risk patterns and behavioral anomalies that rule-based scoring
// cannot detect — particularly around maintainer behavior and process integrity.
type DeepAnalysisResult struct {
	RiskAssessment   string         `json:"risk_assessment"`              // AI's holistic risk assessment
	CompoundRisks    []CompoundRisk `json:"compound_risks,omitempty"`     // Cross-signal risk patterns
	BehaviorFindings []string       `json:"behavior_findings,omitempty"`  // Maintainer/process behavioral anomalies
	MissedByRules    []string       `json:"missed_by_rules,omitempty"`    // Insights rules cannot detect
	Confidence       float64        `json:"confidence"`                   // 0.0-1.0
}

// CompoundRisk represents a cross-cutting risk pattern where multiple weak signals
// combine to indicate a higher likelihood of compromise than any single signal alone.
type CompoundRisk struct {
	Pattern      string   `json:"pattern"`       // e.g., "single maintainer + dormancy + no CI"
	RiskLevel    string   `json:"risk_level"`    // HIGH, MEDIUM, LOW
	Contributing []string `json:"contributing"`  // Which signals combine
	Explanation  string   `json:"explanation"`   // Why this combination matters
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
	Check       string `json:"check"`                      // The check that identified this risk
	Evidence    string `json:"evidence,omitempty"`
	Methodology string `json:"methodology,omitempty"`       // How this check was performed (data sources, APIs)
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
	CIWorkflowRisks  []CIWorkflowRisk `json:"ci_workflow_risks,omitempty"` // Parsed CI/CD workflow risk signals
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
	Methodology     string             `json:"methodology,omitempty"`           // How this check was performed (data sources, APIs)
	ChecksPerformed []CheckResult      `json:"checks_performed,omitempty"`      // Individual sub-check outcomes
	AIInsight       *CategoryAIInsight `json:"ai_insight,omitempty"`            // AI-powered deeper analysis (optional)
}

// CategoryAIInsight contains AI-powered deeper analysis for a single scoring category.
// This augments the rule-based CategoryScore without replacing it.
// Populated only when AI analysis is enabled (--ai flag + API key).
type CategoryAIInsight struct {
	AIRiskLevel    string   `json:"ai_risk_level"`    // AI's risk assessment: HIGH, MEDIUM, LOW
	Confidence     float64  `json:"confidence"`       // 0.0-1.0 confidence in the assessment
	Findings       []string `json:"findings"`         // AI-identified patterns beyond rule-based scoring
	Context        string   `json:"context"`          // Contextual analysis and amplifying/mitigating factors
	Recommendation string   `json:"recommendation"`   // Category-specific action recommendation
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
			HasMaintainerList:   false, // Maven Central does not expose maintainer/owner data
			HasDownloadCounts:   false, // Maven Central does not expose download counts
			HasOwnershipHistory: false,
		}
	default:
		return EcosystemCapabilities{}
	}
}
