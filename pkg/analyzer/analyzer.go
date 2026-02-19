package analyzer

import (
	"errors"
	"fmt"
	"time"

	"github.com/metalstormbass/snyft/pkg/ai"
	"github.com/metalstormbass/snyft/pkg/fetcher"
	"github.com/metalstormbass/snyft/pkg/models"
)

// Analyzer performs supply chain security analysis on dependencies
type Analyzer struct {
	// Platform clients (cached for reuse)
	githubClient    *fetcher.GitHubClient
	gitlabClient    *fetcher.GitLabClient
	bitbucketClient *fetcher.BitbucketClient

	// Package registry clients
	npmClient      *fetcher.NPMClient
	pypiClient     *fetcher.PyPIClient
	mavenClient    *fetcher.MavenClient
	ossfClient     *fetcher.OSSFClient

	// AI analysis client (optional)
	claudeClient *ai.Client
	aiEnabled    bool
	aiTimeout    time.Duration
}

// AnalyzerOption is a functional option for configuring an Analyzer
type AnalyzerOption func(*Analyzer)

// WithAIConfig configures the analyzer with a custom AI configuration
func WithAIConfig(config *ai.Config) AnalyzerOption {
	return func(a *Analyzer) {
		if config == nil || config.APIKey == "" {
			a.claudeClient = nil
			a.aiEnabled = false
			return
		}

		claudeClient, err := ai.NewClient(config)
		if err != nil {
			// Log error but continue - AI analysis is optional
			fmt.Printf("Warning: Failed to initialize AI client: %v\n", err)
			a.claudeClient = nil
			a.aiEnabled = false
			return
		}

		a.claudeClient = claudeClient
		a.aiEnabled = true
		a.aiTimeout = config.Timeout
	}
}

// WithAIDisabled explicitly disables AI analysis
func WithAIDisabled() AnalyzerOption {
	return func(a *Analyzer) {
		a.claudeClient = nil
		a.aiEnabled = false
	}
}

// NewAnalyzer creates a new Analyzer instance with optional configuration
func NewAnalyzer(opts ...AnalyzerOption) *Analyzer {
	a := &Analyzer{
		githubClient:    fetcher.NewGitHubClient(),
		gitlabClient:    fetcher.NewGitLabClient(),
		bitbucketClient: fetcher.NewBitbucketClient(),
		npmClient:       fetcher.NewNPMClient(),
		pypiClient:      fetcher.NewPyPIClient(),
		mavenClient:     fetcher.NewMavenClient(),
		ossfClient:      fetcher.NewOSSFClient(),
	}

	// Apply options
	for _, opt := range opts {
		opt(a)
	}

	// If no AI config was provided via options, try to load from environment
	if a.claudeClient == nil && !a.aiEnabled {
		config, err := ai.LoadFromEnv()
		if err == nil && config.APIKey != "" {
			// Only initialize if API key is present
			claudeClient, err := ai.NewClient(config)
			if err != nil {
				// Log error but continue - AI analysis is optional
				fmt.Printf("Warning: Failed to initialize AI client: %v\n", err)
			} else {
				a.claudeClient = claudeClient
				a.aiEnabled = true
			}
		}
	}

	return a
}

// getGitClient returns the appropriate git platform client for a given repository URL
func (a *Analyzer) getGitClient(repoURL string) fetcher.GitPlatformClient {
	platform := fetcher.DetectPlatform(repoURL)

	switch platform {
	case fetcher.PlatformGitHub:
		return a.githubClient
	case fetcher.PlatformGitLab:
		return a.gitlabClient
	case fetcher.PlatformBitbucket:
		return a.bitbucketClient
	default:
		// For Apache, Eclipse, Sourcehut, Codeberg, generic git, etc.,
		// use the platform-aware factory which returns a GenericGitClient.
		// Only PlatformUnknown falls back to the GitHub client.
		return fetcher.NewGitPlatformClient(repoURL)
	}
}

// Analyze performs a comprehensive supply chain security analysis on a dependency
func (a *Analyzer) Analyze(dep models.Dependency) models.AnalysisResult {
	result := models.AnalysisResult{
		Dependency: dep,
		Timestamp:  time.Now(),
		RiskLevel:  "UNKNOWN",
		RiskScore:  0,
		RiskFactors: []string{},
		Findings:   []models.Finding{},
	}

	// Fetch package metadata from registry
	var repoURL string
	var metadata models.PackageMetadata

	switch dep.Ecosystem {
	case models.EcosystemNPM:
		npmPkg, err := a.npmClient.GetPackageInfo(dep.Name)
		if err != nil {
			if errors.Is(err, fetcher.ErrPackageNotFound) {
				result.Findings = append(result.Findings, models.Finding{
					Severity:    "HIGH",
					Category:    "Package Not Found",
					Description: fmt.Sprintf("Package does not exist in npm registry: %v", err),
					Check:       "Package Registry Validation",
				})
				result.RiskLevel = "HIGH"
				result.RiskScore = 100
			} else {
				result.Findings = append(result.Findings, models.Finding{
					Severity:    "MEDIUM",
					Category:    "Registry API Failure",
					Description: fmt.Sprintf("Failed to fetch package from npm (API error, not confirmed missing): %v", err),
					Check:       "Package Registry Validation",
					Evidence:    "API failure does not confirm package is compromised; further investigation recommended",
				})
				result.RiskLevel = "UNKNOWN"
				result.RiskScore = 0
			}
			return result
		}
		repoURL = npmPkg.RepositoryURL
		metadata = packageMetadataFromNPM(npmPkg)

		// Analyze npm install scripts
		if len(npmPkg.Scripts) > 0 {
			metadata.InstallScripts = npmPkg.Scripts
			metadata.HasInstallScripts = hasInstallTimeScripts(npmPkg.Scripts)
			if metadata.HasInstallScripts {
				scriptAnalysis := AnalyzeNPMScripts(npmPkg.Scripts)
				metadata.InstallScriptAnalysis = convertToModelAnalysis(scriptAnalysis)
			}
		}

	case models.EcosystemPyPI:
		pypiPkg, err := a.pypiClient.GetPackageInfo(dep.Name)
		if err != nil {
			if errors.Is(err, fetcher.ErrPackageNotFound) {
				result.Findings = append(result.Findings, models.Finding{
					Severity:    "HIGH",
					Category:    "Package Not Found",
					Description: fmt.Sprintf("Package does not exist in PyPI registry: %v", err),
					Check:       "Package Registry Validation",
				})
				result.RiskLevel = "HIGH"
				result.RiskScore = 100
			} else {
				result.Findings = append(result.Findings, models.Finding{
					Severity:    "MEDIUM",
					Category:    "Registry API Failure",
					Description: fmt.Sprintf("Failed to fetch package from PyPI (API error, not confirmed missing): %v", err),
					Check:       "Package Registry Validation",
					Evidence:    "API failure does not confirm package is compromised; further investigation recommended",
				})
				result.RiskLevel = "UNKNOWN"
				result.RiskScore = 0
			}
			return result
		}
		repoURL = pypiPkg.RepositoryURL
		metadata = packageMetadataFromPyPI(pypiPkg)

		// Try to fetch and analyze setup.py if repository is available
		if repoURL != "" {
			gitClient := a.getGitClient(repoURL)
			if setupContent, err := gitClient.GetFileContent(repoURL, "setup.py"); err == nil {
				scriptAnalysis := AnalyzePythonSetup(setupContent)
				metadata.InstallScripts = map[string]string{"setup.py": setupContent}
				metadata.HasInstallScripts = true
				metadata.InstallScriptAnalysis = convertToModelAnalysis(scriptAnalysis)
			}
		}

	case models.EcosystemMaven:
		mavenPkg, err := a.mavenClient.GetPackageInfo(dep.Name)
		if err != nil {
			if errors.Is(err, fetcher.ErrPackageNotFound) {
				result.Findings = append(result.Findings, models.Finding{
					Severity:    "HIGH",
					Category:    "Package Not Found",
					Description: fmt.Sprintf("Package does not exist in Maven Central: %v", err),
					Check:       "Package Registry Validation",
				})
				result.RiskLevel = "HIGH"
				result.RiskScore = 100
			} else {
				result.Findings = append(result.Findings, models.Finding{
					Severity:    "MEDIUM",
					Category:    "Registry API Failure",
					Description: fmt.Sprintf("Failed to fetch package from Maven Central (API error, not confirmed missing): %v", err),
					Check:       "Package Registry Validation",
					Evidence:    "API failure does not confirm package is compromised; further investigation recommended",
				})
				result.RiskLevel = "UNKNOWN"
				result.RiskScore = 0
			}
			return result
		}
		repoURL = mavenPkg.RepositoryURL
		metadata = packageMetadataFromMaven(mavenPkg)

		// Try to fetch and analyze pom.xml if repository is available
		if repoURL != "" {
			gitClient := a.getGitClient(repoURL)
			if pomContent, err := gitClient.GetFileContent(repoURL, "pom.xml"); err == nil {
				scriptAnalysis := AnalyzeJavaPOM(pomContent)
				// Always record that a pom.xml exists so the "single benign
				// install script" scoring path (1 risk point) is reachable.
				// Previously HasInstallScripts was only set when dangerous
				// patterns were found, making the benign path unreachable.
				metadata.InstallScripts = map[string]string{"pom.xml": pomContent}
				metadata.HasInstallScripts = true
				metadata.InstallScriptAnalysis = convertToModelAnalysis(scriptAnalysis)
			}
		}
	}

	result.RepositoryURL = repoURL
	result.Metadata = metadata

	// Check for typosquatting before other analysis
	// Typosquatting Detection: Compare package name against popular packages
	// to identify potential name confusion attacks.
	// Source: "Backstabber's Knife Collection" (Ohm et al., 2020)
	checkTyposquatting(&result, dep)

	// PRIMARY CHECK: Verify source code availability for the EXACT version
	// This MUST be the first check before any other scoring
	a.verifySourceCode(&result, dep, repoURL)

	// Analyze dependency sprawl from lock files
	a.analyzeDependencySprawl(&result, dep)

	// Analyze repository if URL is available
	if repoURL != "" {
		a.analyzeRepository(&result, repoURL)
	} else {
		result.Findings = append(result.Findings, models.Finding{
			Severity:    "HIGH",
			Category:    "Missing Source Code",
			Description: "No repository URL found in package metadata",
			Check:       "Repository Availability Check",
		})
		result.SourceCodeAvailable = false
		result.RiskFactors = append(result.RiskFactors, "No public source code repository")
	}

	// Analyze build infrastructure
	a.analyzeBuildInfrastructure(&result, repoURL)

	// Analyze repository health metrics (for Category 7)
	if repoURL != "" {
		a.analyzeHealthMetrics(&result, repoURL)
	}

	// Get OSSF Scorecard (if available)
	if repoURL != "" {
		a.analyzeOSSFScorecard(&result, repoURL)
	}

	// Analyze provenance (if available)
	if repoURL != "" {
		a.analyzeProvenance(&result, repoURL, dep.Ecosystem)
	}

	// Calculate supply chain score (0-22 point rubric)
	a.calculateSupplyChainScore(&result)

	// Derive legacy RiskLevel/RiskScore from SupplyChainScore
	if result.SupplyChainScore != nil {
		result.RiskLevel = result.SupplyChainScore.RiskLevel
		// Map 0-22 to 0-100 (capped at 100)
		mappedScore := result.SupplyChainScore.TotalScore * 100 / 22
		if mappedScore > 100 {
			mappedScore = 100
		}
		result.RiskScore = mappedScore
	}

	// Populate Findings from CategoryScores for backward compatibility
	populateFindingsFromScores(&result)

	// Enrich with AI analysis (if enabled)
	a.enrichWithAIAnalysis(&result)

	return result
}

// populateFindingsFromScores generates Findings from CategoryScores for backward compatibility
func populateFindingsFromScores(result *models.AnalysisResult) {
	if result.SupplyChainScore == nil {
		return
	}
	cs := result.SupplyChainScore.CategoryScores
	categories := []struct {
		name  string
		score models.CategoryScore
	}{
		{"Publisher Control", cs.PublisherControl},
		{"Ownership Changes", cs.OwnershipChanges},
		{"Release Anomalies", cs.ReleaseAnomalies},
		{"Install Execution", cs.InstallExecution},
		{"Dependency Sprawl", cs.DependencySprawl},
		{"Provenance", cs.Provenance},
		{"Health", cs.Health},
		{"Governance", cs.Governance},
		{"Release Security", cs.ReleaseSecurity},
		{"Package Maturity", cs.PackageMaturity},
		{"CI Pipeline Security", cs.CIPipelineSecurity},
	}
	for _, cat := range categories {
		if cat.score.RiskPoints >= 2 {
			result.Findings = append(result.Findings, models.Finding{
				Severity:    "HIGH",
				Category:    cat.name,
				Description: cat.score.Description,
				Check:       cat.name + " Assessment",
				Evidence:    cat.score.Evidence,
				Methodology: cat.score.Methodology,
			})
		} else if cat.score.RiskPoints == 1 {
			result.Findings = append(result.Findings, models.Finding{
				Severity:    "MEDIUM",
				Category:    cat.name,
				Description: cat.score.Description,
				Check:       cat.name + " Assessment",
				Evidence:    cat.score.Evidence,
				Methodology: cat.score.Methodology,
			})
		}
	}
}

// calculateSupplyChainScore implements a 0-22 point supply chain security rubric
// Each of 11 categories is scored 0-2 points (0=good, 2=high risk)
// Total: 0-5=Low risk, 6-16=Medium risk, 17+=High risk
func (a *Analyzer) calculateSupplyChainScore(result *models.AnalysisResult) {
	score := &models.SupplyChainScore{
		CategoryScores: models.CategoryScores{},
	}

	// Build package identifier for evidence attribution
	pkgID := result.Dependency.Name
	if result.Dependency.Version != "" {
		pkgID += "@" + result.Dependency.Version
	}

	// Category 1: Publisher Control (2FA/signing/multi-maintainer)
	score.CategoryScores.PublisherControl = a.scorePublisherControl(result)

	// Category 2: Ownership Changes/Transfers
	score.CategoryScores.OwnershipChanges = a.scoreOwnershipChanges(result)

	// Category 3: Release Anomalies (dormant→sudden activity)
	score.CategoryScores.ReleaseAnomalies = a.scoreReleaseAnomalies(result)

	// Category 4: Install-time Execution (postinstall scripts)
	score.CategoryScores.InstallExecution = a.scoreInstallExecution(result)

	// Category 5: Dependency Sprawl (transitive dependencies)
	score.CategoryScores.DependencySprawl = a.scoreDependencySprawl(result)

	// Category 6: Provenance (reproducible/signed builds)
	score.CategoryScores.Provenance = a.scoreProvenance(result)

	// Category 7: Health (bus factor/review process/CI)
	score.CategoryScores.Health = a.scoreHealth(result)

	// Category 8: Governance (documentation/responsiveness)
	score.CategoryScores.Governance = a.scoreGovernance(result)

	// Category 9: Release Security (CI publishing/branch protection/signed tags)
	score.CategoryScores.ReleaseSecurity = a.scoreReleaseSecurity(result)

	// Category 10: Package Maturity (age/update frequency/staleness)
	score.CategoryScores.PackageMaturity = a.scorePackageMaturity(result)

	// Category 11: CI Pipeline Security (CI config risks/unpinned actions/script injection/self-hosted)
	score.CategoryScores.CIPipelineSecurity = a.scoreCIPipelineSecurity(result)

	// Prefix each category's evidence with the specific package identifier
	// so every finding clearly references which library it applies to
	if pkgID != "" {
		categories := []*models.CategoryScore{
			&score.CategoryScores.PublisherControl,
			&score.CategoryScores.OwnershipChanges,
			&score.CategoryScores.ReleaseAnomalies,
			&score.CategoryScores.InstallExecution,
			&score.CategoryScores.DependencySprawl,
			&score.CategoryScores.Provenance,
			&score.CategoryScores.Health,
			&score.CategoryScores.Governance,
			&score.CategoryScores.ReleaseSecurity,
			&score.CategoryScores.PackageMaturity,
			&score.CategoryScores.CIPipelineSecurity,
		}
		for _, cat := range categories {
			cat.Evidence = pkgID + ": " + cat.Evidence
		}
	}

	// Calculate total score (11 categories, 0-22 points)
	score.TotalScore = score.CategoryScores.PublisherControl.RiskPoints +
		score.CategoryScores.OwnershipChanges.RiskPoints +
		score.CategoryScores.ReleaseAnomalies.RiskPoints +
		score.CategoryScores.InstallExecution.RiskPoints +
		score.CategoryScores.DependencySprawl.RiskPoints +
		score.CategoryScores.Provenance.RiskPoints +
		score.CategoryScores.Health.RiskPoints +
		score.CategoryScores.Governance.RiskPoints +
		score.CategoryScores.ReleaseSecurity.RiskPoints +
		score.CategoryScores.PackageMaturity.RiskPoints +
		score.CategoryScores.CIPipelineSecurity.RiskPoints

	// Determine risk level based on total score (11 categories, 0-22 points)
	// LOW: 0-5 (~23%), MEDIUM: 6-16 (~27-73%), HIGH: 17+ (~77%+)
	if score.TotalScore >= 17 {
		score.RiskLevel = "HIGH"
	} else if score.TotalScore >= 6 {
		score.RiskLevel = "MEDIUM"
	} else {
		score.RiskLevel = "LOW"
	}

	result.SupplyChainScore = score
}

// scorePublisherControl: Comprehensive publisher control risk assessment (0-2 pts)
//
// Core Question: "How easy is it to get publish rights?"
//
// This is the MOST CRITICAL risk factor - maintainer account compromise is the #1 attack vector
// Single maintainers with personal accounts are a single point of failure
//
// Weighted factors (30% of total supply chain risk):
// 1. Maintainer count (bus factor) - CRITICAL
// 2. Organization vs personal account
// 3. Account age (new accounts = red flag)
// 4. Email domain stability
// 5. Package concentration (many packages = high-value target)
// 6. Signing/MFA practices
//
// Justification: "Backstabber's Knife Collection" (Ohm et al., 2020)
// Finding: 90% of supply chain attacks target maintainer accounts, not code vulnerabilities
//
// Scoring:
// - 0 risk points (best): Multiple maintainers, org account, established accounts, signing
// - 1 risk point (moderate): Few maintainers OR personal account OR some concerns
// - 2 risk points (worst): Single maintainer + personal account + red flags
func (a *Analyzer) scorePublisherControl(result *models.AnalysisResult) models.CategoryScore {
	// Perform comprehensive publisher control analysis
	analysis := a.AnalyzePublisherControl(result, result.RepositoryURL)

	// Convert the detailed analysis to a CategoryScore
	return models.CategoryScore{
		Score:       2 - analysis.RiskPoints,
		RiskPoints:  analysis.RiskPoints,
		Description: analysis.Evidence,
		Evidence:    analysis.Evidence,
		Verified:    analysis.Verified,
		Methodology: "Checked maintainer count (bus factor), organization vs personal account type via GitHub API, maintainer account ages, email domain stability (personal vs organizational), package concentration per maintainer (npm), commit/release signing practices, and MFA enforcement (GitHub org-level).",
		ChecksPerformed: analysis.buildPublisherControlChecks(),
	}
}
