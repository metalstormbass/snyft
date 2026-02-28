package analyzer

import (
	"errors"
	"fmt"
	"time"

	"github.com/metalstormbass/snyft/pkg/fetcher"
	"github.com/metalstormbass/snyft/pkg/models"
)

// ValidCheckNames defines the valid check names accepted by the --check flag.
// Keys are the CLI flag values (kebab-case), mapped to display names.
var ValidCheckNames = map[string]string{
	"publisher-control":    "Publisher Control",
	"ownership-changes":    "Ownership Changes",
	"release-anomalies":    "Release Anomalies",
	"install-execution":    "Install Execution",
	"dependency-sprawl":    "Dependency Sprawl",
	"provenance":           "Provenance",
	"health":               "Health",
	"governance":           "Governance",
	"release-security":     "Release Security",
	"package-maturity":     "Package Maturity",
}

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

	// Libraries.io client (optional)
	librariesIOClient *fetcher.LibrariesIOClient

	// Check filter (nil = run all checks)
	checkFilter map[string]bool
}

// AnalyzerOption is a functional option for configuring an Analyzer
type AnalyzerOption func(*Analyzer)

// WithCheckFilter configures the analyzer to only run the specified checks.
// Check names must be valid keys from ValidCheckNames (e.g., "provenance", "health").
func WithCheckFilter(checks []string) AnalyzerOption {
	return func(a *Analyzer) {
		a.checkFilter = make(map[string]bool, len(checks))
		for _, c := range checks {
			a.checkFilter[c] = true
		}
	}
}

// isCheckEnabled returns true if the named check should be executed.
// When no filter is set (checkFilter is nil), all checks are enabled.
func (a *Analyzer) isCheckEnabled(name string) bool {
	if a.checkFilter == nil {
		return true
	}
	return a.checkFilter[name]
}

// NewAnalyzer creates a new Analyzer instance with optional configuration
func NewAnalyzer(opts ...AnalyzerOption) *Analyzer {
	a := &Analyzer{
		githubClient:      fetcher.NewGitHubClient(),
		gitlabClient:      fetcher.NewGitLabClient(),
		bitbucketClient:   fetcher.NewBitbucketClient(),
		npmClient:         fetcher.NewNPMClient(),
		pypiClient:        fetcher.NewPyPIClient(),
		mavenClient:       fetcher.NewMavenClient(),
		ossfClient:        fetcher.NewOSSFClient(),
		librariesIOClient: fetcher.NewLibrariesIOClient(),
	}

	// Apply options
	for _, opt := range opts {
		opt(a)
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
			npmURL := registryURL(dep)
			if errors.Is(err, fetcher.ErrPackageNotFound) {
				result.Findings = append(result.Findings, models.Finding{
					Severity:    "HIGH",
					Category:    "Package Not Found",
					Description: fmt.Sprintf("Package does not exist in npm registry: %v", err),
					Check:       "Package Registry Validation",
					SourceURL:   npmURL,
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
					SourceURL:   npmURL,
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
			pypiURL := registryURL(dep)
			if errors.Is(err, fetcher.ErrPackageNotFound) {
				result.Findings = append(result.Findings, models.Finding{
					Severity:    "HIGH",
					Category:    "Package Not Found",
					Description: fmt.Sprintf("Package does not exist in PyPI registry: %v", err),
					Check:       "Package Registry Validation",
					SourceURL:   pypiURL,
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
					SourceURL:   pypiURL,
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
			mavenURL := registryURL(dep)
			if errors.Is(err, fetcher.ErrPackageNotFound) {
				result.Findings = append(result.Findings, models.Finding{
					Severity:    "HIGH",
					Category:    "Package Not Found",
					Description: fmt.Sprintf("Package does not exist in Maven Central: %v", err),
					Check:       "Package Registry Validation",
					SourceURL:   mavenURL,
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
					SourceURL:   mavenURL,
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

	// Enrich with Libraries.io data (if API key is available)
	a.enrichWithLibrariesIO(&result)

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
			SourceURL:   registryURL(dep),
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

	// Analyze provenance (if available).
	// For Maven, GPG signature data is already populated from Maven Central
	// in packageMetadataFromMaven, so provenance scoring works even without a repo URL.
	if repoURL != "" {
		a.analyzeProvenance(&result, repoURL, dep.Ecosystem)
	} else if dep.Ecosystem == models.EcosystemMaven {
		// Maven GPG signature data was already set during metadata extraction;
		// no additional API calls needed. ProvenanceDetails can note this.
		if result.Metadata.HasMavenGPGSignature {
			result.Metadata.ProvenanceDetails = "Maven Central GPG signature verified (no source repository available)"
		}
	}

	// Calculate supply chain score (0-20 point rubric, 10 categories)
	a.calculateSupplyChainScore(&result)

	// Derive legacy RiskLevel/RiskScore from SupplyChainScore
	if result.SupplyChainScore != nil {
		result.RiskLevel = result.SupplyChainScore.RiskLevel
		result.RiskScore = result.SupplyChainScore.TotalScore * 100 / 20 // Map 0-20 to 0-100
	}

	// Populate Findings from CategoryScores for backward compatibility
	populateFindingsFromScores(&result)

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
	}
	for _, cat := range categories {
		if cat.score.Skipped {
			continue
		}
		if cat.score.RiskPoints >= 2 {
			result.Findings = append(result.Findings, models.Finding{
				Severity:    "HIGH",
				Category:    cat.name,
				Description: cat.score.Description,
				Check:       cat.name + " Assessment",
				Evidence:    cat.score.Evidence,
				Methodology: cat.score.Methodology,
				SourceURL:   cat.score.SourceURL,
			})
		} else if cat.score.RiskPoints == 1 {
			result.Findings = append(result.Findings, models.Finding{
				Severity:    "MEDIUM",
				Category:    cat.name,
				Description: cat.score.Description,
				Check:       cat.name + " Assessment",
				Evidence:    cat.score.Evidence,
				Methodology: cat.score.Methodology,
				SourceURL:   cat.score.SourceURL,
			})
		}
	}
}

// calculateSupplyChainScore implements a 0-20 point supply chain security rubric
// Each of 10 categories is scored 0-2 points (0=good, 2=high risk)
// Total: 0-8=Low risk, 9-12=Medium risk, 13+=High risk
func (a *Analyzer) calculateSupplyChainScore(result *models.AnalysisResult) {
	score := &models.SupplyChainScore{
		CategoryScores: models.CategoryScores{},
	}

	// Build package identifier for evidence attribution
	pkgID := result.Dependency.Name
	if result.Dependency.Version != "" {
		pkgID += "@" + result.Dependency.Version
	}

	skippedScore := models.CategoryScore{
		Skipped:     true,
		Description: "Skipped (not selected via --check flag)",
	}

	// Category 1: Publisher Control (2FA/signing/multi-maintainer)
	if a.isCheckEnabled("publisher-control") {
		score.CategoryScores.PublisherControl = a.scorePublisherControl(result)
	} else {
		score.CategoryScores.PublisherControl = skippedScore
	}

	// Category 2: Ownership Changes/Transfers
	if a.isCheckEnabled("ownership-changes") {
		score.CategoryScores.OwnershipChanges = a.scoreOwnershipChanges(result)
	} else {
		score.CategoryScores.OwnershipChanges = skippedScore
	}

	// Category 3: Release Anomalies (dormant→sudden activity)
	if a.isCheckEnabled("release-anomalies") {
		score.CategoryScores.ReleaseAnomalies = a.scoreReleaseAnomalies(result)
	} else {
		score.CategoryScores.ReleaseAnomalies = skippedScore
	}

	// Category 4: Install-time Execution (postinstall scripts)
	if a.isCheckEnabled("install-execution") {
		score.CategoryScores.InstallExecution = a.scoreInstallExecution(result)
	} else {
		score.CategoryScores.InstallExecution = skippedScore
	}

	// Category 5: Dependency Sprawl (transitive dependencies)
	if a.isCheckEnabled("dependency-sprawl") {
		score.CategoryScores.DependencySprawl = a.scoreDependencySprawl(result)
	} else {
		score.CategoryScores.DependencySprawl = skippedScore
	}

	// Category 6: Provenance (reproducible/signed builds)
	if a.isCheckEnabled("provenance") {
		score.CategoryScores.Provenance = a.scoreProvenance(result)
	} else {
		score.CategoryScores.Provenance = skippedScore
	}

	// Category 7: Health (bus factor/review process/CI)
	if a.isCheckEnabled("health") {
		score.CategoryScores.Health = a.scoreHealth(result)
	} else {
		score.CategoryScores.Health = skippedScore
	}

	// Category 8: Governance (documentation/responsiveness)
	if a.isCheckEnabled("governance") {
		score.CategoryScores.Governance = a.scoreGovernance(result)
	} else {
		score.CategoryScores.Governance = skippedScore
	}

	// Category 9: Release Security (CI publishing/branch protection/signed tags)
	if a.isCheckEnabled("release-security") {
		score.CategoryScores.ReleaseSecurity = a.scoreReleaseSecurity(result)
	} else {
		score.CategoryScores.ReleaseSecurity = skippedScore
	}

	// Category 10: Package Maturity (age/update frequency/staleness)
	if a.isCheckEnabled("package-maturity") {
		score.CategoryScores.PackageMaturity = a.scorePackageMaturity(result)
	} else {
		score.CategoryScores.PackageMaturity = skippedScore
	}

	// Set source URLs for each category so findings link to the data source
	categoryNames := []struct {
		name string
		cat  *models.CategoryScore
	}{
		{"Publisher Control", &score.CategoryScores.PublisherControl},
		{"Ownership Changes", &score.CategoryScores.OwnershipChanges},
		{"Release Anomalies", &score.CategoryScores.ReleaseAnomalies},
		{"Install Execution", &score.CategoryScores.InstallExecution},
		{"Dependency Sprawl", &score.CategoryScores.DependencySprawl},
		{"Provenance", &score.CategoryScores.Provenance},
		{"Health", &score.CategoryScores.Health},
		{"Governance", &score.CategoryScores.Governance},
		{"Release Security", &score.CategoryScores.ReleaseSecurity},
		{"Package Maturity", &score.CategoryScores.PackageMaturity},
	}
	for _, cn := range categoryNames {
		if !cn.cat.Skipped && cn.cat.SourceURL == "" {
			cn.cat.SourceURL = categorySourceURL(cn.name, result)
		}
	}

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
		}
		for _, cat := range categories {
			if !cat.Skipped {
				cat.Evidence = pkgID + ": " + cat.Evidence
			}
		}
	}

	// Count active (non-skipped) checks and calculate total score
	activeChecks := 0
	allCategories := []*models.CategoryScore{
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
	}
	for _, cat := range allCategories {
		if !cat.Skipped {
			score.TotalScore += cat.RiskPoints
			activeChecks++
		}
	}
	score.ActiveChecks = activeChecks
	score.MaxScore = activeChecks * 2

	// Determine risk level based on total score.
	// When all 10 categories are active (default): LOW 0-8, MEDIUM 9-12, HIGH 13+
	// When --check filters are active, thresholds scale proportionally so that
	// the same percentage of max score triggers each risk level.
	highThreshold := 13
	mediumThreshold := 9
	if activeChecks < 10 && activeChecks > 0 {
		// Scale proportionally: ceil(threshold * activeChecks / 10)
		highThreshold = (13*activeChecks + 9) / 10
		mediumThreshold = (9*activeChecks + 9) / 10
	}

	if score.TotalScore >= highThreshold {
		score.RiskLevel = "HIGH"
	} else if score.TotalScore >= mediumThreshold {
		score.RiskLevel = "MEDIUM"
	} else {
		score.RiskLevel = "LOW"
	}

	result.SupplyChainScore = score
}

// enrichWithLibrariesIO fetches additional metadata from Libraries.io and merges
// it into the analysis result's metadata. This is optional enrichment — if the
// API key is not set or the call fails, analysis proceeds without it.
//
// Justification: Dependents count indicates blast radius of a compromise.
// A package depended on by 50,000 repos is a higher-value target than one
// depended on by 5. This data is unavailable from registry APIs alone.
//
// Source: "Small World with High Risks" (Zimmermann et al., 2019)
func (a *Analyzer) enrichWithLibrariesIO(result *models.AnalysisResult) {
	if a.librariesIOClient == nil || !a.librariesIOClient.IsAvailable() {
		return
	}

	info := a.librariesIOClient.GetPackageInfo(string(result.Dependency.Ecosystem), result.Dependency.Name)
	if info == nil {
		return
	}

	result.Metadata.DependentsCount = info.DependentsCount
	result.Metadata.DependentReposCount = info.DependentReposCount
	result.Metadata.ContributionsCount = info.ContributionsCount
	if info.SecurityPolicyURL != "" {
		result.Metadata.SecurityPolicyURL = info.SecurityPolicyURL
	}
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
