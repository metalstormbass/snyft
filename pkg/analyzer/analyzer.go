package analyzer

import (
	"errors"
	"fmt"
	"strings"
	"sync"
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

	// Clone pool for parallel git clone operations (not rate-limited)
	clonePool *fetcher.ClonePool

	// Check filter (nil = run all checks)
	checkFilter map[string]bool
}

// AnalyzerOption is a functional option for configuring an Analyzer
type AnalyzerOption func(*Analyzer)

// WithClonePoolSize configures the size of the parallel clone pool.
// The clone pool runs git clone operations independently of the API worker pool
// and is NOT gated by the GitHub rate limiter (git clones use the git protocol).
// Default: fetcher.DefaultClonePoolSize (20).
func WithClonePoolSize(size int) AnalyzerOption {
	return func(a *Analyzer) {
		a.clonePool = fetcher.NewClonePool(size)
	}
}

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
		clonePool:         fetcher.NewClonePool(fetcher.DefaultClonePoolSize),
	}

	// Apply options
	for _, opt := range opts {
		opt(a)
	}

	return a
}

// ShouldFallbackToScraping returns true when the GitHub API rate limit remaining
// count is below the given threshold. The scan command uses this to decide
// when to switch remaining packages to scraping-only mode. The scan never
// stops — it continues with web scraping for all remaining packages.
func (a *Analyzer) ShouldFallbackToScraping(threshold int) bool {
	return a.githubClient.ShouldFallbackToScraping(threshold)
}

// RateLimitRemaining returns the last observed GitHub API rate limit remaining count.
// Returns -1 if no rate limit header has been received yet.
func (a *Analyzer) RateLimitRemaining() int {
	return a.githubClient.RateLimitRemaining()
}

// SetScrapingOnlyMode enables or disables scraping-only mode on the GitHub
// client. When enabled, all GitHub API calls are skipped and only web scraping
// is used. This is activated when the rate limit gate triggers during a scan,
// allowing remaining packages to still be analyzed with reduced data fidelity.
func (a *Analyzer) SetScrapingOnlyMode(enabled bool) {
	a.githubClient.SetScrapingOnlyMode(enabled)
}

// IsScrapingOnly returns true when the GitHub client is in scraping-only mode.
func (a *Analyzer) IsScrapingOnly() bool {
	return a.githubClient.IsScrapingOnly()
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
	result.ScorecardURL = ossfScorecardURL(repoURL)
	result.Metadata = metadata

	// Trigger bare git clone early for GitHub repos via the dedicated clone pool.
	// The clone pool runs independently of the API/scraping worker pool and is NOT
	// gated by the GitHub rate limiter — git clones use the git protocol, not the API.
	// Clones start as soon as their URLs are resolved and run concurrently (up to
	// pool size) with all other data collection. The clone populates caches for
	// commit authors, signed commits, commit activity, file tree, and file content.
	var cloneDone <-chan struct{}
	if repoURL != "" && fetcher.DetectPlatform(repoURL) == fetcher.PlatformGitHub {
		ghClient := a.githubClient
		cloneDone = a.clonePool.Submit(func() {
			_ = ghClient.CloneAndAnalyze(repoURL)
		})
	}

	// Run data collection steps concurrently. Each method writes to non-overlapping
	// metadata fields on result. Methods that also append to result.Findings or
	// result.RiskFactors use the shared mutex for thread-safe access.
	var mu sync.Mutex
	var wg sync.WaitGroup

	// --- Independent steps (no inter-dependencies) ---

	wg.Add(1)
	go func() {
		defer wg.Done()
		// Enrich with Libraries.io data (if API key is available)
		a.enrichWithLibrariesIO(&result)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		// PRIMARY CHECK: Verify source code availability for the EXACT version
		a.verifySourceCode(&result, dep, repoURL, &mu)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		// Analyze dependency sprawl from lock files
		a.analyzeDependencySprawl(&result, dep)
	}()

	// Analyze repository if URL is available
	if repoURL != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			a.analyzeRepository(&result, repoURL, &mu)
		}()
	} else {
		addFindingSafe(&mu, &result, models.Finding{
			Severity:    "HIGH",
			Category:    "Missing Source Code",
			Description: "No repository URL found in package metadata",
			Check:       "Repository Availability Check",
			SourceURL:   registryURL(dep),
		})
		result.SourceCodeAvailable = false
		addRiskFactorSafe(&mu, &result, "No public source code repository")
	}

	// analyzeBuildInfrastructure + analyzeHealthMetrics form a dependency chain:
	// analyzeHealthMetrics reads CISystems populated by analyzeBuildInfrastructure.
	// Run them sequentially in a single goroutine, parallel with other steps.
	wg.Add(1)
	go func() {
		defer wg.Done()
		a.analyzeBuildInfrastructure(&result, repoURL, &mu)
		if repoURL != "" {
			a.analyzeHealthMetrics(&result, repoURL)
		}
	}()

	if repoURL != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Analyze release documentation (CONTRIBUTING.md, RELEASING.md, etc.)
			a.analyzeReleaseDocumentation(&result, repoURL)
		}()

		wg.Add(1)
		go func() {
			defer wg.Done()
			// Get OSSF Scorecard (if available)
			a.analyzeOSSFScorecard(&result, repoURL, &mu)
		}()

		wg.Add(1)
		go func() {
			defer wg.Done()
			// Analyze provenance (if available)
			a.analyzeProvenance(&result, repoURL, dep.Ecosystem)
		}()
	} else if dep.Ecosystem == models.EcosystemMaven {
		// Maven GPG signature data was already set during metadata extraction;
		// no additional API calls needed. ProvenanceDetails can note this.
		if result.Metadata.HasMavenGPGSignature {
			result.Metadata.ProvenanceDetails = "Maven Central GPG signature verified (no source repository available)"
		}
	}

	// Wait for all data collection steps to complete before scoring
	wg.Wait()

	// Clean up the bare clone temp directory now that all data has been extracted.
	// Wait for clone to finish first if it hasn't already.
	if cloneDone != nil {
		<-cloneDone

		// Analyze actual script files referenced by npm install hooks.
		// Uses the bare clone (no API calls) to read files like scripts/postinstall.js
		// that are pointed to by package.json hook commands.
		if dep.Ecosystem == models.EcosystemNPM && result.Metadata.HasInstallScripts && len(result.Metadata.InstallScripts) > 0 {
			gitClient := a.getGitClient(repoURL)
			readFile := func(path string) (string, error) {
				return gitClient.GetFileContent(repoURL, path)
			}
			filePatterns := AnalyzeNPMScriptFiles(result.Metadata.InstallScripts, readFile)
			if len(filePatterns) > 0 {
				if result.Metadata.InstallScriptAnalysis == nil {
					result.Metadata.InstallScriptAnalysis = &models.InstallScriptAnalysis{}
				}
				for _, p := range filePatterns {
					result.Metadata.InstallScriptAnalysis.DangerousPatterns = append(
						result.Metadata.InstallScriptAnalysis.DangerousPatterns,
						models.DangerousPattern{
							Pattern:     p.Pattern,
							Description: p.Description,
							Severity:    p.Severity,
							Match:       p.Match,
						},
					)
				}
				result.Metadata.InstallScriptAnalysis.HasDangerousPatterns = true
				// Recalculate risk level after merging file-level findings
				highCount := 0
				for _, p := range result.Metadata.InstallScriptAnalysis.DangerousPatterns {
					if p.Severity == "HIGH" {
						highCount++
					}
				}
				if highCount > 0 {
					result.Metadata.InstallScriptAnalysis.RiskLevel = "HIGH"
				} else {
					result.Metadata.InstallScriptAnalysis.RiskLevel = "MEDIUM"
				}
			}
		}

		a.githubClient.CleanupClone(repoURL)
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

	// Score all 10 categories concurrently. Each scoring function only reads
	// from result (no writes) and returns a CategoryScore value that is assigned
	// to a separate struct field — no data races possible.
	var scoreWg sync.WaitGroup

	type scoringTask struct {
		name   string
		target *models.CategoryScore
		fn     func(*models.AnalysisResult) models.CategoryScore
	}

	tasks := []scoringTask{
		{"publisher-control", &score.CategoryScores.PublisherControl, a.scorePublisherControl},
		{"ownership-changes", &score.CategoryScores.OwnershipChanges, a.scoreOwnershipChanges},
		{"release-anomalies", &score.CategoryScores.ReleaseAnomalies, a.scoreReleaseAnomalies},
		{"install-execution", &score.CategoryScores.InstallExecution, a.scoreInstallExecution},
		{"dependency-sprawl", &score.CategoryScores.DependencySprawl, a.scoreDependencySprawl},
		{"provenance", &score.CategoryScores.Provenance, a.scoreProvenance},
		{"health", &score.CategoryScores.Health, a.scoreHealth},
		{"governance", &score.CategoryScores.Governance, a.scoreGovernance},
		{"release-security", &score.CategoryScores.ReleaseSecurity, a.scoreReleaseSecurity},
		{"package-maturity", &score.CategoryScores.PackageMaturity, a.scorePackageMaturity},
	}

	for i := range tasks {
		task := tasks[i]
		if !a.isCheckEnabled(task.name) {
			*task.target = skippedScore
			continue
		}
		scoreWg.Add(1)
		go func() {
			defer scoreWg.Done()
			*task.target = task.fn(result)
		}()
	}

	scoreWg.Wait()

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

	// Build a descriptive finding that references actual data and explains risk
	description := buildPublisherControlDescription(analysis)

	// Convert the detailed analysis to a CategoryScore
	// DataAvailable is true only when we have meaningful data (not just "unknown" entries)
	dataAvailable := analysis.MaintainerCount > 0 || analysis.IsOrganization || analysis.IsPersonalAccount || analysis.SigningChecked
	return models.CategoryScore{
		Score:       2 - analysis.RiskPoints,
		RiskPoints:  analysis.RiskPoints,
		Description: description,
		Evidence:    analysis.Evidence,
		Verified:    analysis.Verified,
		DataAvailable: dataAvailable,
		Methodology: "Checked maintainer count (bus factor), organization vs personal account type via GitHub API, maintainer account ages, email domain stability (personal vs organizational), package concentration per maintainer (npm), commit/release signing practices, and MFA enforcement (GitHub org-level).",
		ChecksPerformed: analysis.buildPublisherControlChecks(),
	}
}

// buildPublisherControlDescription creates a human-readable description from analysis data,
// explaining what was found and why it matters for supply chain risk.
func buildPublisherControlDescription(analysis *PublisherControlAnalysis) string {
	switch analysis.RiskPoints {
	case 2:
		parts := []string{}
		if analysis.SingleMaintainer {
			parts = append(parts, "Single maintainer")
		}
		if analysis.IsPersonalAccount {
			parts = append(parts, "personal account")
		}
		if analysis.HasExpirableDomains {
			parts = append(parts, "personal email")
		}
		if analysis.SigningChecked && !analysis.HasSignedCommits && !analysis.HasSignedReleases {
			parts = append(parts, "no commit/release signing")
		}
		summary := strings.Join(parts, ", ")
		if summary == "" {
			summary = "Multiple high-risk publisher control signals"
		}
		return fmt.Sprintf("%s. Account takeover of a single maintainer gives attackers full package control — the #1 supply chain attack vector.", summary)

	case 1:
		parts := []string{}
		caps := models.GetEcosystemCapabilities(analysis.Ecosystem)
		if analysis.MaintainerCount == 0 && !caps.HasMaintainerList {
			parts = append(parts, fmt.Sprintf("Maintainer count unavailable (%s does not expose this data)", analysis.Ecosystem))
		} else if analysis.MaintainerCount == 0 {
			parts = append(parts, "No maintainer data found")
		} else if analysis.SingleMaintainer {
			parts = append(parts, fmt.Sprintf("Single maintainer (%s)", strings.Join(analysis.MaintainerEmails, ", ")))
		} else {
			parts = append(parts, fmt.Sprintf("%d maintainers found", analysis.MaintainerCount))
		}
		if analysis.HasNewMaintainers {
			parts = append(parts, fmt.Sprintf("%d new account(s) < 6 months old", analysis.NewMaintainerCount))
		}
		// Tiered language based on maintainer count to differentiate risk levels
		suffix := ". Moderate publisher control risk — fewer maintainers or weaker authentication increases susceptibility to account compromise."
		if analysis.MaintainerCount >= 4 {
			suffix = ". Minor publisher control gap — the maintainer team provides reasonable redundancy, but missing security controls (signing, MFA) leave room for improvement."
		} else if analysis.MaintainerCount >= 2 {
			suffix = ". Small maintainer team — while not a single point of failure, a team of 2-3 still has limited redundancy if an account is compromised."
		}
		return strings.Join(parts, "; ") + suffix

	default:
		parts := []string{}
		if analysis.MaintainerCount > 1 {
			parts = append(parts, fmt.Sprintf("%d maintainers", analysis.MaintainerCount))
		}
		if analysis.IsOrganization {
			parts = append(parts, fmt.Sprintf("organization (%s)", analysis.OrgName))
		}
		if analysis.MFAEnforced {
			parts = append(parts, "MFA enforced")
		}
		if analysis.HasSignedCommits || analysis.HasSignedReleases {
			parts = append(parts, "signing enabled")
		}
		if len(parts) == 0 {
			return "Publisher control checks passed. Distributed maintainership reduces single-point-of-failure risk."
		}
		return strings.Join(parts, ", ") + ". Distributed maintainership with strong authentication reduces account takeover risk."
	}
}
