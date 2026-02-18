package analyzer

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/metalstormbass/snyft/pkg/ai"
	"github.com/metalstormbass/snyft/pkg/fetcher"
	"github.com/metalstormbass/snyft/pkg/models"
	"github.com/metalstormbass/snyft/pkg/parser"
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

	// Calculate final risk score
	a.calculateRiskScore(&result)

	// Calculate supply chain score (0-20 point rubric)
	a.calculateSupplyChainScore(&result)

	// Enrich with AI analysis (if enabled)
	a.enrichWithAIAnalysis(&result)

	return result
}

// verifySourceCode performs primary source code availability verification
// This is the FIRST check before any other scoring
func (a *Analyzer) verifySourceCode(result *models.AnalysisResult, dep models.Dependency, repoURL string) {
	var sourceVerification *models.SourceVerification

	// Get the appropriate git platform client for this repository
	var gitClient fetcher.GitPlatformClient
	if repoURL != "" {
		gitClient = a.getGitClient(repoURL)
	} else {
		gitClient = a.githubClient // fallback
	}

	switch dep.Ecosystem {
	case models.EcosystemNPM:
		sourceVerification = a.npmClient.VerifySourceAvailability(dep.Name, dep.Version, repoURL, gitClient)

	case models.EcosystemPyPI:
		sourceVerification = a.pypiClient.VerifySourceAvailability(dep.Name, dep.Version, repoURL, gitClient)

	case models.EcosystemMaven:
		sourceVerification = a.mavenClient.VerifySourceAvailability(dep.Name, dep.Version, repoURL, gitClient)
	}

	if sourceVerification != nil {
		result.SourceVerification = sourceVerification

		// Add findings based on source verification results
		if !sourceVerification.Verified {
			if !sourceVerification.HasSourcePackage && !sourceVerification.HasMatchingGitTag {
				result.Findings = append(result.Findings, models.Finding{
					Severity:    "HIGH",
					Category:    "Source Code Verification Failed",
					Description: "No verifiable source code found for this exact version",
					Check:       "Primary Source Code Verification",
					Evidence:    strings.Join(sourceVerification.VerificationErrors, "; "),
				})
				result.RiskFactors = append(result.RiskFactors, "No verifiable source code for exact version")
			} else if !sourceVerification.HasSourcePackage {
				result.Findings = append(result.Findings, models.Finding{
					Severity:    "HIGH",
					Category:    "Missing Source Package",
					Description: "Package distribution lacks source code",
					Check:       "Source Package Verification",
					Evidence:    sourceVerification.Details,
				})
				result.RiskFactors = append(result.RiskFactors, "No source package available")
			} else if !sourceVerification.HasMatchingGitTag && repoURL != "" {
				// Only flag a missing git tag when a repository URL was available and
				// a tag check was actually attempted. When repoURL is empty the check
				// was never performed, so HasMatchingGitTag == false is not actionable.
				result.Findings = append(result.Findings, models.Finding{
					Severity:    "MEDIUM",
					Category:    "Missing Git Tag",
					Description: fmt.Sprintf("No git tag found for version %s in repository", dep.Version),
					Check:       "Git Tag Verification",
					Evidence:    "Cannot verify build corresponds to repository state",
				})
				result.RiskFactors = append(result.RiskFactors, "No matching git tag for version")
			}
		}
	}
}

func (a *Analyzer) analyzeRepository(result *models.AnalysisResult, repoURL string) {
	gitClient := a.getGitClient(repoURL)
	repoInfo, err := gitClient.GetRepositoryInfo(repoURL)
	if err != nil {
		result.Findings = append(result.Findings, models.Finding{
			Severity:    "MEDIUM",
			Category:    "Repository Access",
			Description: fmt.Sprintf("Failed to fetch repository info: %v", err),
			Check:       "Repository Metadata Check",
		})
		return
	}

	result.SourceCodeAvailable = true

	// Update metadata with repository info
	result.Metadata.RepoOwner = repoInfo.Owner
	result.Metadata.RepoName = repoInfo.Name
	result.Metadata.RepoStars = repoInfo.Stars
	result.Metadata.RepoForks = repoInfo.Forks
	result.Metadata.RepoWatchers = repoInfo.Watchers
	result.Metadata.RepoOpenIssues = repoInfo.OpenIssues
	result.Metadata.RepoLastCommit = repoInfo.PushedAt
	result.Metadata.RepoCreatedAt = repoInfo.CreatedAt
	result.Metadata.RepoUpdatedAt = repoInfo.UpdatedAt
	result.Metadata.RepoDefaultBranch = repoInfo.DefaultBranch
	result.Metadata.RepoArchived = repoInfo.Archived

	// Check for concerning signals
	if repoInfo.Archived {
		result.Findings = append(result.Findings, models.Finding{
			Severity:    "HIGH",
			Category:    "Archived Repository",
			Description: "The repository is archived and no longer maintained",
			Check:       "Repository Status Check",
		})
		result.RiskFactors = append(result.RiskFactors, "Archived repository")
	}

	// Check last commit age
	// Guard against zero timestamps returned by failed scraping fallbacks:
	// a zero PushedAt would compute to ~106,752 days and trigger a false positive.
	if !repoInfo.PushedAt.IsZero() {
		daysSinceLastCommit := time.Since(repoInfo.PushedAt).Hours() / 24
		if daysSinceLastCommit > 365 {
			result.Findings = append(result.Findings, models.Finding{
				Severity:    "MEDIUM",
				Category:    "Stale Repository",
				Description: fmt.Sprintf("No commits in the last %.0f days", daysSinceLastCommit),
				Check:       "Repository Activity Check",
			})
			result.RiskFactors = append(result.RiskFactors, "Inactive development")
		}
	}

	// Check for low activity indicators.
	// Only flag this when we have a verified star count (Stars > 0 means the API
	// or scraper returned data; Stars == 0 could mean the count was never populated,
	// which would produce a false positive for large, popular projects).
	if repoInfo.Stars > 0 && repoInfo.Stars < 10 && repoInfo.Forks < 5 {
		result.Findings = append(result.Findings, models.Finding{
			Severity:    "MEDIUM",
			Category:    "Low Community Engagement",
			Description: "Package has minimal community engagement (low stars/forks)",
			Check:       "Community Engagement Check",
		})
		result.RiskFactors = append(result.RiskFactors, "Limited community adoption")
	}
}

func (a *Analyzer) analyzeDependencySprawl(result *models.AnalysisResult, dep models.Dependency) {
	// Try to find and analyze lock file based on the source manifest.
	// When dep.Source is empty (e.g. scanning by package name via CLI), fall
	// back to the current working directory so that lock files present in the
	// user's project are still used for analysis.
	var dir string
	if dep.Source != "" {
		dir = filepath.Dir(dep.Source)
	} else {
		cwd, err := os.Getwd()
		if err != nil {
			return
		}
		dir = cwd
	}
	var metrics *models.DependencyMetrics
	var err error

	switch dep.Ecosystem {
	case models.EcosystemNPM:
		// Look for package-lock.json first, then fall back to yarn.lock.
		// CountTransitiveDependencies expects npm's JSON lock format; yarn.lock
		// uses a different format so that fallback will return an error, which is
		// handled gracefully below (metrics stays nil, heuristic scoring applies).
		lockfilePath := filepath.Join(dir, "package-lock.json")
		metrics, err = parser.CountTransitiveDependencies(lockfilePath)
		if err != nil {
			yarnPath := filepath.Join(dir, "yarn.lock")
			metrics, err = parser.CountTransitiveDependencies(yarnPath)
		}

	case models.EcosystemPyPI:
		// Look for Pipfile.lock first, then fall back to requirements.txt
		lockfilePath := filepath.Join(dir, "Pipfile.lock")
		metrics, err = parser.CountPythonDependencies(lockfilePath)
		if err != nil {
			// Try requirements.txt
			lockfilePath = filepath.Join(dir, "requirements.txt")
			metrics, err = parser.CountPythonDependencies(lockfilePath)
		}

	case models.EcosystemMaven:
		// For Maven, analyze pom.xml
		pomPath := filepath.Join(dir, "pom.xml")
		metrics, err = parser.CountMavenDependencies(pomPath)
	}

	// If we successfully got metrics, update metadata.
	// When lock file data is verified (Verified=true), it always wins — it's the most
	// accurate source. When lock file data is unverified (Verified=false, e.g. from
	// requirements.txt or pom.xml which only show partial data), preserve the registry-
	// based DirectCount if it is more informative than the lock file's DirectCount.
	if err == nil && metrics != nil {
		if metrics.Verified {
			// Verified lock file data always wins
			result.Metadata.DependencyMetrics = metrics
		} else if result.Metadata.DependencyMetrics != nil && result.Metadata.DependencyMetrics.DirectCount > metrics.DirectCount {
			// Unverified lock file data: keep registry DirectCount if more informative,
			// but update TransitiveCount from the manifest file (e.g. requirements.txt total)
			result.Metadata.DependencyMetrics.TransitiveCount = metrics.TransitiveCount
		} else {
			result.Metadata.DependencyMetrics = metrics
		}
	}
}

func (a *Analyzer) analyzeBuildInfrastructure(result *models.AnalysisResult, repoURL string) {
	if repoURL == "" {
		return
	}

	gitClient := a.getGitClient(repoURL)
	ciSystems, err := gitClient.DetectCISystems(repoURL)
	if err != nil {
		return
	}

	result.Metadata.CISystems = ciSystems
	result.Metadata.HasCI = len(ciSystems) > 0

	// Classify each CI system into structured BuildSystemInfo
	buildSystems := fetcher.ClassifyBuildSystems(ciSystems)

	// For GitHub Actions, optionally inspect workflow content for self-hosted runner detection
	for i, bs := range buildSystems {
		if bs.Platform == "GitHub Actions" && repoURL != "" {
			// Try to fetch a workflow file and check runner type
			workflowContent, err := gitClient.GetFileContent(repoURL, ".github/workflows/release.yml")
			if err != nil {
				workflowContent, _ = gitClient.GetFileContent(repoURL, ".github/workflows/publish.yml")
			}
			if workflowContent != "" {
				isSelfHosted, runnerLabel := fetcher.CheckGitHubActionsRunnerType(workflowContent)
				if isSelfHosted {
					buildSystems[i].IsSelfHosted = true
					buildSystems[i].HostedBy = "Self-hosted"
					buildSystems[i].RunnerDetails = runnerLabel
				} else if runnerLabel != "" {
					buildSystems[i].RunnerDetails = runnerLabel
				}
			}
		}
	}

	result.Metadata.BuildSystems = buildSystems

	// Check if any build system uses self-hosted runners
	for _, bs := range buildSystems {
		if bs.IsSelfHosted {
			result.Metadata.HasSelfHosted = true
			break
		}
	}

	// Parse CI/CD workflow content for risk signals
	a.parseCIWorkflowRisks(result, gitClient, repoURL)

	if len(ciSystems) > 0 {
		// Build a human-readable description showing platform and host
		descriptions := make([]string, 0, len(buildSystems))
		for _, bs := range buildSystems {
			if bs.IsSelfHosted {
				descriptions = append(descriptions, bs.Platform+" (self-hosted)")
			} else {
				descriptions = append(descriptions, bs.Platform+" ("+bs.HostedBy+")")
			}
		}
		result.BuildInfrastructure = "CI detected: " + strings.Join(descriptions, ", ")

		if result.Metadata.HasSelfHosted {
			result.Findings = append(result.Findings, models.Finding{
				Severity:    "HIGH",
				Category:    "Self-Hosted CI Runners",
				Description: "Self-hosted CI runners detected: build environment is not controlled by a trusted cloud provider",
				Check:       "Build System Location Check",
				Evidence:    result.BuildInfrastructure,
			})
			result.RiskFactors = append(result.RiskFactors, "Self-hosted build runners (uncontrolled build environment)")
		}
	} else {
		result.BuildInfrastructure = "No CI detected"
		result.Findings = append(result.Findings, models.Finding{
			Severity:    "MEDIUM",
			Category:    "No CI/CD",
			Description: "No continuous integration system detected",
			Check:       "CI/CD Detection Check",
		})
		result.RiskFactors = append(result.RiskFactors, "No automated build verification")
	}

	// Check for automated release process
	hasReleases, err := gitClient.HasAutomatedReleases(repoURL)
	if err == nil && hasReleases {
		result.Metadata.HasReleaseProcess = true
	} else {
		result.Findings = append(result.Findings, models.Finding{
			Severity:    "LOW",
			Category:    "Manual Releases",
			Description: "No evidence of automated release process",
			Check:       "Release Automation Check",
		})
	}
}

func (a *Analyzer) analyzeHealthMetrics(result *models.AnalysisResult, repoURL string) {
	gitClient := a.getGitClient(repoURL)

	// Get commit statistics for bus factor calculation
	commitStats, err := gitClient.GetCommitStats(repoURL)
	if err == nil && commitStats != nil {
		result.Metadata.BusFactor = commitStats.BusFactor
		result.Metadata.CommitDistribution = commitStats.AuthorCommits
		result.Metadata.TopContributorPct = commitStats.TopContributorPct
	}

	// Get pull request statistics for code review verification
	prStats, err := gitClient.GetPullRequestStats(repoURL)
	if err == nil && prStats != nil {
		result.Metadata.CodeReviewRate = prStats.CodeReviewRate
		result.Metadata.RequiredReviewers = prStats.RequiredReviewers
		result.Metadata.HasBranchProtection = prStats.HasBranchProtection
	}

	// Analyze CI quality
	ciQuality, err := gitClient.AnalyzeCIQuality(repoURL, result.Metadata.CISystems)
	if err == nil && ciQuality != nil {
		result.Metadata.CIQualityScore = ciQuality.QualityScore
		result.Metadata.CIHasTests = ciQuality.HasTests

		// Supplement CI quality with workflow content analysis when the basic
		// heuristic (file-name-only) reports no tests. The AnalyzeCIQuality
		// method in fetcher only checks workflow file names for test keywords.
		// Many projects name their CI workflow "build.yml" or "main.yml" but
		// still run comprehensive tests inside. Checking actual content catches
		// these cases.
		if !ciQuality.HasTests && ciQuality.HasCI {
			hasTestsFromContent := a.checkWorkflowContentForTests(gitClient, repoURL)
			if hasTestsFromContent {
				result.Metadata.CIHasTests = true
				// Boost CI quality score if tests detected in content but not filenames
				// Base CI score is 3 (CI exists) + 1-2 (workflow count). Add 4 for tests.
				if result.Metadata.CIQualityScore < 7 {
					result.Metadata.CIQualityScore = result.Metadata.CIQualityScore + 4
					if result.Metadata.CIQualityScore > 10 {
						result.Metadata.CIQualityScore = 10
					}
				}
			}
		}
	}
}

// checkWorkflowContentForTests fetches actual CI workflow file content and checks
// for test-related commands/steps. This supplements the filename-only heuristic in
// fetcher.AnalyzeCIQuality which misses workflows named "build.yml" or "main.yml"
// that still run tests.
//
// Test: CI workflow content analysis for test detection
// Justification: CI quality assessment based only on workflow filenames produces false
//                negatives for projects that name their CI workflow generically (e.g.,
//                "build.yml", "main.yml") but run comprehensive test suites inside.
// Source: OSSF Scorecard "CI-Tests" methodology
// Methodology: Fetch common workflow file paths and search content for test commands
// Result: Returns true if any workflow content contains test-related patterns
func (a *Analyzer) checkWorkflowContentForTests(gitClient fetcher.GitPlatformClient, repoURL string) bool {
	// Common workflow file paths to check
	workflowPaths := []string{
		".github/workflows/build.yml",
		".github/workflows/main.yml",
		".github/workflows/ci.yml",
		".github/workflows/push.yml",
		".github/workflows/build.yaml",
		".github/workflows/main.yaml",
		".github/workflows/ci.yaml",
	}

	// Test-related patterns in workflow content
	testPatterns := []string{
		"npm test", "npm run test", "yarn test", "pnpm test",
		"pytest", "python -m pytest", "tox",
		"mvn test", "gradle test", "./gradlew test",
		"go test", "cargo test", "dotnet test",
		"jest", "mocha", "vitest", "playwright",
		"run: test", "run: make test",
	}

	for _, path := range workflowPaths {
		content, err := gitClient.GetFileContent(repoURL, path)
		if err != nil || content == "" {
			continue
		}

		lower := strings.ToLower(content)
		for _, pattern := range testPatterns {
			if strings.Contains(lower, pattern) {
				return true
			}
		}
	}
	return false
}

// parseCIWorkflowRisks fetches CI/CD configuration files from the repository and
// parses them for supply chain risk patterns.
//
// Check: CI/CD workflow content analysis for risk signals
// Justification: CI/CD configurations define the release pipeline. Insecure configs
//                (unpinned actions, excessive permissions, dangerous triggers) are
//                direct supply chain attack vectors that can be exploited to inject
//                malicious code into published packages.
// Source: "Backstabber's Knife Collection" (Ohm et al., 2020) - https://arxiv.org/abs/2005.09535
//         GitHub Actions Security Hardening - https://docs.github.com/en/actions/security-guides
//         SLSA Build Level Requirements - https://slsa.dev/spec/v1.0/levels
// Methodology: Fetch CI config file content via Git platform API, dispatch to
//              platform-specific parsers for risk pattern detection
// Result: Populates result.Metadata.CIWorkflowRisks with parsed risk signals
func (a *Analyzer) parseCIWorkflowRisks(result *models.AnalysisResult, gitClient fetcher.GitPlatformClient, repoURL string) {
	if repoURL == "" || len(result.Metadata.CISystems) == 0 {
		return
	}

	configPaths := fetcher.CIConfigPaths()

	for _, ciSystem := range result.Metadata.CISystems {
		paths, ok := configPaths[ciSystem]
		if !ok {
			continue
		}

		for _, path := range paths {
			content, err := gitClient.GetFileContent(repoURL, path)
			if err != nil || content == "" {
				continue
			}

			risk := fetcher.ParseCIWorkflowContent(content, ciSystem)
			if risk.RiskCount > 0 {
				result.Metadata.CIWorkflowRisks = append(result.Metadata.CIWorkflowRisks, risk)

				// Add findings for significant risks
				if risk.HasScriptInjection {
					result.Findings = append(result.Findings, models.Finding{
						Severity:    "HIGH",
						Category:    "CI Script Injection",
						Description: fmt.Sprintf("CI workflow script injection detected in %s config", ciSystem),
						Check:       "CI/CD Workflow Risk Analysis",
						Evidence:    strings.Join(risk.Details, "; "),
					})
				}
				if len(risk.DangerousTriggers) > 0 {
					result.Findings = append(result.Findings, models.Finding{
						Severity:    "HIGH",
						Category:    "Dangerous CI Triggers",
						Description: fmt.Sprintf("Dangerous workflow triggers in %s: %s", ciSystem, strings.Join(risk.DangerousTriggers, ", ")),
						Check:       "CI/CD Workflow Risk Analysis",
						Evidence:    strings.Join(risk.Details, "; "),
					})
				}
				if len(risk.UnpinnedActions) > 0 {
					result.Findings = append(result.Findings, models.Finding{
						Severity:    "MEDIUM",
						Category:    "Unpinned CI Dependencies",
						Description: fmt.Sprintf("%d unpinned actions/orbs/images in %s (vulnerable to tag hijacking)", len(risk.UnpinnedActions), ciSystem),
						Check:       "CI/CD Workflow Risk Analysis",
						Evidence:    strings.Join(risk.UnpinnedActions, ", "),
					})
				}
			}

			// For GitHub Actions, only parse the first found workflow to avoid
			// excessive API calls. Other workflows share similar patterns.
			if ciSystem == "GitHub Actions" {
				break
			}
		}
	}
}

func (a *Analyzer) analyzeOSSFScorecard(result *models.AnalysisResult, repoURL string) {
	scorecard, err := a.ossfClient.GetScorecard(repoURL)
	if err != nil {
		// OSSF scorecard may not be available for all projects
		return
	}

	result.Metadata.OSSFScore = scorecard.Score
	result.Metadata.OSSFChecks = scorecard.Checks

	if scorecard.Score < 5.0 {
		result.Findings = append(result.Findings, models.Finding{
			Severity:    "MEDIUM",
			Category:    "Low OSSF Score",
			Description: fmt.Sprintf("OpenSSF Scorecard score is %.1f/10", scorecard.Score),
			Check:       "OSSF Scorecard Check",
		})
		result.RiskFactors = append(result.RiskFactors, "Low supply chain security score")
	}
}

func (a *Analyzer) analyzeProvenance(result *models.AnalysisResult, repoURL string, ecosystem models.Ecosystem) {
	// Get Git platform provenance information
	if repoURL != "" {
		gitClient := a.getGitClient(repoURL)
		provInfo, err := gitClient.GetProvenanceInfo(repoURL)
		if err == nil {
			result.Metadata.HasSLSAAttestation = provInfo.HasSLSAAttestation
			result.Metadata.SLSALevel = provInfo.SLSALevel
			result.Metadata.HasSigstoreSignature = provInfo.HasSigstoreSignature
			result.Metadata.ReproducibleBuild = provInfo.ReproducibleBuild

			// Update SignedReleases based on actual release data
			if provInfo.TotalReleaseCount > 0 {
				ratio := float64(provInfo.SignedReleaseCount) / float64(provInfo.TotalReleaseCount)
				result.Metadata.SignedReleases = ratio >= 0.5 // At least 50% signed
			}
		}
	}

	// Check ecosystem-specific provenance
	switch ecosystem {
	case models.EcosystemNPM:
		hasProvenance, provenanceURL, err := a.npmClient.CheckNPMProvenance(result.Dependency.Name)
		if err == nil {
			result.Metadata.HasNPMProvenance = hasProvenance
			if hasProvenance {
				result.Metadata.ProvenanceDetails = fmt.Sprintf("npm provenance: %s", provenanceURL)
			}
		}

	case models.EcosystemPyPI:
		hasSignatures, signedCount, totalCount, err := a.pypiClient.CheckPyPISignatures(result.Dependency.Name)
		if err == nil {
			result.Metadata.HasPyPISignatures = hasSignatures
			if hasSignatures {
				result.Metadata.ProvenanceDetails = fmt.Sprintf("PyPI signatures: %d/%d distributions signed", signedCount, totalCount)
			}
		}
	}
}

func (a *Analyzer) calculateRiskScore(result *models.AnalysisResult) {
	score := 0

	// Calculate risk based on findings
	for _, finding := range result.Findings {
		switch finding.Severity {
		case "HIGH":
			score += 30
		case "MEDIUM":
			score += 15
		case "LOW":
			score += 5
		}
	}

	// Cap at 100
	if score > 100 {
		score = 100
	}

	result.RiskScore = score

	// Determine risk level
	if score >= 70 {
		result.RiskLevel = "HIGH"
	} else if score >= 40 {
		result.RiskLevel = "MEDIUM"
	} else {
		result.RiskLevel = "LOW"
	}
}

// Helper functions to convert package info to metadata
func packageMetadataFromNPM(pkg *fetcher.NPMPackage) models.PackageMetadata {
	metadata := models.PackageMetadata{
		DownloadCount:  pkg.Downloads,
		PublishedAt:    pkg.PublishedAt,
		LatestVersion:  pkg.LatestVersion,
		Maintainers:    pkg.Maintainers,
		License:        pkg.License,
		Homepage:       pkg.Homepage,
		InstallScripts: pkg.Scripts,
	}
	// Pre-populate dependency metrics from registry data.
	// analyzeDependencySprawl may override this with more precise lock file data.
	// Verified=false indicates this is a partial count (direct deps from registry,
	// not a full transitive traversal).
	metadata.DependencyMetrics = &models.DependencyMetrics{
		DirectCount: pkg.DirectDepCount,
		Verified:    false,
	}
	return metadata
}

func packageMetadataFromPyPI(pkg *fetcher.PyPIPackage) models.PackageMetadata {
	metadata := models.PackageMetadata{
		DownloadCount: pkg.Downloads,
		PublishedAt:   pkg.PublishedAt,
		LatestVersion: pkg.LatestVersion,
		Maintainers:   pkg.Maintainers,
		License:       pkg.License,
		Homepage:      pkg.Homepage,
	}
	// Pre-populate dependency metrics from registry data.
	// analyzeDependencySprawl may override this with more precise lock file data.
	metadata.DependencyMetrics = &models.DependencyMetrics{
		DirectCount: pkg.DirectDepCount,
		Verified:    false,
	}
	return metadata
}

func packageMetadataFromMaven(pkg *fetcher.MavenPackage) models.PackageMetadata {
	return models.PackageMetadata{
		PublishedAt:   pkg.PublishedAt,
		LatestVersion: pkg.LatestVersion,
		License:       pkg.License,
	}
}

// calculateSupplyChainScore implements a 0-20 point supply chain security rubric
// Each of 10 categories is scored 0-2 points (0=good, 2=high risk)
// Total: 0-5=Low risk, 6-14=Medium risk, 15+=High risk
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
			cat.Evidence = pkgID + ": " + cat.Evidence
		}
	}

	// Calculate total score
	score.TotalScore = score.CategoryScores.PublisherControl.RiskPoints +
		score.CategoryScores.OwnershipChanges.RiskPoints +
		score.CategoryScores.ReleaseAnomalies.RiskPoints +
		score.CategoryScores.InstallExecution.RiskPoints +
		score.CategoryScores.DependencySprawl.RiskPoints +
		score.CategoryScores.Provenance.RiskPoints +
		score.CategoryScores.Health.RiskPoints +
		score.CategoryScores.Governance.RiskPoints +
		score.CategoryScores.ReleaseSecurity.RiskPoints +
		score.CategoryScores.PackageMaturity.RiskPoints

	// Determine risk level based on total score (10 categories, 0-20 points)
	if score.TotalScore >= 15 {
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
		Score:       2 - analysis.RiskPoints, // Convert risk points to score
		RiskPoints:  analysis.RiskPoints,
		Description: analysis.Evidence,
		Evidence:    analysis.Evidence,
		Verified:    analysis.Verified,
	}
}

// classifyOwnershipFromCommitStats analyzes commit authorship patterns to detect ownership transfers.
//
// Test: Commit author pattern analysis for ownership transfer detection
// Justification: Complete or near-complete replacement of active committers is the primary
//                behavioral signal of a malicious ownership transfer. Normal team growth adds
//                new contributors while retaining historical ones; a transfer replaces them.
// Source: "Backstabber's Knife Collection" (Ohm et al., 2020) - ownership takeover pattern analysis
//         https://arxiv.org/abs/2005.09535
// Methodology: Compare authors with recent commits (last 90 days) against historical authors
//              (committed previously but not recently). High ratio of entirely-new recent authors
//              indicates team replacement rather than natural growth.
// Result:
//   - 0 risk: stable ownership (same team or healthy growth with continuity)
//   - 1 risk: partial team turnover (>50% new authors but continuity exists, or dormant project)
//   - 2 risk: near-complete team replacement (≥80% of recent committers are new)
func classifyOwnershipFromCommitStats(stats *fetcher.CommitAuthorStats) (riskPoints int, evidence string) {
	hasRecent := len(stats.RecentAuthors) > 0
	hasHistorical := len(stats.HistoricalAuthors) > 0

	if hasRecent && hasHistorical {
		// We have both recent and historical authors: detect ownership-change pattern
		historicalSet := make(map[string]bool)
		for _, author := range stats.HistoricalAuthors {
			historicalSet[author] = true
		}

		newAuthors := 0
		for _, author := range stats.RecentAuthors {
			if !historicalSet[author] {
				newAuthors++
			}
		}

		newAuthorRatio := float64(newAuthors) / float64(len(stats.RecentAuthors))

		switch {
		case newAuthorRatio >= 0.8:
			// ≥80% of recent committers are entirely new: near-complete team replacement
			// This is the primary behavioral signal of a malicious ownership transfer.
			return 2, fmt.Sprintf(
				"%d/%d recent authors are new (%.0f%% team change; %d historical authors stepped back)",
				newAuthors, len(stats.RecentAuthors), newAuthorRatio*100, len(stats.HistoricalAuthors))

		case newAuthorRatio >= 0.5:
			// Majority new but some continuity: notable churn, moderate concern
			return 1, fmt.Sprintf(
				"%d/%d recent authors are new (%.0f%% partial team change)",
				newAuthors, len(stats.RecentAuthors), newAuthorRatio*100)

		default:
			// Mostly same team with some new contributors: healthy, stable ownership
			return 0, fmt.Sprintf(
				"%d unique authors, %d recent, %d new (stable ownership with continuity)",
				len(stats.UniqueAuthors), len(stats.RecentAuthors), newAuthors)
		}

	} else if hasRecent && !hasHistorical {
		// Only recent authors — project is new or all original contributors are still active
		if len(stats.UniqueAuthors) == 1 {
			return 0, "Single active author (stable, consistent commits)"
		}
		return 0, fmt.Sprintf(
			"%d active authors, all with recent commits (new or continuously active project)",
			len(stats.RecentAuthors))

	} else if !hasRecent && hasHistorical {
		// No recent commits at all: dormant project
		// Dormancy risk is primarily captured by scoreReleaseAnomalies; record here for context
		return 1, fmt.Sprintf(
			"%d authors, none active in last 90 days (dormant project)",
			len(stats.HistoricalAuthors))

	}
	// No author data at all (empty repo or API returned nothing useful)
	return 1, "No commit author data available"
}

// scoreOwnershipChanges: ownership transfers (0-2 pts)
//
// Test: Ownership change risk scoring for supply chain security
// Justification: Recent or sudden ownership changes are one of the most direct signals of a
//                supply chain attack — attackers acquire npm packages, GitHub repos, or PyPI
//                projects from maintainers who no longer monitor them.
// Source: "Backstabber's Knife Collection" (Ohm et al., 2020) - https://arxiv.org/abs/2005.09535
//         "Towards Measuring Supply Chain Attacks" (NDSS 2020)
// Methodology: Multi-source analysis:
//              1. Git commit author change patterns (recent vs. historical committers)
//              2. npm registry maintainer history
//              3. PyPI release author history
//              4. Repository creation date vs. package first-published date (transfer signal)
//              5. Fallback: repository age + maintainer count heuristic
// Result:
//   - 0 risk points (best):  Stable, long-term ownership with continuity
//   - 1 risk point (moderate): Some changes detected, partial data, or unverifiable
//   - 2 risk points (worst): Recent transfer or near-complete team replacement detected
func (a *Analyzer) scoreOwnershipChanges(result *models.AnalysisResult) models.CategoryScore {
	evidenceParts := []string{}
	verified := false
	riskPoints := 1 // Default to medium risk when unable to verify

	// 1. Check Git platform commit author changes (if repository available)
	if result.RepositoryURL != "" {
		gitClient := a.getGitClient(result.RepositoryURL)
		commitStats, err := gitClient.GetCommitAuthors(result.RepositoryURL)
		if err == nil && commitStats != nil {
			verified = true
			pts, ev := classifyOwnershipFromCommitStats(commitStats)
			riskPoints = pts
			if ev != "" {
				evidenceParts = append(evidenceParts, "GitHub: "+ev)
			}
		}
	}

	// 2. Cross-registry transfer signal: if the repository was created significantly
	//    after the package was first published, the repo may have been transferred.
	//    Source: GitHub repo transfers reset the repo creation date while preserving history.
	//    Justification: A package published years before its current repo existed indicates
	//    that the codebase moved — potentially to a new, potentially compromised owner.
	if !result.Metadata.RepoCreatedAt.IsZero() && !result.Metadata.PublishedAt.IsZero() {
		ageDiff := result.Metadata.RepoCreatedAt.Sub(result.Metadata.PublishedAt)
		// Repo created more than 90 days AFTER package was first published
		if ageDiff > 90*24*time.Hour {
			riskPoints = 2
			verified = true
			evidenceParts = append(evidenceParts,
				fmt.Sprintf("Repository created %d days after package first published (possible repo transfer)",
					int(ageDiff.Hours()/24)))
		}
	}

	// 3. Check npm package ownership history
	//    Justification: npm registry records maintainer lists per version; a sudden change in
	//    the maintainer set — especially to a single unknown user — is a takeover signal.
	//    Source: npm security advisories on account takeover (github.blog/2021-12-06-write-access-to-npm)
	if result.Dependency.Ecosystem == models.EcosystemNPM {
		npmHistory, err := a.npmClient.GetOwnershipHistory(result.Dependency.Name)
		if err == nil && npmHistory != nil {
			verified = true

			if npmHistory.RecentTransfer {
				riskPoints = 2
				evidenceParts = append(evidenceParts,
					fmt.Sprintf("npm: Recent ownership transfer detected (%s)",
						npmHistory.TransferDate.Format("2006-01-02")))
			} else if npmHistory.MaintainerChanges > 0 {
				if riskPoints < 2 {
					riskPoints = 1
				}
				evidenceParts = append(evidenceParts,
					fmt.Sprintf("npm: %d historical maintainer changes", npmHistory.MaintainerChanges))
			} else {
				// No ownership change signals — confirmed stable registry history
				// Lower risk if no prior checks raised it; registry-confirmed stability
				// is strong evidence of safe ownership.
				if riskPoints > 0 {
					riskPoints = 0
				}
				if len(npmHistory.CurrentMaintainers) > 0 {
					evidenceParts = append(evidenceParts,
						fmt.Sprintf("npm: Stable ownership (%d maintainers, no transfers detected)",
							len(npmHistory.CurrentMaintainers)))
				} else {
					evidenceParts = append(evidenceParts, "npm: No ownership changes detected")
				}
			}
		}
	}

	// 4. Check PyPI package ownership history
	//    Justification: PyPI release history provides signals about author turnover.
	//    Note: PyPI's public JSON API does not expose the per-release uploader field,
	//    so author-change detection is limited. A successful check with no issues
	//    still confirms the package has a stable, checkable history.
	//    Source: "Backstabber's Knife Collection" (Ohm et al., 2020) - PyPI attack taxonomy
	if result.Dependency.Ecosystem == models.EcosystemPyPI {
		pypiHistory, err := a.pypiClient.GetOwnershipHistory(result.Dependency.Name)
		if err == nil && pypiHistory != nil {
			verified = true

			if pypiHistory.RecentTransfer {
				riskPoints = 2
				evidenceParts = append(evidenceParts,
					fmt.Sprintf("PyPI: Recent ownership transfer detected (%s)",
						pypiHistory.TransferDate.Format("2006-01-02")))
			} else if pypiHistory.AuthorChanges > 0 {
				if riskPoints < 2 {
					riskPoints = 1
				}
				evidenceParts = append(evidenceParts,
					fmt.Sprintf("PyPI: %d historical author changes", pypiHistory.AuthorChanges))
			} else {
				// No ownership change signals — confirmed clean history
				if riskPoints > 0 {
					riskPoints = 0
				}
				if pypiHistory.CurrentAuthor != "" {
					evidenceParts = append(evidenceParts,
						fmt.Sprintf("PyPI: Stable ownership (no transfers detected, author: %s)", pypiHistory.CurrentAuthor))
				} else {
					// PyPI public API omits author/uploader fields for many packages;
					// absence of change signals is still meaningful.
					evidenceParts = append(evidenceParts, "PyPI: No ownership changes detected")
				}
			}
		}
	}

	// 5. Fallback to repository age heuristic if no other data available
	//    Justification: Very new packages with a single maintainer have not had time to
	//    establish a track record, making ownership-change detection impossible and
	//    account-takeover risk higher per Ohm et al. (2020).
	if !verified && !result.Metadata.RepoCreatedAt.IsZero() {
		repoAge := time.Since(result.Metadata.RepoCreatedAt).Hours() / 24 / 365
		verified = true

		switch {
		case repoAge < 0.5 && len(result.Metadata.Maintainers) <= 1:
			// Very new single-maintainer package: cannot verify ownership stability
			riskPoints = 2
			evidenceParts = append(evidenceParts,
				fmt.Sprintf("Repository %.1f years old, single maintainer (cannot verify ownership history)", repoAge))
		case repoAge < 1.0:
			riskPoints = 1
			evidenceParts = append(evidenceParts,
				fmt.Sprintf("Repository %.1f years old (relatively new, limited ownership history)", repoAge))
		default:
			riskPoints = 0
			evidenceParts = append(evidenceParts,
				fmt.Sprintf("Repository %.1f years old (established)", repoAge))
		}
	}

	// Build final evidence string with academic source citation
	evidence := "No ownership data available"
	if len(evidenceParts) > 0 {
		evidence = strings.Join(evidenceParts, "; ")
	}
	evidence += " [Source: Backstabber's Knife Collection (Ohm et al., 2020); Towards Measuring Supply Chain Attacks (NDSS 2020)]"

	// Determine description based on risk points
	description := "Stable long-term ownership"
	switch riskPoints {
	case 2:
		description = "Recent suspicious ownership changes detected"
	case 1:
		description = "Some ownership changes detected"
	}

	return models.CategoryScore{
		Score:       2 - riskPoints, // Invert: 0 risk points = score 2, 2 risk points = score 0
		RiskPoints:  riskPoints,
		Description: description,
		Evidence:    evidence,
		Verified:    verified,
	}
}

// scoreReleaseAnomalies: dormant→sudden activity (0-2 pts)
// Detects dormant packages that suddenly reactivate, checks for unusual release patterns,
// and analyzes commit frequency changes
func (a *Analyzer) scoreReleaseAnomalies(result *models.AnalysisResult) models.CategoryScore {
	const releaseAnomalySource = " [Source: Backstabber's Knife Collection (Ohm et al., 2020)]"

	if result.Metadata.RepoLastCommit.IsZero() || result.RepositoryURL == "" {
		return models.CategoryScore{
			Score:       1,
			RiskPoints:  1,
			Description: "Unable to verify release patterns",
			Evidence:    "No commit history available" + releaseAnomalySource,
			Verified:    false,
		}
	}

	daysSinceLastCommit := time.Since(result.Metadata.RepoLastCommit).Hours() / 24
	daysSinceCreated := time.Since(result.Metadata.RepoCreatedAt).Hours() / 24

	// Very inactive (dormant for over a year)
	if daysSinceLastCommit > 365 {
		return models.CategoryScore{
			Score:       1,
			RiskPoints:  1,
			Description: "Package appears dormant",
			Evidence:    fmt.Sprintf("No commits in %.0f days (>1 year)", daysSinceLastCommit) + releaseAnomalySource,
			Verified:    true,
		}
	}

	// For packages with recent activity, fetch detailed release and commit history
	// to detect suspicious reactivation patterns
	if daysSinceCreated > 365 {
		gitClient := a.getGitClient(result.RepositoryURL)
		// Fetch release history
		releases, err := gitClient.GetReleaseHistory(result.RepositoryURL, 20)
		if err == nil && len(releases) > 0 {
			// Analyze release pattern
			anomaly := a.detectReleaseAnomaly(releases, result.Metadata.RepoCreatedAt)
			if anomaly != nil {
				anomaly.Evidence += releaseAnomalySource
				return *anomaly
			}
		}

		// Fetch commit activity to analyze frequency changes
		oneYearAgo := time.Now().AddDate(-1, 0, 0)
		twoYearsAgo := time.Now().AddDate(-2, 0, 0)

		recentCommits, err1 := gitClient.GetCommitActivity(result.RepositoryURL, oneYearAgo)
		olderCommits, err2 := gitClient.GetCommitActivity(result.RepositoryURL, twoYearsAgo)

		if err1 == nil && err2 == nil {
			anomaly := a.detectCommitFrequencyAnomaly(recentCommits, olderCommits, result.Metadata.RepoCreatedAt)
			if anomaly != nil {
				anomaly.Evidence += releaseAnomalySource
				return *anomaly
			}
		}
	}

	// Regular, consistent activity (active within the year, no anomalies detected)
	return models.CategoryScore{
		Score:       2,
		RiskPoints:  0,
		Description: "Regular, consistent releases",
		Evidence:    fmt.Sprintf("Last commit %.0f days ago, no anomalies detected", daysSinceLastCommit) + releaseAnomalySource,
		Verified:    true,
	}
}

// detectReleaseAnomaly analyzes release history to detect dormant packages that suddenly reactivate
//
// Test: Release anomaly detection via release history analysis
// Justification: Dormant packages reactivating suddenly are a primary attack vector for
//                supply chain compromise. Attackers acquire abandoned packages and inject
//                malicious versions, or use fast-release patterns to push unreviewed changes.
// Source: "Backstabber's Knife Collection" (Ohm et al., 2020) - abandoned package takeover
//         https://arxiv.org/abs/2005.09535
//         "Towards Measuring Supply Chain Attacks on Package Managers" (NDSS 2020)
// Methodology: Analyze release timestamps to detect gaps and frequency anomalies
func (a *Analyzer) detectReleaseAnomaly(releases []fetcher.GitHubRelease, repoCreatedAt time.Time) *models.CategoryScore {
	if len(releases) < 2 {
		return nil
	}

	// Filter out draft and prerelease versions
	validReleases := []fetcher.GitHubRelease{}
	for _, r := range releases {
		if !r.Draft && !r.Prerelease && !r.PublishedAt.IsZero() {
			validReleases = append(validReleases, r)
		}
	}

	if len(validReleases) < 2 {
		return nil
	}

	// Releases are already sorted by GitHub API (most recent first)
	mostRecent := validReleases[0].PublishedAt
	daysSinceRecentRelease := time.Since(mostRecent).Hours() / 24

	// Find the largest gap between consecutive releases
	var maxGapDays float64
	var gapStartDate time.Time
	var gapEndDate time.Time

	for i := 0; i < len(validReleases)-1; i++ {
		gapDays := validReleases[i].PublishedAt.Sub(validReleases[i+1].PublishedAt).Hours() / 24
		if gapDays > maxGapDays {
			maxGapDays = gapDays
			gapStartDate = validReleases[i+1].PublishedAt
			gapEndDate = validReleases[i].PublishedAt
		}
	}

	// Calculate average release cadence (requires at least 3 releases for a meaningful average)
	var avgDaysBetweenReleases float64
	if len(validReleases) >= 3 {
		totalDays := validReleases[0].PublishedAt.Sub(validReleases[len(validReleases)-1].PublishedAt).Hours() / 24
		avgDaysBetweenReleases = totalDays / float64(len(validReleases)-1)
	}

	// Check 1: Absolute dormancy reactivation (>1 year gap, recent activity)
	// Classic abandoned-package-takeover pattern: acquire dormant package, release malicious version
	if maxGapDays > 365 && daysSinceRecentRelease < 90 {
		return &models.CategoryScore{
			Score:      0,
			RiskPoints: 2,
			Description: "Suspicious reactivation after dormancy",
			Evidence: fmt.Sprintf("Dormant for %.0f days (%s to %s), recent release %.0f days ago",
				maxGapDays, gapStartDate.Format("2006-01"), gapEndDate.Format("2006-01"), daysSinceRecentRelease),
			Verified: true,
		}
	}

	// Check 2: Relative dormancy reactivation (gap >> average cadence)
	// A gap much larger than usual cadence signals potential compromise even if < 1 year absolute
	// Threshold: gap > 5x average cadence AND > 6 months absolute AND recent release within 4 months
	if avgDaysBetweenReleases > 0 && maxGapDays > avgDaysBetweenReleases*5 && maxGapDays > 180 && daysSinceRecentRelease < 120 {
		return &models.CategoryScore{
			Score:      0,
			RiskPoints: 2,
			Description: "Suspicious reactivation after relative dormancy",
			Evidence: fmt.Sprintf("Dormant for %.0f days (%.1fx usual %.0f-day release cadence), recent release %.0f days ago",
				maxGapDays, maxGapDays/avgDaysBetweenReleases, avgDaysBetweenReleases, daysSinceRecentRelease),
			Verified: true,
		}
	}

	// Check 3: Unusual release spike (recent release much faster than historical cadence)
	// Attacker pattern: inject malicious version quickly after account compromise
	// Use relative threshold: spike if recent gap < 10% of average (not a fixed 7-day cutoff)
	if len(validReleases) >= 3 && avgDaysBetweenReleases > 60 {
		recentGap := validReleases[0].PublishedAt.Sub(validReleases[1].PublishedAt).Hours() / 24
		spikeThreshold := avgDaysBetweenReleases * 0.10 // Gap < 10% of average is a suspicious spike
		if recentGap < spikeThreshold && daysSinceRecentRelease < 60 {
			return &models.CategoryScore{
				Score:      0,
				RiskPoints: 2,
				Description: "Unusual release pattern detected",
				Evidence: fmt.Sprintf("Avg release every %.0f days, but recent release only %.0f days after previous (%.0f days ago)",
					avgDaysBetweenReleases, recentGap, daysSinceRecentRelease),
				Verified: true,
			}
		}
	}

	return nil
}

// detectCommitFrequencyAnomaly analyzes commit frequency changes to detect suspicious activity
//
// Test: Commit frequency anomaly detection via year-over-year comparison
// Justification: Sudden spikes in commit frequency after dormancy are characteristic of
//                account takeover attacks where adversaries push multiple changes rapidly
//                to avoid detection window.
// Source: "Backstabber's Knife Collection" (Ohm et al., 2020)
//         https://arxiv.org/abs/2005.09535
// Methodology: Compare commit counts in last 12 months vs preceding 12 months
func (a *Analyzer) detectCommitFrequencyAnomaly(recentCommits, olderCommits []fetcher.GitHubCommit, repoCreatedAt time.Time) *models.CategoryScore {
	oneYearAgo := time.Now().AddDate(-1, 0, 0)

	// Count commits in last year vs previous year
	recentCount := len(recentCommits)

	// Filter older commits to only count those from 1-2 years ago (the preceding year)
	previousYearCount := 0
	for _, commit := range olderCommits {
		if commit.Commit.Author.Date.Before(oneYearAgo) {
			previousYearCount++
		}
	}

	// Repo must be at least 2 years old for this check to have meaningful comparison data
	repoAgeYears := time.Since(repoCreatedAt).Hours() / 24 / 365
	if repoAgeYears < 2 {
		return nil
	}

	// Check 1: Absolute spike - near-zero prior activity, high recent activity
	// Classic abandoned-package-takeover: dormant for a year, suddenly many commits
	if previousYearCount < 5 && recentCount > 20 {
		return &models.CategoryScore{
			Score:      0,
			RiskPoints: 2,
			Description: "Suspicious commit frequency spike",
			Evidence: fmt.Sprintf("%d commits in last year vs %d in previous year (sudden spike)",
				recentCount, previousYearCount),
			Verified: true,
		}
	}

	// Check 2: Relative spike - large proportional increase from moderate baseline
	// A 10x+ increase even from a moderate baseline signals unusual activity
	if previousYearCount >= 5 && recentCount >= previousYearCount*10 && recentCount >= 30 {
		return &models.CategoryScore{
			Score:      0,
			RiskPoints: 2,
			Description: "Suspicious commit frequency increase",
			Evidence: fmt.Sprintf("%d commits in last year vs %d in previous year (%.0fx increase)",
				recentCount, previousYearCount, float64(recentCount)/float64(previousYearCount)),
			Verified: true,
		}
	}

	// Check 3: Complete dormancy then some activity (moderate concern)
	// Package was completely inactive but now has some commits - could be legitimate or takeover
	if previousYearCount == 0 && recentCount > 0 && recentCount < 20 {
		return &models.CategoryScore{
			Score:      1,
			RiskPoints: 1,
			Description: "Package reactivated after dormancy",
			Evidence: fmt.Sprintf("0 commits in previous year, %d commits in last year", recentCount),
			Verified: true,
		}
	}

	return nil
}

// hasInstallTimeScripts checks if scripts include install-time hooks
func hasInstallTimeScripts(scripts map[string]string) bool {
	installScriptNames := []string{"preinstall", "install", "postinstall"}
	for _, name := range installScriptNames {
		if script, exists := scripts[name]; exists && script != "" {
			return true
		}
	}
	return false
}

// convertToModelAnalysis converts script analysis to model format
func convertToModelAnalysis(analysis ScriptAnalysis) *models.InstallScriptAnalysis {
	patterns := make([]models.DangerousPattern, len(analysis.DangerousPatterns))
	for i, p := range analysis.DangerousPatterns {
		patterns[i] = models.DangerousPattern{
			Pattern:     p.Pattern,
			Description: p.Description,
			Severity:    p.Severity,
			Match:       p.Match,
		}
	}

	return &models.InstallScriptAnalysis{
		HasDangerousPatterns: analysis.HasDangerousPatterns,
		DangerousPatterns:    patterns,
		RiskLevel:            analysis.RiskLevel,
		ScriptCount:          len(patterns),
	}
}

// scoreInstallExecution: postinstall scripts (0-2 pts)
// Scoring:
//   - 0 risk points (best): No install-time scripts
//   - 1 risk point (moderate): Single benign install script
//   - 2 risk points (worst): Multiple scripts OR dangerous content detected
func (a *Analyzer) scoreInstallExecution(result *models.AnalysisResult) models.CategoryScore {
	const installExecSource = " [Source: Backstabber's Knife Collection (Ohm et al., 2020); Towards Measuring Supply Chain Attacks (NDSS 2020)]"

	// If no install scripts present, return best score
	if !result.Metadata.HasInstallScripts || len(result.Metadata.InstallScripts) == 0 {
		return models.CategoryScore{
			Score:       2,
			RiskPoints:  0,
			Description: "No install-time scripts",
			Evidence:    "No install scripts detected in package" + installExecSource,
			Verified:    true,
		}
	}

	// If we have script analysis with dangerous patterns, return worst score
	if result.Metadata.InstallScriptAnalysis != nil && result.Metadata.InstallScriptAnalysis.HasDangerousPatterns {
		patterns := []string{}
		for _, p := range result.Metadata.InstallScriptAnalysis.DangerousPatterns {
			patterns = append(patterns, fmt.Sprintf("%s (%s)", p.Pattern, p.Severity))
		}

		return models.CategoryScore{
			Score:       0,
			RiskPoints:  2,
			Description: "Dangerous install-time operations detected",
			Evidence:    fmt.Sprintf("Risk level: %s, Patterns: %s", result.Metadata.InstallScriptAnalysis.RiskLevel, strings.Join(patterns, ", ")) + installExecSource,
			Verified:    true,
		}
	}

	// Count install-time script hooks
	installScriptNames := []string{"preinstall", "install", "postinstall", "setup.py", "pom.xml"}
	foundScripts := []string{}

	for _, scriptName := range installScriptNames {
		if script, exists := result.Metadata.InstallScripts[scriptName]; exists && script != "" {
			foundScripts = append(foundScripts, scriptName)
		}
	}

	// Multiple install scripts = higher risk (even if benign)
	if len(foundScripts) >= 2 {
		return models.CategoryScore{
			Score:       0,
			RiskPoints:  2,
			Description: "Multiple install-time scripts detected",
			Evidence:    fmt.Sprintf("Scripts: %s", strings.Join(foundScripts, ", ")) + installExecSource,
			Verified:    true,
		}
	}

	// Single benign install script = moderate risk
	if len(foundScripts) == 1 {
		return models.CategoryScore{
			Score:       0,
			RiskPoints:  1,
			Description: "Single install-time script detected",
			Evidence:    fmt.Sprintf("Script: %s", foundScripts[0]) + installExecSource,
			Verified:    true,
		}
	}

	// Has scripts but none are install-time (shouldn't reach here if HasInstallScripts is correct)
	return models.CategoryScore{
		Score:       2,
		RiskPoints:  0,
		Description: "No install-time scripts",
		Evidence:    "Package has scripts but no install hooks" + installExecSource,
		Verified:    true,
	}
}

// scoreDependencySprawl: transitive dependencies (0-2 pts)
//
// Three scoring paths, in priority order:
//  1. Lock file (Verified=true): score by total transitive count in project lock file
//     Thresholds: <10 = low, 10-50 = moderate, >50 = high
//  2. Registry direct dep count (Verified=false, DirectCount known): score by direct dep count
//     from the published package metadata (npm `dependencies`, PyPI `requires_dist`).
//     Thresholds: 0-5 = low, 6-15 = moderate, >15 = high
//     Source: "Small World with High Risks" (Zimmermann et al., 2019) — each direct dep
//     carries its own transitive tree, expanding the attack surface multiplicatively.
//  3. No data: neutral 1-point score (unknown risk)
func (a *Analyzer) scoreDependencySprawl(result *models.AnalysisResult) models.CategoryScore {
	const depSprawlSource = " [Source: Small World with High Risks (Zimmermann et al., 2019)]"

	// Path 1: lock file provides exact transitive count
	if result.Metadata.DependencyMetrics != nil && result.Metadata.DependencyMetrics.Verified {
		metrics := result.Metadata.DependencyMetrics
		transitiveCount := metrics.TransitiveCount

		// Score based on total transitive dependency count from project lock file
		// 0 points = few dependencies (< 10) = low risk
		// 1 point = moderate dependencies (10-50) = medium risk
		// 2 points = many dependencies (50+) = high risk
		if transitiveCount < 10 {
			return models.CategoryScore{
				Score:       2,
				RiskPoints:  0,
				Description: "Few transitive dependencies",
				Evidence:    fmt.Sprintf("%d total dependencies (%d direct)", transitiveCount, metrics.DirectCount) + depSprawlSource,
				Verified:    true,
			}
		} else if transitiveCount <= 50 {
			return models.CategoryScore{
				Score:       1,
				RiskPoints:  1,
				Description: "Moderate transitive dependencies",
				Evidence:    fmt.Sprintf("%d total dependencies (%d direct)", transitiveCount, metrics.DirectCount) + depSprawlSource,
				Verified:    true,
			}
		} else {
			return models.CategoryScore{
				Score:       0,
				RiskPoints:  2,
				Description: "Many transitive dependencies",
				Evidence:    fmt.Sprintf("%d total dependencies (%d direct)", transitiveCount, metrics.DirectCount) + depSprawlSource,
				Verified:    true,
			}
		}
	}

	// Path 2: use direct dep count from registry (npm dependencies / PyPI requires_dist).
	// DependencyMetrics is always pre-populated by packageMetadataFromNPM/PyPI, so
	// Verified=false && DependencyMetrics!=nil reliably means "registry data was fetched".
	// This distinguishes "genuinely zero deps" (DirectCount=0) from "no data at all" (nil).
	//
	// Justification: "Small World with High Risks" (Zimmermann et al., 2019) shows each
	// direct dependency carries its own transitive tree, multiplicatively expanding the
	// attack surface. Direct dep count from registry is a reliable proxy for total
	// transitive exposure when a lock file is unavailable.
	if result.Metadata.DependencyMetrics != nil && !result.Metadata.DependencyMetrics.Verified {
		directCount := result.Metadata.DependencyMetrics.DirectCount

		// Score based on direct dependency count from the package registry
		// 0 pts = 0-5 direct deps (minimal sprawl — small or no dep tree)
		// 1 pt  = 6-15 direct deps (moderate sprawl)
		// 2 pts = 16+ direct deps (high sprawl — each dep multiplies attack surface)
		if directCount <= 5 {
			return models.CategoryScore{
				Score:       2,
				RiskPoints:  0,
				Description: "Few direct dependencies",
				Evidence:    fmt.Sprintf("%d direct dependencies (from registry metadata)", directCount) + depSprawlSource,
				Verified:    false,
			}
		} else if directCount <= 15 {
			return models.CategoryScore{
				Score:       1,
				RiskPoints:  1,
				Description: "Moderate direct dependencies",
				Evidence:    fmt.Sprintf("%d direct dependencies (from registry metadata)", directCount) + depSprawlSource,
				Verified:    false,
			}
		} else {
			return models.CategoryScore{
				Score:       0,
				RiskPoints:  2,
				Description: "Many direct dependencies",
				Evidence:    fmt.Sprintf("%d direct dependencies (from registry metadata)", directCount) + depSprawlSource,
				Verified:    false,
			}
		}
	}

	// Path 3: no dependency data available (DependencyMetrics=nil means neither npm/pypi
	// nor lock file provided data). Assign neutral moderate risk.
	// Stars and download counts are NOT valid proxies for dependency sprawl.
	return models.CategoryScore{
		Score:       1,
		RiskPoints:  1,
		Description: "Dependency count unavailable",
		Evidence:    "No lock file or registry dependency data found" + depSprawlSource,
		Verified:    false,
	}
}

// scoreProvenance: reproducible/signed builds (0-2 pts)
// Scoring: 0=no provenance, 1=partial provenance, 2=full provenance with signatures
func (a *Analyzer) scoreProvenance(result *models.AnalysisResult) models.CategoryScore {
	evidence := []string{}
	provenanceScore := 0

	// Check for SLSA attestations (highest quality provenance)
	if result.Metadata.HasSLSAAttestation {
		provenanceScore += 2
		evidence = append(evidence, fmt.Sprintf("SLSA attestation (%s)", result.Metadata.SLSALevel))
	}

	// Check for Sigstore signatures
	if result.Metadata.HasSigstoreSignature {
		provenanceScore += 2
		evidence = append(evidence, "Sigstore/Cosign signatures")
	}

	// Check for ecosystem-specific provenance
	if result.Metadata.HasNPMProvenance {
		provenanceScore += 2
		evidence = append(evidence, "npm provenance attestations")
	}

	if result.Metadata.HasPyPISignatures {
		provenanceScore += 2
		evidence = append(evidence, "PyPI cryptographic signatures")
	}

	// Check for signed releases (GitHub releases with signatures)
	if result.Metadata.SignedReleases {
		provenanceScore += 1
		evidence = append(evidence, "signed GitHub releases")
	}

	// Check for reproducible builds
	if result.Metadata.ReproducibleBuild {
		provenanceScore += 1
		evidence = append(evidence, "reproducible build configuration")
	}

	// Check OSSF Scorecard for additional provenance indicators
	if result.Metadata.OSSFChecks != nil {
		if signingScore, exists := result.Metadata.OSSFChecks["Signed-Releases"]; exists && signingScore >= 7 {
			provenanceScore += 1
			evidence = append(evidence, fmt.Sprintf("OSSF Signed-Releases: %d/10", signingScore))
		}
	}

	// Determine final risk level based on accumulated provenance indicators
	// Strong indicators (SLSA, Sigstore, npm provenance, PyPI signatures) = 2 points each
	// Weaker indicators (signed releases, reproducible builds, OSSF) = 1 point each
	// Score >= 2: Full provenance (0 risk points) - at least one strong indicator
	// Score 1: Partial provenance (1 risk point) - only weak indicators
	// Score 0: No provenance (2 risk points)

	var riskPoints int
	var description string
	var score int

	if provenanceScore >= 2 {
		// Full provenance - at least one strong indicator or multiple weak ones
		riskPoints = 0
		score = 2
		description = "Full provenance with signatures"
	} else if provenanceScore >= 1 {
		// Partial provenance - only weak indicators
		riskPoints = 1
		score = 1
		description = "Partial provenance"
	} else {
		// No provenance
		riskPoints = 2
		score = 0
		description = "No provenance evidence"
	}

	evidenceStr := "No provenance data"
	if len(evidence) > 0 {
		evidenceStr = strings.Join(evidence, ", ")
	}

	// Add provenance details if available
	if result.Metadata.ProvenanceDetails != "" {
		evidenceStr = evidenceStr + "; " + result.Metadata.ProvenanceDetails
	}

	evidenceStr += " [Source: SLSA v1.0 Specification (slsa.dev); Sigstore (sigstore.dev)]"

	return models.CategoryScore{
		Score:       score,
		RiskPoints:  riskPoints,
		Description: description,
		Evidence:    evidenceStr,
		Verified:    len(evidence) > 0 || provenanceScore == 0,
	}
}

// scoreHealth: bus factor/review process/CI (0-2 pts)
//
// Test: Repository health scoring for supply chain risk
// Justification: Low bus factor, absent code review, and missing CI each create vectors
//                for undetected compromise. A single maintainer is a single point of failure;
//                unreviewed code allows malicious commits; no CI means no automated verification.
// Source: "Measuring the Health of Open Source Software Ecosystems" (Manikas & Hansen, 2013)
//         "Backstabber's Knife Collection" (Ohm et al., 2020) - maintainer compromise patterns
//         OSSF Scorecard methodology - https://github.com/ossf/scorecard
// Methodology: Three-component scoring (bus factor, code review, CI quality) with OSSF
//              Scorecard supplementation when direct API data is unavailable. TopContributorPct
//              gates the bus factor point to prevent inflated bus factor from masking concentration.
// Result:
//   - 0 risk points (best): Distributed development (bus factor >= 3, <90% concentration),
//                            code reviews enforced, high-quality CI with tests
//   - 1 risk point (moderate): Two of three components satisfied
//   - 2 risk points (worst): At most one component satisfied (concentrated development,
//                             no reviews, no CI)
func (a *Analyzer) scoreHealth(result *models.AnalysisResult) models.CategoryScore {
	points := 0
	evidence := []string{}
	verified := false

	// Component 1: Bus Factor (from commit distribution)
	//
	// Justification: Low bus factor = concentrated development = single point of failure.
	// A bus factor >= 3 indicates distributed knowledge, but only if commit concentration
	// is not extreme. A project with bus factor 3 but top contributor at 90%+ has nominal
	// diversity but practical concentration — the bus factor point is revoked.
	// Source: "Small World with High Risks" (Zimmermann et al., 2019) — key person dependency
	busFactor := result.Metadata.BusFactor
	if busFactor > 0 {
		verified = true
		if busFactor >= 3 {
			// Check top contributor concentration: a high bus factor is meaningless
			// if one person still does 90%+ of all commits
			if result.Metadata.TopContributorPct >= 90 {
				// Nominal diversity but practical concentration — no point awarded
				evidence = append(evidence, fmt.Sprintf("Bus factor: %d but top contributor: %.0f%% (concentrated)", busFactor, result.Metadata.TopContributorPct))
			} else {
				// Genuinely distributed development
				points++
				evidence = append(evidence, fmt.Sprintf("Bus factor: %d", busFactor))
				if result.Metadata.TopContributorPct >= 80 {
					evidence = append(evidence, fmt.Sprintf("Top contributor: %.0f%% of commits", result.Metadata.TopContributorPct))
				}
			}
		} else if busFactor == 2 {
			evidence = append(evidence, fmt.Sprintf("Bus factor: %d (moderate)", busFactor))
		} else {
			evidence = append(evidence, fmt.Sprintf("Bus factor: %d (high risk)", busFactor))
		}
	} else {
		// Fallback 1: OSSF Scorecard "Contributors" or "Maintained" checks
		// These are available when direct API calls fail (e.g., rate limiting)
		ossfContribScore := 0
		if result.Metadata.OSSFChecks != nil {
			if cs, ok := result.Metadata.OSSFChecks["Contributors"]; ok {
				ossfContribScore = cs
			}
		}
		if ossfContribScore >= 7 {
			points++
			evidence = append(evidence, fmt.Sprintf("OSSF Contributors: %d/10", ossfContribScore))
			verified = true
		} else if ossfContribScore > 0 {
			evidence = append(evidence, fmt.Sprintf("OSSF Contributors: %d/10 (low)", ossfContribScore))
			verified = true
		} else {
			// Fallback 2: maintainer count from registry
			maintainerCount := len(result.Metadata.Maintainers)
			if maintainerCount >= 3 {
				points++
				evidence = append(evidence, fmt.Sprintf("%d maintainers", maintainerCount))
				verified = true
			} else if maintainerCount > 0 {
				evidence = append(evidence, fmt.Sprintf("Only %d maintainer(s)", maintainerCount))
				verified = true
			}
		}
	}

	// Component 2: Code Review Process
	//
	// Justification: Unreviewed code is the primary vector for malicious commit injection.
	// Branch protection with required reviewers is the gold standard; high PR review rate
	// is a strong signal. When direct API data is unavailable (e.g., GitLab/Bitbucket stubs
	// or rate limiting), OSSF Scorecard "Code-Review" check supplements.
	// Source: "Expectations, Outcomes, and Challenges Of Modern Code Review" (Bacchelli & Bird, 2013)
	//         "Modern Code Review: A Case Study at Google" (Sadowski et al., 2018)
	if result.Metadata.HasBranchProtection && result.Metadata.RequiredReviewers > 0 {
		points++
		evidence = append(evidence, fmt.Sprintf("%d required reviewers", result.Metadata.RequiredReviewers))
		verified = true
	} else if result.Metadata.CodeReviewRate > 0 {
		if result.Metadata.CodeReviewRate >= 75 {
			points++
			evidence = append(evidence, fmt.Sprintf("%.0f%% PRs reviewed", result.Metadata.CodeReviewRate))
		} else if result.Metadata.CodeReviewRate >= 50 {
			evidence = append(evidence, fmt.Sprintf("%.0f%% PRs reviewed (moderate)", result.Metadata.CodeReviewRate))
		} else {
			evidence = append(evidence, fmt.Sprintf("%.0f%% PRs reviewed (low)", result.Metadata.CodeReviewRate))
		}
		verified = true
	} else {
		// Fallback: OSSF Scorecard "Code-Review" check
		ossfReviewScore := 0
		if result.Metadata.OSSFChecks != nil {
			if rs, ok := result.Metadata.OSSFChecks["Code-Review"]; ok {
				ossfReviewScore = rs
			}
		}
		if ossfReviewScore >= 7 {
			points++
			evidence = append(evidence, fmt.Sprintf("OSSF Code-Review: %d/10", ossfReviewScore))
			verified = true
		} else if ossfReviewScore > 0 {
			evidence = append(evidence, fmt.Sprintf("OSSF Code-Review: %d/10 (low)", ossfReviewScore))
			verified = true
		} else {
			evidence = append(evidence, "No code review process detected")
		}
	}

	// Component 3: CI Quality
	//
	// Justification: CI with automated tests catches malicious or buggy code before release.
	// High-quality CI (score >= 7) earns a point; CI presence without quality assessment
	// also earns a point since CI existence is itself a meaningful supply chain signal.
	// When neither direct CI data nor quality is available, OSSF "CI-Tests" supplements.
	// Source: "Continuous Integration, Delivery and Deployment: A Systematic Review" (Shahin et al., 2017)
	if result.Metadata.CIQualityScore >= 7 {
		// High-quality CI with tests
		points++
		evidence = append(evidence, fmt.Sprintf("CI quality: %d/10", result.Metadata.CIQualityScore))
		if result.Metadata.CIHasTests {
			evidence = append(evidence, "CI includes tests")
		}
		verified = true
	} else if result.Metadata.CIQualityScore >= 4 {
		// Moderate CI — not enough for a point but acknowledged
		evidence = append(evidence, fmt.Sprintf("CI quality: %d/10 (moderate)", result.Metadata.CIQualityScore))
		verified = true
	} else if result.Metadata.CIQualityScore > 0 {
		// Basic CI only
		evidence = append(evidence, fmt.Sprintf("CI quality: %d/10 (basic)", result.Metadata.CIQualityScore))
		verified = true
	} else if result.Metadata.HasCI {
		// CI detected but quality not assessed (e.g., API failure or non-GitHub platform).
		// CI presence is still a meaningful signal for supply chain integrity —
		// automated builds reduce the window for unverified code to reach users.
		points++
		evidence = append(evidence, fmt.Sprintf("CI detected: %v (quality not assessed)", result.Metadata.CISystems))
		verified = true
	} else {
		// Fallback: OSSF Scorecard "CI-Tests" check
		ossfCIScore := 0
		if result.Metadata.OSSFChecks != nil {
			if cs, ok := result.Metadata.OSSFChecks["CI-Tests"]; ok {
				ossfCIScore = cs
			}
		}
		if ossfCIScore >= 7 {
			points++
			evidence = append(evidence, fmt.Sprintf("OSSF CI-Tests: %d/10", ossfCIScore))
			verified = true
		} else if ossfCIScore > 0 {
			evidence = append(evidence, fmt.Sprintf("OSSF CI-Tests: %d/10 (low)", ossfCIScore))
			verified = true
		} else {
			evidence = append(evidence, "No CI detected")
		}
	}

	// Map internal points (0-3) to CategoryScore fields (0-2 range)
	// All other scoring categories use Score 0-2; health must be consistent.
	// 0-1 internal points = high risk (Score 0, RiskPoints 2)
	// 2 internal points   = moderate risk (Score 1, RiskPoints 1)
	// 3 internal points   = low risk (Score 2, RiskPoints 0)
	var score, riskPoints int
	switch {
	case points >= 3:
		score = 2
		riskPoints = 0
	case points >= 2:
		score = 1
		riskPoints = 1
	default:
		score = 0
		riskPoints = 2
	}

	description := "Poor health: high bus factor, no CI, or no reviews"
	switch {
	case points >= 3:
		description = "Good health: distributed development, CI with tests, code reviews"
	case points >= 2:
		description = "Moderate health: some good practices but gaps remain"
	case points >= 1:
		description = "Limited health: few contributors or missing CI/reviews"
	}

	return models.CategoryScore{
		Score:       score,
		RiskPoints:  riskPoints,
		Description: description,
		Evidence:    strings.Join(evidence, "; ") + " [Source: OSSF Scorecard; Small World with High Risks (Zimmermann et al., 2019)]",
		Verified:    verified,
	}
}

// enrichWithAIAnalysis enhances the analysis result with AI-powered semantic analysis.
// This method is opt-in and only runs if the Claude API client is configured.
//
// Methodology:
//  1. Per-Category Analysis - Runs AI analysis for each of the 10 scoring categories,
//     providing deeper contextual analysis beyond the rule-based checks. Results are
//     stored as CategoryScore.AIInsight on each category score.
//  2. Attack Pattern Matching - Compares observed behaviors to documented supply chain
//     attack patterns (event-stream, ua-parser-js, coa, node-ipc, eslint-scope, etc.)
//  3. Executive Summary - Generates a stakeholder-friendly explanation of the overall
//     risk assessment.
//
// The per-category analysis runs all 10 categories in parallel using Claude Haiku for
// speed and cost efficiency. The attack matching and executive summary use Claude Sonnet
// for higher quality cross-cutting analysis.
//
// Justification: AI analysis provides contextual understanding of risk patterns that
// static rules may miss - semantic interpretation of install scripts, contextual
// assessment of ownership patterns, intelligent interpretation of anomalies.
//
// All failures are graceful - AI analysis never blocks or fails the main scan.
func (a *Analyzer) enrichWithAIAnalysis(result *models.AnalysisResult) {
	// Check if AI analysis is enabled (client initialized and not explicitly disabled)
	if a.claudeClient == nil || !a.aiEnabled {
		return
	}

	// Initialize AI analysis result
	aiResult := &models.AIAnalysisResult{
		Timestamp:         time.Now(),
		ModelVersion:      "claude-sonnet-4.5",
		OverallConfidence: 0.0,
		SemanticFindings:  []models.SemanticFinding{},
		AttackPatterns:    []models.AttackPatternMatch{},
	}

	// Extended timeout for AI operations: 10 parallel category analyses + attack matching + exec summary
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	// Step 1: Run per-category AI analysis in parallel.
	// This augments each CategoryScore with an AIInsight containing deeper contextual analysis.
	// Results are written directly into result.SupplyChainScore.CategoryScores.*.AIInsight.
	// Failures are graceful - a failed category analysis leaves AIInsight as nil.
	checkAnalyzer := ai.NewCheckAnalyzer(a.claudeClient)
	checkAnalyzer.AnalyzeAllCategories(ctx, result.Dependency.Name, result.Dependency.Ecosystem, result)

	// Step 2: Run attack pattern matching (cross-cutting analysis)
	attackPatterns, err := a.runAttackPatternMatching(ctx, result)
	if err != nil {
		// Log error but continue - don't fail the scan
		aiResult.AnalysisNotes += fmt.Sprintf("Attack pattern matching failed: %v; ", err)
	} else if attackPatterns != nil {
		aiResult.AttackPatterns = attackPatterns
	}

	// Step 3: Generate executive explanation (cross-cutting summary)
	execSummary, err := a.generateExecutiveExplanation(ctx, result)
	if err != nil {
		// Log error but continue
		aiResult.AnalysisNotes += fmt.Sprintf("Executive explanation generation failed: %v; ", err)
	} else if execSummary != nil {
		aiResult.ExecutiveSummary = execSummary
	}

	// Calculate overall confidence based on successful cross-cutting analyses
	confidenceCount := 0
	confidenceSum := 0.0

	if len(aiResult.AttackPatterns) > 0 {
		confidenceCount++
		// Average confidence from attack patterns
		for _, ap := range aiResult.AttackPatterns {
			confidenceSum += ap.Confidence
		}
		confidenceSum /= float64(len(aiResult.AttackPatterns))
	}

	if aiResult.ExecutiveSummary != nil && aiResult.ExecutiveSummary.Confidence > 0 {
		confidenceCount++
		confidenceSum += aiResult.ExecutiveSummary.Confidence
	}

	if confidenceCount > 0 {
		aiResult.OverallConfidence = confidenceSum / float64(confidenceCount)
	}

	// Attach AI analysis result if we have cross-cutting findings.
	// Note: per-category insights are stored on CategoryScore.AIInsight directly,
	// not on AIAnalysisResult - they belong with their respective category scores.
	if len(aiResult.AttackPatterns) > 0 || aiResult.ExecutiveSummary != nil || aiResult.AnalysisNotes != "" {
		result.AIAnalysis = aiResult
	}
}

// runAttackPatternMatching compares package behavior to documented supply chain attack patterns
// Returns nil on error or if no patterns match
func (a *Analyzer) runAttackPatternMatching(ctx context.Context, result *models.AnalysisResult) ([]models.AttackPatternMatch, error) {
	// Generate attack pattern matching prompt
	prompt := ai.NewAttackPatternMatchingPrompt(
		result.Dependency.Name,
		result.Dependency.Ecosystem,
		*result,
	)

	systemPrompt, userPrompt := prompt.Render()

	// Create message parameters
	params := anthropic.MessageNewParams{
		Model:       anthropic.ModelClaudeSonnet4_5,
		MaxTokens:   int64(prompt.MaxTokens),
		Temperature: anthropic.Float(float64(prompt.Temperature)),
		System: []anthropic.TextBlockParam{
			{
				Text: systemPrompt,
				Type: "text",
			},
		},
		Messages: []anthropic.MessageParam{
			anthropic.NewUserMessage(anthropic.NewTextBlock(userPrompt)),
		},
	}

	// Call Claude API
	message, err := a.claudeClient.CreateMessage(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("failed to call Claude API: %w", err)
	}

	// Parse response to extract attack patterns
	// For now, we'll parse the text response and extract structured data
	// In a production system, you might want to use structured output or JSON mode
	attackPatterns := a.parseAttackPatternResponse(message)

	return attackPatterns, nil
}

// generateExecutiveExplanation creates a stakeholder-friendly summary of the risk assessment
// Returns nil on error
func (a *Analyzer) generateExecutiveExplanation(ctx context.Context, result *models.AnalysisResult) (*models.ExecutiveExplanation, error) {
	// Generate executive explanation prompt
	// Target audience: technical stakeholders (developers, security engineers)
	prompt := ai.NewExecutiveExplanationPrompt(
		result.Dependency.Name,
		result.Dependency.Ecosystem,
		*result,
		"technical stakeholders (developers, security engineers)",
	)

	systemPrompt, userPrompt := prompt.Render()

	// Create message parameters
	params := anthropic.MessageNewParams{
		Model:       anthropic.ModelClaudeSonnet4_5,
		MaxTokens:   int64(prompt.MaxTokens),
		Temperature: anthropic.Float(float64(prompt.Temperature)),
		System: []anthropic.TextBlockParam{
			{
				Text: systemPrompt,
				Type: "text",
			},
		},
		Messages: []anthropic.MessageParam{
			anthropic.NewUserMessage(anthropic.NewTextBlock(userPrompt)),
		},
	}

	// Call Claude API
	message, err := a.claudeClient.CreateMessage(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("failed to call Claude API: %w", err)
	}

	// Parse response to extract executive explanation
	execExplanation := a.parseExecutiveExplanationResponse(message)

	return execExplanation, nil
}

// parseAttackPatternResponse extracts structured attack pattern data from Claude's response.
// For each recognized attack pattern mentioned in the AI response, it extracts the surrounding
// context as evidence rather than using generic placeholders.
func (a *Analyzer) parseAttackPatternResponse(message *anthropic.Message) []models.AttackPatternMatch {
	patterns := []models.AttackPatternMatch{}

	// Extract text content from message
	if len(message.Content) == 0 {
		return patterns
	}

	// Get the text content
	var responseText string
	for _, block := range message.Content {
		if block.Type == "text" {
			responseText += block.Text
		}
	}

	// Known attack patterns with descriptions and required academic sources
	knownPatterns := map[string]string{
		"Typosquatting":                  "Package name manipulation attack",
		"Account Takeover":               "Maintainer account compromise",
		"Dependency Confusion":           "Public/private namespace collision",
		"Malicious Install Script":      "Code execution during installation",
		"Abandoned Package Takeover":    "Compromised unmaintained package",
		"Build Chain Compromise":         "CI/CD pipeline attack",
		"Transitive Dependency Poisoning": "Indirect dependency compromise",
		"Subdomain Takeover":             "Repository URL hijacking",
	}

	// Split response into sentences for context extraction
	sentences := splitIntoSentences(responseText)

	for patternName, description := range knownPatterns {
		if strings.Contains(responseText, patternName) {
			// Extract sentences mentioning this pattern as concrete evidence
			evidence := extractEvidenceForPattern(sentences, patternName)
			academicSource := a.getAcademicSourceForPattern(patternName)

			pattern := models.AttackPatternMatch{
				PatternName:    patternName,
				Description:    description,
				Confidence:     0.7,
				Severity:       "MEDIUM",
				Evidence:       evidence,
				Indicators:     extractIndicatorsForPattern(sentences, patternName),
				AcademicSource: academicSource,
			}
			patterns = append(patterns, pattern)
		}
	}

	return patterns
}

// splitIntoSentences splits text into sentences, preserving bullet points as individual items.
func splitIntoSentences(text string) []string {
	var sentences []string
	lines := strings.Split(text, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Treat bullet points and numbered items as individual sentences
		if strings.HasPrefix(line, "- ") || strings.HasPrefix(line, "* ") ||
			(len(line) > 2 && line[0] >= '1' && line[0] <= '9' && line[1] == '.') {
			sentences = append(sentences, line)
			continue
		}
		// Split on sentence-ending punctuation followed by space or end
		// but keep each as a meaningful unit
		parts := strings.FieldsFunc(line, func(r rune) bool {
			return r == '\n'
		})
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if part != "" {
				sentences = append(sentences, part)
			}
		}
	}
	return sentences
}

// extractEvidenceForPattern finds sentences that mention a pattern and returns them as
// concrete evidence items. Each evidence item includes the AI's actual reasoning about
// why this pattern applies, rather than a generic "pattern mentioned" placeholder.
func extractEvidenceForPattern(sentences []string, patternName string) []string {
	var evidence []string
	patternLower := strings.ToLower(patternName)

	for _, sentence := range sentences {
		if strings.Contains(strings.ToLower(sentence), patternLower) {
			// Clean up the sentence - remove markdown formatting
			clean := strings.TrimSpace(sentence)
			clean = strings.TrimLeft(clean, "-*• ")
			clean = strings.TrimLeft(clean, "0123456789.")
			clean = strings.TrimSpace(clean)

			// Skip very short or header-only lines that lack substance
			if len(clean) < 20 {
				continue
			}
			// Skip lines that are just the pattern name repeated
			if strings.ToLower(strings.TrimSpace(clean)) == patternLower {
				continue
			}

			evidence = append(evidence, clean)
		}
	}

	// If no specific evidence was extracted from the AI response, provide a
	// structured fallback that references the academic source instead of a vague label
	if len(evidence) == 0 {
		evidence = []string{
			fmt.Sprintf("AI analysis identified indicators consistent with the %s attack vector as documented in supply chain security research", patternName),
		}
	}

	// Cap evidence to avoid excessive output
	if len(evidence) > 5 {
		evidence = evidence[:5]
	}

	return evidence
}

// extractIndicatorsForPattern finds specific indicator mentions near an attack pattern reference.
func extractIndicatorsForPattern(sentences []string, patternName string) []string {
	var indicators []string
	patternLower := strings.ToLower(patternName)

	// Known indicator keywords per pattern
	indicatorKeywords := map[string][]string{
		"Account Takeover":               {"single maintainer", "no 2fa", "no mfa", "credential", "one maintainer", "account compromise"},
		"Typosquatting":                  {"name similar", "character difference", "name resembl", "typo", "misspell"},
		"Dependency Confusion":           {"private", "internal", "namespace", "public registry"},
		"Malicious Install Script":      {"postinstall", "preinstall", "install script", "network request", "obfuscat", "child process"},
		"Abandoned Package Takeover":    {"dormant", "inactive", "no releases", "abandoned", "unmaintained", "ownership transfer"},
		"Build Chain Compromise":         {"local publish", "no ci", "self-hosted", "no attestation", "no provenance", "unsigned"},
		"Transitive Dependency Poisoning": {"transitive", "indirect", "deep dependency", "dependency tree"},
		"Subdomain Takeover":             {"404", "repository missing", "domain expired", "url hijack"},
	}

	keywords, ok := indicatorKeywords[patternName]
	if !ok {
		return indicators
	}

	for _, sentence := range sentences {
		sentLower := strings.ToLower(sentence)
		// Only look at sentences near the pattern mention or that contain indicator keywords
		if !strings.Contains(sentLower, patternLower) {
			continue
		}
		for _, kw := range keywords {
			if strings.Contains(sentLower, kw) {
				clean := strings.TrimSpace(sentence)
				clean = strings.TrimLeft(clean, "-*• ")
				clean = strings.TrimSpace(clean)
				if len(clean) > 10 {
					indicators = append(indicators, clean)
					break
				}
			}
		}
	}

	if len(indicators) > 5 {
		indicators = indicators[:5]
	}

	return indicators
}

// parseExecutiveExplanationResponse extracts structured executive explanation from Claude's response
func (a *Analyzer) parseExecutiveExplanationResponse(message *anthropic.Message) *models.ExecutiveExplanation {
	if len(message.Content) == 0 {
		return nil
	}

	// Extract text content
	var responseText string
	for _, block := range message.Content {
		if block.Type == "text" {
			responseText += block.Text
		}
	}

	// Parse the response to extract structured sections
	// This is a simplified parser
	explanation := &models.ExecutiveExplanation{
		Summary:           a.extractSection(responseText, "Executive Summary", "Business Impact"),
		BusinessImpact:    a.extractSection(responseText, "Business Impact", "Technical Explanation"),
		RecommendedAction: a.extractSection(responseText, "Recommendations", "Additional Context"),
		TechnicalDetails:  a.extractSection(responseText, "Technical Explanation", "Risk Assessment"),
		Confidence:        0.8, // Default confidence
		GeneratedAt:       time.Now(),
	}

	// Extract key risks (look for bullet points or numbered lists)
	explanation.KeyRisks = a.extractKeyRisks(responseText)

	return explanation
}

// extractSection extracts text between two section headers
func (a *Analyzer) extractSection(text, startMarker, endMarker string) string {
	startIdx := strings.Index(text, startMarker)
	if startIdx == -1 {
		return ""
	}

	// Start after the marker
	startIdx += len(startMarker)

	// Find the end marker
	endIdx := strings.Index(text[startIdx:], endMarker)
	if endIdx == -1 {
		// If no end marker, take the rest or limit to 500 chars
		if len(text[startIdx:]) > 500 {
			return strings.TrimSpace(text[startIdx : startIdx+500])
		}
		return strings.TrimSpace(text[startIdx:])
	}

	section := text[startIdx : startIdx+endIdx]
	return strings.TrimSpace(section)
}

// extractKeyRisks extracts key risk points from the response text
func (a *Analyzer) extractKeyRisks(text string) []string {
	risks := []string{}

	// Look for lines starting with bullet points or numbers
	lines := strings.Split(text, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "- ") || strings.HasPrefix(line, "* ") {
			risk := strings.TrimPrefix(line, "- ")
			risk = strings.TrimPrefix(risk, "* ")
			risks = append(risks, risk)
		} else if len(line) > 2 && line[0] >= '1' && line[0] <= '9' && line[1] == '.' {
			risk := strings.TrimSpace(line[2:])
			risks = append(risks, risk)
		}
	}

	// Limit to top 5 risks
	if len(risks) > 5 {
		risks = risks[:5]
	}

	return risks
}

// getAcademicSourceForPattern returns the academic citation for a known attack pattern.
// Every pattern must have a specific, verifiable source - no vague references allowed.
func (a *Analyzer) getAcademicSourceForPattern(patternName string) string {
	sources := map[string]string{
		"Typosquatting":                  "Towards Measuring Supply Chain Attacks on Package Managers for Interpreted Languages (Ohm et al., NDSS 2020)",
		"Account Takeover":               "Backstabber's Knife Collection: A Review of Open Source Software Supply Chain Attacks (Ohm et al., 2020) - https://arxiv.org/abs/2005.09535",
		"Dependency Confusion":           "Dependency Confusion: How I Hacked Into Apple, Microsoft and Dozens of Other Companies (Alex Birsan, 2021) - https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610",
		"Malicious Install Script":      "Backstabber's Knife Collection: A Review of Open Source Software Supply Chain Attacks (Ohm et al., 2020) - https://arxiv.org/abs/2005.09535",
		"Abandoned Package Takeover":    "Towards Measuring Supply Chain Attacks on Package Managers for Interpreted Languages (Ohm et al., NDSS 2020)",
		"Build Chain Compromise":         "SLSA: Supply chain Levels for Software Artifacts, Threats & mitigations - https://slsa.dev/spec/v1.0/threats",
		"Transitive Dependency Poisoning": "Small World with High Risks: A Study of Security Threats in the npm Ecosystem (Zimmermann et al., 2019) - https://doi.org/10.1145/3133956.3134059",
		"Subdomain Takeover":             "Backstabber's Knife Collection (Ohm et al., 2020) - Repository hijacking via abandoned infrastructure - https://arxiv.org/abs/2005.09535",
	}

	if source, ok := sources[patternName]; ok {
		return source
	}
	// Fallback must still be a specific, verifiable reference
	return "Backstabber's Knife Collection: A Review of Open Source Software Supply Chain Attacks (Ohm et al., 2020) - https://arxiv.org/abs/2005.09535"
}
