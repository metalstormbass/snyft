package analyzer

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"

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
}

// NewAnalyzer creates a new Analyzer instance
func NewAnalyzer() *Analyzer {
	return &Analyzer{
		githubClient:    fetcher.NewGitHubClient(),
		gitlabClient:    fetcher.NewGitLabClient(),
		bitbucketClient: fetcher.NewBitbucketClient(),
		npmClient:       fetcher.NewNPMClient(),
		pypiClient:      fetcher.NewPyPIClient(),
		mavenClient:     fetcher.NewMavenClient(),
		ossfClient:      fetcher.NewOSSFClient(),
	}
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
		// Fall back to GitHub client for unknown platforms
		return a.githubClient
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
			result.Findings = append(result.Findings, models.Finding{
				Severity:    "HIGH",
				Category:    "Package Not Found",
				Description: fmt.Sprintf("Failed to fetch package from npm: %v", err),
				Check:       "Package Registry Validation",
			})
			result.RiskLevel = "HIGH"
			result.RiskScore = 100
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
			result.Findings = append(result.Findings, models.Finding{
				Severity:    "HIGH",
				Category:    "Package Not Found",
				Description: fmt.Sprintf("Failed to fetch package from PyPI: %v", err),
				Check:       "Package Registry Validation",
			})
			result.RiskLevel = "HIGH"
			result.RiskScore = 100
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
			result.Findings = append(result.Findings, models.Finding{
				Severity:    "HIGH",
				Category:    "Package Not Found",
				Description: fmt.Sprintf("Failed to fetch package from Maven Central: %v", err),
				Check:       "Package Registry Validation",
			})
			result.RiskLevel = "HIGH"
			result.RiskScore = 100
			return result
		}
		repoURL = mavenPkg.RepositoryURL
		metadata = packageMetadataFromMaven(mavenPkg)

		// Try to fetch and analyze pom.xml if repository is available
		if repoURL != "" {
			gitClient := a.getGitClient(repoURL)
			if pomContent, err := gitClient.GetFileContent(repoURL, "pom.xml"); err == nil {
				scriptAnalysis := AnalyzeJavaPOM(pomContent)
				if scriptAnalysis.HasDangerousPatterns {
					metadata.InstallScripts = map[string]string{"pom.xml": pomContent}
					metadata.HasInstallScripts = true
					metadata.InstallScriptAnalysis = convertToModelAnalysis(scriptAnalysis)
				}
			}
		}
	}

	result.RepositoryURL = repoURL
	result.Metadata = metadata

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

	// Calculate supply chain score (0-14 point rubric)
	a.calculateSupplyChainScore(&result)

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
			} else if !sourceVerification.HasMatchingGitTag {
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

	// Check for low activity indicators
	if repoInfo.Stars < 10 && repoInfo.Forks < 5 {
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
	// Try to find and analyze lock file based on the source manifest
	if dep.Source == "" {
		return
	}

	dir := filepath.Dir(dep.Source)
	var metrics *models.DependencyMetrics
	var err error

	switch dep.Ecosystem {
	case models.EcosystemNPM:
		// Look for package-lock.json
		lockfilePath := filepath.Join(dir, "package-lock.json")
		metrics, err = parser.CountTransitiveDependencies(lockfilePath)

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

	// If we successfully got metrics, add them to metadata
	if err == nil && metrics != nil {
		result.Metadata.DependencyMetrics = metrics
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

	if len(ciSystems) > 0 {
		result.BuildInfrastructure = "CI detected: " + strings.Join(ciSystems, ", ")
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
	return models.PackageMetadata{
		DownloadCount:  pkg.Downloads,
		PublishedAt:    pkg.PublishedAt,
		LatestVersion:  pkg.LatestVersion,
		Maintainers:    pkg.Maintainers,
		License:        pkg.License,
		Homepage:       pkg.Homepage,
		InstallScripts: pkg.Scripts,
	}
}

func packageMetadataFromPyPI(pkg *fetcher.PyPIPackage) models.PackageMetadata {
	return models.PackageMetadata{
		DownloadCount: pkg.Downloads,
		PublishedAt:   pkg.PublishedAt,
		LatestVersion: pkg.LatestVersion,
		Maintainers:   pkg.Maintainers,
		License:       pkg.License,
		Homepage:      pkg.Homepage,
	}
}

func packageMetadataFromMaven(pkg *fetcher.MavenPackage) models.PackageMetadata {
	return models.PackageMetadata{
		PublishedAt:   pkg.PublishedAt,
		LatestVersion: pkg.LatestVersion,
		License:       pkg.License,
	}
}

// calculateSupplyChainScore implements a 0-16 point supply chain security rubric
// Each of 8 categories is scored 0-2 points (0=good, 2=high risk)
// Total: 0-3=Low risk, 4-8=Medium risk, 9+=High risk
func (a *Analyzer) calculateSupplyChainScore(result *models.AnalysisResult) {
	score := &models.SupplyChainScore{
		CategoryScores: models.CategoryScores{},
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

	// Calculate total score
	score.TotalScore = score.CategoryScores.PublisherControl.RiskPoints +
		score.CategoryScores.OwnershipChanges.RiskPoints +
		score.CategoryScores.ReleaseAnomalies.RiskPoints +
		score.CategoryScores.InstallExecution.RiskPoints +
		score.CategoryScores.DependencySprawl.RiskPoints +
		score.CategoryScores.Provenance.RiskPoints +
		score.CategoryScores.Health.RiskPoints +
		score.CategoryScores.Governance.RiskPoints

	// Determine risk level based on total score
	if score.TotalScore >= 9 {
		score.RiskLevel = "HIGH"
	} else if score.TotalScore >= 4 {
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

// scoreOwnershipChanges: ownership transfers (0-2 pts)
// Detects maintainer changes via GitHub commits API, npm/pypi ownership history,
// and identifies recent transfers or new maintainers
func (a *Analyzer) scoreOwnershipChanges(result *models.AnalysisResult) models.CategoryScore {
	evidenceParts := []string{}
	verified := false
	riskPoints := 1 // Default to medium risk if unable to verify

	// 1. Check Git platform commit author changes (if repository available)
	if result.RepositoryURL != "" {
		gitClient := a.getGitClient(result.RepositoryURL)
		commitStats, err := gitClient.GetCommitAuthors(result.RepositoryURL)
		if err == nil && commitStats != nil {
			verified = true

			// Analyze commit author patterns
			if len(commitStats.RecentAuthors) > 0 && len(commitStats.HistoricalAuthors) > 0 {
				// Check if recent authors are completely different from historical authors
				historicalSet := make(map[string]bool)
				for _, author := range commitStats.HistoricalAuthors {
					historicalSet[author] = true
				}

				newAuthors := 0
				for _, author := range commitStats.RecentAuthors {
					if !historicalSet[author] {
						newAuthors++
					}
				}

				// If most/all recent authors are new = potential ownership change
				if newAuthors > 0 && float64(newAuthors)/float64(len(commitStats.RecentAuthors)) > 0.5 {
					riskPoints = 2
					evidenceParts = append(evidenceParts,
						fmt.Sprintf("GitHub: %d new commit authors in last 90 days", newAuthors))
				} else {
					evidenceParts = append(evidenceParts,
						fmt.Sprintf("GitHub: %d unique authors, %d recent", len(commitStats.UniqueAuthors), len(commitStats.RecentAuthors)))
				}
			} else if len(commitStats.UniqueAuthors) == 1 {
				// Single author throughout history
				evidenceParts = append(evidenceParts, "GitHub: Single author (stable)")
			}
		}
	}

	// 2. Check npm package ownership history
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
			} else if len(npmHistory.CurrentMaintainers) > 0 {
				evidenceParts = append(evidenceParts,
					fmt.Sprintf("npm: Stable ownership (%d maintainers)", len(npmHistory.CurrentMaintainers)))
			}
		}
	}

	// 3. Check PyPI package ownership history
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
			} else if pypiHistory.CurrentAuthor != "" {
				evidenceParts = append(evidenceParts, "PyPI: Stable ownership")
			}
		}
	}

	// 4. Fallback to repository age heuristic if no other data available
	if !verified && !result.Metadata.RepoCreatedAt.IsZero() {
		repoAge := time.Since(result.Metadata.RepoCreatedAt).Hours() / 24 / 365
		verified = true

		// Very new packages with single maintainer = higher risk
		if repoAge < 0.5 && len(result.Metadata.Maintainers) <= 1 {
			riskPoints = 2
			evidenceParts = append(evidenceParts,
				fmt.Sprintf("Repository %.1f years old, single maintainer", repoAge))
		} else if repoAge < 1.0 {
			riskPoints = 1
			evidenceParts = append(evidenceParts,
				fmt.Sprintf("Repository %.1f years old", repoAge))
		} else {
			riskPoints = 0
			evidenceParts = append(evidenceParts,
				fmt.Sprintf("Repository %.1f years old", repoAge))
		}
	}

	// Build final evidence string
	evidence := "No ownership data available"
	if len(evidenceParts) > 0 {
		evidence = strings.Join(evidenceParts, "; ")
	}

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
	if result.Metadata.RepoLastCommit.IsZero() || result.RepositoryURL == "" {
		return models.CategoryScore{
			Score:       0,
			RiskPoints:  1,
			Description: "Unable to verify release patterns",
			Evidence:    "No commit history available",
			Verified:    false,
		}
	}

	daysSinceLastCommit := time.Since(result.Metadata.RepoLastCommit).Hours() / 24
	daysSinceCreated := time.Since(result.Metadata.RepoCreatedAt).Hours() / 24

	// Very inactive (dormant for over a year)
	if daysSinceLastCommit > 365 {
		return models.CategoryScore{
			Score:       0,
			RiskPoints:  1,
			Description: "Package appears dormant",
			Evidence:    fmt.Sprintf("No commits in %.0f days (>1 year)", daysSinceLastCommit),
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
				return *anomaly
			}
		}
	}

	// Regular, consistent activity (active within the year, no anomalies detected)
	return models.CategoryScore{
		Score:       2,
		RiskPoints:  0,
		Description: "Regular, consistent releases",
		Evidence:    fmt.Sprintf("Last commit %.0f days ago, no anomalies detected", daysSinceLastCommit),
		Verified:    true,
	}
}

// detectReleaseAnomaly analyzes release history to detect dormant packages that suddenly reactivate
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

	// Sort by published date (most recent first)
	// Already sorted by GitHub API, but let's ensure it
	mostRecent := validReleases[0].PublishedAt
	daysSinceRecentRelease := time.Since(mostRecent).Hours() / 24

	// Look for a long gap in release history
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

	// Suspicious reactivation: long dormancy (>365 days) followed by recent release (<90 days)
	if maxGapDays > 365 && daysSinceRecentRelease < 90 {
		return &models.CategoryScore{
			Score:       0,
			RiskPoints:  2,
			Description: "Suspicious reactivation after dormancy",
			Evidence:    fmt.Sprintf("Dormant for %.0f days (%s to %s), recent release %.0f days ago",
				maxGapDays, gapStartDate.Format("2006-01"), gapEndDate.Format("2006-01"), daysSinceRecentRelease),
			Verified:    true,
		}
	}

	// Calculate average release frequency
	if len(validReleases) > 2 {
		totalDays := validReleases[0].PublishedAt.Sub(validReleases[len(validReleases)-1].PublishedAt).Hours() / 24
		avgDaysBetweenReleases := totalDays / float64(len(validReleases)-1)

		// Unusual pattern: recent release much faster than average (possible supply chain attack)
		if len(validReleases) >= 3 {
			recentGap := validReleases[0].PublishedAt.Sub(validReleases[1].PublishedAt).Hours() / 24
			if avgDaysBetweenReleases > 90 && recentGap < 7 && daysSinceRecentRelease < 30 {
				return &models.CategoryScore{
					Score:       0,
					RiskPoints:  2,
					Description: "Unusual release pattern detected",
					Evidence:    fmt.Sprintf("Avg release every %.0f days, but recent release only %.0f days ago (unusual spike)",
						avgDaysBetweenReleases, recentGap),
					Verified:    true,
				}
			}
		}
	}

	return nil
}

// detectCommitFrequencyAnomaly analyzes commit frequency changes to detect suspicious activity
func (a *Analyzer) detectCommitFrequencyAnomaly(recentCommits, olderCommits []fetcher.GitHubCommit, repoCreatedAt time.Time) *models.CategoryScore {
	oneYearAgo := time.Now().AddDate(-1, 0, 0)

	// Count commits in last year vs previous year
	recentCount := len(recentCommits)

	// Filter older commits to only count those from year 1-2 ago
	previousYearCount := 0
	for _, commit := range olderCommits {
		if commit.Commit.Author.Date.Before(oneYearAgo) {
			previousYearCount++
		}
	}

	// Repo must be at least 2 years old for this check
	repoAgeYears := time.Since(repoCreatedAt).Hours() / 24 / 365
	if repoAgeYears < 2 {
		return nil
	}

	// Suspicious reactivation: little to no commits in previous year, but many recent commits
	if previousYearCount < 5 && recentCount > 20 {
		return &models.CategoryScore{
			Score:       0,
			RiskPoints:  2,
			Description: "Suspicious commit frequency spike",
			Evidence:    fmt.Sprintf("%d commits in last year vs %d in previous year (sudden spike)",
				recentCount, previousYearCount),
			Verified:    true,
		}
	}

	// Package was dormant, now has some activity (moderate concern)
	if previousYearCount == 0 && recentCount > 0 && recentCount < 20 {
		return &models.CategoryScore{
			Score:       0,
			RiskPoints:  1,
			Description: "Package reactivated after dormancy",
			Evidence:    fmt.Sprintf("0 commits in previous year, %d commits in last year", recentCount),
			Verified:    true,
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
	// If no install scripts present, return best score
	if !result.Metadata.HasInstallScripts || len(result.Metadata.InstallScripts) == 0 {
		return models.CategoryScore{
			Score:       2,
			RiskPoints:  0,
			Description: "No install-time scripts",
			Evidence:    "No install scripts detected in package",
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
			Evidence:    fmt.Sprintf("Risk level: %s, Patterns: %s", result.Metadata.InstallScriptAnalysis.RiskLevel, strings.Join(patterns, ", ")),
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
			Evidence:    fmt.Sprintf("Scripts: %s", strings.Join(foundScripts, ", ")),
			Verified:    true,
		}
	}

	// Single benign install script = moderate risk
	if len(foundScripts) == 1 {
		return models.CategoryScore{
			Score:       0,
			RiskPoints:  1,
			Description: "Single install-time script detected",
			Evidence:    fmt.Sprintf("Script: %s", foundScripts[0]),
			Verified:    true,
		}
	}

	// Has scripts but none are install-time (shouldn't reach here if HasInstallScripts is correct)
	return models.CategoryScore{
		Score:       2,
		RiskPoints:  0,
		Description: "No install-time scripts",
		Evidence:    "Package has scripts but no install hooks",
		Verified:    true,
	}
}

// scoreDependencySprawl: transitive dependencies (0-2 pts)
// Scoring: 0 points (few: <10), 1 point (moderate: 10-50), 2 points (many: 50+)
func (a *Analyzer) scoreDependencySprawl(result *models.AnalysisResult) models.CategoryScore {
	// If we have dependency metrics from lock file analysis, use them
	if result.Metadata.DependencyMetrics != nil && result.Metadata.DependencyMetrics.Verified {
		metrics := result.Metadata.DependencyMetrics
		transitiveCount := metrics.TransitiveCount

		// Score based on transitive dependency count
		// 0 points = few dependencies (< 10) = low risk
		// 1 point = moderate dependencies (10-50) = medium risk
		// 2 points = many dependencies (50+) = high risk
		if transitiveCount < 10 {
			return models.CategoryScore{
				Score:       2,
				RiskPoints:  0,
				Description: "Few transitive dependencies",
				Evidence:    fmt.Sprintf("%d total dependencies (%d direct)", transitiveCount, metrics.DirectCount),
				Verified:    true,
			}
		} else if transitiveCount <= 50 {
			return models.CategoryScore{
				Score:       1,
				RiskPoints:  1,
				Description: "Moderate transitive dependencies",
				Evidence:    fmt.Sprintf("%d total dependencies (%d direct)", transitiveCount, metrics.DirectCount),
				Verified:    true,
			}
		} else {
			return models.CategoryScore{
				Score:       0,
				RiskPoints:  2,
				Description: "Many transitive dependencies",
				Evidence:    fmt.Sprintf("%d total dependencies (%d direct)", transitiveCount, metrics.DirectCount),
				Verified:    true,
			}
		}
	}

	// Fallback: use heuristics based on ecosystem and package popularity
	// Popular packages tend to have more dependencies
	if result.Metadata.RepoStars > 1000 || result.Metadata.DownloadCount > 1000000 {
		return models.CategoryScore{
			Score:       2,
			RiskPoints:  0,
			Description: "Popular package (likely audited dependencies)",
			Evidence:    fmt.Sprintf("%d stars, %d downloads", result.Metadata.RepoStars, result.Metadata.DownloadCount),
			Verified:    false,
		}
	}

	// Low popularity = unknown dependency tree
	if result.Metadata.RepoStars < 10 {
		return models.CategoryScore{
			Score:       0,
			RiskPoints:  2,
			Description: "Unknown dependency tree (low adoption)",
			Evidence:    fmt.Sprintf("%d stars", result.Metadata.RepoStars),
			Verified:    false,
		}
	}

	return models.CategoryScore{
		Score:       0,
		RiskPoints:  1,
		Description: "Moderate adoption (some dependency risk)",
		Evidence:    fmt.Sprintf("%d stars", result.Metadata.RepoStars),
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

	return models.CategoryScore{
		Score:       score,
		RiskPoints:  riskPoints,
		Description: description,
		Evidence:    evidenceStr,
		Verified:    len(evidence) > 0 || provenanceScore == 0,
	}
}

// scoreHealth: bus factor/review process/CI (0-2 pts)
// Score: 0 = high bus factor/no CI/no reviews (high risk)
//        1 = moderate indicators (medium risk)
//        2 = low bus factor with CI and reviews (low risk)
func (a *Analyzer) scoreHealth(result *models.AnalysisResult) models.CategoryScore {
	points := 0
	evidence := []string{}
	verified := false

	// Component 1: Bus Factor (from commit distribution)
	// Low bus factor = concentrated development = higher risk
	busFactor := result.Metadata.BusFactor
	if busFactor > 0 {
		verified = true
		if busFactor >= 3 {
			// Multiple contributors (low risk)
			points++
			evidence = append(evidence, fmt.Sprintf("Bus factor: %d", busFactor))
		} else if busFactor == 2 {
			// Moderate risk - 2 contributors
			evidence = append(evidence, fmt.Sprintf("Bus factor: %d (moderate)", busFactor))
		} else {
			// High risk - single contributor
			evidence = append(evidence, fmt.Sprintf("Bus factor: %d (high risk)", busFactor))
		}

		// Additional evidence: top contributor concentration
		if result.Metadata.TopContributorPct > 0 {
			if result.Metadata.TopContributorPct >= 80 {
				evidence = append(evidence, fmt.Sprintf("Top contributor: %.0f%% of commits", result.Metadata.TopContributorPct))
			}
		}
	} else {
		// Fallback to maintainer count if bus factor unavailable
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

	// Component 2: Code Review Process
	// No reviews = higher risk
	if result.Metadata.HasBranchProtection && result.Metadata.RequiredReviewers > 0 {
		// Branch protection with required reviews (best case)
		points++
		evidence = append(evidence, fmt.Sprintf("%d required reviewers", result.Metadata.RequiredReviewers))
		verified = true
	} else if result.Metadata.CodeReviewRate > 0 {
		// Some code reviews happening
		if result.Metadata.CodeReviewRate >= 75 {
			// Most PRs reviewed (good)
			points++
			evidence = append(evidence, fmt.Sprintf("%.0f%% PRs reviewed", result.Metadata.CodeReviewRate))
		} else if result.Metadata.CodeReviewRate >= 50 {
			// Some PRs reviewed (moderate)
			evidence = append(evidence, fmt.Sprintf("%.0f%% PRs reviewed (moderate)", result.Metadata.CodeReviewRate))
		} else {
			// Few PRs reviewed (low)
			evidence = append(evidence, fmt.Sprintf("%.0f%% PRs reviewed (low)", result.Metadata.CodeReviewRate))
		}
		verified = true
	} else {
		evidence = append(evidence, "No code review process detected")
	}

	// Component 3: CI Quality
	// No CI or low-quality CI = higher risk
	if result.Metadata.CIQualityScore > 0 {
		verified = true
		if result.Metadata.CIQualityScore >= 7 {
			// High-quality CI with tests
			points++
			evidence = append(evidence, fmt.Sprintf("CI quality: %d/10", result.Metadata.CIQualityScore))
			if result.Metadata.CIHasTests {
				evidence = append(evidence, "CI includes tests")
			}
		} else if result.Metadata.CIQualityScore >= 4 {
			// Moderate CI
			evidence = append(evidence, fmt.Sprintf("CI quality: %d/10 (moderate)", result.Metadata.CIQualityScore))
		} else {
			// Basic CI only
			evidence = append(evidence, fmt.Sprintf("CI quality: %d/10 (basic)", result.Metadata.CIQualityScore))
		}
	} else if result.Metadata.HasCI {
		// CI detected but quality not assessed
		evidence = append(evidence, fmt.Sprintf("CI: %v", result.Metadata.CISystems))
		verified = true
	} else {
		evidence = append(evidence, "No CI detected")
	}

	// Calculate risk points based on total points earned
	// Points earned represents good indicators, so we invert for risk
	// 0-1 points earned = high risk (2 risk points)
	// 2 points earned = medium risk (1 risk point)
	// 3+ points earned = low risk (0 risk points)
	riskPoints := 2
	if points >= 3 {
		riskPoints = 0
	} else if points >= 2 {
		riskPoints = 1
	}

	// Determine description
	description := "Poor health: high bus factor, no CI, or no reviews"
	if points >= 3 {
		description = "Good health: distributed development, CI with tests, code reviews"
	} else if points >= 2 {
		description = "Moderate health: some good practices but gaps remain"
	} else if points >= 1 {
		description = "Limited health: few contributors or missing CI/reviews"
	}

	return models.CategoryScore{
		Score:       points,
		RiskPoints:  riskPoints,
		Description: description,
		Evidence:    strings.Join(evidence, "; "),
		Verified:    verified,
	}
}
