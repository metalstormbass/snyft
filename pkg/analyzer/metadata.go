package analyzer

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/metalstormbass/snyft/pkg/fetcher"
	"github.com/metalstormbass/snyft/pkg/models"
	"github.com/metalstormbass/snyft/pkg/parser"
)

// addFindingSafe appends a finding to result.Findings, using the mutex if non-nil.
// When mu is nil (e.g. in tests or sequential code), appends directly without locking.
func addFindingSafe(mu *sync.Mutex, result *models.AnalysisResult, f models.Finding) {
	if mu != nil {
		mu.Lock()
		defer mu.Unlock()
	}
	result.Findings = append(result.Findings, f)
}

// addRiskFactorSafe appends a risk factor to result.RiskFactors, using the mutex if non-nil.
func addRiskFactorSafe(mu *sync.Mutex, result *models.AnalysisResult, rf string) {
	if mu != nil {
		mu.Lock()
		defer mu.Unlock()
	}
	result.RiskFactors = append(result.RiskFactors, rf)
}

// verifySourceCode performs primary source code availability verification
// This is the FIRST check before any other scoring
func (a *Analyzer) verifySourceCode(result *models.AnalysisResult, dep models.Dependency, repoURL string, mu *sync.Mutex) {
	// Skip version-dependent source verification when version could not be
	// determined (e.g. Maven BOM imports, unresolved property references).
	// An undetermined version is a parser limitation, not a supply chain risk.
	if dep.IsVersionUnknown() {
		return
	}

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
			srcURL := registryURL(dep)
			repoSrcURL := repoSourceURL(repoURL)
			if !sourceVerification.HasSourcePackage && !sourceVerification.HasMatchingGitTag {
				sourceLink := srcURL
				if repoSrcURL != "" {
					sourceLink = repoSrcURL
				}
				addFindingSafe(mu, result, models.Finding{
					Severity:    "HIGH",
					Category:    "Source Code Verification Failed",
					Description: "No verifiable source code found for this exact version",
					Check:       "Primary Source Code Verification",
					Evidence:    strings.Join(sourceVerification.VerificationErrors, "; "),
					SourceURL:   sourceLink,
				})
				addRiskFactorSafe(mu, result, "No verifiable source code for exact version")
			} else if !sourceVerification.HasSourcePackage {
				addFindingSafe(mu, result, models.Finding{
					Severity:    "HIGH",
					Category:    "Missing Source Package",
					Description: "Package distribution lacks source code",
					Check:       "Source Package Verification",
					Evidence:    sourceVerification.Details,
					SourceURL:   srcURL,
				})
				addRiskFactorSafe(mu, result, "No source package available")
			} else if !sourceVerification.HasMatchingGitTag && repoURL != "" {
				// Only flag a missing git tag when a repository URL was available and
				// a tag check was actually attempted. When repoURL is empty the check
				// was never performed, so HasMatchingGitTag == false is not actionable.
				addFindingSafe(mu, result, models.Finding{
					Severity:    "MEDIUM",
					Category:    "Missing Git Tag",
					Description: fmt.Sprintf("No git tag found for version %s in repository", dep.Version),
					Check:       "Git Tag Verification",
					Evidence:    "Cannot verify build corresponds to repository state",
					SourceURL:   repoSrcURL + "/tags",
				})
				addRiskFactorSafe(mu, result, "No matching git tag for version")
			}
		}
	}
}

func (a *Analyzer) analyzeRepository(result *models.AnalysisResult, repoURL string, mu *sync.Mutex) {
	repoSrcURL := repoSourceURL(repoURL)
	gitClient := a.getGitClient(repoURL)
	repoInfo, err := gitClient.GetRepositoryInfo(repoURL)
	if err != nil {
		addFindingSafe(mu, result, models.Finding{
			Severity:    "MEDIUM",
			Category:    "Repository Access",
			Description: fmt.Sprintf("Failed to fetch repository info: %v", err),
			Check:       "Repository Metadata Check",
			SourceURL:   repoSrcURL,
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
		addFindingSafe(mu, result, models.Finding{
			Severity:    "HIGH",
			Category:    "Archived Repository",
			Description: "The repository is archived and no longer maintained",
			Check:       "Repository Status Check",
			SourceURL:   repoSrcURL,
		})
		addRiskFactorSafe(mu, result, "Archived repository")
	}

	// Check last commit age
	// Guard against zero timestamps returned by failed scraping fallbacks:
	// a zero PushedAt would compute to ~106,752 days and trigger a false positive.
	if !repoInfo.PushedAt.IsZero() {
		daysSinceLastCommit := time.Since(repoInfo.PushedAt).Hours() / 24
		if daysSinceLastCommit > 365 {
			addFindingSafe(mu, result, models.Finding{
				Severity:    "MEDIUM",
				Category:    "Stale Repository",
				Description: fmt.Sprintf("No commits in the last %.0f days", daysSinceLastCommit),
				Check:       "Repository Activity Check",
				SourceURL:   repoSrcURL + "/commits",
			})
			addRiskFactorSafe(mu, result, "Inactive development")
		}
	}

	// Check for low activity indicators.
	// Only flag this when we have a verified star count (Stars > 0 means the API
	// or scraper returned data; Stars == 0 could mean the count was never populated,
	// which would produce a false positive for large, popular projects).
	if repoInfo.Stars > 0 && repoInfo.Stars < 10 && repoInfo.Forks < 5 {
		addFindingSafe(mu, result, models.Finding{
			Severity:    "MEDIUM",
			Category:    "Low Community Engagement",
			Description: "Package has minimal community engagement (low stars/forks)",
			Check:       "Community Engagement Check",
			SourceURL:   repoSrcURL,
		})
		addRiskFactorSafe(mu, result, "Limited community adoption")
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
		// Look for Pipfile.lock first, then poetry.lock, then fall back to requirements.txt
		lockfilePath := filepath.Join(dir, "Pipfile.lock")
		metrics, err = parser.CountPythonDependencies(lockfilePath)
		if err != nil {
			lockfilePath = filepath.Join(dir, "poetry.lock")
			metrics, err = parser.CountPythonDependencies(lockfilePath)
		}
		if err != nil {
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

func (a *Analyzer) analyzeBuildInfrastructure(result *models.AnalysisResult, repoURL string, mu *sync.Mutex) {
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

	// Parse CI workflow configurations for supply chain risk signals.
	// The parsers detect: unpinned actions/orbs (tag hijacking), excessive permissions,
	// dangerous triggers (pull_request_target), script injection, secrets in logs,
	// and missing environment protection on publish workflows.
	//
	// Check: CI/CD workflow security analysis
	// Justification: Insecure CI configurations create direct supply chain attack vectors.
	// Source: "Backstabber's Knife Collection" (Ohm et al., 2020);
	//         GitHub Actions Security Hardening; SLSA Build Level Requirements
	// Methodology: Fetch CI config file content via git platform API, parse for insecure patterns
	// Result: Populates CIWorkflowRisks consumed by scoreReleaseSecurity
	ciConfigPaths := fetcher.CIConfigPaths()
	for _, bs := range buildSystems {
		paths, ok := ciConfigPaths[bs.Platform]
		if !ok {
			continue
		}

		for _, cfgPath := range paths {
			content, err := gitClient.GetFileContent(repoURL, cfgPath)
			if err != nil || content == "" {
				continue
			}

			risk := fetcher.ParseCIWorkflowContent(content, bs.Platform)
			if risk.RiskCount > 0 {
				result.Metadata.CIWorkflowRisks = append(result.Metadata.CIWorkflowRisks, risk)
			}

			// For non-GitHub Actions platforms, one config file is sufficient.
			// GitHub Actions repos may have multiple workflow files worth checking.
			if bs.Platform != "GitHub Actions" {
				break
			}
		}
	}

	// Generate findings from critical CI workflow risks
	ciSourceURL := repoSourceURL(repoURL) + "/actions"
	for _, ciRisk := range result.Metadata.CIWorkflowRisks {
		if ciRisk.HasScriptInjection {
			addFindingSafe(mu, result, models.Finding{
				Severity:    "HIGH",
				Category:    "CI Script Injection",
				Description: fmt.Sprintf("Script injection risk detected in %s workflow: untrusted input interpolated into run steps", ciRisk.Platform),
				Check:       "CI Workflow Security Analysis",
				Evidence:    strings.Join(ciRisk.Details, "; "),
				SourceURL:   ciSourceURL,
			})
			addRiskFactorSafe(mu, result, "CI workflow vulnerable to script injection")
		}
		if len(ciRisk.DangerousTriggers) > 0 {
			addFindingSafe(mu, result, models.Finding{
				Severity:    "HIGH",
				Category:    "Dangerous CI Triggers",
				Description: fmt.Sprintf("Dangerous workflow triggers in %s: %s", ciRisk.Platform, strings.Join(ciRisk.DangerousTriggers, ", ")),
				Check:       "CI Workflow Security Analysis",
				Evidence:    strings.Join(ciRisk.Details, "; "),
				SourceURL:   ciSourceURL,
			})
			addRiskFactorSafe(mu, result, "CI workflow uses dangerous triggers")
		}
		if ciRisk.HasExcessivePermissions {
			addFindingSafe(mu, result, models.Finding{
				Severity:    "MEDIUM",
				Category:    "Excessive CI Permissions",
				Description: fmt.Sprintf("Overly broad permissions in %s workflow (violates least privilege)", ciRisk.Platform),
				Check:       "CI Workflow Security Analysis",
				Evidence:    strings.Join(ciRisk.Details, "; "),
				SourceURL:   ciSourceURL,
			})
		}
		if len(ciRisk.UnpinnedActions) > 0 {
			addFindingSafe(mu, result, models.Finding{
				Severity:    "MEDIUM",
				Category:    "Unpinned CI Dependencies",
				Description: fmt.Sprintf("%d unpinned actions/orbs in %s (vulnerable to tag hijacking)", len(ciRisk.UnpinnedActions), ciRisk.Platform),
				Check:       "CI Workflow Security Analysis",
				Evidence:    strings.Join(ciRisk.UnpinnedActions, ", "),
				SourceURL:   ciSourceURL,
			})
		}
		if ciRisk.MissingEnvironmentProtection {
			addFindingSafe(mu, result, models.Finding{
				Severity:    "MEDIUM",
				Category:    "Missing CI Environment Protection",
				Description: fmt.Sprintf("Publish/deploy workflow in %s lacks environment protection rules (no manual approval gate)", ciRisk.Platform),
				Check:       "CI Workflow Security Analysis",
				SourceURL:   ciSourceURL,
			})
		}
	}

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
			addFindingSafe(mu, result, models.Finding{
				Severity:    "HIGH",
				Category:    "Self-Hosted CI Runners",
				Description: "Self-hosted CI runners detected: build environment is not controlled by a trusted cloud provider",
				Check:       "Build System Location Check",
				Evidence:    result.BuildInfrastructure,
				SourceURL:   ciSourceURL,
			})
			addRiskFactorSafe(mu, result, "Self-hosted build runners (uncontrolled build environment)")
		}
	} else {
		result.BuildInfrastructure = "No CI detected"
		addFindingSafe(mu, result, models.Finding{
			Severity:    "MEDIUM",
			Category:    "No CI/CD",
			Description: "No continuous integration system detected",
			Check:       "CI/CD Detection Check",
			SourceURL:   repoSourceURL(repoURL),
		})
		addRiskFactorSafe(mu, result, "No automated build verification")
	}

	// Check for automated release process
	hasReleases, err := gitClient.HasAutomatedReleases(repoURL)
	if errors.Is(err, fetcher.ErrDataUnavailable) {
		// Platform does not support release detection; skip finding rather than
		// penalizing for missing data.
	} else if err == nil && hasReleases {
		result.Metadata.HasReleaseProcess = true
	} else {
		addFindingSafe(mu, result, models.Finding{
			Severity:    "LOW",
			Category:    "Manual Releases",
			Description: "No evidence of automated release process",
			Check:       "Release Automation Check",
			SourceURL:   repoSourceURL(repoURL) + "/releases",
		})
	}
}

func (a *Analyzer) analyzeHealthMetrics(result *models.AnalysisResult, repoURL string) {
	gitClient := a.getGitClient(repoURL)

	// Get commit statistics for bus factor calculation.
	// ErrDataUnavailable means the platform cannot provide this data; leave
	// defaults (zero) so the health scorer falls back to maintainer-count heuristic.
	commitStats, err := gitClient.GetCommitStats(repoURL)
	if err == nil && commitStats != nil {
		result.Metadata.BusFactor = commitStats.BusFactor
		result.Metadata.CommitDistribution = commitStats.AuthorCommits
		result.Metadata.TopContributorPct = commitStats.TopContributorPct
	}

	// Get pull request statistics for code review verification.
	// ErrDataUnavailable leaves defaults so health scorer treats review data as unknown.
	prStats, err := gitClient.GetPullRequestStats(repoURL)
	if err == nil && prStats != nil {
		result.Metadata.CodeReviewRate = prStats.CodeReviewRate
		result.Metadata.RequiredReviewers = prStats.RequiredReviewers
		result.Metadata.HasBranchProtection = prStats.HasBranchProtection
		result.Metadata.BranchProtectionDenied = prStats.BranchProtectionDenied
	}

	// Analyze CI quality.
	// ErrDataUnavailable leaves defaults so CI quality is treated as unknown.
	ciQuality, err := gitClient.AnalyzeCIQuality(repoURL, result.Metadata.CISystems)
	if err == nil && ciQuality != nil {
		result.Metadata.CIQualityScore = ciQuality.QualityScore
	}
}

func (a *Analyzer) analyzeOSSFScorecard(result *models.AnalysisResult, repoURL string, mu *sync.Mutex) {
	scorecard, err := a.ossfClient.GetScorecard(repoURL)
	if err != nil {
		// OSSF scorecard may not be available for all projects
		return
	}

	result.Metadata.OSSFScore = scorecard.Score
	result.Metadata.OSSFChecks = scorecard.Checks

	if scorecard.Score < 5.0 {
		addFindingSafe(mu, result, models.Finding{
			Severity:    "MEDIUM",
			Category:    "Low OSSF Score",
			Description: fmt.Sprintf("OpenSSF Scorecard overall score is %.1f/10 — indicates weak supply chain security practices across multiple dimensions (branch protection, code review, signed releases, dependency management)", scorecard.Score),
			Check:       "OSSF Scorecard Check",
			SourceURL:   ossfScorecardURL(repoURL),
		})
		addRiskFactorSafe(mu, result, "Low supply chain security score")
	}
}

func (a *Analyzer) analyzeProvenance(result *models.AnalysisResult, repoURL string, ecosystem models.Ecosystem) {
	// Get Git platform provenance information.
	// ErrDataUnavailable means the platform cannot provide provenance data;
	// leave defaults (all false) so the provenance scorer treats it as unknown.
	if repoURL != "" {
		gitClient := a.getGitClient(repoURL)
		provInfo, err := gitClient.GetProvenanceInfo(repoURL)
		if err == nil && provInfo != nil {
			result.Metadata.TotalReleaseCount = provInfo.TotalReleaseCount

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
		provResult, err := a.npmClient.CheckNPMProvenance(result.Dependency.Name)
		if err == nil && provResult != nil {
			result.Metadata.HasNPMProvenance = provResult.HasProvenance
			if provResult.HasProvenance {
				result.Metadata.ProvenanceDetails = fmt.Sprintf("npm provenance: %s", provResult.ProvenanceURL)
			}
		}

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
	metadata := models.PackageMetadata{
		PublishedAt:   pkg.PublishedAt,
		LatestVersion: pkg.LatestVersion,
		License:       pkg.License,
	}

	// Populate maintainer list from POM <developers> section.
	// Maven Central does not expose a maintainer list via its API, but POM files
	// include developers who maintain the project. This serves as proxy data for
	// the Publisher Control (Category 1) assessment.
	// Source: Maven POM reference — https://maven.apache.org/pom.html#developers
	for _, dev := range pkg.Developers {
		var maintainer string
		switch {
		case dev.Name != "" && dev.Email != "":
			maintainer = dev.Name + " <" + dev.Email + ">"
		case dev.Name != "":
			maintainer = dev.Name
		case dev.Email != "":
			maintainer = dev.Email
		case dev.ID != "":
			maintainer = dev.ID
		default:
			continue
		}
		metadata.Maintainers = append(metadata.Maintainers, maintainer)
	}

	// Pre-populate dependency metrics from POM dependency data.
	// This provides a dependency sprawl signal from Maven Central even when no
	// local pom.xml is available (e.g. scanning by package name via CLI).
	// analyzeDependencySprawl may override this with local pom.xml data.
	if pkg.DirectDepCount > 0 || pkg.ScopeBreakdown != nil {
		metadata.DependencyMetrics = &models.DependencyMetrics{
			DirectCount:         pkg.DirectDepCount,
			Verified:            false, // POM shows only direct deps, not transitive
			MavenScopeBreakdown: pkg.ScopeBreakdown,
		}
	}

	// Use latest publish date as staleness fallback when no git repo is available.
	// This allows Package Maturity (Category 10) staleness checks to function
	// even without a source repository URL.
	if !pkg.LastPublishedAt.IsZero() {
		metadata.RepoUpdatedAt = pkg.LastPublishedAt
	}

	// Record GPG signature status for provenance scoring
	metadata.HasMavenGPGSignature = pkg.HasGPGSignature

	return metadata
}
