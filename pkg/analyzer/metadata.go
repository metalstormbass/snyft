package analyzer

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/metalstormbass/snyft/pkg/fetcher"
	"github.com/metalstormbass/snyft/pkg/models"
	"github.com/metalstormbass/snyft/pkg/parser"
)

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
	for _, ciRisk := range result.Metadata.CIWorkflowRisks {
		if ciRisk.HasScriptInjection {
			result.Findings = append(result.Findings, models.Finding{
				Severity:    "HIGH",
				Category:    "CI Script Injection",
				Description: fmt.Sprintf("Script injection risk detected in %s workflow: untrusted input interpolated into run steps", ciRisk.Platform),
				Check:       "CI Workflow Security Analysis",
				Evidence:    strings.Join(ciRisk.Details, "; "),
			})
			result.RiskFactors = append(result.RiskFactors, "CI workflow vulnerable to script injection")
		}
		if len(ciRisk.DangerousTriggers) > 0 {
			result.Findings = append(result.Findings, models.Finding{
				Severity:    "HIGH",
				Category:    "Dangerous CI Triggers",
				Description: fmt.Sprintf("Dangerous workflow triggers in %s: %s", ciRisk.Platform, strings.Join(ciRisk.DangerousTriggers, ", ")),
				Check:       "CI Workflow Security Analysis",
				Evidence:    strings.Join(ciRisk.Details, "; "),
			})
			result.RiskFactors = append(result.RiskFactors, "CI workflow uses dangerous triggers")
		}
		if ciRisk.HasExcessivePermissions {
			result.Findings = append(result.Findings, models.Finding{
				Severity:    "MEDIUM",
				Category:    "Excessive CI Permissions",
				Description: fmt.Sprintf("Overly broad permissions in %s workflow (violates least privilege)", ciRisk.Platform),
				Check:       "CI Workflow Security Analysis",
				Evidence:    strings.Join(ciRisk.Details, "; "),
			})
		}
		if len(ciRisk.UnpinnedActions) > 0 {
			result.Findings = append(result.Findings, models.Finding{
				Severity:    "MEDIUM",
				Category:    "Unpinned CI Dependencies",
				Description: fmt.Sprintf("%d unpinned actions/orbs in %s (vulnerable to tag hijacking)", len(ciRisk.UnpinnedActions), ciRisk.Platform),
				Check:       "CI Workflow Security Analysis",
				Evidence:    strings.Join(ciRisk.UnpinnedActions, ", "),
			})
		}
		if ciRisk.MissingEnvironmentProtection {
			result.Findings = append(result.Findings, models.Finding{
				Severity:    "MEDIUM",
				Category:    "Missing CI Environment Protection",
				Description: fmt.Sprintf("Publish/deploy workflow in %s lacks environment protection rules (no manual approval gate)", ciRisk.Platform),
				Check:       "CI Workflow Security Analysis",
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
	if errors.Is(err, fetcher.ErrDataUnavailable) {
		// Platform does not support release detection; skip finding rather than
		// penalizing for missing data.
	} else if err == nil && hasReleases {
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
	}

	// Analyze CI quality.
	// ErrDataUnavailable leaves defaults so CI quality is treated as unknown.
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
	// Get Git platform provenance information.
	// ErrDataUnavailable means the platform cannot provide provenance data;
	// leave defaults (all false) so the provenance scorer treats it as unknown.
	if repoURL != "" {
		gitClient := a.getGitClient(repoURL)
		provInfo, err := gitClient.GetProvenanceInfo(repoURL)
		if err == nil && provInfo != nil {
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
		provResult, err := a.npmClient.CheckNPMProvenance(result.Dependency.Name)
		if err == nil && provResult != nil {
			result.Metadata.HasNPMProvenance = provResult.HasProvenance
			if provResult.HasProvenance {
				result.Metadata.ProvenanceDetails = fmt.Sprintf("npm provenance: %s", provResult.ProvenanceURL)
				// npm provenance attestations are signed via Sigstore using OIDC-based
				// keyless signing. When present, they constitute a valid Sigstore signature.
				// Source: npm provenance docs — https://docs.npmjs.com/generating-provenance-statements
				// Source: Sigstore — https://www.sigstore.dev/
				result.Metadata.HasSigstoreSignature = true
				// If the attestation uses the SLSA predicate type, it is a valid SLSA
				// attestation generated by a trusted CI builder (GitHub Actions).
				// Source: SLSA specification v1.0 — https://slsa.dev/spec/v1.0/
				if provResult.IsSLSA {
					result.Metadata.HasSLSAAttestation = true
					if result.Metadata.SLSALevel == "" {
						result.Metadata.SLSALevel = "SLSA_BUILD_LEVEL_2"
					}
				}
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
