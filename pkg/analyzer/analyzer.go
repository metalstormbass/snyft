package analyzer

import (
	"fmt"
	"strings"
	"time"

	"github.com/metalstormbass/snyft/pkg/fetcher"
	"github.com/metalstormbass/snyft/pkg/models"
)

// Analyzer performs supply chain security analysis on dependencies
type Analyzer struct {
	githubClient   *fetcher.GitHubClient
	npmClient      *fetcher.NPMClient
	pypiClient     *fetcher.PyPIClient
	mavenClient    *fetcher.MavenClient
	ossfClient     *fetcher.OSSFClient
}

// NewAnalyzer creates a new Analyzer instance
func NewAnalyzer() *Analyzer {
	return &Analyzer{
		githubClient:  fetcher.NewGitHubClient(),
		npmClient:     fetcher.NewNPMClient(),
		pypiClient:    fetcher.NewPyPIClient(),
		mavenClient:   fetcher.NewMavenClient(),
		ossfClient:    fetcher.NewOSSFClient(),
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
	}

	result.RepositoryURL = repoURL
	result.Metadata = metadata

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

	// Get OSSF Scorecard (if available)
	if repoURL != "" {
		a.analyzeOSSFScorecard(&result, repoURL)
	}

	// Calculate final risk score
	a.calculateRiskScore(&result)

	// Calculate supply chain score (0-14 point rubric)
	a.calculateSupplyChainScore(&result)

	return result
}

func (a *Analyzer) analyzeRepository(result *models.AnalysisResult, repoURL string) {
	repoInfo, err := a.githubClient.GetRepositoryInfo(repoURL)
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

func (a *Analyzer) analyzeBuildInfrastructure(result *models.AnalysisResult, repoURL string) {
	if repoURL == "" {
		return
	}

	ciSystems, err := a.githubClient.DetectCISystems(repoURL)
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
	hasReleases, err := a.githubClient.HasAutomatedReleases(repoURL)
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

// calculateSupplyChainScore implements a 0-14 point supply chain security rubric
// Each of 7 categories is scored 0-2 points (0=good, 2=high risk)
// Total: 0-3=Low risk, 4-7=Medium risk, 8+=High risk
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

	// Calculate total score
	score.TotalScore = score.CategoryScores.PublisherControl.RiskPoints +
		score.CategoryScores.OwnershipChanges.RiskPoints +
		score.CategoryScores.ReleaseAnomalies.RiskPoints +
		score.CategoryScores.InstallExecution.RiskPoints +
		score.CategoryScores.DependencySprawl.RiskPoints +
		score.CategoryScores.Provenance.RiskPoints +
		score.CategoryScores.Health.RiskPoints

	// Determine risk level based on total score
	if score.TotalScore >= 8 {
		score.RiskLevel = "HIGH"
	} else if score.TotalScore >= 4 {
		score.RiskLevel = "MEDIUM"
	} else {
		score.RiskLevel = "LOW"
	}

	result.SupplyChainScore = score
}

// scorePublisherControl: 2FA/signing/multi-maintainer (0-2 pts)
func (a *Analyzer) scorePublisherControl(result *models.AnalysisResult) models.CategoryScore {
	maintainerCount := len(result.Metadata.Maintainers)

	if maintainerCount == 0 {
		// Fallback: unable to verify maintainer count
		return models.CategoryScore{
			Score:       0,
			RiskPoints:  1,
			Description: "Unable to verify maintainer information",
			Evidence:    "No maintainer data available from registry",
			Verified:    false,
		}
	}

	if maintainerCount == 1 {
		return models.CategoryScore{
			Score:       0,
			RiskPoints:  2,
			Description: "Single maintainer (bus factor = 1)",
			Evidence:    fmt.Sprintf("Only %d maintainer", maintainerCount),
			Verified:    true,
		}
	} else if maintainerCount <= 3 {
		return models.CategoryScore{
			Score:       0,
			RiskPoints:  1,
			Description: "Few maintainers (limited redundancy)",
			Evidence:    fmt.Sprintf("%d maintainers", maintainerCount),
			Verified:    true,
		}
	}

	return models.CategoryScore{
		Score:       2,
		RiskPoints:  0,
		Description: "Multiple maintainers (good redundancy)",
		Evidence:    fmt.Sprintf("%d maintainers", maintainerCount),
		Verified:    true,
	}
}

// scoreOwnershipChanges: ownership transfers (0-2 pts)
func (a *Analyzer) scoreOwnershipChanges(result *models.AnalysisResult) models.CategoryScore {
	// Check for recent repository transfers or maintainer changes
	// For now, use repository age and maintainer count as proxy

	if result.Metadata.RepoCreatedAt.IsZero() {
		return models.CategoryScore{
			Score:       0,
			RiskPoints:  1,
			Description: "Unable to verify ownership history",
			Evidence:    "Repository creation date unavailable",
			Verified:    false,
		}
	}

	repoAge := time.Since(result.Metadata.RepoCreatedAt).Hours() / 24 / 365

	// Very new packages with single maintainer = higher risk
	if repoAge < 0.5 && len(result.Metadata.Maintainers) == 1 {
		return models.CategoryScore{
			Score:       0,
			RiskPoints:  2,
			Description: "New package with single maintainer",
			Evidence:    fmt.Sprintf("Repository %.1f years old, 1 maintainer", repoAge),
			Verified:    true,
		}
	}

	if repoAge < 1.0 {
		return models.CategoryScore{
			Score:       0,
			RiskPoints:  1,
			Description: "Relatively new package",
			Evidence:    fmt.Sprintf("Repository %.1f years old", repoAge),
			Verified:    true,
		}
	}

	return models.CategoryScore{
		Score:       2,
		RiskPoints:  0,
		Description: "Established package with stable ownership",
		Evidence:    fmt.Sprintf("Repository %.1f years old", repoAge),
		Verified:    true,
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
		// Fetch release history
		releases, err := a.githubClient.GetReleaseHistory(result.RepositoryURL, 20)
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

		recentCommits, err1 := a.githubClient.GetCommitActivity(result.RepositoryURL, oneYearAgo)
		olderCommits, err2 := a.githubClient.GetCommitActivity(result.RepositoryURL, twoYearsAgo)

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

// scoreInstallExecution: postinstall scripts (0-2 pts)
func (a *Analyzer) scoreInstallExecution(result *models.AnalysisResult) models.CategoryScore {
	if len(result.Metadata.InstallScripts) == 0 {
		// No install scripts - lowest risk
		return models.CategoryScore{
			Score:       2,
			RiskPoints:  0,
			Description: "No install-time scripts",
			Evidence:    "No postinstall, preinstall, or install scripts detected",
			Verified:    true,
		}
	}

	// Check for dangerous install-time scripts
	dangerousScripts := []string{"postinstall", "preinstall", "install"}
	foundScripts := []string{}

	for _, scriptName := range dangerousScripts {
		if script, exists := result.Metadata.InstallScripts[scriptName]; exists && script != "" {
			foundScripts = append(foundScripts, scriptName)
		}
	}

	if len(foundScripts) == 0 {
		// Has scripts but none are install-time
		return models.CategoryScore{
			Score:       2,
			RiskPoints:  0,
			Description: "No install-time scripts",
			Evidence:    "Package has scripts but no install hooks",
			Verified:    true,
		}
	}

	if len(foundScripts) >= 2 {
		// Multiple install scripts = higher risk
		return models.CategoryScore{
			Score:       0,
			RiskPoints:  2,
			Description: "Multiple install-time scripts detected",
			Evidence:    "Scripts: " + strings.Join(foundScripts, ", "),
			Verified:    true,
		}
	}

	// Single install script = moderate risk
	return models.CategoryScore{
		Score:       0,
		RiskPoints:  1,
		Description: "Install-time script detected",
		Evidence:    "Script: " + strings.Join(foundScripts, ", "),
		Verified:    true,
	}
}

// scoreDependencySprawl: transitive dependencies (0-2 pts)
func (a *Analyzer) scoreDependencySprawl(result *models.AnalysisResult) models.CategoryScore {
	// For now, use heuristics based on ecosystem and package popularity
	// Future enhancement: actually count transitive dependencies

	// Popular packages tend to have more dependencies
	if result.Metadata.RepoStars > 1000 || result.Metadata.DownloadCount > 1000000 {
		return models.CategoryScore{
			Score:       2,
			RiskPoints:  0,
			Description: "Popular package (likely audited dependencies)",
			Evidence:    fmt.Sprintf("%d stars, %d downloads", result.Metadata.RepoStars, result.Metadata.DownloadCount),
			Verified:    true,
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
func (a *Analyzer) scoreProvenance(result *models.AnalysisResult) models.CategoryScore {
	// Check for signed releases and build reproducibility indicators
	if result.Metadata.SignedReleases {
		return models.CategoryScore{
			Score:       2,
			RiskPoints:  0,
			Description: "Releases are cryptographically signed",
			Evidence:    "Signed releases detected",
			Verified:    true,
		}
	}

	// Check OSSF Scorecard for signing/provenance checks
	if result.Metadata.OSSFChecks != nil {
		if signingScore, exists := result.Metadata.OSSFChecks["Signed-Releases"]; exists {
			if signingScore >= 8 {
				return models.CategoryScore{
					Score:       2,
					RiskPoints:  0,
					Description: "Good signing practices (OSSF)",
					Evidence:    fmt.Sprintf("OSSF Signed-Releases score: %d/10", signingScore),
					Verified:    true,
				}
			} else if signingScore >= 5 {
				return models.CategoryScore{
					Score:       0,
					RiskPoints:  1,
					Description: "Some signing practices (OSSF)",
					Evidence:    fmt.Sprintf("OSSF Signed-Releases score: %d/10", signingScore),
					Verified:    true,
				}
			}
		}
	}

	// No provenance information available
	return models.CategoryScore{
		Score:       0,
		RiskPoints:  2,
		Description: "No evidence of signed releases",
		Evidence:    "No signing or provenance information found",
		Verified:    true,
	}
}

// scoreHealth: bus factor/review process/CI (0-2 pts)
func (a *Analyzer) scoreHealth(result *models.AnalysisResult) models.CategoryScore {
	healthScore := 0
	evidence := []string{}

	// Check CI presence (worth 1 point)
	if result.Metadata.HasCI {
		healthScore++
		evidence = append(evidence, fmt.Sprintf("CI: %v", result.Metadata.CISystems))
	} else {
		evidence = append(evidence, "No CI detected")
	}

	// Check bus factor (worth 1 point)
	maintainerCount := len(result.Metadata.Maintainers)
	if maintainerCount >= 3 {
		healthScore++
		evidence = append(evidence, fmt.Sprintf("%d maintainers", maintainerCount))
	} else if maintainerCount > 0 {
		evidence = append(evidence, fmt.Sprintf("Only %d maintainer(s)", maintainerCount))
	}

	// Convert health score to risk points (invert: high health = low risk)
	riskPoints := 2 - healthScore
	if riskPoints < 0 {
		riskPoints = 0
	}

	description := "Poor health indicators"
	if healthScore >= 2 {
		description = "Good health indicators"
	} else if healthScore == 1 {
		description = "Moderate health indicators"
	}

	verified := maintainerCount > 0 || result.Metadata.HasCI

	return models.CategoryScore{
		Score:       healthScore,
		RiskPoints:  riskPoints,
		Description: description,
		Evidence:    strings.Join(evidence, ", "),
		Verified:    verified,
	}
}
