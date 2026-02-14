package analyzer

import (
	"fmt"
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

	return result
}

func (a *Analyzer) analyzeRepository(result *models.AnalysisResult, repoURL string) {
	repoInfo, err := a.githubClient.GetRepositoryInfo(repoURL)
	if err != nil {
		result.Findings = append(result.Findings, models.Finding{
			Severity:    "MEDIUM",
			Category:    "Repository Access",
			Description: fmt.Sprintf("Failed to fetch repository info: %v", err),
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
		})
		result.RiskFactors = append(result.RiskFactors, "Inactive development")
	}

	// Check for low activity indicators
	if repoInfo.Stars < 10 && repoInfo.Forks < 5 {
		result.Findings = append(result.Findings, models.Finding{
			Severity:    "MEDIUM",
			Category:    "Low Community Engagement",
			Description: "Package has minimal community engagement (low stars/forks)",
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
		result.BuildInfrastructure = fmt.Sprintf("CI detected: %v", ciSystems)
	} else {
		result.BuildInfrastructure = "No CI detected"
		result.Findings = append(result.Findings, models.Finding{
			Severity:    "MEDIUM",
			Category:    "No CI/CD",
			Description: "No continuous integration system detected",
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
		DownloadCount: pkg.Downloads,
		PublishedAt:   pkg.PublishedAt,
		LatestVersion: pkg.LatestVersion,
		Maintainers:   pkg.Maintainers,
		License:       pkg.License,
		Homepage:      pkg.Homepage,
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
