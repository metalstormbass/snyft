package analyzer

import (
	"fmt"
	"strings"

	"github.com/metalstormbass/snyft/pkg/models"
)

// registryURL returns the web URL for a package on its ecosystem's registry.
func registryURL(dep models.Dependency) string {
	switch dep.Ecosystem {
	case models.EcosystemNPM:
		return fmt.Sprintf("https://www.npmjs.com/package/%s", dep.Name)
	case models.EcosystemPyPI:
		return fmt.Sprintf("https://pypi.org/project/%s/", dep.Name)
	case models.EcosystemMaven:
		// Maven names use groupId:artifactId format
		parts := strings.SplitN(dep.Name, ":", 2)
		if len(parts) == 2 {
			return fmt.Sprintf("https://central.sonatype.com/artifact/%s/%s", parts[0], parts[1])
		}
		return fmt.Sprintf("https://central.sonatype.com/search?q=%s", dep.Name)
	default:
		return ""
	}
}

// repoSourceURL returns the repository URL suitable for display.
// It normalizes API URLs to web URLs.
func repoSourceURL(repoURL string) string {
	if repoURL == "" {
		return ""
	}
	// Strip .git suffix if present
	return strings.TrimSuffix(repoURL, ".git")
}

// ossfScorecardURL returns the OSSF Scorecard web URL for a repository.
func ossfScorecardURL(repoURL string) string {
	repoURL = strings.TrimSuffix(repoURL, ".git")
	// Extract github.com/owner/repo from the URL
	for _, prefix := range []string{"https://", "http://"} {
		repoURL = strings.TrimPrefix(repoURL, prefix)
	}
	// Only GitHub repos have OSSF Scorecard results
	if strings.HasPrefix(repoURL, "github.com/") {
		return fmt.Sprintf("https://scorecard.dev/viewer/?uri=%s", repoURL)
	}
	return ""
}

// categorySourceURL determines the best source URL for a category score based
// on what data sources it primarily uses. When multiple sources are involved,
// we pick the most informative one for the user.
func categorySourceURL(category string, result *models.AnalysisResult) string {
	dep := result.Dependency
	repoURL := repoSourceURL(result.RepositoryURL)

	switch category {
	case "Publisher Control":
		// Publisher control primarily checks registry maintainer data
		if url := registryURL(dep); url != "" {
			return url
		}
		return repoURL

	case "Ownership Changes":
		// Ownership changes checks commit history and registry history
		if repoURL != "" {
			return repoURL + "/commits"
		}
		return registryURL(dep)

	case "Release Anomalies":
		// Release anomalies checks release history
		if repoURL != "" {
			return repoURL + "/releases"
		}
		return registryURL(dep)

	case "Install Execution":
		// Install execution checks package scripts in registry
		return registryURL(dep)

	case "Dependency Sprawl":
		// Dependency sprawl checks registry dependency lists
		return registryURL(dep)

	case "Provenance":
		// Provenance checks registry attestations and repo releases
		if repoURL != "" {
			return repoURL + "/releases"
		}
		return registryURL(dep)

	case "Health":
		// Health checks contributors and branch protection
		if repoURL != "" {
			return repoURL
		}
		return registryURL(dep)

	case "Governance":
		// Governance checks SECURITY.md and issue responsiveness
		if repoURL != "" {
			return repoURL
		}
		return registryURL(dep)

	case "Release Security":
		// Release security checks CI workflows and branch protection
		if repoURL != "" {
			return repoURL + "/actions"
		}
		return registryURL(dep)

	case "Package Maturity":
		// Package maturity checks publish dates and release cadence
		return registryURL(dep)

	default:
		if repoURL != "" {
			return repoURL
		}
		return registryURL(dep)
	}
}
