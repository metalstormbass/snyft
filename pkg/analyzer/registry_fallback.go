package analyzer

import (
	"github.com/metalstormbass/snyft/pkg/fetcher"
	"github.com/metalstormbass/snyft/pkg/models"
)

// getRegistryVersionHistory fetches version publish timestamps from the appropriate
// package registry based on the dependency's ecosystem. Returns up to `limit` versions
// sorted newest-first.
//
// This is used as a fallback when GitHub releases/tags are unavailable, allowing
// release anomaly detection and cadence analysis to still function using registry data.
//
// Justification: Many packages never create GitHub releases/tags but still have complete
// version history in their registry (npm, PyPI, Maven Central). Without this fallback,
// release-related checks would score UNAVAILABLE/SKIPPED for these packages, reducing
// the accuracy of supply chain risk assessment.
// Source: npm registry API (time field), PyPI JSON API (releases field),
//         Maven Central Solr search API (timestamp field)
func (a *Analyzer) getRegistryVersionHistory(dep models.Dependency, limit int) []fetcher.RegistryRelease {
	var releases []fetcher.RegistryRelease
	var err error

	switch dep.Ecosystem {
	case models.EcosystemNPM:
		releases, err = a.npmClient.GetVersionHistory(dep.Name)
	case models.EcosystemPyPI:
		releases, err = a.pypiClient.GetVersionHistory(dep.Name)
	case models.EcosystemMaven:
		releases, err = a.mavenClient.GetVersionHistory(dep.Name)
	default:
		return nil
	}

	if err != nil || len(releases) == 0 {
		return nil
	}

	// Apply limit
	if limit > 0 && len(releases) > limit {
		releases = releases[:limit]
	}

	return releases
}
