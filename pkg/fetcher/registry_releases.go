package fetcher

import (
	"time"
)

// RegistryRelease represents a version release from any source (git platform or package registry).
// This is the common type used by release analysis functions, abstracting over the differences
// between GitHub releases, npm versions, PyPI releases, and Maven versions.
//
// Justification: When a package has no GitHub releases/tags, release analysis can fall back
// to registry data (npm time field, PyPI releases, Maven metadata) to assess release patterns.
// Source: "Backstabber's Knife Collection" (Ohm et al., 2020) — dormancy reactivation detection
//         requires temporal release data regardless of whether it comes from git or the registry.
type RegistryRelease struct {
	Version      string
	PublishedAt  time.Time
	IsPrerelease bool
}

// GitHubReleasesToRegistryReleases converts GitHub releases to the common RegistryRelease type.
func GitHubReleasesToRegistryReleases(ghReleases []GitHubRelease) []RegistryRelease {
	releases := make([]RegistryRelease, 0, len(ghReleases))
	for _, r := range ghReleases {
		releases = append(releases, RegistryRelease{
			Version:      r.TagName,
			PublishedAt:  r.PublishedAt,
			IsPrerelease: r.Prerelease || r.Draft,
		})
	}
	return releases
}
