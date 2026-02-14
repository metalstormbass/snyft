package fetcher

import (
	"strings"
)

// cleanRepositoryURL normalizes repository URLs from package registries
func cleanRepositoryURL(repoURL string) string {
	repoURL = strings.TrimSpace(repoURL)

	// Remove common prefixes
	repoURL = strings.TrimPrefix(repoURL, "git+")
	repoURL = strings.TrimPrefix(repoURL, "git://")
	repoURL = strings.TrimPrefix(repoURL, "ssh://git@")

	// Remove .git suffix
	repoURL = strings.TrimSuffix(repoURL, ".git")

	// Ensure https:// prefix for GitHub URLs
	if strings.Contains(repoURL, "github.com") && !strings.HasPrefix(repoURL, "http") {
		if strings.HasPrefix(repoURL, "git@github.com:") {
			// Convert git@github.com:owner/repo to https://github.com/owner/repo
			repoURL = strings.Replace(repoURL, "git@github.com:", "https://github.com/", 1)
		} else {
			repoURL = "https://" + repoURL
		}
	}

	return repoURL
}
