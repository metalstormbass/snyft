package fetcher

import (
	"strings"
)

// normalizeNPMRepoURL handles the many forms the npm registry `repository` field
// can take and returns a canonical https:// URL without a trailing .git suffix.
//
// Handled forms:
//   - "git+https://github.com/user/repo.git" → "https://github.com/user/repo"
//   - "git://github.com/user/repo.git"       → "https://github.com/user/repo"
//   - "github:user/repo"                     → "https://github.com/user/repo"
//   - "gitlab:user/repo"                     → "https://gitlab.com/user/repo"
//   - "bitbucket:user/repo"                  → "https://bitbucket.org/user/repo"
//   - "user/repo"  (npm shorthand)           → "https://github.com/user/repo"
//   - "https://github.com/user/repo.git"     → "https://github.com/user/repo"
func normalizeNPMRepoURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}

	// Strip git+ wrapper (e.g. "git+https://...")
	raw = strings.TrimPrefix(raw, "git+")

	// Handle platform shorthand prefixes: "github:", "gitlab:", "bitbucket:"
	if strings.HasPrefix(raw, "github:") {
		path := raw[len("github:"):]
		path = strings.TrimSuffix(path, ".git")
		return "https://github.com/" + path
	}
	if strings.HasPrefix(raw, "gitlab:") {
		path := raw[len("gitlab:"):]
		path = strings.TrimSuffix(path, ".git")
		return "https://gitlab.com/" + path
	}
	if strings.HasPrefix(raw, "bitbucket:") {
		path := raw[len("bitbucket:"):]
		path = strings.TrimSuffix(path, ".git")
		return "https://bitbucket.org/" + path
	}

	// Handle git:// protocol — convert to https://
	if strings.HasPrefix(raw, "git://") {
		raw = "https://" + raw[6:]
	}

	// At this point the URL should start with https:// or http:// — strip .git and return
	if strings.HasPrefix(raw, "https://") || strings.HasPrefix(raw, "http://") {
		raw = strings.TrimSuffix(raw, ".git")
		return raw
	}

	// npm shorthand: "user/repo" (no protocol, no platform prefix, single slash)
	// Distinguish from a full host path like "github.com/user/repo" which has a dot in the first segment.
	slashIdx := strings.Index(raw, "/")
	if slashIdx > 0 {
		firstSegment := raw[:slashIdx]
		// If the first segment contains no dot it is a GitHub username, not a hostname
		if !strings.Contains(firstSegment, ".") {
			path := strings.TrimSuffix(raw, ".git")
			return "https://github.com/" + path
		}
		// Looks like a bare host path (e.g. "github.com/user/repo") — add https://
		raw = strings.TrimSuffix(raw, ".git")
		return "https://" + raw
	}

	// Fallback: return as-is
	return raw
}

// isSourceRepoHost returns true if the URL contains a known source code hosting domain.
// Used by PyPI URL extraction to filter "Homepage" and fallback fields.
func isSourceRepoHost(url string) bool {
	lower := strings.ToLower(url)
	for _, host := range []string{
		"github.com",
		"gitlab.com",
		"bitbucket.org",
		"codeberg.org",
		"sr.ht",
		"sourceforge.net",
	} {
		if strings.Contains(lower, host) {
			return true
		}
	}
	return false
}
