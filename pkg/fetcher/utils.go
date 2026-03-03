package fetcher

import (
	"fmt"
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

// ParseRepoURL extracts the owner and repository name from a repository URL.
// It handles all common protocol variants:
//   - https://github.com/owner/repo
//   - http://github.com/owner/repo
//   - git://github.com/owner/repo.git
//   - git+https://github.com/owner/repo.git
//   - ssh://git@github.com/owner/repo.git
//   - git@github.com:owner/repo.git
//
// The .git suffix is stripped from the repository name if present.
// Returns an error if the URL does not contain enough path segments to extract
// both an owner and a repository name.
func ParseRepoURL(rawURL string) (owner, repo string, err error) {
	u := rawURL

	// Strip protocol prefixes (order matters: longer prefixes first)
	for _, prefix := range []string{"git+https://", "git+http://", "https://", "http://", "git://", "ssh://"} {
		if strings.HasPrefix(u, prefix) {
			u = u[len(prefix):]
			break
		}
	}

	// Strip git@ prefix and convert colon to slash (git@host:owner/repo → host/owner/repo)
	if strings.HasPrefix(u, "git@") {
		u = u[len("git@"):]
		// Replace the first colon with a slash (git@host:owner/repo)
		if colonIdx := strings.Index(u, ":"); colonIdx >= 0 {
			u = u[:colonIdx] + "/" + u[colonIdx+1:]
		}
	}

	// u is now "host/owner/repo/..." — split into segments
	parts := strings.SplitN(u, "/", 4)
	if len(parts) < 3 {
		return "", "", fmt.Errorf("malformed repository URL %q: expected host/owner/repo", rawURL)
	}

	owner = parts[1]
	repo = strings.SplitN(parts[2], "/", 2)[0]
	repo = strings.TrimSuffix(repo, ".git")

	if owner == "" || repo == "" {
		return "", "", fmt.Errorf("malformed repository URL %q: empty owner or repo", rawURL)
	}

	return owner, repo, nil
}

// NormalizeRepoURL converts a repository URL into a canonical form suitable for
// use as a cache key. It strips protocol prefixes, .git suffixes, and normalizes
// to lowercase "host/owner/repo". This allows grouping packages that point to the
// same repository even if their URLs differ in protocol or suffix.
func NormalizeRepoURL(repoURL string) string {
	if repoURL == "" {
		return ""
	}

	owner, repo, err := ParseRepoURL(repoURL)
	if err != nil {
		// Fallback: lowercase and strip .git
		return strings.ToLower(strings.TrimSuffix(repoURL, ".git"))
	}

	// Determine host from the URL
	lower := strings.ToLower(repoURL)
	host := "github.com" // default
	for _, h := range []string{
		"gitlab.com",
		"bitbucket.org",
		"codeberg.org",
		"sr.ht",
		"sourceforge.net",
		"gitbox.apache.org",
		"git.eclipse.org",
	} {
		if strings.Contains(lower, h) {
			host = h
			break
		}
	}

	return host + "/" + strings.ToLower(owner) + "/" + strings.ToLower(repo)
}

// isSourceRepoHost returns true if the URL contains a known source code hosting domain.
// Used by PyPI URL extraction and Maven POM fallback to filter non-repo URLs.
func isSourceRepoHost(url string) bool {
	lower := strings.ToLower(url)
	for _, host := range []string{
		"github.com",
		"gitlab.com",
		"bitbucket.org",
		"codeberg.org",
		"sr.ht",
		"sourceforge.net",
		"gitbox.apache.org",
		"git.eclipse.org",
		"heptapod.net",
	} {
		if strings.Contains(lower, host) {
			return true
		}
	}
	return false
}
