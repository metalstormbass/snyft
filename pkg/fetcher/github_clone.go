package fetcher

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// gitCloneData holds data extracted from a bare git clone.
// All fields are populated by CloneAndAnalyze and then cached in repoCache
// so that GetCommitAuthors, CheckSignedCommits, GetCommitActivity, fileExists,
// and GetFileContent can serve data without the clone directory on disk.
// The clone directory is deleted immediately after all data extraction completes.
type gitCloneData struct {
	// commitAuthors is the extracted CommitAuthorStats from git shortlog + git log.
	commitAuthors *CommitAuthorStats

	// signedCommits holds the result of checking commit signatures via git log %G?.
	signedCommits *cachedSignedCommits

	// commitActivity is the list of recent commits (matching GetCommitActivity format).
	commitActivity []GitHubCommit

	// mergeCommitRate is the percentage of merge commits (0-100). A high rate
	// (>50%) indicates code review via pull requests is likely happening.
	// -1 means the data was not extracted (distinct from 0% merge commits).
	mergeCommitRate float64

	// fileTree is the set of all file paths in HEAD (from git ls-tree -r HEAD --name-only).
	fileTree map[string]bool

	// fileContentsMu protects concurrent access to fileContents.
	fileContentsMu sync.RWMutex

	// fileContents caches file content pre-fetched via git show HEAD:<path> during
	// CloneAndAnalyze. Populated eagerly for well-known analysis files before the
	// clone directory is deleted. GetCloneFileContent serves from this cache only.
	fileContents map[string]string

	// ready indicates that clone data is available for use.
	ready bool
}

// cloneTimeout is the maximum time allowed for a bare clone to complete.
const cloneTimeout = 60 * time.Second

// filesToPreFetch lists well-known file paths that downstream analysis steps read
// via GetFileContent → GetCloneFileContent. These are pre-fetched from the bare
// clone before the clone directory is deleted, so they can be served from the
// in-memory cache without keeping the clone on disk.
var filesToPreFetch = []string{
	// Governance files (release_docs.go, governance.go)
	"SECURITY.md",
	".github/SECURITY.md",
	"CONTRIBUTING.md",
	"RELEASING.md",
	"RELEASE.md",
	".github/CONTRIBUTING.md",
	"docs/RELEASING.md",
	"docs/RELEASE.md",
	"docs/releasing.md",
	"docs/release.md",

	// CI workflow configs (metadata.go via CIConfigPaths)
	".github/workflows/release.yml",
	".github/workflows/publish.yml",
	".github/workflows/deploy.yml",
	".github/workflows/ci.yml",
	".github/workflows/build.yml",
	".github/workflows/main.yml",
	".github/workflows/release.yaml",
	".github/workflows/publish.yaml",
	".github/workflows/deploy.yaml",
	".circleci/config.yml",
	".gitlab-ci.yml",
	".travis.yml",
	"azure-pipelines.yml",
	"Jenkinsfile",
	".drone.yml",
	".drone.yaml",
	".buildkite/pipeline.yml",
	".buildkite/pipeline.yaml",

	// Package build files (analyzer.go)
	"setup.py",
	"pom.xml",
}

// CloneAndAnalyze performs a bare git clone, extracts all needed data (commit
// info, file tree, and file contents for well-known paths), caches it, and
// then deletes the clone directory immediately. This prevents clone directories
// from accumulating on disk during large scans.
//
// The clone runs with --bare --filter=blob:none --depth=500 to minimize bandwidth:
//   - --bare: no working tree (saves disk)
//   - --filter=blob:none: skip file content blobs (fetched on demand via git show)
//   - --depth=500: caps commit history to 500 commits (sufficient for analysis)
//
// This method is safe to call concurrently for different repos. For the same repo,
// it uses the cache to avoid duplicate clones.
func (c *GitHubClient) CloneAndAnalyze(repoURL string) error {
	owner, repo, err := parseGitHubURL(repoURL)
	if err != nil {
		return err
	}

	cacheKey := owner + "/" + repo

	// Check if already cloned
	if c.cache != nil {
		if _, ok := c.cache.getCloneData(cacheKey); ok {
			return nil
		}
	}

	// Build clone URL
	cloneURL := fmt.Sprintf("https://github.com/%s/%s.git", owner, repo)

	// Create temp directory
	tmpDir, err := os.MkdirTemp("", "snyft-clone-*")
	if err != nil {
		return fmt.Errorf("failed to create temp dir for clone: %w", err)
	}

	// Clone with timeout
	ctx, cancel := context.WithTimeout(context.Background(), cloneTimeout)
	defer cancel()

	cloneDir := filepath.Join(tmpDir, repo+".git")
	cmd := exec.CommandContext(ctx, "git", "clone",
		"--bare",
		"--filter=blob:none",
		"--depth=500",
		"--single-branch",
		cloneURL,
		cloneDir,
	)
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")

	if output, err := cmd.CombinedOutput(); err != nil {
		_ = os.RemoveAll(tmpDir)
		return fmt.Errorf("git clone failed: %w\n%s", err, string(output))
	}

	// Extract all data in parallel
	data := &gitCloneData{
		fileContents:    make(map[string]string),
		mergeCommitRate: -1, // -1 = not yet extracted
	}

	var extractWg sync.WaitGroup
	var extractMu sync.Mutex
	var extractErrors []error

	// 1. Extract commit authors (git shortlog + git log for timestamps)
	extractWg.Add(1)
	go func() {
		defer extractWg.Done()
		authors, err := extractCommitAuthors(ctx, cloneDir)
		if err != nil {
			extractMu.Lock()
			extractErrors = append(extractErrors, fmt.Errorf("commit authors: %w", err))
			extractMu.Unlock()
			return
		}
		data.commitAuthors = authors
	}()

	// 2. Extract signed commit info (git log --format='%H %G?')
	extractWg.Add(1)
	go func() {
		defer extractWg.Done()
		signed, err := extractSignedCommits(ctx, cloneDir)
		if err != nil {
			extractMu.Lock()
			extractErrors = append(extractErrors, fmt.Errorf("signed commits: %w", err))
			extractMu.Unlock()
			return
		}
		data.signedCommits = signed
	}()

	// 3. Extract recent commit activity (git log --since=1year)
	extractWg.Add(1)
	go func() {
		defer extractWg.Done()
		activity, err := extractCommitActivity(ctx, cloneDir)
		if err != nil {
			extractMu.Lock()
			extractErrors = append(extractErrors, fmt.Errorf("commit activity: %w", err))
			extractMu.Unlock()
			return
		}
		data.commitActivity = activity
	}()

	// 4. Extract file tree (git ls-tree -r HEAD --name-only)
	extractWg.Add(1)
	go func() {
		defer extractWg.Done()
		tree, err := extractFileTree(ctx, cloneDir)
		if err != nil {
			extractMu.Lock()
			extractErrors = append(extractErrors, fmt.Errorf("file tree: %w", err))
			extractMu.Unlock()
			return
		}
		data.fileTree = tree
	}()

	// 5. Extract merge commit rate (git rev-list --count --merges / total)
	extractWg.Add(1)
	go func() {
		defer extractWg.Done()
		rate, err := extractMergeCommitRate(ctx, cloneDir)
		if err != nil {
			extractMu.Lock()
			extractErrors = append(extractErrors, fmt.Errorf("merge commit rate: %w", err))
			extractMu.Unlock()
			return
		}
		data.mergeCommitRate = rate
	}()

	extractWg.Wait()

	// 5. Pre-fetch file contents for well-known analysis paths before deleting
	// the clone directory. Only fetch files that exist in the file tree.
	if data.fileTree != nil {
		prefetchFileContents(ctx, cloneDir, data)
	}

	// Delete the clone directory immediately — all needed data is now in memory.
	_ = os.RemoveAll(tmpDir)

	// Mark as ready even if some extractions failed — partial data is useful
	data.ready = true

	// Cache the clone data
	if c.cache != nil {
		c.cache.setCloneData(cacheKey, data)

		// Also populate the individual caches so methods that check them
		// before checking cloneData still benefit
		if data.commitAuthors != nil {
			c.cache.setCommitAuthors(cacheKey, data.commitAuthors)
		}
		if data.signedCommits != nil {
			c.cache.setSignedCommits(cacheKey, data.signedCommits)
		}
	}

	return nil
}

// prefetchFileContents fetches content for well-known analysis files from the
// bare clone via git show and stores them in the fileContents cache. Errors for
// individual files are silently ignored (they may not exist in every repo).
func prefetchFileContents(ctx context.Context, cloneDir string, data *gitCloneData) {
	for _, path := range filesToPreFetch {
		if !data.fileTree[path] {
			continue
		}
		cmd := exec.CommandContext(ctx, "git", "-C", cloneDir, "show", "HEAD:"+path)
		output, err := cmd.Output()
		if err != nil {
			continue
		}
		data.fileContents[path] = string(output)
	}
}

// CleanupClone is a no-op retained for backward compatibility.
// Clone directories are now deleted immediately after data extraction in
// CloneAndAnalyze, so there is nothing to clean up here.
func (c *GitHubClient) CleanupClone(_ string) {}

// GetCloneFileContent returns a file's content from the pre-fetched cache.
// Files are eagerly fetched during CloneAndAnalyze before the clone directory
// is deleted. Returns ("", error) if the file was not pre-fetched or clone
// data is not available. Callers should fall back to API/raw-URL fetching.
func (c *GitHubClient) GetCloneFileContent(owner, repo, path string) (string, error) {
	cacheKey := owner + "/" + repo
	if c.cache == nil {
		return "", fmt.Errorf("no cache")
	}

	data, ok := c.cache.getCloneData(cacheKey)
	if !ok || !data.ready {
		return "", fmt.Errorf("clone data not available")
	}

	data.fileContentsMu.RLock()
	content, exists := data.fileContents[path]
	data.fileContentsMu.RUnlock()

	if !exists {
		return "", fmt.Errorf("file not in clone cache: %s", path)
	}
	return content, nil
}

// HasCloneData returns true if clone data is available for the given repo.
func (c *GitHubClient) HasCloneData(repoURL string) bool {
	owner, repo, err := parseGitHubURL(repoURL)
	if err != nil {
		return false
	}
	if c.cache == nil {
		return false
	}
	data, ok := c.cache.getCloneData(owner + "/" + repo)
	return ok && data.ready
}


// extractCommitAuthors runs git log to extract commit author stats.
// This provides richer data than git shortlog because we get timestamps.
func extractCommitAuthors(ctx context.Context, cloneDir string) (*CommitAuthorStats, error) {
	// Use git log with a format that gives us author email, name, and date
	cmd := exec.CommandContext(ctx, "git", "-C", cloneDir, "log",
		"--format=%aE|%aN|%aI",
		"--no-merges",
	)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git log failed: %w", err)
	}

	stats := &CommitAuthorStats{
		AuthorCommitCounts: make(map[string]int),
		AuthorFirstCommit:  make(map[string]time.Time),
		AuthorLastCommit:   make(map[string]time.Time),
		RecentAuthors:      []string{},
		HistoricalAuthors:  []string{},
	}

	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		parts := strings.SplitN(line, "|", 3)
		if len(parts) < 3 {
			continue
		}

		email := strings.TrimSpace(parts[0])
		name := strings.TrimSpace(parts[1])
		dateStr := strings.TrimSpace(parts[2])

		// Use email as primary identifier, fall back to name
		authorID := email
		if authorID == "" {
			authorID = name
		}
		if authorID == "" {
			continue
		}

		commitDate, err := time.Parse(time.RFC3339, dateStr)
		if err != nil {
			// Try other formats
			commitDate, err = time.Parse("2006-01-02T15:04:05-07:00", dateStr)
			if err != nil {
				continue
			}
		}

		stats.TotalCommits++
		stats.AuthorCommitCounts[authorID]++

		if first, exists := stats.AuthorFirstCommit[authorID]; !exists || commitDate.Before(first) {
			stats.AuthorFirstCommit[authorID] = commitDate
		}
		if last, exists := stats.AuthorLastCommit[authorID]; !exists || commitDate.After(last) {
			stats.AuthorLastCommit[authorID] = commitDate
		}
	}

	// Build unique authors list and categorize recent vs historical
	seen := make(map[string]bool)
	ninetyDaysAgo := time.Now().AddDate(0, 0, -90)

	for authorID, lastCommit := range stats.AuthorLastCommit {
		if !seen[authorID] {
			stats.UniqueAuthors = append(stats.UniqueAuthors, authorID)
			seen[authorID] = true

			if lastCommit.After(ninetyDaysAgo) {
				stats.RecentAuthors = append(stats.RecentAuthors, authorID)
			} else {
				stats.HistoricalAuthors = append(stats.HistoricalAuthors, authorID)
			}
		}
	}

	return stats, nil
}

// extractSignedCommits runs git log --format='%H %G?' to check commit signatures.
// %G? outputs: G (good sig), B (bad sig), U (untrusted), X (expired), Y (expired key),
// R (revoked), E (cannot check), N (no sig).
func extractSignedCommits(ctx context.Context, cloneDir string) (*cachedSignedCommits, error) {
	cmd := exec.CommandContext(ctx, "git", "-C", cloneDir, "log",
		"--format=%H %G?",
		"-100", // match the 100 commit limit used by CheckSignedCommits API path
	)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git log for signatures failed: %w", err)
	}

	totalCommits := 0
	verifiedCount := 0

	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		totalCommits++
		// The last character is the signature status
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			status := parts[len(parts)-1]
			if status == "G" || status == "U" {
				// G = good signature, U = untrusted but valid signature
				// Both indicate the commit was signed
				verifiedCount++
			}
		}
	}

	hasSigning := false
	if totalCommits > 0 {
		hasSigning = float64(verifiedCount)/float64(totalCommits) > 0.5
	}

	return &cachedSignedCommits{
		hasSigning:    hasSigning,
		verifiedCount: verifiedCount,
	}, nil
}

// extractCommitActivity runs git log --since=1year to get recent commit data.
// Returns commits in the GitHubCommit format expected by GetCommitActivity callers.
func extractCommitActivity(ctx context.Context, cloneDir string) ([]GitHubCommit, error) {
	since := time.Now().AddDate(-1, 0, 0) // 1 year ago
	cmd := exec.CommandContext(ctx, "git", "-C", cloneDir, "log",
		"--format=%H|%aN|%aE|%aI|%s",
		"--since="+since.Format(time.RFC3339),
		"--no-merges",
	)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git log for activity failed: %w", err)
	}

	var commits []GitHubCommit
	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		parts := strings.SplitN(line, "|", 5)
		if len(parts) < 5 {
			continue
		}

		sha := parts[0]
		name := parts[1]
		email := parts[2]
		dateStr := parts[3]
		message := parts[4]

		commitDate, _ := time.Parse(time.RFC3339, dateStr)

		commits = append(commits, GitHubCommit{
			SHA: sha,
			Commit: GitHubCommitInfo{
				Author: GitHubCommitAuthor{
					Name:  name,
					Email: email,
					Date:  commitDate,
				},
				Message: message,
			},
		})
	}

	return commits, nil
}

// extractFileTree runs git ls-tree -r HEAD --name-only to get the full file listing.
func extractFileTree(ctx context.Context, cloneDir string) (map[string]bool, error) {
	cmd := exec.CommandContext(ctx, "git", "-C", cloneDir, "ls-tree",
		"-r", "HEAD", "--name-only",
	)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git ls-tree failed: %w", err)
	}

	tree := make(map[string]bool)
	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		path := strings.TrimSpace(scanner.Text())
		if path != "" {
			tree[path] = true
		}
	}

	return tree, nil
}


// extractMergeCommitRate counts merge commits vs total commits to estimate
// code review rate. Repositories using PR-based workflows have a high percentage
// of merge commits, indicating code review is happening.
//
// Justification: Pull request workflows produce merge commits when PRs are merged.
// A merge commit rate >50% strongly indicates a PR-based workflow with code review.
// Source: "Small World with High Risks" (Zimmermann et al., 2019) — projects with
// PR-based review have significantly lower compromise risk.
func extractMergeCommitRate(ctx context.Context, cloneDir string) (float64, error) {
	// Count total commits
	totalCmd := exec.CommandContext(ctx, "git", "-C", cloneDir, "rev-list", "--count", "HEAD")
	totalOutput, err := totalCmd.Output()
	if err != nil {
		return -1, fmt.Errorf("git rev-list --count failed: %w", err)
	}
	totalStr := strings.TrimSpace(string(totalOutput))
	var totalCommits int
	if _, err := fmt.Sscanf(totalStr, "%d", &totalCommits); err != nil || totalCommits == 0 {
		return 0, nil
	}

	// Count merge commits
	mergeCmd := exec.CommandContext(ctx, "git", "-C", cloneDir, "rev-list", "--count", "--merges", "HEAD")
	mergeOutput, err := mergeCmd.Output()
	if err != nil {
		return -1, fmt.Errorf("git rev-list --count --merges failed: %w", err)
	}
	mergeStr := strings.TrimSpace(string(mergeOutput))
	var mergeCommits int
	if _, err := fmt.Sscanf(mergeStr, "%d", &mergeCommits); err != nil {
		return 0, nil
	}

	return float64(mergeCommits) / float64(totalCommits) * 100, nil
}

// getMergeCommitRateFromClone returns the merge commit rate from clone data.
func (c *GitHubClient) getMergeCommitRateFromClone(owner, repo string) (float64, bool) {
	cacheKey := owner + "/" + repo
	if c.cache == nil {
		return -1, false
	}
	data, ok := c.cache.getCloneData(cacheKey)
	if !ok || !data.ready || data.mergeCommitRate < 0 {
		return -1, false
	}
	return data.mergeCommitRate, true
}

// repoCache methods for clone data

func (rc *repoCache) getCloneData(key string) (*gitCloneData, bool) {
	rc.mu.RLock()
	defer rc.mu.RUnlock()
	v, ok := rc.cloneData[key]
	return v, ok
}

func (rc *repoCache) setCloneData(key string, data *gitCloneData) {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	rc.cloneData[key] = data
}

// fileExistsInClone checks if a file exists in the clone's file tree.
func (c *GitHubClient) fileExistsInClone(owner, repo, path string) (bool, bool) {
	cacheKey := owner + "/" + repo
	if c.cache == nil {
		return false, false
	}
	data, ok := c.cache.getCloneData(cacheKey)
	if !ok || !data.ready || data.fileTree == nil {
		return false, false
	}
	return data.fileTree[path], true
}

// getCommitActivityFromClone returns cached commit activity from clone data.
func (c *GitHubClient) getCommitActivityFromClone(owner, repo string, since time.Time) ([]GitHubCommit, bool) {
	cacheKey := owner + "/" + repo
	if c.cache == nil {
		return nil, false
	}
	data, ok := c.cache.getCloneData(cacheKey)
	if !ok || !data.ready || data.commitActivity == nil {
		return nil, false
	}

	// Filter to requested time range
	var filtered []GitHubCommit
	for _, commit := range data.commitActivity {
		if commit.Commit.Author.Date.After(since) || commit.Commit.Author.Date.Equal(since) {
			filtered = append(filtered, commit)
		}
	}
	return filtered, true
}

// getFileTreeFromClone returns the file tree from clone data for use by detectCIViaTree.
func (c *GitHubClient) getFileTreeFromClone(owner, repo string) (map[string]bool, bool) {
	cacheKey := owner + "/" + repo
	if c.cache == nil {
		return nil, false
	}
	data, ok := c.cache.getCloneData(cacheKey)
	if !ok || !data.ready || data.fileTree == nil {
		return nil, false
	}
	return data.fileTree, true
}

// getSignedCommitsFromClone returns signed commit data from the bare clone.
func (c *GitHubClient) getSignedCommitsFromClone(owner, repo string) (bool, int, bool) {
	cacheKey := owner + "/" + repo
	if c.cache == nil {
		return false, 0, false
	}
	data, ok := c.cache.getCloneData(cacheKey)
	if !ok || !data.ready || data.signedCommits == nil {
		return false, 0, false
	}
	return data.signedCommits.hasSigning, data.signedCommits.verifiedCount, true
}

// getCommitAuthorsFromClone returns commit author stats from the bare clone.
func (c *GitHubClient) getCommitAuthorsFromClone(owner, repo string) (*CommitAuthorStats, bool) {
	cacheKey := owner + "/" + repo
	if c.cache == nil {
		return nil, false
	}
	data, ok := c.cache.getCloneData(cacheKey)
	if !ok || !data.ready || data.commitAuthors == nil {
		return nil, false
	}
	return data.commitAuthors, true
}

// getCommitStatsFromClone derives CommitStats from clone commit author data.
func (c *GitHubClient) getCommitStatsFromClone(owner, repo string) (*CommitStats, bool) {
	cacheKey := owner + "/" + repo
	if c.cache == nil {
		return nil, false
	}
	data, ok := c.cache.getCloneData(cacheKey)
	if !ok || !data.ready || data.commitAuthors == nil {
		return nil, false
	}

	authors := data.commitAuthors
	totalCommits := authors.TotalCommits
	if totalCommits == 0 {
		return nil, false
	}

	busFactor := calculateBusFactor(authors.AuthorCommitCounts, totalCommits)

	topContributorPct := 0.0
	maxCommits := 0
	for _, count := range authors.AuthorCommitCounts {
		if count > maxCommits {
			maxCommits = count
		}
	}
	topContributorPct = float64(maxCommits) / float64(totalCommits) * 100

	return &CommitStats{
		TotalCommits:      totalCommits,
		AuthorCommits:     authors.AuthorCommitCounts,
		BusFactor:         busFactor,
		TopContributorPct: topContributorPct,
	}, true
}

