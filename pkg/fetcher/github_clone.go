package fetcher

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// gitCloneData holds data extracted from a bare git clone.
// All fields are populated by cloneAndAnalyze and then cached in repoCache
// so that GetCommitAuthors, CheckSignedCommits, GetCommitActivity, fileExists,
// and GetFileContent can serve data from the local clone instead of making
// API calls or scraping.
type gitCloneData struct {
	// commitAuthors is the extracted CommitAuthorStats from git shortlog + git log.
	commitAuthors *CommitAuthorStats

	// signedCommits holds the result of checking commit signatures via git log %G?.
	signedCommits *cachedSignedCommits

	// commitActivity is the list of recent commits (matching GetCommitActivity format).
	commitActivity []GitHubCommit

	// fileTree is the set of all file paths in HEAD (from git ls-tree -r HEAD --name-only).
	fileTree map[string]bool

	// fileContents caches file content fetched via git show HEAD:<path>.
	// Only populated on demand via getCloneFileContent.
	fileContents map[string]string

	// cloneDir is the temp directory holding the bare clone (for on-demand file reads).
	// Empty after cleanup.
	cloneDir string

	// diskSizeMB is the size of the clone directory in megabytes.
	diskSizeMB float64

	// ready indicates that clone data is available for use.
	ready bool
}

// cloneTimeout is the maximum time allowed for a bare clone to complete.
const cloneTimeout = 60 * time.Second

// cloneSizeWarnMB is the threshold at which we flag a clone as large.
const cloneSizeWarnMB = 50.0

// CloneAndAnalyze performs a bare git clone and extracts commit data, file tree,
// and signature information. Results are cached in repoCache so downstream methods
// (GetCommitAuthors, CheckSignedCommits, etc.) can use local data instead of API calls.
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
		fileContents: make(map[string]string),
		cloneDir:     cloneDir,
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

	extractWg.Wait()

	// Calculate disk size
	data.diskSizeMB = dirSizeMB(cloneDir)

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

// CleanupClone removes the temp directory for a cloned repo.
// Should be called after analysis is complete for the repo.
func (c *GitHubClient) CleanupClone(repoURL string) {
	owner, repo, err := parseGitHubURL(repoURL)
	if err != nil {
		return
	}
	cacheKey := owner + "/" + repo
	if c.cache == nil {
		return
	}
	if data, ok := c.cache.getCloneData(cacheKey); ok && data.cloneDir != "" {
		// Remove the parent temp dir (snyft-clone-*)
		parentDir := filepath.Dir(data.cloneDir)
		_ = os.RemoveAll(parentDir)
		data.cloneDir = ""
	}
}

// GetCloneFileContent fetches a file's content from the bare clone via git show.
// Returns ("", error) if the file doesn't exist or clone data is not available.
func (c *GitHubClient) GetCloneFileContent(owner, repo, path string) (string, error) {
	cacheKey := owner + "/" + repo
	if c.cache == nil {
		return "", fmt.Errorf("no cache")
	}

	data, ok := c.cache.getCloneData(cacheKey)
	if !ok || !data.ready || data.cloneDir == "" {
		return "", fmt.Errorf("clone data not available")
	}

	// Check if already fetched
	if content, exists := data.fileContents[path]; exists {
		return content, nil
	}

	// Fetch via git show
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "git", "-C", data.cloneDir, "show", "HEAD:"+path)
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("file not found in clone: %s", path)
	}

	content := string(output)
	data.fileContents[path] = content
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

// CloneDiskSizeMB returns the size of the clone directory in MB, or 0 if no clone data.
func (c *GitHubClient) CloneDiskSizeMB(repoURL string) float64 {
	owner, repo, err := parseGitHubURL(repoURL)
	if err != nil {
		return 0
	}
	if c.cache == nil {
		return 0
	}
	data, ok := c.cache.getCloneData(owner + "/" + repo)
	if !ok {
		return 0
	}
	return data.diskSizeMB
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

// dirSizeMB calculates the total size of a directory in megabytes.
func dirSizeMB(path string) float64 {
	var size int64
	_ = filepath.Walk(path, func(_ string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if !info.IsDir() {
			size += info.Size()
		}
		return nil
	})
	return float64(size) / (1024 * 1024)
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

// gitAvailable checks if git is available on the system.
func gitAvailable() bool {
	_, err := exec.LookPath("git")
	return err == nil
}

// parseShortlogCount parses a line from git shortlog -sn output: "  42\tAuthor Name"
func parseShortlogCount(line string) (count int, name string, ok bool) {
	line = strings.TrimSpace(line)
	parts := strings.SplitN(line, "\t", 2)
	if len(parts) != 2 {
		return 0, "", false
	}
	n, err := strconv.Atoi(strings.TrimSpace(parts[0]))
	if err != nil {
		return 0, "", false
	}
	return n, strings.TrimSpace(parts[1]), true
}
