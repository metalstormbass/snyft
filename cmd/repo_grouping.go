package cmd

import (
	"fmt"
	"io"
	"sort"
	"sync"

	"github.com/metalstormbass/snyft/pkg/analyzer"
	"github.com/metalstormbass/snyft/pkg/fetcher"
	"github.com/metalstormbass/snyft/pkg/models"
)

// repoGroup holds a normalized repo URL and the indices of dependencies that
// belong to that repository. This enables repo-level deduplication: instead of
// analyzing the same repository N times for N artifacts, we analyze it once.
//
// Justification: Large dependency lists (e.g. 7,749 Maven artifacts) often map
// to far fewer unique repositories (~400). Repo-level checks (governance, CI,
// health, clone) are identical for all artifacts from the same repo.
//
// Source: "Small World with High Risks" (Zimmermann et al., 2019) — dependency
// networks exhibit high repo-level duplication, especially in Maven ecosystems
// where a single project like AWS SDK publishes 100+ artifacts.
type repoGroup struct {
	NormalizedURL string
	DepIndices    []int
}

// resolveRepoURLs performs parallel registry lookups to resolve source repository
// URLs for all dependencies. This is Phase 1 of repo-level grouping: fast
// registry-only calls (npm, PyPI, Maven Central) with no GitHub API usage.
//
// The resolved URLs are stored in each dependency's ResolvedRepoURL field for
// use during grouping (Phase 2) and analysis (Phase 3).
func resolveRepoURLs(deps []models.Dependency, a *analyzer.Analyzer, numWorkers int, statusOut io.Writer) {
	if len(deps) == 0 {
		return
	}

	var wg sync.WaitGroup
	jobs := make(chan int, len(deps))

	// Start workers
	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range jobs {
				repoURL := a.ResolveRepoURL(deps[idx])
				deps[idx].ResolvedRepoURL = repoURL
			}
		}()
	}

	// Queue all jobs
	for i := range deps {
		jobs <- i
	}
	close(jobs)

	wg.Wait()
}

// groupByRepo groups dependencies by their normalized source repository URL.
// Returns a slice of repoGroups (sorted by group size descending for stats)
// and a map from normalized URL to group index. Dependencies without a resolved
// repo URL are placed in a special "" group.
func groupByRepo(deps []models.Dependency) ([]repoGroup, map[string]int) {
	groupMap := make(map[string]int) // normalized URL -> index in groups
	var groups []repoGroup

	for i, dep := range deps {
		key := fetcher.NormalizeRepoURL(dep.ResolvedRepoURL)

		if idx, ok := groupMap[key]; ok {
			groups[idx].DepIndices = append(groups[idx].DepIndices, i)
		} else {
			groupMap[key] = len(groups)
			groups = append(groups, repoGroup{
				NormalizedURL: key,
				DepIndices:    []int{i},
			})
		}
	}

	return groups, groupMap
}

// sortDepsByRepoGroup reorders dependencies so that packages from the same
// repository are adjacent. This maximizes repo analysis cache hits in the
// worker pool: when workers process adjacent same-repo packages, the first
// one triggers the full repo analysis and subsequent ones get cache hits
// instead of all racing to analyze the same repo concurrently.
func sortDepsByRepoGroup(deps []models.Dependency) {
	sort.SliceStable(deps, func(i, j int) bool {
		keyI := fetcher.NormalizeRepoURL(deps[i].ResolvedRepoURL)
		keyJ := fetcher.NormalizeRepoURL(deps[j].ResolvedRepoURL)
		return keyI < keyJ
	})
}

// printRepoGroupStats prints a summary of repo-level deduplication showing how
// many unique repositories the dependency list maps to.
func printRepoGroupStats(groups []repoGroup, totalDeps int, statusOut io.Writer) {
	if len(groups) == 0 {
		return
	}

	// Count deps with resolved repo URLs
	resolvedCount := 0
	unresolvedCount := 0
	for _, g := range groups {
		if g.NormalizedURL == "" {
			unresolvedCount = len(g.DepIndices)
		} else {
			resolvedCount += len(g.DepIndices)
		}
	}

	repoCount := len(groups)
	if unresolvedCount > 0 {
		repoCount-- // don't count the "" group as a repo
	}

	if repoCount > 0 && resolvedCount > repoCount {
		_, _ = fmt.Fprintf(statusOut, "🔗 Repo grouping: %d packages → %d unique repos", resolvedCount, repoCount)
		if unresolvedCount > 0 {
			_, _ = fmt.Fprintf(statusOut, " (%d without repo URL)", unresolvedCount)
		}

		// Show the top 3 largest groups for context
		type groupSize struct {
			url  string
			size int
		}
		var sorted []groupSize
		for _, g := range groups {
			if g.NormalizedURL != "" && len(g.DepIndices) > 1 {
				sorted = append(sorted, groupSize{g.NormalizedURL, len(g.DepIndices)})
			}
		}
		sort.Slice(sorted, func(i, j int) bool {
			return sorted[i].size > sorted[j].size
		})
		if len(sorted) > 0 {
			_, _ = fmt.Fprintf(statusOut, "\n   Top groups:")
			limit := 3
			if len(sorted) < limit {
				limit = len(sorted)
			}
			for i := 0; i < limit; i++ {
				_, _ = fmt.Fprintf(statusOut, " %s (%d pkgs)", sorted[i].url, sorted[i].size)
				if i < limit-1 {
					_, _ = fmt.Fprint(statusOut, ",")
				}
			}
		}
		_, _ = fmt.Fprintln(statusOut)
	}
}
