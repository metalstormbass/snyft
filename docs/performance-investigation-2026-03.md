# Performance Investigation: PRs #239-261 Regression Analysis

**Date:** 2026-03-03
**Scope:** Research-only investigation of performance regressions introduced by recent PRs

## Executive Summary

The recent performance PRs (#257-261) added caching, GraphQL batching, scraping-first, cross-package deduplication, and tag pagination changes. While these are net improvements for API quota efficiency, several introduce **latency regressions** or **missed optimization opportunities** that explain why scans feel slower than before.

The **top 3 bottlenecks** are:
1. **Scraping-first is slower than API** — HTML fetch + DOM parse is slower than JSON API for every method that switched
2. **Sequential per-issue API calls in `GetAverageIssueResponseTime`** — up to 11 sequential API calls per repo (1 list + 10 comments)
3. **Triple-scraping in `CheckGitTag`** — the same tag data can be scraped up to 3 times before falling through

---

## Finding 1: Scraping-First is Slower Than API (PR #260)

**Severity: HIGH — affects every scan without GITHUB_TOKEN**

**Files:** `pkg/fetcher/github.go` lines 379-386, 1401-1408, 1980-1987, 2376-2384

**Problem:** PR #260 changed the primary data path to scraping when no token is set. While this preserves the 60 req/hr unauthenticated API quota, **scraping is inherently slower** than API calls:

- **API path:** HTTP GET → JSON parse (fast, structured)
- **Scraping path:** HTTP GET → full HTML download (often 100KB+) → goquery DOM parse → CSS selector traversal → regex extraction

**Affected methods and their scraping overhead:**

| Method | File:Line | Scraping Function | What It Parses |
|--------|-----------|-------------------|----------------|
| `GetRepositoryInfo()` | github.go:379 | `scrapeRepositoryInfo()` | Full repo page DOM |
| `getReleases()` | github.go:1401 | `scrapeReleases()` | Paginated releases pages (up to 50 pages) |
| `GetCommitStats()` | github.go:1980 | `scrapeCommitStats()` | Full repo page DOM for contributor sidebar |
| `getWorkflowFiles()` | github.go:2376 | `scrapeWorkflowFiles()` | Tree page DOM |
| `CheckGitTag()` | github.go:799-811 | `scrapeTagNames()` | Up to 3 tag listing pages |
| `fetchIdentity()` | github.go (identity) | `scrapeIdentity()` | User profile page DOM |

**Key concern:** `scrapeReleases()` (line 1492) paginates through up to `maxPaginationPages=50` release pages. Each page requires a full HTML download + DOM parse. The API path fetches the same data as compact JSON with `per_page=100`.

**Impact:** For a repo with 200 releases, scraping requires 4+ HTML page fetches vs 2 JSON API calls. Each HTML page is typically 5-10x larger than the equivalent JSON response.

---

## Finding 2: Sequential Issue Response Time Calculation (Pre-existing, worsened by caching)

**Severity: HIGH — up to 11 sequential API calls per unique repo**

**File:** `pkg/fetcher/github.go` lines 2549-2650

**Problem:** `GetAverageIssueResponseTime()` fetches 100 closed issues (1 call), then for each non-PR issue, sequentially fetches its comments (1 call each) until 10 issues with responses are found:

```
Call 1: GET /repos/{owner}/{repo}/issues?state=closed&per_page=100
Call 2: GET /repos/{owner}/{repo}/issues/{n1}/comments   ← sequential
Call 3: GET /repos/{owner}/{repo}/issues/{n2}/comments   ← sequential
...
Call 11: GET /repos/{owner}/{repo}/issues/{n10}/comments  ← sequential
```

Lines 2592-2632: The `for` loop iterates issues sequentially, making one `doRequest()` per issue. These could be parallelized with goroutines since they're independent.

**Why caching makes this worse:** PR #261 caches the result per-repo, so the penalty is paid only once per unique repo. But for scans with many unique repos, each repo pays the full 11-call penalty sequentially. With the rate limiter's `Wait()` call (line 346), each request may also be throttled.

---

## Finding 3: Triple-Scraping in CheckGitTag (PR #260)

**Severity: MEDIUM — affects every package version check without token**

**File:** `pkg/fetcher/github.go` lines 776-873

**Problem:** When `shouldPreferScraping()` is true, `CheckGitTag()` can make up to **3 rounds of scraping** for a single version check:

**Round 1** (lines 799-805): HEAD requests to `github.com/{owner}/{repo}/releases/tag/{variant}` for 7 tag variants. Each is a separate HTTP HEAD request.

**Round 2** (line 809): If Round 1 fails, calls `searchTagsPaginated()` which:
- Checks tag name cache (line 904-908)
- On cache miss, calls `scrapeTagNames()` which fetches up to 3 HTML pages (lines 1049-1093)

**Round 3** (lines 863-866): If `shouldPreferScraping()` is false (can't happen in this branch, but the structure creates confusion), calls `searchTagsPaginated()` again.

**The actual worst case without token:**
1. 7 HEAD requests to github.com (tag variants) — lines 800-805
2. `searchTagsPaginated()` → `scrapeTagNames()` → 3 HTML pages scraped — line 809
3. Total: **10 HTTP requests** for a single version check

**Cache interaction:** `scrapeTagNames()` has its own cache check (line 1039), AND `searchTagsPaginated()` has a separate cache check (line 904). On first call, both miss. On second call for the same repo, both hit. But the first call is expensive.

---

## Finding 4: Sequential Per-PR Review Checks in GetPullRequestStats

**Severity: MEDIUM — up to 21 sequential API calls per unique repo**

**File:** `pkg/fetcher/github.go` lines 2157-2225

**Problem:** `GetPullRequestStats()` fetches 100 closed PRs (1 call), then for each merged PR (up to 20), sequentially calls `prHasReviews()` (lines 2195-2199):

```go
for _, pr := range prs {
    if pr.MergedAt != nil {
        stats.MergedPRs++
        if stats.MergedPRs <= maxReviewChecks {
            if c.prHasReviews(owner, repo, pr.Number) {  // 1 API call each
                stats.PRsWithReviews++
            }
        }
    }
}
```

Each `prHasReviews()` call (lines 2227-2255) makes an individual REST API request. These are independent and could be parallelized.

**Total cost:** 1 (PR list) + 20 (review checks) + 1 (branch protection) = **22 sequential API calls** per unique repo.

---

## Finding 5: GraphQL Batch Doesn't Cover Expensive Operations

**Severity: MEDIUM — missed optimization opportunity**

**File:** `pkg/fetcher/github_graphql.go` lines 122-177

**Problem:** The GraphQL batch query (PR #259) batches repo info, releases, governance files, and branch protection — but the **most expensive operations** are NOT batched:

| Operation | Batched in GraphQL? | Sequential API Cost |
|-----------|---------------------|---------------------|
| Repo info | Yes | 1 call → 0 |
| Releases (30) | Yes | 1-3 calls → 0 |
| Governance files (7) | Yes | 7 HEAD calls → 0 |
| Branch protection | Yes | 1 call → 0 |
| PR review stats | **No** | 21 calls (sequential) |
| Commit stats | **No** | 1 call |
| Commit authors | **No** | 1-3 calls |
| Signed commits | **No** | 1 call |
| Issue response time | **No** | 11 calls (sequential) |

The GraphQL API supports fetching PR review data and commit history, which would eliminate the 21+11 sequential API calls for PR stats and issue response time.

---

## Finding 6: Single RWMutex for 13 Cache Maps

**Severity: LOW — contention unlikely in current architecture**

**File:** `pkg/fetcher/github.go` lines 62-95

**Problem:** All 13 cache maps share a single `sync.RWMutex` (line 63). Write operations on any cache type block reads on all other cache types.

**Why it's low severity:** The analyzer runs analysis steps sequentially within each package (no goroutines in `pkg/analyzer/`), and the worker pool in `cmd/scan.go` (lines 437-458) shares a single `GitHubClient` instance (line 415) but workers mostly access different cache keys. Write locks are brief (single map insertion).

**When it could matter:** If the worker count is high (e.g., `--workers 20`) and many workers simultaneously hit cache misses for the same operation type, write locks on one cache could briefly block reads on unrelated caches.

---

## Finding 7: fileExists Cache Pollution from Incomplete GraphQL Batch

**Severity: LOW**

**File:** `pkg/fetcher/github_graphql.go` lines 362-371

**Problem:** The GraphQL batch only checks 7 governance files:
```go
govFiles := map[string]bool{
    "SECURITY.md":              r.SecurityMd != nil,
    ".github/SECURITY.md":     r.SecurityMdGh != nil,
    "CONTRIBUTING.md":         r.ContributingMd != nil,
    ".github/CONTRIBUTING.md": r.ContributingMdGh != nil,
    "CODEOWNERS":             r.Codeowners != nil,
    ".github/CODEOWNERS":     r.CodeownersGh != nil,
    "CODE_OF_CONDUCT.md":     r.CodeOfConduct != nil,
}
```

But `DetectCISystems` checks ~20 different file paths. Those paths are NOT in the GraphQL batch, so they still require individual `fileExists()` API calls even when GraphQL was successful. The `populateCachesFromBatch()` function (line 405) only populates the 7 governance files.

---

## Finding 8: Scraping Timeout Accumulation Without Token

**Severity: MEDIUM**

**File:** `pkg/fetcher/scraper_utils.go` line 21

**Problem:** The scrape client uses a 10-second timeout. When GitHub returns pages slowly (high load, geographic latency), each scraping call can take up to 10 seconds. In the worst case for a single package analysis without token:

| Step | Method | Max Scraping Calls | Max Timeout |
|------|--------|--------------------|-------------|
| Repo info | `scrapeRepositoryInfo()` | 1 | 10s |
| Releases | `scrapeReleases()` | 50 pages | 500s |
| Tags | `scrapeTagNames()` | 3 pages | 30s |
| Commit stats | `scrapeCommitStats()` | 1 | 10s |
| Identity | `scrapeIdentity()` | 1 | 10s |
| Workflows | `scrapeWorkflowFiles()` | 2 (HEAD + main) | 20s |
| File checks | `checkFileViaRawURL()` | ~20 | 200s |

**Theoretical worst case:** 780 seconds of timeout accumulation. In practice, most complete in <1s, but slow GitHub responses compound across the many scraping calls.

---

## Finding 9: No Parallelization Within Per-Package Analysis

**Severity: MEDIUM — structural limitation**

**File:** `pkg/analyzer/analyzer.go` lines 125-343

**Problem:** All 12 analysis steps run strictly sequentially:

```
1. Package registry fetch      ← blocks until complete
2. Libraries.io enrichment     ← blocks until complete
3. Source code verification    ← blocks until complete
4. Dependency sprawl           ← blocks (filesystem only, fast)
5. Repository analysis         ← blocks until complete
6. Build infrastructure        ← blocks until complete
7. Health metrics              ← blocks until complete (21+ API calls)
8. Release documentation       ← blocks until complete
9. OSSF Scorecard              ← blocks until complete
10. Provenance analysis        ← blocks until complete
11. Score calculation          ← blocks (local computation, fast)
```

Steps 5-10 are independent of each other once the repo URL is known. Running them concurrently within a single package analysis could reduce per-package latency by ~60%.

**Note:** The worker pool in `cmd/scan.go` parallelizes across packages (10 workers by default), but within each package, everything is serial.

---

## Finding 10: Tag Search Reduced from 10 to 3 Pages (PR #257)

**Severity: LOW — correctness concern more than performance**

**File:** `pkg/fetcher/github.go` line 880

**Problem:** `maxTagSearchPages` was reduced from 10 to 3 (covering ~300 tags). Repos with >300 tags where the target version is in position 301+ will incorrectly report "tag not found".

**Performance aspect:** This actually *improves* performance (fewer pages fetched), but at the cost of correctness for large repos with many tags.

---

## Recommendations (Prioritized)

### Quick Wins (Low effort, high impact)

1. **Parallelize `GetAverageIssueResponseTime` comment fetches** — Use goroutine pool for the 10 independent `/issues/{n}/comments` calls. Expected: ~10x speedup for this method (11 sequential → 1+1 parallel).

2. **Parallelize `GetPullRequestStats` review checks** — Same pattern: 20 independent `/pulls/{n}/reviews` calls can run concurrently. Expected: ~20x speedup for this method.

3. **Add scraping-first toggle flag** — Allow `--prefer-api` to bypass scraping and use unauthenticated API directly. Users who don't need quota preservation can trade 60 req/hr for faster scans.

### Medium Effort (Structural changes)

4. **Extend GraphQL batch to include PR reviews and commit data** — The GraphQL API supports `pullRequests(first: 20, states: MERGED) { reviews { ... } }` and `defaultBranchRef { target { ... history(first: 100) } }`. This could eliminate 30+ sequential REST calls per repo.

5. **Parallelize analysis steps within a package** — Steps 5-10 in `Analyze()` are independent after step 4. Running them concurrently with `errgroup` could reduce per-package time by ~60%.

6. **Deduplicate `CheckGitTag` scraping attempts** — The cache check in `searchTagsPaginated()` (line 904) and `scrapeTagNames()` (line 1039) are redundant. Consolidate to a single cache-checked scraping path.

### Low Priority (Nice to have)

7. **Per-cache-type mutexes** — Replace single `sync.RWMutex` with per-map locks to eliminate cross-cache contention. Low impact with current architecture but future-proofs for higher concurrency.

8. **Scraping response size limits** — Some GitHub pages are large. The current 5MB limit (scraper_utils.go line 53) is generous. Consider reducing for known-small pages (tag listings, profile pages).
