# API Call Efficiency: Research & Optimization Opportunities

**Date:** 2026-03-02
**Author:** fancy-otter (research task)
**Status:** Research only — no code changes

## Context

This document surveys optimization opportunities for reducing GitHub API consumption during snyft scans. It builds on:

- **PR #240** — Shared caching for org/user lookups, default branch caching, HTTP client reuse (merged)
- **brave-panda's rate limit gate** — Checkpoint-based scan resume when API quota runs low (in progress on `work/brave-panda`)

## Current API Call Budget Per Package (Worst Case)

| Function | REST Calls | Notes |
|---|---|---|
| GetPullRequestStats + prHasReviews | ~102 | 1 PR list + up to 100 review checks + branch protection |
| DetectCISystems (fileExists) | ~49 | 49 file HEAD requests; early-exit typically reduces to 1-5 |
| GetAverageIssueResponseTime | ~11 | 1 issue list + up to 10 nested comment calls |
| GetCommitAuthors | 5 | 5 pages of 100 commits each |
| CheckGitTag | 5-10 | 5 tag format variants, tries scraping then API |
| getReleases (paginated) | 1-50 | Cached after first call; typical: 1-3 pages |
| GetRepositoryInfo | 1 | Cached |
| GetCommitActivity | 1 | Single page |
| CheckSignedCommits | 1 | Single page of 30 |
| GetCommitStats | 1 | Scraping-first, API fallback |
| getWorkflowFiles | 1 | Scraping-first |
| CheckVerifiedOrganization | 0 | Shared via fetchOrgInfo (PR #240) |
| CheckOrgMFARequired | 0 | Shared via fetchOrgInfo (PR #240) |
| GetUserAccountCreatedDate | 0 | Shared via fetchIdentity (PR #240) |
| **Total worst case** | **~180+** | |
| **Typical case** | **~40-60** | |

## Optimization Opportunities

### 1. GraphQL Batching (Highest Impact)

**What:** Replace multiple REST calls with a single GitHub GraphQL v4 query per repository.

**Impact:** Could reduce ~154 REST calls to ~5 GraphQL points per scan — a **~97% reduction** in API budget consumption.

#### 1a. PR Reviews — the biggest win

**Current:** `GetPullRequestStats` fetches 100 PRs, then `prHasReviews` makes a separate `GET /repos/{owner}/{repo}/pulls/{id}/reviews` call **for each merged PR**. Worst case: 101 REST calls.

**With GraphQL:** A single query fetches PRs with `reviews(first: 1) { totalCount }` and `reviewDecision` inline — collapsing 101 calls into 1 query (~2 points).

```graphql
query PRReviewStats($owner: String!, $name: String!) {
  repository(owner: $owner, name: $name) {
    pullRequests(first: 100, states: MERGED, orderBy: {field: UPDATED_AT, direction: DESC}) {
      nodes {
        number
        mergedAt
        reviewDecision          # APPROVED, CHANGES_REQUESTED, etc.
        reviews(first: 1) {
          totalCount             # Has reviews? totalCount > 0
        }
      }
    }
    defaultBranchRef {
      branchProtectionRule {
        requiredApprovingReviewCount
        requiresApprovingReviews
      }
    }
  }
}
```

#### 1b. CI/Governance File Existence — second biggest win

**Current:** `DetectCISystems` checks up to 49 file paths via individual HEAD requests.

**With GraphQL:** Use aliased `object(expression: "HEAD:path")` fields to check all files in a single query (~1 point). Returns `null` when file doesn't exist, an object when it does.

```graphql
query CheckFiles($owner: String!, $name: String!) {
  repository(owner: $owner, name: $name) {
    gha_dir: object(expression: "HEAD:.github/workflows") { oid }
    gitlab_ci: object(expression: "HEAD:.gitlab-ci.yml") { oid }
    travis: object(expression: "HEAD:.travis.yml") { oid }
    circleci: object(expression: "HEAD:.circleci/config.yml") { oid }
    security_md: object(expression: "HEAD:SECURITY.md") { oid }
    codeowners: object(expression: "HEAD:.github/CODEOWNERS") { oid }
    # ... all 49 paths as aliases
  }
}
```

Can also retrieve file **content** inline (for workflow analysis) by adding `... on Blob { text }`.

#### 1c. Repo Metadata + Releases + Commits — moderate win

**Current:** 3+ separate REST calls for `GetRepositoryInfo`, `getReleases`, `GetCommitActivity`.

**With GraphQL:** Combine into a single query (~2-4 points depending on page sizes). Commit signature data is richer in GraphQL — includes `wasSignedByGitHub` field not available in REST.

#### 1d. "Mega-Query" Strategy

Combine all three categories above into 1-2 GraphQL queries per repository:

- **Query 1:** Repo metadata + file existence checks + releases + recent commits + commit signatures
- **Query 2:** PR stats with inline review counts

Total: **2 GraphQL queries (~5-7 points) instead of ~154 REST calls**.

#### Caveats

- **Requires authentication.** No anonymous GraphQL access. The scraping-first fallback path for unauthenticated users must remain.
- **Separate rate limit pool.** GraphQL has its own 5,000 points/hour budget (authenticated), separate from REST's 5,000 requests/hour. Could use both pools strategically.
- **Point cost formula:** `sum(first × parent_first) / 100`, rounded up, minimum 1.
- **Partial errors possible.** A single GraphQL query can return data for some fields and errors for others (e.g., branch protection requires admin scope). Code must handle the `errors` array.
- **Test mocking.** Current `NewGitHubClientWithBaseURL` pattern works for REST; GraphQL would need a separate mock handler since all queries go to `POST /graphql`.
- **Go implementation:** Can use raw `net/http` POST (no new dependency) or `github.com/shurcooL/githubv4` for type-safe struct tags.

---

### 2. Commit Data Deduplication (Medium Impact)

**What:** `GetCommitActivity`, `GetCommitAuthors`, `CheckSignedCommits`, and `GetCommitStats` each make **independent** API calls to `GET /repos/{owner}/{repo}/commits` with different parameters — they don't share any cached data.

**Impact:** Could save 3-5 REST calls per repo by caching the commit list similarly to how PR #240 cached org/identity data.

**Approach:** Add a `cachedCommits` field to `repoCache` storing the first 100-500 commits. `GetCommitActivity`, `GetCommitAuthors`, `CheckSignedCommits`, and `GetCommitStats` would all pull from this shared cache. The different `per_page` and `since` parameters would require the cache to store the superset (e.g., 500 commits without date filter), then filter in-memory.

**Complexity:** Low-medium. Same pattern as `fetchIdentity`/`fetchOrgInfo` from PR #240.

---

### 3. Conditional Requests with ETags (Low Impact for Current Architecture)

**What:** GitHub REST responses include `ETag` and `Last-Modified` headers. Subsequent requests with `If-None-Match: <etag>` return `304 Not Modified` with **no rate limit cost**.

**Impact for current architecture:** Minimal. Snyft runs single-shot scans — there is no second request for the same resource within a scan (PR #240's caching already handles that). ETags only help when the same data is requested across separate scan invocations.

**Impact for future architecture:** High if snyft adds:
- **Watch/monitoring mode** — re-scanning the same repos periodically
- **CI integration** — scanning on every PR where most dependencies haven't changed
- **Persistent cache** — storing ETags on disk between runs

**Implementation:** Store `(endpoint, ETag, response_body)` tuples in a persistent cache (SQLite or flat JSON file). On subsequent scans, send `If-None-Match` header. On `304`, return cached body. On `200`, update cache.

**Note:** GraphQL does NOT support ETags (all requests are POST to a single endpoint). This optimization only applies to REST calls.

---

### 4. Cross-Analyzer Cache Sharing (Medium Impact)

**What:** When scanning a project with many dependencies from the same GitHub org/owner (e.g., `@babel/core`, `@babel/parser`, `@babel/traverse`), each dependency triggers separate owner-level checks (org verification, MFA, account age). PR #240 made these checks share a cache **within a single GitHubClient**, but only one client exists per Analyzer.

**Current state:** The Analyzer creates one `GitHubClient` at init time (`analyzer.go:74`), and all dependencies within a scan share it. So within a single scan, this is already handled.

**Where it would matter:**
- If the architecture changes to multiple Analyzers (e.g., per-ecosystem)
- If a "workspace scan" mode is added that scans multiple projects
- Repository-level data (commits, releases, PRs) is keyed by `owner/repo`, so packages from the **same repo** (monorepo dependencies) already benefit from caching

**Current gap:** The `owner/repo` data cached by one dependency's analysis is available to subsequent dependencies in the same scan (since they share the GitHubClient). The caching from PR #240 already addresses the main cross-dependency sharing need within a single scan.

---

### 5. Request Parallelism Tuning (Low-Medium Impact)

**What:** The scan currently uses 10 parallel workers (configurable via `--workers`). Each worker makes serial API calls for one dependency at a time. The API calls within a single dependency analysis are also serial.

**Opportunity:** Within a single dependency analysis, some API calls are independent and could run concurrently:
- `GetRepositoryInfo`, `getReleases`, and `GetCommitAuthors` don't depend on each other
- `CheckIfOrganization` and `GetPullRequestStats` don't depend on each other

**Impact:** Would reduce wall-clock time but not API call count. The rate limiter already manages throughput across workers. Main benefit is latency reduction for individual package analysis.

**Risk:** More concurrent requests could hit GitHub's secondary rate limits (900 points/minute for REST, 100 concurrent connections). The current serial-within-worker approach is safer.

---

### 6. Smart Endpoint Selection (Low Impact)

**What:** Some REST endpoints return richer data than currently used. For example:

- `GET /repos/{owner}/{repo}/commits` with `per_page=100` returns commit objects that include both author info AND signature verification data. Currently, `GetCommitAuthors` and `CheckSignedCommits` call this endpoint separately.
- `GET /repos/{owner}/{repo}/pulls?state=closed` returns PRs that already include `merged_at` — no need for a separate merge check.

**Impact:** Minor — mostly overlaps with the commit deduplication opportunity (#2 above).

---

### 7. Registry API Efficiency (Out of Scope for GitHub, but Relevant)

**What:** npm/PyPI/Maven registry API calls are separate from GitHub and have their own efficiency considerations.

**Quick observations:**
- npm registry calls are currently not cached between dependencies from the same package (rare scenario)
- PyPI JSON API returns all version metadata in one call (already efficient)
- Maven Central search API is used for metadata (already a single call)

**Not investigated in depth** — this research focused on GitHub API calls, which are the bottleneck.

---

## Recommendation Priority

| Priority | Optimization | Effort | Impact | API Calls Saved |
|---|---|---|---|---|
| **P0** | GraphQL PR review batching | Medium | Very High | ~100 per repo |
| **P0** | GraphQL file existence batching | Medium | Very High | ~40 per repo |
| **P1** | GraphQL mega-query (repo+releases+commits) | Medium | High | ~8 per repo |
| **P1** | Commit data deduplication (REST cache) | Low | Medium | ~5 per repo |
| **P2** | Conditional requests (ETags) | Medium | Low (now), High (future) | 0 now; many later |
| **P3** | Request parallelism within analysis | Low | Low (latency only) | 0 (latency benefit) |

### Suggested Implementation Order

1. **Start with GraphQL for PR reviews and file checks** — these two alone cut ~140 calls per repo. They can be implemented as opt-in when `GITHUB_TOKEN` is set, with REST as fallback.
2. **Add commit data caching** — low effort, same pattern as PR #240, pure REST improvement.
3. **Expand GraphQL to mega-query** — once the GraphQL infrastructure (client, mocking, error handling) exists from step 1, adding more fields is incremental.
4. **Add ETag support** if/when persistent caching or watch mode is added.

### Interaction with brave-panda's Rate Limit Gate

The rate limit gate (`ShouldStop` at threshold 50) works orthogonally to these optimizations:
- GraphQL batching reduces the rate at which quota is consumed, so the gate triggers later (or not at all)
- ETags would reduce quota consumption to zero for unchanged resources
- Commit deduplication reduces REST calls, extending the window before the gate triggers
- The gate's `Remaining()` tracking currently reads REST `X-RateLimit-Remaining` headers; GraphQL has its own rate limit response (`rateLimit { remaining }` in the query response) — these would need separate tracking if both REST and GraphQL are used simultaneously

## Appendix: GraphQL Rate Limit vs REST Rate Limit

| Aspect | REST API | GraphQL API |
|---|---|---|
| Primary limit | 5,000 requests/hour | 5,000 points/hour |
| Unit | 1 request = 1 unit | 1 query = 1+ points (node-based) |
| Unauthenticated | 60 requests/hour | **Not supported** |
| Secondary (per-minute) | 900 points/min | 2,000 points/min |
| Concurrent requests | 100 (shared) | 100 (shared with REST) |
| ETag / conditional requests | Yes (304 = free) | No |
| Separate pools? | Yes — REST and GraphQL have independent primary limits |

**Key insight:** Since REST and GraphQL have **independent** primary rate limit pools, a hybrid approach could effectively double the available API budget: use GraphQL for bulk queries (PR reviews, file checks) while keeping REST for simple cached lookups (repo info, releases) that are already optimized.
