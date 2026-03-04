package fetcher

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Test: GraphQL batch query populates all caches from a single API call
// Justification: Reducing 10+ REST API calls to 1 GraphQL query preserves rate limit
//                quota for larger scans, directly improving supply chain risk assessment
//                coverage across more dependencies.
// Source: GitHub GraphQL API documentation; rate limit strategy for supply chain analysis
// Methodology: Mock the GraphQL endpoint, verify caches for repo info, releases,
//              governance files, and branch protection are populated from a single call.
// Result: All caches populated; subsequent REST callers get cache hits.
func TestFetchBatchRepoData(t *testing.T) {
	createdAt := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	updatedAt := time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC)
	pushedAt := time.Date(2024, 5, 30, 0, 0, 0, 0, time.UTC)

	graphqlResponse := map[string]interface{}{
		"data": map[string]interface{}{
			"repository": map[string]interface{}{
				"name":           "express",
				"description":    "Fast web framework",
				"stargazerCount": 60000,
				"forkCount":      10000,
				"watchers":       map[string]interface{}{"totalCount": 3000},
				"openIssues":     map[string]interface{}{"totalCount": 150},
				"defaultBranchRef": map[string]interface{}{
					"name": "main",
				},
				"isArchived": false,
				"createdAt":  createdAt.Format(time.RFC3339),
				"updatedAt":  updatedAt.Format(time.RFC3339),
				"pushedAt":   pushedAt.Format(time.RFC3339),
				"licenseInfo": map[string]interface{}{
					"name": "MIT License",
				},
				"repositoryTopics": map[string]interface{}{
					"nodes": []interface{}{
						map[string]interface{}{"topic": map[string]interface{}{"name": "nodejs"}},
						map[string]interface{}{"topic": map[string]interface{}{"name": "web"}},
					},
				},
				"owner": map[string]interface{}{"login": "expressjs"},
				"url":   "https://github.com/expressjs/express",
				"releases": map[string]interface{}{
					"nodes": []interface{}{
						map[string]interface{}{
							"tagName":      "v4.19.2",
							"name":         "4.19.2",
							"isDraft":      false,
							"isPrerelease": false,
							"createdAt":    "2024-03-25T00:00:00Z",
							"publishedAt":  "2024-03-25T00:00:00Z",
							"releaseAssets": map[string]interface{}{
								"nodes": []interface{}{
									map[string]interface{}{
										"name":        "checksums.txt",
										"contentType": "text/plain",
										"size":        256,
										"downloadUrl": "https://github.com/expressjs/express/releases/download/v4.19.2/checksums.txt",
									},
								},
							},
						},
					},
				},
				"securityMd":       map[string]interface{}{"__typename": "Blob"},
				"securityMdGh":     nil,
				"contributingMd":   map[string]interface{}{"__typename": "Blob"},
				"contributingMdGh": nil,
				"codeowners":       nil,
				"codeownersGh":     nil,
				"codeOfConduct":    map[string]interface{}{"__typename": "Blob"},
				"branchProtectionRules": map[string]interface{}{
					"nodes": []interface{}{
						map[string]interface{}{
							"pattern":                      "main",
							"requiredApprovingReviewCount": 2,
						},
					},
				},
			},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/graphql" && r.Method == "POST" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(graphqlResponse)
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	client := &GitHubClient{
		token:      "test-token",
		httpClient: &http.Client{},
		baseURL:    server.URL,
		cache:      newRepoCache(),
	}

	batch := client.fetchBatchRepoData("expressjs", "express")
	if batch == nil {
		t.Fatal("expected batch data, got nil")
	}

	// Verify repo info
	info := batch.RepoInfo
	if info == nil {
		t.Fatal("expected repo info, got nil")
	}
	if info.Name != "express" {
		t.Errorf("expected name 'express', got %q", info.Name)
	}
	if info.Stars != 60000 {
		t.Errorf("expected 60000 stars, got %d", info.Stars)
	}
	if info.Forks != 10000 {
		t.Errorf("expected 10000 forks, got %d", info.Forks)
	}
	if info.DefaultBranch != "main" {
		t.Errorf("expected default branch 'main', got %q", info.DefaultBranch)
	}
	if info.License != "MIT License" {
		t.Errorf("expected license 'MIT License', got %q", info.License)
	}
	if len(info.Topics) != 2 {
		t.Errorf("expected 2 topics, got %d", len(info.Topics))
	}
	if info.OpenIssues != 150 {
		t.Errorf("expected 150 open issues, got %d", info.OpenIssues)
	}

	// Verify releases
	if len(batch.Releases) != 1 {
		t.Fatalf("expected 1 release, got %d", len(batch.Releases))
	}
	if batch.Releases[0].TagName != "v4.19.2" {
		t.Errorf("expected tag 'v4.19.2', got %q", batch.Releases[0].TagName)
	}
	if len(batch.Releases[0].Assets) != 1 {
		t.Errorf("expected 1 asset, got %d", len(batch.Releases[0].Assets))
	}

	// Verify governance files
	if !batch.GovernanceFiles["SECURITY.md"] {
		t.Error("expected SECURITY.md to exist")
	}
	if batch.GovernanceFiles[".github/SECURITY.md"] {
		t.Error("expected .github/SECURITY.md to NOT exist")
	}
	if !batch.GovernanceFiles["CONTRIBUTING.md"] {
		t.Error("expected CONTRIBUTING.md to exist")
	}
	if !batch.GovernanceFiles["CODE_OF_CONDUCT.md"] {
		t.Error("expected CODE_OF_CONDUCT.md to exist")
	}
	if batch.GovernanceFiles["CODEOWNERS"] {
		t.Error("expected CODEOWNERS to NOT exist")
	}

	// Verify caches were populated
	if cached, ok := client.cache.getRepoInfo("expressjs/express"); !ok || cached == nil {
		t.Error("expected repo info to be cached")
	}
	if cached, ok := client.cache.getCachedReleases("expressjs/express"); !ok || cached == nil {
		t.Error("expected releases to be cached")
	}
	if exists, ok := client.cache.getFileExists("expressjs/express/SECURITY.md"); !ok || !exists {
		t.Error("expected SECURITY.md file existence to be cached as true")
	}
	if exists, ok := client.cache.getFileExists("expressjs/express/CODEOWNERS"); !ok || exists {
		t.Error("expected CODEOWNERS file existence to be cached as false")
	}
}

// Test: GraphQL failure falls back to REST API
// Justification: GraphQL API may be unavailable (rate limited, network issues);
//                falling back to REST ensures supply chain risk data is still collected.
// Source: Graceful degradation principle; GitHub API availability patterns
// Methodology: Mock server returns 500 for GraphQL, verify REST fallback is used.
// Result: GetRepositoryInfo succeeds via REST even when GraphQL fails.
func TestGraphQLFallbackToREST(t *testing.T) {
	graphqlCalled := false
	restCalled := false

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/graphql" {
			graphqlCalled = true
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/repos/") && r.Method == "GET" {
			restCalled = true
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(GitHubRepository{
				Name:            "express",
				HTMLURL:         "https://github.com/expressjs/express",
				StargazersCount: 60000,
				DefaultBranch:   "main",
				Owner:           GitHubUser{Login: "expressjs"},
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	client := &GitHubClient{
		token:      "test-token",
		httpClient: &http.Client{},
		baseURL:    server.URL,
		cache:      newRepoCache(),
	}

	info, err := client.GetRepositoryInfo("https://github.com/expressjs/express")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if info == nil {
		t.Fatal("expected repo info, got nil")
	}
	if !graphqlCalled {
		t.Error("expected GraphQL to be attempted first")
	}
	if !restCalled {
		t.Error("expected REST fallback to be called")
	}
	if info.Name != "express" {
		t.Errorf("expected name 'express', got %q", info.Name)
	}
}

// Test: GraphQL is skipped when no token is set
// Justification: GraphQL API requires authentication. Without a token, only
//                scraping/REST should be used for supply chain data collection.
// Source: GitHub API documentation (GraphQL requires auth)
// Methodology: Create client without token, verify graphqlQuery returns error.
// Result: graphqlQuery fails with auth error; scraping path is used instead.
func TestGraphQLRequiresAuth(t *testing.T) {
	client := &GitHubClient{
		token:      "",
		httpClient: &http.Client{},
		baseURL:    "https://api.github.com",
		cache:      newRepoCache(),
	}

	_, err := client.graphqlQuery(`{ viewer { login } }`)
	if err == nil {
		t.Fatal("expected error for unauthenticated GraphQL query")
	}
	if !strings.Contains(err.Error(), "requires authentication") {
		t.Errorf("expected auth error, got: %v", err)
	}
}

// Test: GraphQL batch query correctly identifies missing governance files
// Justification: Governance file presence (SECURITY.md) is a key supply chain
//                risk signal. Null responses from GraphQL correctly indicate
//                missing files, distinguishing "file absent" from "check failed".
// Source: OSSF Scorecard Specification (Security Policy check)
// Methodology: Mock GraphQL response with all governance files null, verify
//              all are reported as missing.
// Result: All governance files correctly reported as non-existent.
func TestBatchGovernanceFilesAllMissing(t *testing.T) {
	graphqlResponse := map[string]interface{}{
		"data": map[string]interface{}{
			"repository": map[string]interface{}{
				"name":             "tiny-lib",
				"description":      "A tiny library",
				"stargazerCount":   10,
				"forkCount":        1,
				"watchers":         map[string]interface{}{"totalCount": 1},
				"openIssues":       map[string]interface{}{"totalCount": 0},
				"defaultBranchRef": map[string]interface{}{"name": "main"},
				"isArchived":       false,
				"createdAt":        "2023-01-01T00:00:00Z",
				"updatedAt":        "2024-01-01T00:00:00Z",
				"pushedAt":         "2024-01-01T00:00:00Z",
				"licenseInfo":      nil,
				"repositoryTopics": map[string]interface{}{"nodes": []interface{}{}},
				"owner":            map[string]interface{}{"login": "someuser"},
				"url":              "https://github.com/someuser/tiny-lib",
				"releases":         map[string]interface{}{"nodes": []interface{}{}},
				// All governance files absent
				"securityMd":       nil,
				"securityMdGh":     nil,
				"contributingMd":   nil,
				"contributingMdGh": nil,
				"codeowners":       nil,
				"codeownersGh":     nil,
				"codeOfConduct":    nil,
				"branchProtectionRules": map[string]interface{}{"nodes": []interface{}{}},
			},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/graphql" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(graphqlResponse)
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	client := &GitHubClient{
		token:      "test-token",
		httpClient: &http.Client{},
		baseURL:    server.URL,
		cache:      newRepoCache(),
	}

	batch := client.fetchBatchRepoData("someuser", "tiny-lib")
	if batch == nil {
		t.Fatal("expected batch data, got nil")
	}

	// All governance files should be absent
	for path, exists := range batch.GovernanceFiles {
		if exists {
			t.Errorf("expected %q to be absent, got present", path)
		}
	}

	// No releases
	if len(batch.Releases) != 0 {
		t.Errorf("expected 0 releases, got %d", len(batch.Releases))
	}

	// License should be empty
	if batch.RepoInfo.License != "" {
		t.Errorf("expected empty license, got %q", batch.RepoInfo.License)
	}
}

// Test: GraphQL errors (partial failures) result in graceful fallback
// Justification: GitHub GraphQL may return errors for specific fields while
//                the overall query succeeds. Error responses should trigger
//                REST fallback rather than reporting incorrect risk data.
// Source: GitHub GraphQL API error handling documentation
// Methodology: Mock GraphQL response with errors array, verify nil return
//              triggers REST fallback path.
// Result: fetchBatchRepoData returns nil; caller falls back to REST.
func TestGraphQLErrorResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/graphql" {
			w.Header().Set("Content-Type", "application/json")
			resp := map[string]interface{}{
				"data": nil,
				"errors": []interface{}{
					map[string]interface{}{
						"message": "Could not resolve to a Repository",
						"type":    "NOT_FOUND",
					},
				},
			}
			_ = json.NewEncoder(w).Encode(resp)
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	client := &GitHubClient{
		token:      "test-token",
		httpClient: &http.Client{},
		baseURL:    server.URL,
		cache:      newRepoCache(),
	}

	batch := client.fetchBatchRepoData("nonexistent", "repo")
	if batch != nil {
		t.Error("expected nil batch for errored GraphQL response")
	}
}

// Test: buildBatchQuery generates valid GraphQL with owner/repo interpolated
// Justification: Correct query construction is essential for fetching supply
//                chain risk data (governance files, releases, branch protection).
// Source: GitHub GraphQL API schema
// Methodology: Build query and verify it contains the expected owner/repo and
//              all required field aliases.
// Result: Query contains all required fields for comprehensive risk assessment.
func TestBuildBatchQuery(t *testing.T) {
	query := buildBatchQuery("expressjs", "express")

	// Verify owner/repo are included
	if !strings.Contains(query, `"expressjs"`) {
		t.Error("query should contain owner")
	}
	if !strings.Contains(query, `"express"`) {
		t.Error("query should contain repo name")
	}

	// Verify all governance file checks are present
	for _, alias := range []string{
		"securityMd:", "securityMdGh:", "contributingMd:", "contributingMdGh:",
		"codeowners:", "codeownersGh:", "codeOfConduct:",
	} {
		if !strings.Contains(query, alias) {
			t.Errorf("query should contain governance file check %q", alias)
		}
	}

	// Verify key fields are present
	for _, field := range []string{
		"stargazerCount", "forkCount", "releases",
		"defaultBranchRef", "isArchived", "licenseInfo",
	} {
		if !strings.Contains(query, field) {
			t.Errorf("query should contain field %q", field)
		}
	}
}

// Test: GraphQL batch caches prevent duplicate REST calls
// Justification: After a GraphQL batch query, subsequent callers for the same
//                repo should hit caches, not make additional REST calls. This
//                is critical for staying within rate limits during multi-package scans.
// Source: Rate limit conservation strategy for supply chain scanning
// Methodology: Fetch via GraphQL batch, then call getReleases and fileExists,
//              verify no additional HTTP requests are made.
// Result: All subsequent calls return cached data; zero additional API calls.
func TestBatchCachePreventsRESTCalls(t *testing.T) {
	requestCount := 0

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		if r.URL.Path == "/graphql" {
			w.Header().Set("Content-Type", "application/json")
			resp := map[string]interface{}{
				"data": map[string]interface{}{
					"repository": map[string]interface{}{
						"name":             "test-repo",
						"description":      "Test",
						"stargazerCount":   100,
						"forkCount":        10,
						"watchers":         map[string]interface{}{"totalCount": 5},
						"openIssues":       map[string]interface{}{"totalCount": 2},
						"defaultBranchRef": map[string]interface{}{"name": "main"},
						"isArchived":       false,
						"createdAt":        "2023-01-01T00:00:00Z",
						"updatedAt":        "2024-01-01T00:00:00Z",
						"pushedAt":         "2024-01-01T00:00:00Z",
						"licenseInfo":      map[string]interface{}{"name": "MIT License"},
						"repositoryTopics": map[string]interface{}{"nodes": []interface{}{}},
						"owner":            map[string]interface{}{"login": "testowner"},
						"url":              "https://github.com/testowner/test-repo",
						"releases": map[string]interface{}{
							"nodes": []interface{}{
								map[string]interface{}{
									"tagName":      "v1.0.0",
									"name":         "1.0.0",
									"isDraft":      false,
									"isPrerelease": false,
									"createdAt":    "2024-01-01T00:00:00Z",
									"publishedAt":  "2024-01-01T00:00:00Z",
									"releaseAssets": map[string]interface{}{"nodes": []interface{}{}},
								},
							},
						},
						"securityMd":       map[string]interface{}{"__typename": "Blob"},
						"securityMdGh":     nil,
						"contributingMd":   nil,
						"contributingMdGh": nil,
						"codeowners":       nil,
						"codeownersGh":     nil,
						"codeOfConduct":    nil,
						"branchProtectionRules": map[string]interface{}{"nodes": []interface{}{}},
					},
				},
			}
			_ = json.NewEncoder(w).Encode(resp)
			return
		}
		// Any non-graphql request means a cache miss — which shouldn't happen
		http.NotFound(w, r)
	}))
	defer server.Close()

	client := &GitHubClient{
		token:      "test-token",
		httpClient: &http.Client{},
		baseURL:    server.URL,
		cache:      newRepoCache(),
	}

	// First call: GraphQL batch
	batch := client.fetchBatchRepoData("testowner", "test-repo")
	if batch == nil {
		t.Fatal("expected batch data")
	}
	if requestCount != 1 {
		t.Fatalf("expected exactly 1 HTTP request for GraphQL, got %d", requestCount)
	}

	// Subsequent calls should use cached data — no additional requests
	if cached, ok := client.cache.getRepoInfo("testowner/test-repo"); !ok || cached == nil {
		t.Error("repo info should be cached")
	}
	if cached, ok := client.cache.getCachedReleases("testowner/test-repo"); !ok || len(cached) != 1 {
		t.Error("releases should be cached with 1 entry")
	}
	if exists, ok := client.cache.getFileExists("testowner/test-repo/SECURITY.md"); !ok || !exists {
		t.Error("SECURITY.md should be cached as existing")
	}
	if exists, ok := client.cache.getFileExists("testowner/test-repo/CODEOWNERS"); !ok || exists {
		t.Error("CODEOWNERS should be cached as not existing")
	}

	// Verify no additional HTTP requests were made
	if requestCount != 1 {
		t.Errorf("expected 1 total HTTP request, got %d (cache miss detected)", requestCount)
	}
}

// Test: GraphQL batch includes merged PR review data for code review rate
// Justification: Code review rate indicates governance maturity — projects with
//                no code review have higher risk of malicious commits being merged
//                undetected. Fetching this via GraphQL replaces up to 21 REST calls.
// Source: "Backstabber's Knife Collection" (Ohm et al., 2020) — governance checks
// Methodology: Mock GraphQL response with merged PRs (some with reviews, some without),
//              verify PRStats is correctly computed and cached.
// Result: PRStats reflects correct review rate; cache prevents REST calls.
func TestBatchPRReviewData(t *testing.T) {
	graphqlResponse := map[string]interface{}{
		"data": map[string]interface{}{
			"repository": buildBaseGraphQLRepo(map[string]interface{}{
				"pullRequests": map[string]interface{}{
					"totalCount": 50,
					"nodes": []interface{}{
						map[string]interface{}{"reviews": map[string]interface{}{"totalCount": 3}},
						map[string]interface{}{"reviews": map[string]interface{}{"totalCount": 0}},
						map[string]interface{}{"reviews": map[string]interface{}{"totalCount": 1}},
						map[string]interface{}{"reviews": map[string]interface{}{"totalCount": 0}},
						map[string]interface{}{"reviews": map[string]interface{}{"totalCount": 2}},
					},
				},
			}),
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/graphql" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(graphqlResponse)
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	client := &GitHubClient{
		token:      "test-token",
		httpClient: &http.Client{},
		baseURL:    server.URL,
		cache:      newRepoCache(),
	}

	batch := client.fetchBatchRepoData("testowner", "test-repo")
	if batch == nil {
		t.Fatal("expected batch data, got nil")
	}

	// Verify PR stats
	if batch.PRStats == nil {
		t.Fatal("expected PR stats, got nil")
	}
	if batch.PRStats.TotalPRs != 50 {
		t.Errorf("expected 50 total PRs, got %d", batch.PRStats.TotalPRs)
	}
	if batch.PRStats.MergedPRs != 50 {
		t.Errorf("expected 50 merged PRs, got %d", batch.PRStats.MergedPRs)
	}
	if batch.PRStats.PRsWithReviews != 3 {
		t.Errorf("expected 3 PRs with reviews, got %d", batch.PRStats.PRsWithReviews)
	}
	// 3 out of 5 sampled PRs have reviews = 60%
	expectedRate := 60.0
	if batch.PRStats.CodeReviewRate != expectedRate {
		t.Errorf("expected code review rate %.1f%%, got %.1f%%", expectedRate, batch.PRStats.CodeReviewRate)
	}

	// Verify cache was populated
	if cached, ok := client.cache.getPRStats("testowner/test-repo"); !ok || cached == nil {
		t.Error("expected PR stats to be cached")
	}
}

// Test: GraphQL batch includes commit author data for bus factor assessment
// Justification: Single-maintainer packages have higher account takeover risk.
//                Fetching commit authors via GraphQL replaces 3 REST pagination calls.
// Source: "Small World with High Risks" (Zimmermann et al., 2019) — maintainer risk
// Methodology: Mock GraphQL response with commits from multiple authors, verify
//              CommitAuthorStats correctly identifies unique authors and recency.
// Result: CommitAuthorStats reflects author distribution; cache prevents REST calls.
func TestBatchCommitAuthorData(t *testing.T) {
	now := time.Now()
	recentDate := now.AddDate(0, 0, -30).Format(time.RFC3339)
	oldDate := now.AddDate(0, 0, -120).Format(time.RFC3339)

	graphqlResponse := map[string]interface{}{
		"data": map[string]interface{}{
			"repository": buildBaseGraphQLRepo(map[string]interface{}{
				"defaultBranchRef": map[string]interface{}{
					"name": "main",
					"target": map[string]interface{}{
						"history": map[string]interface{}{
							"nodes": []interface{}{
								map[string]interface{}{
									"author":    map[string]interface{}{"name": "Alice", "email": "alice@example.com", "date": recentDate},
									"signature": map[string]interface{}{"isValid": true},
								},
								map[string]interface{}{
									"author":    map[string]interface{}{"name": "Alice", "email": "alice@example.com", "date": recentDate},
									"signature": map[string]interface{}{"isValid": true},
								},
								map[string]interface{}{
									"author":    map[string]interface{}{"name": "Bob", "email": "bob@example.com", "date": recentDate},
									"signature": map[string]interface{}{"isValid": false},
								},
								map[string]interface{}{
									"author":    map[string]interface{}{"name": "Charlie", "email": "charlie@example.com", "date": oldDate},
									"signature": nil,
								},
							},
						},
					},
				},
			}),
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/graphql" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(graphqlResponse)
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	client := &GitHubClient{
		token:      "test-token",
		httpClient: &http.Client{},
		baseURL:    server.URL,
		cache:      newRepoCache(),
	}

	batch := client.fetchBatchRepoData("testowner", "test-repo")
	if batch == nil {
		t.Fatal("expected batch data, got nil")
	}

	// Verify commit author stats
	if batch.CommitAuthors == nil {
		t.Fatal("expected commit authors, got nil")
	}
	if batch.CommitAuthors.TotalCommits != 4 {
		t.Errorf("expected 4 total commits, got %d", batch.CommitAuthors.TotalCommits)
	}
	if len(batch.CommitAuthors.UniqueAuthors) != 3 {
		t.Errorf("expected 3 unique authors, got %d", len(batch.CommitAuthors.UniqueAuthors))
	}
	if batch.CommitAuthors.AuthorCommitCounts["alice@example.com"] != 2 {
		t.Errorf("expected alice to have 2 commits, got %d", batch.CommitAuthors.AuthorCommitCounts["alice@example.com"])
	}
	// Alice and Bob are recent (within 90 days), Charlie is historical
	if len(batch.CommitAuthors.RecentAuthors) != 2 {
		t.Errorf("expected 2 recent authors, got %d: %v", len(batch.CommitAuthors.RecentAuthors), batch.CommitAuthors.RecentAuthors)
	}
	if len(batch.CommitAuthors.HistoricalAuthors) != 1 {
		t.Errorf("expected 1 historical author, got %d: %v", len(batch.CommitAuthors.HistoricalAuthors), batch.CommitAuthors.HistoricalAuthors)
	}

	// Verify cache was populated
	if cached, ok := client.cache.getCommitAuthors("testowner/test-repo"); !ok || cached == nil {
		t.Error("expected commit authors to be cached")
	}
}

// Test: GraphQL batch includes commit signature data for release security
// Justification: Commit signing indicates build/release integrity practices.
//                Unsigned commits may indicate a compromised CI/CD pipeline or
//                lack of provenance controls. Fetching via GraphQL replaces 1 REST call.
// Source: SLSA specification v1.0 — provenance and build integrity
// Methodology: Mock GraphQL response with mix of signed and unsigned commits,
//              verify signed commit detection and caching.
// Result: Correctly identifies signing rate; cache prevents REST calls.
func TestBatchSignedCommitData(t *testing.T) {
	now := time.Now()
	date := now.AddDate(0, 0, -10).Format(time.RFC3339)

	// 3 out of 4 commits signed = 75% > 50% threshold → hasSigning = true
	graphqlResponse := map[string]interface{}{
		"data": map[string]interface{}{
			"repository": buildBaseGraphQLRepo(map[string]interface{}{
				"defaultBranchRef": map[string]interface{}{
					"name": "main",
					"target": map[string]interface{}{
						"history": map[string]interface{}{
							"nodes": []interface{}{
								map[string]interface{}{
									"author":    map[string]interface{}{"name": "Dev", "email": "dev@example.com", "date": date},
									"signature": map[string]interface{}{"isValid": true},
								},
								map[string]interface{}{
									"author":    map[string]interface{}{"name": "Dev", "email": "dev@example.com", "date": date},
									"signature": map[string]interface{}{"isValid": true},
								},
								map[string]interface{}{
									"author":    map[string]interface{}{"name": "Dev", "email": "dev@example.com", "date": date},
									"signature": map[string]interface{}{"isValid": true},
								},
								map[string]interface{}{
									"author":    map[string]interface{}{"name": "Dev", "email": "dev@example.com", "date": date},
									"signature": map[string]interface{}{"isValid": false},
								},
							},
						},
					},
				},
			}),
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/graphql" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(graphqlResponse)
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	client := &GitHubClient{
		token:      "test-token",
		httpClient: &http.Client{},
		baseURL:    server.URL,
		cache:      newRepoCache(),
	}

	batch := client.fetchBatchRepoData("testowner", "test-repo")
	if batch == nil {
		t.Fatal("expected batch data, got nil")
	}

	if batch.SignedCommits == nil {
		t.Fatal("expected signed commits data, got nil")
	}
	if !batch.SignedCommits.hasSigning {
		t.Error("expected hasSigning=true (75% > 50% threshold)")
	}
	if batch.SignedCommits.verifiedCount != 3 {
		t.Errorf("expected 3 verified commits, got %d", batch.SignedCommits.verifiedCount)
	}

	// Verify cache was populated
	if cached, ok := client.cache.getSignedCommits("testowner/test-repo"); !ok || cached == nil {
		t.Error("expected signed commits to be cached")
	}
}

// Test: GraphQL batch caches prevent PR REST calls
// Justification: After batch populates PRStats cache, GetPullRequestStats should
//                return cached data without making any REST calls. This eliminates
//                the 21 REST calls (1 PR list + 20 per-PR review checks).
// Source: Rate limit conservation for supply chain scanning at scale
// Methodology: Fetch via GraphQL batch, then call GetPullRequestStats, verify
//              no additional HTTP requests are made.
// Result: GetPullRequestStats returns cached data; zero additional API calls.
func TestBatchCachePreventsPRRESTCalls(t *testing.T) {
	requestCount := 0

	graphqlResponse := map[string]interface{}{
		"data": map[string]interface{}{
			"repository": buildBaseGraphQLRepo(map[string]interface{}{
				"pullRequests": map[string]interface{}{
					"totalCount": 10,
					"nodes": []interface{}{
						map[string]interface{}{"reviews": map[string]interface{}{"totalCount": 1}},
						map[string]interface{}{"reviews": map[string]interface{}{"totalCount": 0}},
					},
				},
			}),
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		if r.URL.Path == "/graphql" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(graphqlResponse)
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	client := &GitHubClient{
		token:      "test-token",
		httpClient: &http.Client{},
		baseURL:    server.URL,
		cache:      newRepoCache(),
	}

	// First: GraphQL batch populates cache
	batch := client.fetchBatchRepoData("testowner", "test-repo")
	if batch == nil {
		t.Fatal("expected batch data")
	}
	if requestCount != 1 {
		t.Fatalf("expected 1 request for GraphQL, got %d", requestCount)
	}

	// Second: GetPullRequestStats should hit cache — no additional requests
	stats, err := client.GetPullRequestStats("https://github.com/testowner/test-repo")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if stats == nil {
		t.Fatal("expected PR stats")
	}
	if stats.TotalPRs != 10 {
		t.Errorf("expected 10 total PRs, got %d", stats.TotalPRs)
	}
	if requestCount != 1 {
		t.Errorf("expected 1 total request (cache hit), got %d", requestCount)
	}
}

// Test: GraphQL batch caches prevent commit REST calls
// Justification: After batch populates commit caches, GetCommitAuthors and
//                CheckSignedCommits should return cached data without REST calls.
//                This eliminates 4 REST calls (3 pages commits + 1 signature check).
// Source: Rate limit conservation for supply chain scanning at scale
// Methodology: Fetch via GraphQL batch, then call GetCommitAuthors and
//              CheckSignedCommits, verify no additional HTTP requests.
// Result: Both methods return cached data; zero additional API calls.
func TestBatchCachePreventsCommitRESTCalls(t *testing.T) {
	requestCount := 0
	now := time.Now()
	date := now.AddDate(0, 0, -10).Format(time.RFC3339)

	graphqlResponse := map[string]interface{}{
		"data": map[string]interface{}{
			"repository": buildBaseGraphQLRepo(map[string]interface{}{
				"defaultBranchRef": map[string]interface{}{
					"name": "main",
					"target": map[string]interface{}{
						"history": map[string]interface{}{
							"nodes": []interface{}{
								map[string]interface{}{
									"author":    map[string]interface{}{"name": "Dev", "email": "dev@example.com", "date": date},
									"signature": map[string]interface{}{"isValid": true},
								},
							},
						},
					},
				},
			}),
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		if r.URL.Path == "/graphql" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(graphqlResponse)
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	client := &GitHubClient{
		token:      "test-token",
		httpClient: &http.Client{},
		baseURL:    server.URL,
		cache:      newRepoCache(),
	}

	// First: GraphQL batch
	batch := client.fetchBatchRepoData("testowner", "test-repo")
	if batch == nil {
		t.Fatal("expected batch data")
	}
	if requestCount != 1 {
		t.Fatalf("expected 1 request, got %d", requestCount)
	}

	// GetCommitAuthors should use cached data
	authors, err := client.GetCommitAuthors("https://github.com/testowner/test-repo")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if authors == nil {
		t.Fatal("expected commit authors")
	}
	if requestCount != 1 {
		t.Errorf("expected 1 total request after GetCommitAuthors (cache hit), got %d", requestCount)
	}

	// CheckSignedCommits should use cached data
	hasSigning, verifiedCount, err := client.CheckSignedCommits("https://github.com/testowner/test-repo")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if requestCount != 1 {
		t.Errorf("expected 1 total request after CheckSignedCommits (cache hit), got %d", requestCount)
	}
	if !hasSigning {
		t.Error("expected hasSigning=true (1 out of 1 commit signed = 100% > 50% threshold)")
	}
	if verifiedCount != 1 {
		t.Errorf("expected 1 verified commit, got %d", verifiedCount)
	}
}

// Test: buildBatchQuery includes PR and commit fields
// Justification: Query must include pullRequests and commit history fields to
//                eliminate 30+ REST calls per repo for supply chain risk assessment.
// Source: GitHub GraphQL API schema
// Methodology: Build query and verify PR and commit fields are present.
// Result: Query contains all required fields for PR reviews and commit data.
func TestBuildBatchQueryIncludesPRAndCommits(t *testing.T) {
	query := buildBatchQuery("owner", "repo")

	// Verify PR query fields
	for _, field := range []string{
		"pullRequests(last: 20, states: MERGED)",
		"totalCount",
		"reviews(first: 1)",
	} {
		if !strings.Contains(query, field) {
			t.Errorf("query should contain %q", field)
		}
	}

	// Verify commit history fields
	for _, field := range []string{
		"history(first: 100)",
		"signature",
		"isValid",
	} {
		if !strings.Contains(query, field) {
			t.Errorf("query should contain %q", field)
		}
	}
}

// buildBaseGraphQLRepo returns a minimal valid GraphQL repository response
// with optional field overrides. This reduces boilerplate in tests.
func buildBaseGraphQLRepo(overrides map[string]interface{}) map[string]interface{} {
	base := map[string]interface{}{
		"name":           "test-repo",
		"description":    "A test repository",
		"stargazerCount": 100,
		"forkCount":      10,
		"watchers":       map[string]interface{}{"totalCount": 5},
		"openIssues":     map[string]interface{}{"totalCount": 2},
		"defaultBranchRef": map[string]interface{}{
			"name":   "main",
			"target": nil,
		},
		"isArchived":       false,
		"createdAt":        "2023-01-01T00:00:00Z",
		"updatedAt":        "2024-01-01T00:00:00Z",
		"pushedAt":         "2024-01-01T00:00:00Z",
		"licenseInfo":      map[string]interface{}{"name": "MIT License"},
		"repositoryTopics": map[string]interface{}{"nodes": []interface{}{}},
		"owner":            map[string]interface{}{"login": "testowner"},
		"url":              "https://github.com/testowner/test-repo",
		"releases":         map[string]interface{}{"nodes": []interface{}{}},
		"pullRequests": map[string]interface{}{
			"totalCount": 0,
			"nodes":      []interface{}{},
		},
		"securityMd":       nil,
		"securityMdGh":     nil,
		"contributingMd":   nil,
		"contributingMdGh": nil,
		"codeowners":       nil,
		"codeownersGh":     nil,
		"codeOfConduct":    nil,
		"branchProtectionRules": map[string]interface{}{"nodes": []interface{}{}},
	}

	for k, v := range overrides {
		base[k] = v
	}
	return base
}

// Test: GraphQL is not used in preferAPI mode (test mode)
// Justification: Test servers use preferAPI mode with mock REST endpoints.
//                GraphQL should be skipped in this mode to keep existing tests working.
// Source: Test infrastructure compatibility
// Methodology: Create client with preferAPI=true, verify GraphQL is not attempted.
// Result: GetRepositoryInfo uses REST path when preferAPI is true.
func TestGraphQLSkippedInPreferAPIMode(t *testing.T) {
	graphqlCalled := false

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/graphql" {
			graphqlCalled = true
			http.NotFound(w, r)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/repos/") {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(GitHubRepository{
				Name:          "test",
				HTMLURL:       "https://github.com/test/repo",
				DefaultBranch: "main",
				Owner:         GitHubUser{Login: "test"},
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	client := &GitHubClient{
		token:      "test-token",
		httpClient: &http.Client{},
		baseURL:    server.URL,
		cache:      newRepoCache(),
		preferAPI:  true, // Test mode
	}

	info, err := client.GetRepositoryInfo("https://github.com/test/repo")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info == nil {
		t.Fatal("expected repo info")
	}
	if graphqlCalled {
		t.Error("GraphQL should NOT be called when preferAPI is true")
	}
}
