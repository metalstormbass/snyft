package fetcher

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/metalstormbass/snyft/pkg/models"
)

// graphqlEndpoint is the GitHub GraphQL API endpoint.
const graphqlEndpoint = "https://api.github.com/graphql"

// graphqlRequest is the JSON payload sent to the GraphQL API.
type graphqlRequest struct {
	Query     string            `json:"query"`
	Variables map[string]string `json:"variables,omitempty"`
}

// graphqlResponse is the top-level response from the GraphQL API.
type graphqlResponse struct {
	Data   json.RawMessage  `json:"data"`
	Errors []graphqlError   `json:"errors,omitempty"`
}

// graphqlError represents a single error returned by the GraphQL API.
type graphqlError struct {
	Message string `json:"message"`
	Type    string `json:"type"`
}

// graphqlQuery executes a GraphQL query against the GitHub API.
// Returns the raw JSON data field from the response. Requires authentication
// (GraphQL API does not support unauthenticated requests).
func (c *GitHubClient) graphqlQuery(query string) (json.RawMessage, error) {
	if c.token == "" {
		return nil, fmt.Errorf("GraphQL API requires authentication")
	}

	payload := graphqlRequest{Query: query}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal GraphQL request: %w", err)
	}

	// Use the graphqlEndpoint for real requests, but support custom baseURL
	// for test servers by appending /graphql to the base URL.
	endpoint := graphqlEndpoint
	if c.baseURL != "https://api.github.com" {
		endpoint = c.baseURL + "/graphql"
	}

	req, err := http.NewRequest("POST", endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create GraphQL request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.doRequest(req)
	if err != nil {
		return nil, fmt.Errorf("GraphQL request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read GraphQL response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GraphQL API returned %d: %s", resp.StatusCode, string(respBody))
	}

	var gqlResp graphqlResponse
	if err := json.Unmarshal(respBody, &gqlResp); err != nil {
		return nil, fmt.Errorf("failed to parse GraphQL response: %w", err)
	}

	if len(gqlResp.Errors) > 0 {
		msgs := make([]string, len(gqlResp.Errors))
		for i, e := range gqlResp.Errors {
			msgs[i] = e.Message
		}
		return nil, fmt.Errorf("GraphQL errors: %s", strings.Join(msgs, "; "))
	}

	return gqlResp.Data, nil
}

// batchRepoData holds the parsed result of a batched GraphQL query.
// It aggregates data that would otherwise require 30+ REST API calls.
type batchRepoData struct {
	RepoInfo         *models.RepositoryInfo
	Releases         []GitHubRelease
	DefaultBranch    string
	GovernanceFiles map[string]bool // path -> exists
	PRStats         *PRStats            // merged PR review stats
	CommitAuthors    *CommitAuthorStats  // commit author distribution
	SignedCommits    *cachedSignedCommits // commit signature verification
}

// buildBatchQuery constructs a GraphQL query that fetches repo metadata,
// recent releases, governance file existence, merged PRs
// with review status, and commit history with author/signature data in one call.
//
// This replaces 30+ REST API calls:
//   - GET /repos/{owner}/{repo}              (repo info)
//   - GET /repos/{owner}/{repo}/releases     (releases)
//   - HEAD /repos/{owner}/{repo}/contents/SECURITY.md (governance)
//   - HEAD /repos/{owner}/{repo}/contents/.github/SECURITY.md
//   - HEAD /repos/{owner}/{repo}/contents/CONTRIBUTING.md
//   - HEAD /repos/{owner}/{repo}/contents/.github/CONTRIBUTING.md
//   - HEAD /repos/{owner}/{repo}/contents/CODEOWNERS
//   - HEAD /repos/{owner}/{repo}/contents/.github/CODEOWNERS
//   - HEAD /repos/{owner}/{repo}/contents/CODE_OF_CONDUCT.md
//   - GET  /repos/{owner}/{repo}/branches/{branch}/protection
//   - GET  /repos/{owner}/{repo}/pulls?state=closed (PR list)
//   - GET  /repos/{owner}/{repo}/pulls/{n}/reviews  (up to 20 per-PR review checks)
//   - GET  /repos/{owner}/{repo}/commits (3 pages for commit authors)
//   - GET  /repos/{owner}/{repo}/commits (1 page for signed commits)
func buildBatchQuery(owner, repo string) string {
	// GitHub GraphQL uses `object` queries to check file existence.
	// A non-null result means the file exists in the default branch.
	return fmt.Sprintf(`{
  repository(owner: %q, name: %q) {
    name
    description
    stargazerCount
    forkCount
    watchers { totalCount }
    openIssues: issues(states: OPEN) { totalCount }
    defaultBranchRef {
      name
      target {
        ... on Commit {
          history(first: 100) {
            nodes {
              author {
                name
                email
                date
              }
              signature {
                isValid
              }
            }
          }
        }
      }
    }
    isArchived
    createdAt
    updatedAt
    pushedAt
    licenseInfo { name }
    repositoryTopics(first: 20) {
      nodes { topic { name } }
    }
    owner { login }
    url
    releases(first: 30, orderBy: {field: CREATED_AT, direction: DESC}) {
      nodes {
        tagName
        name
        isDraft
        isPrerelease
        createdAt
        publishedAt
        releaseAssets(first: 20) {
          nodes {
            name
            contentType
            size
            downloadUrl
          }
        }
      }
    }
    pullRequests(last: 20, states: MERGED) {
      totalCount
      nodes {
        reviews(first: 1) {
          totalCount
        }
      }
    }
    securityMd: object(expression: "HEAD:SECURITY.md") { __typename }
    securityMdGh: object(expression: "HEAD:.github/SECURITY.md") { __typename }
    contributingMd: object(expression: "HEAD:CONTRIBUTING.md") { __typename }
    contributingMdGh: object(expression: "HEAD:.github/CONTRIBUTING.md") { __typename }
    codeowners: object(expression: "HEAD:CODEOWNERS") { __typename }
    codeownersGh: object(expression: "HEAD:.github/CODEOWNERS") { __typename }
    codeOfConduct: object(expression: "HEAD:CODE_OF_CONDUCT.md") { __typename }
  }
}`, owner, repo)
}

// graphqlRepoResponse mirrors the GraphQL response shape for repository data.
type graphqlRepoResponse struct {
	Repository *graphqlRepository `json:"repository"`
}

type graphqlRepository struct {
	Name                 string                  `json:"name"`
	Description          string                  `json:"description"`
	StargazerCount       int                     `json:"stargazerCount"`
	ForkCount            int                     `json:"forkCount"`
	Watchers             graphqlTotalCount       `json:"watchers"`
	OpenIssues           graphqlTotalCount       `json:"openIssues"`
	DefaultBranchRef     *graphqlRef             `json:"defaultBranchRef"`
	IsArchived           bool                    `json:"isArchived"`
	CreatedAt            time.Time               `json:"createdAt"`
	UpdatedAt            time.Time               `json:"updatedAt"`
	PushedAt             time.Time               `json:"pushedAt"`
	LicenseInfo          *graphqlLicense         `json:"licenseInfo"`
	RepositoryTopics     graphqlTopicConnection  `json:"repositoryTopics"`
	Owner                graphqlOwner            `json:"owner"`
	URL                  string                  `json:"url"`
	Releases             graphqlReleaseConnection     `json:"releases"`
	PullRequests         graphqlPullRequestConnection `json:"pullRequests"`

	// Governance file existence checks (non-null = file exists)
	SecurityMd       *graphqlObject `json:"securityMd"`
	SecurityMdGh     *graphqlObject `json:"securityMdGh"`
	ContributingMd   *graphqlObject `json:"contributingMd"`
	ContributingMdGh *graphqlObject `json:"contributingMdGh"`
	Codeowners       *graphqlObject `json:"codeowners"`
	CodeownersGh     *graphqlObject `json:"codeownersGh"`
	CodeOfConduct    *graphqlObject `json:"codeOfConduct"`

}

type graphqlTotalCount struct {
	TotalCount int `json:"totalCount"`
}

type graphqlRef struct {
	Name   string             `json:"name"`
	Target *graphqlCommitTarget `json:"target"`
}

type graphqlCommitTarget struct {
	History *graphqlCommitHistory `json:"history"`
}

type graphqlCommitHistory struct {
	Nodes []graphqlCommitNode `json:"nodes"`
}

type graphqlCommitNode struct {
	Author    graphqlCommitAuthor    `json:"author"`
	Signature *graphqlCommitSignature `json:"signature"`
}

type graphqlCommitAuthor struct {
	Name  string    `json:"name"`
	Email string    `json:"email"`
	Date  time.Time `json:"date"`
}

type graphqlCommitSignature struct {
	IsValid bool `json:"isValid"`
}

type graphqlLicense struct {
	Name string `json:"name"`
}

type graphqlOwner struct {
	Login string `json:"login"`
}

type graphqlObject struct {
	TypeName string `json:"__typename"`
}

type graphqlTopicConnection struct {
	Nodes []graphqlTopicNode `json:"nodes"`
}

type graphqlTopicNode struct {
	Topic graphqlTopic `json:"topic"`
}

type graphqlTopic struct {
	Name string `json:"name"`
}

type graphqlReleaseConnection struct {
	Nodes []graphqlRelease `json:"nodes"`
}

type graphqlRelease struct {
	TagName       string                   `json:"tagName"`
	Name          string                   `json:"name"`
	IsDraft       bool                     `json:"isDraft"`
	IsPrerelease  bool                     `json:"isPrerelease"`
	CreatedAt     time.Time                `json:"createdAt"`
	PublishedAt   time.Time                `json:"publishedAt"`
	ReleaseAssets graphqlReleaseAssetConnection `json:"releaseAssets"`
}

type graphqlReleaseAssetConnection struct {
	Nodes []graphqlReleaseAsset `json:"nodes"`
}

type graphqlReleaseAsset struct {
	Name        string `json:"name"`
	ContentType string `json:"contentType"`
	Size        int64  `json:"size"`
	DownloadURL string `json:"downloadUrl"`
}

type graphqlPullRequestConnection struct {
	TotalCount int                  `json:"totalCount"`
	Nodes      []graphqlPullRequest `json:"nodes"`
}

type graphqlPullRequest struct {
	Reviews graphqlReviewConnection `json:"reviews"`
}

type graphqlReviewConnection struct {
	TotalCount int `json:"totalCount"`
}

// fetchBatchRepoData executes a single GraphQL query to fetch repository info,
// releases, governance file existence, and branch protection rules. The results
// are cached so subsequent REST-based callers (getReleases, fileExists,
// getBranchProtection, GetRepositoryInfo) get cache hits instead of making
// additional network requests.
//
// Returns nil if the GraphQL query fails (caller should fall back to REST).
func (c *GitHubClient) fetchBatchRepoData(owner, repo string) *batchRepoData {
	query := buildBatchQuery(owner, repo)
	data, err := c.graphqlQuery(query)
	if err != nil {
		return nil
	}

	var resp graphqlRepoResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil
	}

	if resp.Repository == nil {
		return nil
	}

	r := resp.Repository

	// Build RepositoryInfo
	defaultBranch := "main"
	if r.DefaultBranchRef != nil {
		defaultBranch = r.DefaultBranchRef.Name
	}

	var topics []string
	for _, tn := range r.RepositoryTopics.Nodes {
		topics = append(topics, tn.Topic.Name)
	}

	licenseName := ""
	if r.LicenseInfo != nil {
		licenseName = r.LicenseInfo.Name
	}

	repoInfo := &models.RepositoryInfo{
		URL:           r.URL,
		Owner:         r.Owner.Login,
		Name:          r.Name,
		Description:   r.Description,
		Stars:         r.StargazerCount,
		Forks:         r.ForkCount,
		Watchers:      r.Watchers.TotalCount,
		OpenIssues:    r.OpenIssues.TotalCount,
		DefaultBranch: defaultBranch,
		Archived:      r.IsArchived,
		CreatedAt:     r.CreatedAt,
		UpdatedAt:     r.UpdatedAt,
		PushedAt:      r.PushedAt,
		License:       licenseName,
		Topics:        topics,
	}

	// Build releases
	var releases []GitHubRelease
	for _, rel := range r.Releases.Nodes {
		ghRelease := GitHubRelease{
			TagName:     rel.TagName,
			Name:        rel.Name,
			Draft:       rel.IsDraft,
			Prerelease:  rel.IsPrerelease,
			CreatedAt:   rel.CreatedAt,
			PublishedAt: rel.PublishedAt,
		}
		for _, asset := range rel.ReleaseAssets.Nodes {
			ghRelease.Assets = append(ghRelease.Assets, GitHubAsset{
				Name:               asset.Name,
				ContentType:        asset.ContentType,
				Size:               asset.Size,
				BrowserDownloadURL: asset.DownloadURL,
			})
		}
		releases = append(releases, ghRelease)
	}

	// Build governance file existence map
	govFiles := map[string]bool{
		"SECURITY.md":                r.SecurityMd != nil,
		".github/SECURITY.md":       r.SecurityMdGh != nil,
		"CONTRIBUTING.md":           r.ContributingMd != nil,
		".github/CONTRIBUTING.md":   r.ContributingMdGh != nil,
		"CODEOWNERS":               r.Codeowners != nil,
		".github/CODEOWNERS":       r.CodeownersGh != nil,
		"CODE_OF_CONDUCT.md":       r.CodeOfConduct != nil,
	}

	// Build PR stats from merged PRs with review data
	prStats := buildPRStatsFromGraphQL(r)

	// Build commit author stats and signed commit data from commit history
	commitAuthors, signedCommits := buildCommitDataFromGraphQL(r)

	result := &batchRepoData{
		RepoInfo:               repoInfo,
		Releases:               releases,
		DefaultBranch:          defaultBranch,
		GovernanceFiles: govFiles,
		PRStats:         prStats,
		CommitAuthors:          commitAuthors,
		SignedCommits:          signedCommits,
	}

	// Populate caches so subsequent REST-path callers get cache hits.
	c.populateCachesFromBatch(owner, repo, result)

	return result
}

// populateCachesFromBatch stores batch query results in the per-repo caches.
// This ensures that methods like getReleases and fileExists
// find cached data and skip their own REST API calls.
func (c *GitHubClient) populateCachesFromBatch(owner, repo string, batch *batchRepoData) {
	if c.cache == nil {
		return
	}

	cacheKey := owner + "/" + repo

	// Cache repo info
	if batch.RepoInfo != nil {
		c.cache.setRepoInfo(cacheKey, batch.RepoInfo)
	}

	// Cache releases
	if batch.Releases != nil {
		c.cache.setCachedReleases(cacheKey, batch.Releases)
	}

	// Cache governance file existence
	for path, exists := range batch.GovernanceFiles {
		fileCacheKey := owner + "/" + repo + "/" + path
		c.cache.setFileExists(fileCacheKey, exists)
	}

	// Cache PR stats
	if batch.PRStats != nil {
		c.cache.setPRStats(cacheKey, batch.PRStats)
	}

	// Cache commit author stats
	if batch.CommitAuthors != nil {
		c.cache.setCommitAuthors(cacheKey, batch.CommitAuthors)
	}

	// Cache signed commit data
	if batch.SignedCommits != nil {
		c.cache.setSignedCommits(cacheKey, batch.SignedCommits)
	}
}

// buildPRStatsFromGraphQL constructs PRStats from the GraphQL pullRequests
// data. This replaces up to 21 REST API calls:
// 1 for the PR list + up to 20 per-PR review checks.
func buildPRStatsFromGraphQL(r *graphqlRepository) *PRStats {
	stats := &PRStats{}

	prs := r.PullRequests.Nodes
	stats.TotalPRs = r.PullRequests.TotalCount
	stats.MergedPRs = r.PullRequests.TotalCount

	// Count PRs with at least one review
	for _, pr := range prs {
		if pr.Reviews.TotalCount > 0 {
			stats.PRsWithReviews++
		}
	}

	// Calculate code review rate based on the sampled PRs
	sampledPRs := len(prs)
	if sampledPRs > 0 {
		stats.CodeReviewRate = float64(stats.PRsWithReviews) / float64(sampledPRs) * 100
	}

	return stats
}

// buildCommitDataFromGraphQL constructs CommitAuthorStats and cachedSignedCommits
// from the GraphQL defaultBranchRef commit history. This replaces 3 pages of
// commit REST calls for author stats plus 1 page for signature verification.
func buildCommitDataFromGraphQL(r *graphqlRepository) (*CommitAuthorStats, *cachedSignedCommits) {
	if r.DefaultBranchRef == nil || r.DefaultBranchRef.Target == nil || r.DefaultBranchRef.Target.History == nil {
		return nil, nil
	}

	commits := r.DefaultBranchRef.Target.History.Nodes
	if len(commits) == 0 {
		return nil, nil
	}

	// Build commit author stats
	stats := &CommitAuthorStats{
		AuthorCommitCounts: make(map[string]int),
		AuthorFirstCommit:  make(map[string]time.Time),
		AuthorLastCommit:   make(map[string]time.Time),
		RecentAuthors:      []string{},
		HistoricalAuthors:  []string{},
	}

	verifiedCount := 0

	for _, commit := range commits {
		authorName := commit.Author.Name
		authorEmail := commit.Author.Email
		commitDate := commit.Author.Date

		// Use email as unique identifier (more reliable than name)
		authorID := authorEmail
		if authorID == "" {
			authorID = authorName
		}
		if authorID == "" {
			continue
		}

		stats.TotalCommits++
		stats.AuthorCommitCounts[authorID]++

		if firstCommit, exists := stats.AuthorFirstCommit[authorID]; !exists || commitDate.Before(firstCommit) {
			stats.AuthorFirstCommit[authorID] = commitDate
		}
		if lastCommit, exists := stats.AuthorLastCommit[authorID]; !exists || commitDate.After(lastCommit) {
			stats.AuthorLastCommit[authorID] = commitDate
		}

		// Count verified signatures
		if commit.Signature != nil && commit.Signature.IsValid {
			verifiedCount++
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

	// Consider "signed commits enabled" if >50% of recent commits are signed
	hasSigning := float64(verifiedCount)/float64(len(commits)) > 0.5

	signedCommitsData := &cachedSignedCommits{
		hasSigning:    hasSigning,
		verifiedCount: verifiedCount,
	}

	return stats, signedCommitsData
}

// batchCheckPRReviewsGraphQL fetches review status for multiple PRs in a single
// GraphQL query. Returns a map of PR number -> hasReviews. Returns nil if the
// query fails (caller should fall back to individual REST calls).
//
// This replaces up to 20 individual GET /repos/{owner}/{repo}/pulls/{n}/reviews
// REST calls with a single GraphQL request.
func (c *GitHubClient) batchCheckPRReviewsGraphQL(owner, repo string, prNumbers []int) map[int]bool {
	if len(prNumbers) == 0 {
		return make(map[int]bool)
	}

	// Build aliased fields: pr1: pullRequest(number: 1) { reviews(first: 1) { totalCount } }
	var fields []string
	for _, num := range prNumbers {
		fields = append(fields, fmt.Sprintf("pr%d: pullRequest(number: %d) { reviews(first: 1) { totalCount } }", num, num))
	}

	query := fmt.Sprintf("{ repository(owner: %q, name: %q) { %s } }", owner, repo, strings.Join(fields, " "))

	data, err := c.graphqlQuery(query)
	if err != nil {
		return nil
	}

	// Parse: { "repository": { "pr1": { "reviews": { "totalCount": N } }, ... } }
	var wrapper struct {
		Repository json.RawMessage `json:"repository"`
	}
	if err := json.Unmarshal(data, &wrapper); err != nil {
		return nil
	}

	var prMap map[string]json.RawMessage
	if err := json.Unmarshal(wrapper.Repository, &prMap); err != nil {
		return nil
	}

	result := make(map[int]bool)
	for _, num := range prNumbers {
		key := fmt.Sprintf("pr%d", num)
		if raw, ok := prMap[key]; ok {
			var pr struct {
				Reviews struct {
					TotalCount int `json:"totalCount"`
				} `json:"reviews"`
			}
			if err := json.Unmarshal(raw, &pr); err == nil {
				result[num] = pr.Reviews.TotalCount > 0
			}
		}
	}

	return result
}
