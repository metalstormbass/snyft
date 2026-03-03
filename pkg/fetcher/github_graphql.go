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
// It aggregates data that would otherwise require 10+ REST API calls.
type batchRepoData struct {
	RepoInfo         *models.RepositoryInfo
	Releases         []GitHubRelease
	DefaultBranch    string
	GovernanceFiles  map[string]bool // path -> exists
	BranchProtection *GitHubBranchProtection
	BranchProtectionDenied bool
}

// buildBatchQuery constructs a GraphQL query that fetches repo metadata,
// recent releases, governance file existence, and branch protection in one call.
//
// This replaces 10+ REST API calls:
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
    defaultBranchRef { name }
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
    securityMd: object(expression: "HEAD:SECURITY.md") { __typename }
    securityMdGh: object(expression: "HEAD:.github/SECURITY.md") { __typename }
    contributingMd: object(expression: "HEAD:CONTRIBUTING.md") { __typename }
    contributingMdGh: object(expression: "HEAD:.github/CONTRIBUTING.md") { __typename }
    codeowners: object(expression: "HEAD:CODEOWNERS") { __typename }
    codeownersGh: object(expression: "HEAD:.github/CODEOWNERS") { __typename }
    codeOfConduct: object(expression: "HEAD:CODE_OF_CONDUCT.md") { __typename }
    branchProtectionRules(first: 5) {
      nodes {
        pattern
        requiredApprovingReviewCount
      }
    }
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
	Releases             graphqlReleaseConnection `json:"releases"`

	// Governance file existence checks (non-null = file exists)
	SecurityMd       *graphqlObject `json:"securityMd"`
	SecurityMdGh     *graphqlObject `json:"securityMdGh"`
	ContributingMd   *graphqlObject `json:"contributingMd"`
	ContributingMdGh *graphqlObject `json:"contributingMdGh"`
	Codeowners       *graphqlObject `json:"codeowners"`
	CodeownersGh     *graphqlObject `json:"codeownersGh"`
	CodeOfConduct    *graphqlObject `json:"codeOfConduct"`

	// Branch protection
	BranchProtectionRules graphqlBranchProtectionConnection `json:"branchProtectionRules"`
}

type graphqlTotalCount struct {
	TotalCount int `json:"totalCount"`
}

type graphqlRef struct {
	Name string `json:"name"`
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

type graphqlBranchProtectionConnection struct {
	Nodes []graphqlBranchProtectionRule `json:"nodes"`
}

type graphqlBranchProtectionRule struct {
	Pattern                      string `json:"pattern"`
	RequiredApprovingReviewCount int    `json:"requiredApprovingReviewCount"`
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

	// Build branch protection
	var branchProtection *GitHubBranchProtection
	for _, rule := range r.BranchProtectionRules.Nodes {
		// Match the default branch pattern
		if rule.Pattern == defaultBranch || rule.Pattern == "*" {
			branchProtection = &GitHubBranchProtection{
				RequiredReviews: &GitHubRequiredReviews{
					RequiredApprovingReviewCount: rule.RequiredApprovingReviewCount,
				},
			}
			break
		}
	}

	result := &batchRepoData{
		RepoInfo:               repoInfo,
		Releases:               releases,
		DefaultBranch:          defaultBranch,
		GovernanceFiles:        govFiles,
		BranchProtection:       branchProtection,
		BranchProtectionDenied: false,
	}

	// Populate caches so subsequent REST-path callers get cache hits.
	c.populateCachesFromBatch(owner, repo, result)

	return result
}

// populateCachesFromBatch stores batch query results in the per-repo caches.
// This ensures that methods like getReleases, fileExists, and getBranchProtection
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
}
