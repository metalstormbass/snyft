package fetcher

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/metalstormbass/snyft/pkg/models"
)

// GitHubClient handles interactions with GitHub API
type GitHubClient struct {
	token      string
	httpClient *http.Client
	baseURL    string
}

// NewGitHubClient creates a new GitHub API client
func NewGitHubClient() *GitHubClient {
	return &GitHubClient{
		token: os.Getenv("GITHUB_TOKEN"),
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		baseURL: "https://api.github.com",
	}
}

// GetRepositoryInfo fetches repository information from GitHub
func (c *GitHubClient) GetRepositoryInfo(repoURL string) (*models.RepositoryInfo, error) {
	owner, repo, err := parseGitHubURL(repoURL)
	if err != nil {
		return nil, err
	}

	url := fmt.Sprintf("%s/repos/%s/%s", c.baseURL, owner, repo)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("GitHub API returned %d: %s", resp.StatusCode, string(body))
	}

	var ghRepo GitHubRepository
	if err := json.NewDecoder(resp.Body).Decode(&ghRepo); err != nil {
		return nil, err
	}

	return &models.RepositoryInfo{
		URL:           ghRepo.HTMLURL,
		Owner:         ghRepo.Owner.Login,
		Name:          ghRepo.Name,
		Description:   ghRepo.Description,
		Stars:         ghRepo.StargazersCount,
		Forks:         ghRepo.ForksCount,
		Watchers:      ghRepo.WatchersCount,
		OpenIssues:    ghRepo.OpenIssuesCount,
		DefaultBranch: ghRepo.DefaultBranch,
		Archived:      ghRepo.Archived,
		CreatedAt:     ghRepo.CreatedAt,
		UpdatedAt:     ghRepo.UpdatedAt,
		PushedAt:      ghRepo.PushedAt,
		License:       getLicenseName(ghRepo.License),
		Topics:        ghRepo.Topics,
	}, nil
}

// DetectCISystems checks for common CI/CD systems in the repository
func (c *GitHubClient) DetectCISystems(repoURL string) ([]string, error) {
	owner, repo, err := parseGitHubURL(repoURL)
	if err != nil {
		return nil, err
	}

	var ciSystems []string

	// Check for GitHub Actions
	if c.fileExists(owner, repo, ".github/workflows") {
		ciSystems = append(ciSystems, "GitHub Actions")
	}

	// Check for Travis CI
	if c.fileExists(owner, repo, ".travis.yml") {
		ciSystems = append(ciSystems, "Travis CI")
	}

	// Check for Circle CI
	if c.fileExists(owner, repo, ".circleci/config.yml") {
		ciSystems = append(ciSystems, "Circle CI")
	}

	// Check for Jenkins
	if c.fileExists(owner, repo, "Jenkinsfile") {
		ciSystems = append(ciSystems, "Jenkins")
	}

	// Check for GitLab CI
	if c.fileExists(owner, repo, ".gitlab-ci.yml") {
		ciSystems = append(ciSystems, "GitLab CI")
	}

	return ciSystems, nil
}

// HasAutomatedReleases checks if the repository has automated releases
func (c *GitHubClient) HasAutomatedReleases(repoURL string) (bool, error) {
	owner, repo, err := parseGitHubURL(repoURL)
	if err != nil {
		return false, err
	}

	url := fmt.Sprintf("%s/repos/%s/%s/releases", c.baseURL, owner, repo)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return false, err
	}

	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, nil
	}

	var releases []GitHubRelease
	if err := json.NewDecoder(resp.Body).Decode(&releases); err != nil {
		return false, err
	}

	return len(releases) > 0, nil
}

func (c *GitHubClient) fileExists(owner, repo, path string) bool {
	url := fmt.Sprintf("%s/repos/%s/%s/contents/%s", c.baseURL, owner, repo, path)
	req, err := http.NewRequest("HEAD", url, nil)
	if err != nil {
		return false
	}

	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode == http.StatusOK
}

// GitHub API response structures
type GitHubRepository struct {
	Name            string         `json:"name"`
	FullName        string         `json:"full_name"`
	HTMLURL         string         `json:"html_url"`
	Description     string         `json:"description"`
	StargazersCount int            `json:"stargazers_count"`
	ForksCount      int            `json:"forks_count"`
	WatchersCount   int            `json:"watchers_count"`
	OpenIssuesCount int            `json:"open_issues_count"`
	DefaultBranch   string         `json:"default_branch"`
	Archived        bool           `json:"archived"`
	CreatedAt       time.Time      `json:"created_at"`
	UpdatedAt       time.Time      `json:"updated_at"`
	PushedAt        time.Time      `json:"pushed_at"`
	License         *GitHubLicense `json:"license"`
	Topics          []string       `json:"topics"`
	Owner           GitHubUser     `json:"owner"`
}

type GitHubUser struct {
	Login string `json:"login"`
}

type GitHubLicense struct {
	Key  string `json:"key"`
	Name string `json:"name"`
}

type GitHubRelease struct {
	TagName string    `json:"tag_name"`
	Name    string    `json:"name"`
	Draft   bool      `json:"draft"`
	Created time.Time `json:"created_at"`
}

func parseGitHubURL(repoURL string) (owner, repo string, err error) {
	// Handle various GitHub URL formats:
	// https://github.com/owner/repo
	// git://github.com/owner/repo.git
	// git+https://github.com/owner/repo.git

	repoURL = strings.TrimSpace(repoURL)
	repoURL = strings.TrimPrefix(repoURL, "git+")
	repoURL = strings.TrimPrefix(repoURL, "git://")
	repoURL = strings.TrimPrefix(repoURL, "https://")
	repoURL = strings.TrimPrefix(repoURL, "http://")
	repoURL = strings.TrimSuffix(repoURL, ".git")

	parts := strings.Split(repoURL, "/")
	if len(parts) < 3 || !strings.Contains(parts[0], "github") {
		return "", "", fmt.Errorf("invalid GitHub URL: %s", repoURL)
	}

	// Find github.com and get owner/repo
	for i, part := range parts {
		if strings.Contains(part, "github") && i+2 < len(parts) {
			return parts[i+1], parts[i+2], nil
		}
	}

	return "", "", fmt.Errorf("could not parse GitHub URL: %s", repoURL)
}

func getLicenseName(license *GitHubLicense) string {
	if license == nil {
		return ""
	}
	return license.Name
}
