package fetcher

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// OSSFClient handles interactions with OpenSSF Scorecard API
type OSSFClient struct {
	httpClient *http.Client
	baseURL    string
}

// OSSFScorecard represents an OpenSSF Scorecard result
type OSSFScorecard struct {
	Score  float64
	Checks map[string]int
}

// NewOSSFClient creates a new OSSF Scorecard client
func NewOSSFClient() *OSSFClient {
	return &OSSFClient{
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		baseURL: "https://api.securityscorecards.dev",
	}
}

// GetScorecard fetches the OpenSSF Scorecard for a repository
func (c *OSSFClient) GetScorecard(repoURL string) (*OSSFScorecard, error) {
	owner, repo, err := parseGitHubURL(repoURL)
	if err != nil {
		return nil, err
	}

	// OSSF Scorecard API endpoint
	url := fmt.Sprintf("%s/projects/github.com/%s/%s", c.baseURL, owner, repo)

	resp, err := c.httpClient.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch OSSF scorecard: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("scorecard not found for repository")
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OSSF API returned status %d", resp.StatusCode)
	}

	var ossfResp OSSFResponse
	if err := json.NewDecoder(resp.Body).Decode(&ossfResp); err != nil {
		return nil, fmt.Errorf("failed to decode OSSF response: %w", err)
	}

	scorecard := &OSSFScorecard{
		Score:  ossfResp.Score,
		Checks: make(map[string]int),
	}

	for _, check := range ossfResp.Checks {
		scorecard.Checks[check.Name] = check.Score
	}

	return scorecard, nil
}

// OSSF API response structures
type OSSFResponse struct {
	Date   string      `json:"date"`
	Repo   OSSFRepo    `json:"repo"`
	Score  float64     `json:"score"`
	Checks []OSSFCheck `json:"checks"`
}

type OSSFRepo struct {
	Name   string `json:"name"`
	Commit string `json:"commit"`
}

type OSSFCheck struct {
	Name   string `json:"name"`
	Score  int    `json:"score"`
	Reason string `json:"reason"`
}
