package fetcher

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestCheckSignedCommits(t *testing.T) {
	tests := []struct {
		name               string
		commits            []GitHubCommit
		expectedHasSigning bool
		expectedCount      int
	}{
		{
			name: "all commits signed",
			commits: []GitHubCommit{
				{SHA: "abc123", Commit: GitHubCommitInfo{Verification: GitHubCommitVerification{Verified: true}}},
				{SHA: "def456", Commit: GitHubCommitInfo{Verification: GitHubCommitVerification{Verified: true}}},
			},
			expectedHasSigning: true,
			expectedCount:      2,
		},
		{
			name: "no commits signed",
			commits: []GitHubCommit{
				{SHA: "abc123", Commit: GitHubCommitInfo{Verification: GitHubCommitVerification{Verified: false}}},
				{SHA: "def456", Commit: GitHubCommitInfo{Verification: GitHubCommitVerification{Verified: false}}},
			},
			expectedHasSigning: false,
			expectedCount:      0,
		},
		{
			name: "more than 50% signed",
			commits: []GitHubCommit{
				{SHA: "abc123", Commit: GitHubCommitInfo{Verification: GitHubCommitVerification{Verified: true}}},
				{SHA: "def456", Commit: GitHubCommitInfo{Verification: GitHubCommitVerification{Verified: true}}},
				{SHA: "ghi789", Commit: GitHubCommitInfo{Verification: GitHubCommitVerification{Verified: false}}},
			},
			expectedHasSigning: true,
			expectedCount:      2,
		},
		{
			name: "less than 50% signed",
			commits: []GitHubCommit{
				{SHA: "abc123", Commit: GitHubCommitInfo{Verification: GitHubCommitVerification{Verified: true}}},
				{SHA: "def456", Commit: GitHubCommitInfo{Verification: GitHubCommitVerification{Verified: false}}},
				{SHA: "ghi789", Commit: GitHubCommitInfo{Verification: GitHubCommitVerification{Verified: false}}},
			},
			expectedHasSigning: false,
			expectedCount:      1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mock server
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(tt.commits)
			}))
			defer server.Close()

			client := &GitHubClient{
				httpClient: &http.Client{},
				baseURL:    server.URL,
			}

			hasSigning, count, err := client.CheckSignedCommits("https://github.com/test/repo")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if hasSigning != tt.expectedHasSigning {
				t.Errorf("expected hasSigning=%v, got %v", tt.expectedHasSigning, hasSigning)
			}

			if count != tt.expectedCount {
				t.Errorf("expected count=%d, got %d", tt.expectedCount, count)
			}
		})
	}
}

func TestCheckSignedReleases(t *testing.T) {
	tests := []struct {
		name         string
		releases     []GitHubRelease
		expectedSigned bool
	}{
		{
			name: "releases with .asc signature",
			releases: []GitHubRelease{
				{
					TagName: "v1.0.0",
					Assets: []GitHubAsset{
						{Name: "release.tar.gz"},
						{Name: "release.tar.gz.asc"},
					},
				},
			},
			expectedSigned: true,
		},
		{
			name: "releases with .sig signature",
			releases: []GitHubRelease{
				{
					TagName: "v1.0.0",
					Assets: []GitHubAsset{
						{Name: "release.tar.gz"},
						{Name: "release.tar.gz.sig"},
					},
				},
			},
			expectedSigned: true,
		},
		{
			name: "releases with .gpg signature",
			releases: []GitHubRelease{
				{
					TagName: "v1.0.0",
					Assets: []GitHubAsset{
						{Name: "release.tar.gz"},
						{Name: "release.tar.gz.gpg"},
					},
				},
			},
			expectedSigned: true,
		},
		{
			name: "releases without signatures",
			releases: []GitHubRelease{
				{
					TagName: "v1.0.0",
					Assets: []GitHubAsset{
						{Name: "release.tar.gz"},
						{Name: "release.zip"},
					},
				},
			},
			expectedSigned: false,
		},
		{
			name:           "no releases",
			releases:       []GitHubRelease{},
			expectedSigned: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mock server
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(tt.releases)
			}))
			defer server.Close()

			client := &GitHubClient{
				httpClient: &http.Client{},
				baseURL:    server.URL,
			}

			hasSigned, err := client.CheckSignedReleases("https://github.com/test/repo")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if hasSigned != tt.expectedSigned {
				t.Errorf("expected hasSigned=%v, got %v", tt.expectedSigned, hasSigned)
			}
		})
	}
}

func TestParseGitHubURL(t *testing.T) {
	tests := []struct {
		name          string
		url           string
		expectedOwner string
		expectedRepo  string
		expectError   bool
	}{
		{
			name:          "standard https URL",
			url:           "https://github.com/owner/repo",
			expectedOwner: "owner",
			expectedRepo:  "repo",
			expectError:   false,
		},
		{
			name:          "git protocol URL",
			url:           "git://github.com/owner/repo.git",
			expectedOwner: "owner",
			expectedRepo:  "repo",
			expectError:   false,
		},
		{
			name:          "git+https URL",
			url:           "git+https://github.com/owner/repo.git",
			expectedOwner: "owner",
			expectedRepo:  "repo",
			expectError:   false,
		},
		{
			name:        "invalid URL - not github",
			url:         "https://gitlab.com/owner/repo",
			expectError: true,
		},
		{
			name:        "invalid URL - missing parts",
			url:         "https://github.com/owner",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			owner, repo, err := parseGitHubURL(tt.url)

			if tt.expectError {
				if err == nil {
					t.Error("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if owner != tt.expectedOwner {
				t.Errorf("expected owner=%s, got %s", tt.expectedOwner, owner)
			}

			if repo != tt.expectedRepo {
				t.Errorf("expected repo=%s, got %s", tt.expectedRepo, repo)
			}
		})
	}
}

func TestGetRepositoryInfo(t *testing.T) {
	mockRepo := GitHubRepository{
		Name:            "test-repo",
		FullName:        "owner/test-repo",
		HTMLURL:         "https://github.com/owner/test-repo",
		Description:     "Test repository",
		StargazersCount: 100,
		ForksCount:      20,
		WatchersCount:   50,
		OpenIssuesCount: 5,
		DefaultBranch:   "main",
		Archived:        false,
		CreatedAt:       time.Now().Add(-365 * 24 * time.Hour),
		UpdatedAt:       time.Now(),
		PushedAt:        time.Now(),
		Owner:           GitHubUser{Login: "owner"},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(mockRepo)
	}))
	defer server.Close()

	client := &GitHubClient{
		httpClient: &http.Client{},
		baseURL:    server.URL,
	}

	info, err := client.GetRepositoryInfo("https://github.com/owner/test-repo")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if info.Name != mockRepo.Name {
		t.Errorf("expected name=%s, got %s", mockRepo.Name, info.Name)
	}

	if info.Owner != mockRepo.Owner.Login {
		t.Errorf("expected owner=%s, got %s", mockRepo.Owner.Login, info.Owner)
	}

	if info.Stars != mockRepo.StargazersCount {
		t.Errorf("expected stars=%d, got %d", mockRepo.StargazersCount, info.Stars)
	}
}
