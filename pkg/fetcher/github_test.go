package fetcher

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestGetCommitAuthors(t *testing.T) {
	tests := []struct {
		name          string
		commits       []GitHubCommit
		wantAuthors   int
		wantRecent    int
		wantHistorical int
	}{
		{
			name: "single author stable",
			commits: []GitHubCommit{
				{
					SHA: "abc123",
					Commit: GitHubCommitInfo{
						Author: GitHubCommitAuthor{
							Name:  "Alice",
							Email: "alice@example.com",
							Date:  time.Now().AddDate(0, 0, -10),
						},
					},
				},
				{
					SHA: "def456",
					Commit: GitHubCommitInfo{
						Author: GitHubCommitAuthor{
							Name:  "Alice",
							Email: "alice@example.com",
							Date:  time.Now().AddDate(0, 0, -20),
						},
					},
				},
			},
			wantAuthors:    1,
			wantRecent:     1,
			wantHistorical: 0,
		},
		{
			name: "ownership change detected",
			commits: []GitHubCommit{
				{
					SHA: "abc123",
					Commit: GitHubCommitInfo{
						Author: GitHubCommitAuthor{
							Name:  "Bob",
							Email: "bob@example.com",
							Date:  time.Now().AddDate(0, 0, -10),
						},
					},
				},
				{
					SHA: "def456",
					Commit: GitHubCommitInfo{
						Author: GitHubCommitAuthor{
							Name:  "Alice",
							Email: "alice@example.com",
							Date:  time.Now().AddDate(0, 0, -200),
						},
					},
				},
			},
			wantAuthors:    2,
			wantRecent:     1,
			wantHistorical: 1,
		},
		{
			name: "multiple recent authors",
			commits: []GitHubCommit{
				{
					SHA: "abc123",
					Commit: GitHubCommitInfo{
						Author: GitHubCommitAuthor{
							Name:  "Alice",
							Email: "alice@example.com",
							Date:  time.Now().AddDate(0, 0, -10),
						},
					},
				},
				{
					SHA: "def456",
					Commit: GitHubCommitInfo{
						Author: GitHubCommitAuthor{
							Name:  "Bob",
							Email: "bob@example.com",
							Date:  time.Now().AddDate(0, 0, -20),
						},
					},
				},
				{
					SHA: "ghi789",
					Commit: GitHubCommitInfo{
						Author: GitHubCommitAuthor{
							Name:  "Charlie",
							Email: "charlie@example.com",
							Date:  time.Now().AddDate(0, 0, -30),
						},
					},
				},
			},
			wantAuthors:    3,
			wantRecent:     3,
			wantHistorical: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mock server
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(tt.commits)
			}))
			defer server.Close()

			client := &GitHubClient{
				token:      "",
				httpClient: &http.Client{},
				baseURL:    server.URL,
			}

			stats, err := client.GetCommitAuthors("https://github.com/test/repo")
			if err != nil {
				t.Fatalf("GetCommitAuthors() error = %v", err)
			}

			if len(stats.UniqueAuthors) != tt.wantAuthors {
				t.Errorf("GetCommitAuthors() unique authors = %v, want %v", len(stats.UniqueAuthors), tt.wantAuthors)
			}

			if len(stats.RecentAuthors) != tt.wantRecent {
				t.Errorf("GetCommitAuthors() recent authors = %v, want %v", len(stats.RecentAuthors), tt.wantRecent)
			}

			if len(stats.HistoricalAuthors) != tt.wantHistorical {
				t.Errorf("GetCommitAuthors() historical authors = %v, want %v", len(stats.HistoricalAuthors), tt.wantHistorical)
			}
		})
	}
}

func TestGetCommitAuthors_EmptyCommits(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]GitHubCommit{})
	}))
	defer server.Close()

	client := &GitHubClient{
		token:      "",
		httpClient: &http.Client{},
		baseURL:    server.URL,
	}

	stats, err := client.GetCommitAuthors("https://github.com/test/repo")
	if err != nil {
		t.Fatalf("GetCommitAuthors() error = %v", err)
	}

	if stats.TotalCommits != 0 {
		t.Errorf("GetCommitAuthors() total commits = %v, want 0", stats.TotalCommits)
	}

	if len(stats.UniqueAuthors) != 0 {
		t.Errorf("GetCommitAuthors() unique authors = %v, want 0", len(stats.UniqueAuthors))
	}
}

func TestGetCommitAuthors_APIError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("Not Found"))
	}))
	defer server.Close()

	client := &GitHubClient{
		token:      "",
		httpClient: &http.Client{},
		baseURL:    server.URL,
	}

	_, err := client.GetCommitAuthors("https://github.com/test/repo")
	if err == nil {
		t.Error("GetCommitAuthors() expected error, got nil")
	}
}
