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

func TestCalculateBusFactor(t *testing.T) {
	tests := []struct {
		name          string
		authorCommits map[string]int
		totalCommits  int
		want          int
	}{
		{
			name: "Single author (100% concentration)",
			authorCommits: map[string]int{
				"alice": 100,
			},
			totalCommits: 100,
			want:         1,
		},
		{
			name: "Two authors, balanced",
			authorCommits: map[string]int{
				"alice": 50,
				"bob":   50,
			},
			totalCommits: 100,
			want:         2,
		},
		{
			name: "Two authors, one dominant",
			authorCommits: map[string]int{
				"alice": 80,
				"bob":   20,
			},
			totalCommits: 100,
			want:         1, // Alice alone accounts for >50%
		},
		{
			name: "Three authors, distributed",
			authorCommits: map[string]int{
				"alice":  40,
				"bob":    35,
				"carol":  25,
			},
			totalCommits: 100,
			want:         2, // Alice + Bob = 75% (need 2 for 50%)
		},
		{
			name: "Many authors, highly distributed",
			authorCommits: map[string]int{
				"alice":  15,
				"bob":    15,
				"carol":  15,
				"dave":   15,
				"eve":    10,
				"frank":  10,
				"grace":  10,
				"heidi":  10,
			},
			totalCommits: 100,
			want:         4, // Need 4 authors to reach 60% (>50%)
		},
		{
			name:          "Empty (edge case)",
			authorCommits: map[string]int{},
			totalCommits:  0,
			want:          0,
		},
		{
			name: "Five authors, one dominant",
			authorCommits: map[string]int{
				"alice": 60,
				"bob":   15,
				"carol": 10,
				"dave":  10,
				"eve":   5,
			},
			totalCommits: 100,
			want:         1, // Alice alone = 60%
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := calculateBusFactor(tt.authorCommits, tt.totalCommits)
			if got != tt.want {
				t.Errorf("calculateBusFactor() = %d, want %d", got, tt.want)
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

func TestParseGitHubURL(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		owner   string
		repo    string
		wantErr bool
	}{
		{
			name:    "standard https URL",
			url:     "https://github.com/owner/repo",
			owner:   "owner",
			repo:    "repo",
			wantErr: false,
		},
		{
			name:    "Standard HTTPS URL",
			url:     "https://github.com/metalstormbass/snyft",
			owner:   "metalstormbass",
			repo:    "snyft",
			wantErr: false,
		},
		{
			name:    "HTTPS URL with .git",
			url:     "https://github.com/owner/repo.git",
			owner:   "owner",
			repo:    "repo",
			wantErr: false,
		},
		{
			name:    "git protocol URL",
			url:     "git://github.com/owner/repo.git",
			owner:   "owner",
			repo:    "repo",
			wantErr: false,
		},
		{
			name:    "git+https URL",
			url:     "git+https://github.com/owner/repo.git",
			owner:   "owner",
			repo:    "repo",
			wantErr: false,
		},
		{
			name:    "Git+HTTPS URL",
			url:     "git+https://github.com/owner/repo",
			owner:   "owner",
			repo:    "repo",
			wantErr: false,
		},
		{
			name:    "HTTP URL",
			url:     "http://github.com/owner/repo",
			owner:   "owner",
			repo:    "repo",
			wantErr: false,
		},
		{
			name:    "invalid URL - not github",
			url:     "https://gitlab.com/owner/repo",
			owner:   "",
			repo:    "",
			wantErr: true,
		},
		{
			name:    "Invalid URL - not GitHub",
			url:     "https://gitlab.com/owner/repo",
			owner:   "",
			repo:    "",
			wantErr: true,
		},
		{
			name:    "Invalid URL - malformed",
			url:     "not-a-url",
			owner:   "",
			repo:    "",
			wantErr: true,
		},
		{
			name:    "invalid URL - missing parts",
			url:     "https://github.com/owner",
			owner:   "",
			repo:    "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			owner, repo, err := parseGitHubURL(tt.url)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseGitHubURL() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if owner != tt.owner {
				t.Errorf("parseGitHubURL() owner = %s, want %s", owner, tt.owner)
			}
			if repo != tt.repo {
				t.Errorf("parseGitHubURL() repo = %s, want %s", repo, tt.repo)
			}
		})
	}
}

func TestContainsString(t *testing.T) {
	client := NewGitHubClient()

	tests := []struct {
		name  string
		slice []string
		str   string
		want  bool
	}{
		{
			name:  "String present",
			slice: []string{"GitHub Actions", "Travis CI", "Circle CI"},
			str:   "Travis CI",
			want:  true,
		},
		{
			name:  "String not present",
			slice: []string{"GitHub Actions", "Travis CI"},
			str:   "Jenkins",
			want:  false,
		},
		{
			name:  "Empty slice",
			slice: []string{},
			str:   "anything",
			want:  false,
		},
		{
			name:  "Case sensitive - different case",
			slice: []string{"GitHub Actions"},
			str:   "github actions",
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := client.containsString(tt.slice, tt.str)
			if got != tt.want {
				t.Errorf("containsString() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestWorkflowsContainTests(t *testing.T) {
	client := NewGitHubClient()

	tests := []struct {
		name      string
		workflows []string
		want      bool
	}{
		{
			name:      "Test workflow present",
			workflows: []string{"test.yml", "build.yml"},
			want:      true,
		},
		{
			name:      "CI workflow present",
			workflows: []string{"ci.yml", "deploy.yml"},
			want:      true,
		},
		{
			name:      "Check workflow present",
			workflows: []string{"check.yml"},
			want:      true,
		},
		{
			name:      "Lint workflow present",
			workflows: []string{"lint.yml", "release.yml"},
			want:      true,
		},
		{
			name:      "No test-related workflows",
			workflows: []string{"deploy.yml", "release.yml"},
			want:      false,
		},
		{
			name:      "Empty workflows",
			workflows: []string{},
			want:      false,
		},
		{
			name:      "Mixed case - test in name",
			workflows: []string{"TestSuite.yaml"},
			want:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := client.workflowsContainTests(tt.workflows)
			if got != tt.want {
				t.Errorf("workflowsContainTests() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetLicenseName(t *testing.T) {
	tests := []struct {
		name    string
		license *GitHubLicense
		want    string
	}{
		{
			name: "MIT License",
			license: &GitHubLicense{
				Key:  "mit",
				Name: "MIT License",
			},
			want: "MIT License",
		},
		{
			name: "Apache 2.0",
			license: &GitHubLicense{
				Key:  "apache-2.0",
				Name: "Apache License 2.0",
			},
			want: "Apache License 2.0",
		},
		{
			name:    "Nil license",
			license: nil,
			want:    "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getLicenseName(tt.license)
			if got != tt.want {
				t.Errorf("getLicenseName() = %s, want %s", got, tt.want)
			}
		})
	}
}

// TestCommitStats validates CommitStats structure
func TestCommitStats(t *testing.T) {
	stats := &CommitStats{
		TotalCommits: 100,
		AuthorCommits: map[string]int{
			"alice": 60,
			"bob":   40,
		},
		BusFactor:         1,
		TopContributorPct: 60.0,
	}

	if stats.TotalCommits != 100 {
		t.Errorf("TotalCommits = %d, want 100", stats.TotalCommits)
	}

	if stats.BusFactor != 1 {
		t.Errorf("BusFactor = %d, want 1", stats.BusFactor)
	}

	if stats.TopContributorPct != 60.0 {
		t.Errorf("TopContributorPct = %.1f, want 60.0", stats.TopContributorPct)
	}
}

// TestPRStats validates PRStats structure
func TestPRStats(t *testing.T) {
	stats := &PRStats{
		TotalPRs:            100,
		MergedPRs:           80,
		PRsWithReviews:      60,
		CodeReviewRate:      75.0,
		RequiredReviewers:   2,
		HasBranchProtection: true,
	}

	if stats.CodeReviewRate != 75.0 {
		t.Errorf("CodeReviewRate = %.1f, want 75.0", stats.CodeReviewRate)
	}

	if !stats.HasBranchProtection {
		t.Error("HasBranchProtection should be true")
	}

	if stats.RequiredReviewers != 2 {
		t.Errorf("RequiredReviewers = %d, want 2", stats.RequiredReviewers)
	}
}

// TestCIQuality validates CIQuality structure and scoring
func TestCIQuality(t *testing.T) {
	tests := []struct {
		name           string
		quality        *CIQuality
		expectedMinScore int
		expectedMaxScore int
	}{
		{
			name: "High quality CI",
			quality: &CIQuality{
				HasCI:         true,
				CISystems:     []string{"GitHub Actions"},
				HasTests:      true,
				WorkflowCount: 3,
				QualityScore:  9, // 3 (CI) + 4 (tests) + 2 (workflows)
			},
			expectedMinScore: 9,
			expectedMaxScore: 10,
		},
		{
			name: "Moderate CI",
			quality: &CIQuality{
				HasCI:         true,
				CISystems:     []string{"Travis CI"},
				HasTests:      false,
				WorkflowCount: 1,
				QualityScore:  4, // 3 (CI) + 1 (single workflow)
			},
			expectedMinScore: 4,
			expectedMaxScore: 4,
		},
		{
			name: "No CI",
			quality: &CIQuality{
				HasCI:        false,
				QualityScore: 0,
			},
			expectedMinScore: 0,
			expectedMaxScore: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.quality.QualityScore < tt.expectedMinScore || tt.quality.QualityScore > tt.expectedMaxScore {
				t.Errorf("QualityScore = %d, want range [%d, %d]",
					tt.quality.QualityScore, tt.expectedMinScore, tt.expectedMaxScore)
			}

			// Validate score is in valid range (0-10)
			if tt.quality.QualityScore < 0 || tt.quality.QualityScore > 10 {
				t.Errorf("QualityScore out of valid range: %d", tt.quality.QualityScore)
			}
		})
	}
}
