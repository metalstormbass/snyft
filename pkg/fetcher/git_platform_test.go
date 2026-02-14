package fetcher

import (
	"testing"
)

func TestDetectPlatform(t *testing.T) {
	tests := []struct {
		name     string
		repoURL  string
		expected PlatformType
	}{
		{
			name:     "GitHub HTTPS",
			repoURL:  "https://github.com/owner/repo",
			expected: PlatformGitHub,
		},
		{
			name:     "GitHub SSH",
			repoURL:  "git@github.com:owner/repo.git",
			expected: PlatformGitHub,
		},
		{
			name:     "GitHub git protocol",
			repoURL:  "git://github.com/owner/repo.git",
			expected: PlatformGitHub,
		},
		{
			name:     "GitLab HTTPS",
			repoURL:  "https://gitlab.com/owner/repo",
			expected: PlatformGitLab,
		},
		{
			name:     "GitLab SSH",
			repoURL:  "git@gitlab.com:owner/repo.git",
			expected: PlatformGitLab,
		},
		{
			name:     "GitLab self-hosted",
			repoURL:  "https://gitlab.example.com/owner/repo",
			expected: PlatformGitLab,
		},
		{
			name:     "Bitbucket HTTPS",
			repoURL:  "https://bitbucket.org/owner/repo",
			expected: PlatformBitbucket,
		},
		{
			name:     "Bitbucket SSH",
			repoURL:  "git@bitbucket.org:owner/repo.git",
			expected: PlatformBitbucket,
		},
		{
			name:     "Sourcehut",
			repoURL:  "https://git.sr.ht/~owner/repo",
			expected: PlatformSourcehut,
		},
		{
			name:     "Codeberg",
			repoURL:  "https://codeberg.org/owner/repo",
			expected: PlatformCodeberg,
		},
		{
			name:     "Unknown platform",
			repoURL:  "https://unknown.com/owner/repo",
			expected: PlatformUnknown,
		},
		{
			name:     "Empty URL",
			repoURL:  "",
			expected: PlatformUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := DetectPlatform(tt.repoURL)
			if result != tt.expected {
				t.Errorf("DetectPlatform(%q) = %v, want %v", tt.repoURL, result, tt.expected)
			}
		})
	}
}

func TestNewGitPlatformClient(t *testing.T) {
	tests := []struct {
		name         string
		repoURL      string
		expectedType string
	}{
		{
			name:         "GitHub",
			repoURL:      "https://github.com/owner/repo",
			expectedType: "GitHub",
		},
		{
			name:         "GitLab",
			repoURL:      "https://gitlab.com/owner/repo",
			expectedType: "GitLab",
		},
		{
			name:         "Bitbucket",
			repoURL:      "https://bitbucket.org/owner/repo",
			expectedType: "Bitbucket",
		},
		{
			name:         "Unknown falls back to GitHub",
			repoURL:      "https://unknown.com/owner/repo",
			expectedType: "GitHub",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := NewGitPlatformClient(tt.repoURL)
			if client == nil {
				t.Fatalf("NewGitPlatformClient(%q) returned nil", tt.repoURL)
			}
			if client.GetPlatformName() != tt.expectedType {
				t.Errorf("NewGitPlatformClient(%q).GetPlatformName() = %v, want %v",
					tt.repoURL, client.GetPlatformName(), tt.expectedType)
			}
		})
	}
}

func TestParseGitLabURL(t *testing.T) {
	tests := []struct {
		name           string
		repoURL        string
		expectedOwner  string
		expectedRepo   string
		expectedInstance string
		shouldError    bool
	}{
		{
			name:           "GitLab.com HTTPS",
			repoURL:        "https://gitlab.com/owner/repo",
			expectedOwner:  "owner",
			expectedRepo:   "repo",
			expectedInstance: "gitlab.com",
			shouldError:    false,
		},
		{
			name:           "GitLab.com SSH",
			repoURL:        "git@gitlab.com:owner/repo.git",
			expectedOwner:  "owner",
			expectedRepo:   "repo",
			expectedInstance: "gitlab.com",
			shouldError:    false,
		},
		{
			name:           "GitLab self-hosted",
			repoURL:        "https://gitlab.example.com/owner/repo",
			expectedOwner:  "owner",
			expectedRepo:   "repo",
			expectedInstance: "gitlab.example.com",
			shouldError:    false,
		},
		{
			name:        "Invalid URL",
			repoURL:     "https://github.com/owner/repo",
			shouldError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			owner, repo, instance, err := parseGitLabURL(tt.repoURL)
			if tt.shouldError {
				if err == nil {
					t.Errorf("parseGitLabURL(%q) expected error, got none", tt.repoURL)
				}
			} else {
				if err != nil {
					t.Fatalf("parseGitLabURL(%q) unexpected error: %v", tt.repoURL, err)
				}
				if owner != tt.expectedOwner {
					t.Errorf("owner = %q, want %q", owner, tt.expectedOwner)
				}
				if repo != tt.expectedRepo {
					t.Errorf("repo = %q, want %q", repo, tt.expectedRepo)
				}
				if instance != tt.expectedInstance {
					t.Errorf("instance = %q, want %q", instance, tt.expectedInstance)
				}
			}
		})
	}
}

func TestParseBitbucketURL(t *testing.T) {
	tests := []struct {
		name          string
		repoURL       string
		expectedOwner string
		expectedRepo  string
		shouldError   bool
	}{
		{
			name:          "Bitbucket HTTPS",
			repoURL:       "https://bitbucket.org/owner/repo",
			expectedOwner: "owner",
			expectedRepo:  "repo",
			shouldError:   false,
		},
		{
			name:          "Bitbucket SSH",
			repoURL:       "git@bitbucket.org:owner/repo.git",
			expectedOwner: "owner",
			expectedRepo:  "repo",
			shouldError:   false,
		},
		{
			name:        "Invalid URL",
			repoURL:     "https://github.com/owner/repo",
			shouldError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			owner, repo, err := parseBitbucketURL(tt.repoURL)
			if tt.shouldError {
				if err == nil {
					t.Errorf("parseBitbucketURL(%q) expected error, got none", tt.repoURL)
				}
			} else {
				if err != nil {
					t.Fatalf("parseBitbucketURL(%q) unexpected error: %v", tt.repoURL, err)
				}
				if owner != tt.expectedOwner {
					t.Errorf("owner = %q, want %q", owner, tt.expectedOwner)
				}
				if repo != tt.expectedRepo {
					t.Errorf("repo = %q, want %q", repo, tt.expectedRepo)
				}
			}
		})
	}
}
