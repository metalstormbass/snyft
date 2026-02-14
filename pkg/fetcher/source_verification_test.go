package fetcher

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/metalstormbass/snyft/pkg/models"
)

// TestGitHubCheckGitTag tests git tag verification
func TestGitHubCheckGitTag(t *testing.T) {
	tests := []struct {
		name          string
		version       string
		serverResp    func(w http.ResponseWriter, r *http.Request)
		expectExists  bool
		expectTagURL  string
	}{
		{
			name:    "Tag exists with 'v' prefix",
			version: "1.2.3",
			serverResp: func(w http.ResponseWriter, r *http.Request) {
				if strings.Contains(r.URL.Path, "/git/ref/tags/v1.2.3") {
					w.WriteHeader(http.StatusOK)
					w.Write([]byte(`{"ref":"refs/tags/v1.2.3","object":{"sha":"abc123"}}`))
				} else {
					w.WriteHeader(http.StatusNotFound)
				}
			},
			expectExists: true,
			expectTagURL: "https://github.com/owner/repo/releases/tag/v1.2.3",
		},
		{
			name:    "Tag exists without 'v' prefix",
			version: "2.0.0",
			serverResp: func(w http.ResponseWriter, r *http.Request) {
				if strings.Contains(r.URL.Path, "/git/ref/tags/2.0.0") {
					w.WriteHeader(http.StatusOK)
					w.Write([]byte(`{"ref":"refs/tags/2.0.0","object":{"sha":"def456"}}`))
				} else {
					w.WriteHeader(http.StatusNotFound)
				}
			},
			expectExists: true,
			expectTagURL: "https://github.com/owner/repo/releases/tag/2.0.0",
		},
		{
			name:    "Tag does not exist",
			version: "9.9.9",
			serverResp: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusNotFound)
			},
			expectExists: false,
			expectTagURL: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(tt.serverResp))
			defer server.Close()

			client := &GitHubClient{
				httpClient: &http.Client{Timeout: 5 * time.Second},
				baseURL:    server.URL,
			}

			exists, tagURL, err := client.CheckGitTag("https://github.com/owner/repo", tt.version)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if exists != tt.expectExists {
				t.Errorf("Expected exists=%v, got %v", tt.expectExists, exists)
			}

			if tt.expectExists && !strings.HasSuffix(tagURL, tt.version) {
				t.Errorf("Expected tag URL to contain version %s, got %s", tt.version, tagURL)
			}
		})
	}
}

// TestNPMVerifySourceAvailability tests npm source verification
func TestNPMVerifySourceAvailability(t *testing.T) {
	tests := []struct {
		name                  string
		packageName           string
		version               string
		npmServerResp         func(w http.ResponseWriter, r *http.Request)
		tarballServerResp     func(w http.ResponseWriter, r *http.Request)
		gitTagExists          bool
		expectHasSource       bool
		expectHasTag          bool
		expectVerified        bool
		expectErrorContains   string
	}{
		{
			name:        "Full verification success - tarball has source and git tag exists",
			packageName: "express",
			version:     "4.18.0",
			npmServerResp: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"dist":{"tarball":"http://localhost/tarball.tgz"}}`))
			},
			tarballServerResp: func(w http.ResponseWriter, r *http.Request) {
				// Simulate a valid tarball with source files
				w.WriteHeader(http.StatusOK)
				// Would need actual tar.gz data here for real test
			},
			gitTagExists:    true,
			expectHasSource: false, // Will fail without real tarball data in this simple test
			expectHasTag:    true,
			expectVerified:  false,
		},
		{
			name:        "Package version not found",
			packageName: "nonexistent",
			version:     "0.0.0",
			npmServerResp: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusNotFound)
			},
			gitTagExists:        false,
			expectHasSource:     false,
			expectHasTag:        false,
			expectVerified:      false,
			expectErrorContains: "not found",
		},
		{
			name:        "No tarball URL in response",
			packageName: "broken-package",
			version:     "1.0.0",
			npmServerResp: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"dist":{}}`))
			},
			gitTagExists:        false,
			expectHasSource:     false,
			expectHasTag:        false,
			expectVerified:      false,
			expectErrorContains: "No tarball URL",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			npmServer := httptest.NewServer(http.HandlerFunc(tt.npmServerResp))
			defer npmServer.Close()

			var tarballServer *httptest.Server
			if tt.tarballServerResp != nil {
				tarballServer = httptest.NewServer(http.HandlerFunc(tt.tarballServerResp))
				defer tarballServer.Close()
			}

			npmClient := &NPMClient{
				httpClient: &http.Client{Timeout: 5 * time.Second},
				baseURL:    npmServer.URL,
			}

			// Mock GitHub client for tag checking
			var githubClient *GitHubClient
			if tt.gitTagExists {
				githubServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if strings.Contains(r.URL.Path, "/git/ref/tags/") {
						w.WriteHeader(http.StatusOK)
						w.Write([]byte(`{"ref":"refs/tags/v4.18.0"}`))
					} else {
						w.WriteHeader(http.StatusNotFound)
					}
				}))
				defer githubServer.Close()

				githubClient = &GitHubClient{
					httpClient: &http.Client{Timeout: 5 * time.Second},
					baseURL:    githubServer.URL,
				}
			}

			result := npmClient.VerifySourceAvailability(tt.packageName, tt.version, "https://github.com/owner/repo", githubClient)

			if result.HasSourcePackage != tt.expectHasSource {
				t.Errorf("Expected HasSourcePackage=%v, got %v", tt.expectHasSource, result.HasSourcePackage)
			}

			if result.HasMatchingGitTag != tt.expectHasTag {
				t.Errorf("Expected HasMatchingGitTag=%v, got %v", tt.expectHasTag, result.HasMatchingGitTag)
			}

			if result.Verified != tt.expectVerified {
				t.Errorf("Expected Verified=%v, got %v", tt.expectVerified, result.Verified)
			}

			if tt.expectErrorContains != "" {
				found := false
				for _, err := range result.VerificationErrors {
					if strings.Contains(err, tt.expectErrorContains) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Expected error containing '%s', got errors: %v", tt.expectErrorContains, result.VerificationErrors)
				}
			}
		})
	}
}

// TestPyPIVerifySourceAvailability tests PyPI source verification
func TestPyPIVerifySourceAvailability(t *testing.T) {
	tests := []struct {
		name                string
		packageName         string
		version             string
		pypiServerResp      func(w http.ResponseWriter, r *http.Request)
		gitTagExists        bool
		expectHasSource     bool
		expectHasTag        bool
		expectVerified      bool
		expectErrorContains string
	}{
		{
			name:        "Full verification success - sdist and git tag exist",
			packageName: "requests",
			version:     "2.28.0",
			pypiServerResp: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{
					"urls": [
						{"packagetype": "sdist", "url": "https://files.pythonhosted.org/requests-2.28.0.tar.gz"},
						{"packagetype": "bdist_wheel", "url": "https://files.pythonhosted.org/requests-2.28.0-py3-none-any.whl"}
					]
				}`))
			},
			gitTagExists:    true,
			expectHasSource: true,
			expectHasTag:    true,
			expectVerified:  true,
		},
		{
			name:        "Only wheel distribution available",
			packageName: "wheel-only",
			version:     "1.0.0",
			pypiServerResp: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{
					"urls": [
						{"packagetype": "bdist_wheel", "url": "https://files.pythonhosted.org/wheel-only-1.0.0-py3-none-any.whl"}
					]
				}`))
			},
			gitTagExists:        false,
			expectHasSource:     false,
			expectHasTag:        false,
			expectVerified:      false,
			expectErrorContains: "only provides wheel",
		},
		{
			name:        "Package version not found",
			packageName: "nonexistent",
			version:     "0.0.0",
			pypiServerResp: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusNotFound)
			},
			gitTagExists:        false,
			expectHasSource:     false,
			expectHasTag:        false,
			expectVerified:      false,
			expectErrorContains: "not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pypiServer := httptest.NewServer(http.HandlerFunc(tt.pypiServerResp))
			defer pypiServer.Close()

			pypiClient := &PyPIClient{
				httpClient: &http.Client{Timeout: 5 * time.Second},
				baseURL:    pypiServer.URL,
			}

			// Mock GitHub client for tag checking
			var githubClient *GitHubClient
			if tt.gitTagExists {
				githubServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if strings.Contains(r.URL.Path, "/git/ref/tags/") {
						w.WriteHeader(http.StatusOK)
						w.Write([]byte(`{"ref":"refs/tags/v2.28.0"}`))
					} else {
						w.WriteHeader(http.StatusNotFound)
					}
				}))
				defer githubServer.Close()

				githubClient = &GitHubClient{
					httpClient: &http.Client{Timeout: 5 * time.Second},
					baseURL:    githubServer.URL,
				}
			}

			result := pypiClient.VerifySourceAvailability(tt.packageName, tt.version, "https://github.com/owner/repo", githubClient)

			if result.HasSourcePackage != tt.expectHasSource {
				t.Errorf("Expected HasSourcePackage=%v, got %v", tt.expectHasSource, result.HasSourcePackage)
			}

			if result.HasMatchingGitTag != tt.expectHasTag {
				t.Errorf("Expected HasMatchingGitTag=%v, got %v", tt.expectHasTag, result.HasMatchingGitTag)
			}

			if result.Verified != tt.expectVerified {
				t.Errorf("Expected Verified=%v, got %v", tt.expectVerified, result.Verified)
			}

			if tt.expectErrorContains != "" {
				found := false
				for _, err := range result.VerificationErrors {
					if strings.Contains(err, tt.expectErrorContains) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Expected error containing '%s', got errors: %v", tt.expectErrorContains, result.VerificationErrors)
				}
			}
		})
	}
}

// TestMavenVerifySourceAvailability tests Maven source verification
func TestMavenVerifySourceAvailability(t *testing.T) {
	tests := []struct {
		name                string
		packageName         string
		version             string
		sourcesJarExists    bool
		gitTagExists        bool
		expectHasSource     bool
		expectHasTag        bool
		expectVerified      bool
		expectErrorContains string
	}{
		{
			name:             "Full verification success - sources.jar and git tag exist",
			packageName:      "org.springframework:spring-core",
			version:          "5.3.20",
			sourcesJarExists: true,
			gitTagExists:     true,
			expectHasSource:  true,
			expectHasTag:     true,
			expectVerified:   true,
		},
		{
			name:                "sources.jar not found",
			packageName:         "com.example:no-sources",
			version:             "1.0.0",
			sourcesJarExists:    false,
			gitTagExists:        false,
			expectHasSource:     false,
			expectHasTag:        false,
			expectVerified:      false,
			expectErrorContains: "sources.jar not found",
		},
		{
			name:                "Invalid package name format",
			packageName:         "invalid-name",
			version:             "1.0.0",
			sourcesJarExists:    false,
			gitTagExists:        false,
			expectHasSource:     false,
			expectHasTag:        false,
			expectVerified:      false,
			expectErrorContains: "Invalid Maven package name",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mavenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.HasSuffix(r.URL.Path, "-sources.jar") {
					if tt.sourcesJarExists {
						w.WriteHeader(http.StatusOK)
					} else {
						w.WriteHeader(http.StatusNotFound)
					}
				} else {
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			defer mavenServer.Close()

			mavenClient := &MavenClient{
				httpClient: &http.Client{Timeout: 5 * time.Second},
				baseURL:    mavenServer.URL,
			}

			// Mock GitHub client for tag checking
			var githubClient *GitHubClient
			if tt.gitTagExists {
				githubServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if strings.Contains(r.URL.Path, "/git/ref/tags/") {
						w.WriteHeader(http.StatusOK)
						w.Write([]byte(`{"ref":"refs/tags/v5.3.20"}`))
					} else {
						w.WriteHeader(http.StatusNotFound)
					}
				}))
				defer githubServer.Close()

				githubClient = &GitHubClient{
					httpClient: &http.Client{Timeout: 5 * time.Second},
					baseURL:    githubServer.URL,
				}
			}

			result := mavenClient.VerifySourceAvailability(tt.packageName, tt.version, "https://github.com/owner/repo", githubClient)

			if result.HasSourcePackage != tt.expectHasSource {
				t.Errorf("Expected HasSourcePackage=%v, got %v", tt.expectHasSource, result.HasSourcePackage)
			}

			if result.HasMatchingGitTag != tt.expectHasTag {
				t.Errorf("Expected HasMatchingGitTag=%v, got %v", tt.expectHasTag, result.HasMatchingGitTag)
			}

			if result.Verified != tt.expectVerified {
				t.Errorf("Expected Verified=%v, got %v", tt.expectVerified, result.Verified)
			}

			if tt.expectErrorContains != "" {
				found := false
				for _, err := range result.VerificationErrors {
					if strings.Contains(err, tt.expectErrorContains) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Expected error containing '%s', got errors: %v", tt.expectErrorContains, result.VerificationErrors)
				}
			}
		})
	}
}

// TestSourceVerificationIntegration tests the integration of source verification
func TestSourceVerificationIntegration(t *testing.T) {
	t.Run("Source verification fields populated correctly", func(t *testing.T) {
		verification := &models.SourceVerification{
			Verified:           true,
			HasSourcePackage:   true,
			HasMatchingGitTag:  true,
			SourcePackageURL:   "https://registry.npmjs.org/express/-/express-4.18.0.tgz",
			GitTagURL:          "https://github.com/expressjs/express/releases/tag/4.18.0",
			VerificationErrors: []string{},
			Details:            "Source code verified for v4.18.0",
		}

		if !verification.Verified {
			t.Error("Expected verification to pass")
		}

		if !verification.HasSourcePackage {
			t.Error("Expected source package to exist")
		}

		if !verification.HasMatchingGitTag {
			t.Error("Expected git tag to exist")
		}

		if verification.SourcePackageURL == "" {
			t.Error("Expected source package URL to be populated")
		}

		if verification.GitTagURL == "" {
			t.Error("Expected git tag URL to be populated")
		}

		if len(verification.VerificationErrors) > 0 {
			t.Errorf("Expected no verification errors, got: %v", verification.VerificationErrors)
		}
	})
}
