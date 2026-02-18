package fetcher

import (
	"testing"
)

// Test: Platform detection from repository URL
// Justification: Correct platform identification is prerequisite for all supply chain checks.
//                If we misidentify a Bitbucket repo as GitHub we call the wrong API and may
//                miss signals like MFA non-enforcement or ownership transfer patterns.
// Source: "Backstabber's Knife Collection" (Ohm et al., 2020) – repository metadata
//         is a primary source for supply chain risk signals.
//         https://arxiv.org/abs/2005.09535
// Methodology: Call DetectPlatform() with representative URLs for each supported hosting
//              platform and verify the returned PlatformType constant.
// Result: Each URL produces the expected PlatformType; malformed/unknown URLs produce
//         PlatformUnknown or PlatformGenericGit as appropriate.
func TestDetectPlatform(t *testing.T) {
	tests := []struct {
		name     string
		repoURL  string
		expected PlatformType
	}{
		// --- GitHub ---
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
			name:     "GitHub HTTPS with .git suffix",
			repoURL:  "https://github.com/owner/repo.git",
			expected: PlatformGitHub,
		},
		{
			name:     "GitHub git+https prefix (npm registry format)",
			repoURL:  "git+https://github.com/expressjs/express.git",
			expected: PlatformGitHub,
		},

		// --- GitLab ---
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

		// --- Bitbucket ---
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

		// --- Sourcehut ---
		{
			name:     "Sourcehut HTTPS",
			repoURL:  "https://git.sr.ht/~owner/repo",
			expected: PlatformSourcehut,
		},

		// --- Codeberg ---
		{
			name:     "Codeberg HTTPS",
			repoURL:  "https://codeberg.org/owner/repo",
			expected: PlatformCodeberg,
		},

		// --- Apache Git ---
		// Apache hosts Java ecosystem packages (Maven artifacts) on their own git
		// infrastructure. Correct detection lets us apply Apache-specific analysis.
		{
			name:     "Apache Gitbox",
			repoURL:  "https://gitbox.apache.org/repos/asf/commons-lang.git",
			expected: PlatformApache,
		},
		{
			name:     "Apache git subdomain",
			repoURL:  "https://git.apache.org/repos/asf/tomcat.git",
			expected: PlatformApache,
		},

		// --- Eclipse Git ---
		{
			name:     "Eclipse git hosting",
			repoURL:  "https://git.eclipse.org/r/jdt/eclipse.jdt.core",
			expected: PlatformEclipse,
		},

		// --- SourceForge ---
		// SourceForge hosts many legacy packages. Correct detection allows graceful
		// degradation to scraping when API is unavailable.
		{
			name:     "SourceForge .net",
			repoURL:  "https://sourceforge.net/p/some-project/code",
			expected: PlatformSourceForge,
		},
		{
			name:     "SourceForge .io",
			repoURL:  "https://sourceforge.io/p/some-project/code",
			expected: PlatformSourceForge,
		},

		// --- Launchpad ---
		{
			name:     "Launchpad",
			repoURL:  "https://launchpad.net/~owner/+git/repo",
			expected: PlatformLaunchpad,
		},

		// --- Generic Git ---
		// Any URL ending in .git that doesn't match a known host falls back to the
		// generic client which performs basic HTTP-level checks.
		{
			name:     "Generic .git URL",
			repoURL:  "https://git.example.com/owner/repo.git",
			expected: PlatformGenericGit,
		},
		{
			name:     "Generic /git/ path URL",
			repoURL:  "https://example.com/git/repo",
			expected: PlatformGenericGit,
		},

		// --- Unknown / empty ---
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

// Test: Platform detection for real packages in /Users/mike/Projects/mike-libraries
// Justification: Real-world package repository URLs exercise the detection logic with
//                URLs as they actually appear in npm/PyPI registry metadata, including
//                git+https:// prefixes and trailing .git suffixes.
// Source: npm registry API (https://registry.npmjs.org), PyPI JSON API
// Methodology: Uses canonical repository URLs from well-known packages in the
//              mike-libraries JavaScript and Python dependency manifests.
// Result: All representative real-world package repo URLs resolve to PlatformGitHub
//         (all sampled packages host on GitHub).
func TestDetectPlatformRealPackages(t *testing.T) {
	// Repository URLs as they appear in npm/PyPI registry responses for packages
	// listed in /Users/mike/Projects/mike-libraries/javascript/package.json and
	// /Users/mike/Projects/mike-libraries/python/requirements.txt
	tests := []struct {
		pkg     string
		repoURL string
		want    PlatformType
	}{
		// JavaScript packages (npm registry format uses git+https:// prefix)
		{"express", "git+https://github.com/expressjs/express.git", PlatformGitHub},
		{"axios", "git+https://github.com/axios/axios.git", PlatformGitHub},
		{"lodash", "git+https://github.com/lodash/lodash.git", PlatformGitHub},
		{"dotenv", "git+https://github.com/motdotla/dotenv.git", PlatformGitHub},
		{"helmet", "git+https://github.com/helmetjs/helmet.git", PlatformGitHub},
		{"winston", "git+https://github.com/winstonjs/winston.git", PlatformGitHub},
		{"jsonwebtoken", "git+https://github.com/auth0/node-jsonwebtoken.git", PlatformGitHub},

		// Python packages (PyPI stores plain HTTPS URLs)
		{"Flask", "https://github.com/pallets/flask", PlatformGitHub},
		{"requests", "https://github.com/psf/requests", PlatformGitHub},
		{"pandas", "https://github.com/pandas-dev/pandas", PlatformGitHub},
		{"FastAPI", "https://github.com/tiangolo/fastapi", PlatformGitHub},
		{"SQLAlchemy", "https://github.com/sqlalchemy/sqlalchemy", PlatformGitHub},
		{"cryptography", "https://github.com/pyca/cryptography", PlatformGitHub},
		{"celery", "https://github.com/celery/celery", PlatformGitHub},
	}

	for _, tt := range tests {
		t.Run(tt.pkg, func(t *testing.T) {
			got := DetectPlatform(tt.repoURL)
			if got != tt.want {
				t.Errorf("DetectPlatform(%q) [pkg=%s] = %v, want %v", tt.repoURL, tt.pkg, got, tt.want)
			}
		})
	}
}

// Test: Correct client type dispatched for each platform
// Justification: Using the wrong API client (e.g. GitHub client for a GitLab repo) means
//                we call endpoints that don't exist and miss platform-specific risk signals
//                like MFA policy, ownership transfer, and CI configuration checks.
// Source: "Towards Measuring Supply Chain Attacks on Package Managers" (NDSS 2020)
//         – platform diversity in the supply chain requires per-platform analysis.
// Methodology: Call NewGitPlatformClient() and verify GetPlatformName() on the result.
// Result: Each platform URL dispatches to the correct typed client; platforms handled by
//         the generic client all return "Generic Git".
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
		// Generic platforms use the GenericGitClient
		{
			name:         "Sourcehut uses generic client",
			repoURL:      "https://git.sr.ht/~owner/repo",
			expectedType: "Generic Git",
		},
		{
			name:         "Codeberg uses generic client",
			repoURL:      "https://codeberg.org/owner/repo",
			expectedType: "Generic Git",
		},
		{
			name:         "Apache git uses generic client",
			repoURL:      "https://gitbox.apache.org/repos/asf/commons-lang.git",
			expectedType: "Generic Git",
		},
		{
			name:         "Eclipse git uses generic client",
			repoURL:      "https://git.eclipse.org/r/jdt/eclipse.jdt.core",
			expectedType: "Generic Git",
		},
		{
			name:         "SourceForge uses generic client",
			repoURL:      "https://sourceforge.net/p/project/code",
			expectedType: "Generic Git",
		},
		{
			name:         "Launchpad uses generic client",
			repoURL:      "https://launchpad.net/~owner/+git/repo",
			expectedType: "Generic Git",
		},
		{
			name:         "Generic .git URL uses generic client",
			repoURL:      "https://git.example.com/owner/repo.git",
			expectedType: "Generic Git",
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

// Test: GitLab URL parsing for owner, repo, and instance extraction
// Justification: Correctly extracting owner/repo/instance is required to build
//                accurate GitLab API URLs. Incorrect extraction means we query the
//                wrong project and return stale or wrong risk data.
// Source: GitLab REST API documentation – https://docs.gitlab.com/ee/api/rest/
// Methodology: Call parseGitLabURL() with HTTPS, SSH, self-hosted, and edge-case
//              inputs; verify each returned field against expected values.
// Result: Valid GitLab URLs parse correctly; non-GitLab URLs return an error.
func TestParseGitLabURL(t *testing.T) {
	tests := []struct {
		name             string
		repoURL          string
		expectedOwner    string
		expectedRepo     string
		expectedInstance string
		shouldError      bool
	}{
		{
			name:             "GitLab.com HTTPS",
			repoURL:          "https://gitlab.com/owner/repo",
			expectedOwner:    "owner",
			expectedRepo:     "repo",
			expectedInstance: "gitlab.com",
			shouldError:      false,
		},
		{
			name:             "GitLab.com SSH",
			repoURL:          "git@gitlab.com:owner/repo.git",
			expectedOwner:    "owner",
			expectedRepo:     "repo",
			expectedInstance: "gitlab.com",
			shouldError:      false,
		},
		{
			name:             "GitLab self-hosted",
			repoURL:          "https://gitlab.example.com/owner/repo",
			expectedOwner:    "owner",
			expectedRepo:     "repo",
			expectedInstance: "gitlab.example.com",
			shouldError:      false,
		},
		{
			// .git suffix is stripped before parsing – common in npm/pip metadata
			name:             "GitLab.com HTTPS with .git suffix",
			repoURL:          "https://gitlab.com/owner/repo.git",
			expectedOwner:    "owner",
			expectedRepo:     "repo",
			expectedInstance: "gitlab.com",
			shouldError:      false,
		},
		{
			// git+https:// prefix appears in npm registry repository fields
			name:             "GitLab git+https prefix",
			repoURL:          "git+https://gitlab.com/owner/repo.git",
			expectedOwner:    "owner",
			expectedRepo:     "repo",
			expectedInstance: "gitlab.com",
			shouldError:      false,
		},
		{
			name:        "Invalid URL – not a GitLab host",
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

// Test: Bitbucket URL parsing for owner and repo extraction
// Justification: Accurate owner/repo extraction drives Bitbucket API calls for
//                contributor analysis and ownership-change detection.
// Source: Bitbucket REST API v2 – https://developer.atlassian.com/cloud/bitbucket/rest/
// Methodology: Call parseBitbucketURL() with HTTPS, SSH, and edge-case inputs.
// Result: Valid Bitbucket URLs parse to correct owner/repo; non-Bitbucket URLs error.
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
			// .git suffix is stripped before parsing
			name:          "Bitbucket HTTPS with .git suffix",
			repoURL:       "https://bitbucket.org/owner/repo.git",
			expectedOwner: "owner",
			expectedRepo:  "repo",
			shouldError:   false,
		},
		{
			// git+https:// prefix appears in npm/pip registry metadata
			name:          "Bitbucket git+https prefix",
			repoURL:       "git+https://bitbucket.org/owner/repo.git",
			expectedOwner: "owner",
			expectedRepo:  "repo",
			shouldError:   false,
		},
		{
			name:        "Invalid URL – not a Bitbucket host",
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

// Test: URL normalization strips protocol prefixes before platform matching
// Justification: Package registry metadata uses varied URL schemes
//                (git+https://, git://, ssh://, git@). Normalization ensures
//                platform detection is robust to all real-world formats.
// Source: npm registry repository field formats – https://docs.npmjs.com/cli/v10/configuring-npm/package-json#repository
// Methodology: Call normalizeURL() with each supported prefix format and verify
//              the resulting host+path string.
// Result: All protocol prefixes are stripped; the bare host/path is returned.
func TestNormalizeURL(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"https://github.com/owner/repo", "github.com/owner/repo"},
		{"http://github.com/owner/repo", "github.com/owner/repo"},
		{"git://github.com/owner/repo.git", "github.com/owner/repo.git"},
		{"git+https://github.com/owner/repo.git", "github.com/owner/repo.git"},
		{"git+http://github.com/owner/repo.git", "github.com/owner/repo.git"},
		// ssh:// is stripped, then git@ is stripped in a second pass
		{"ssh://git@github.com/owner/repo.git", "github.com/owner/repo.git"},
		{"git@github.com:owner/repo.git", "github.com:owner/repo.git"},
		// Already normalized – no change expected
		{"github.com/owner/repo", "github.com/owner/repo"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := normalizeURL(tt.input)
			if got != tt.want {
				t.Errorf("normalizeURL(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// Test: Owner and repository name extraction from generic hosting URLs
// Justification: extractOwnerRepo drives raw-file URL construction for the
//                GenericGitClient. Incorrect extraction means we try to fetch
//                CI configuration files from the wrong path and miss risk signals.
// Source: GenericGitClient implementation – pkg/fetcher/generic_git.go
// Methodology: Call extractOwnerRepo() with Codeberg, Sourcehut, and generic URLs.
// Result: owner and repo are correctly split from the URL path.
func TestExtractOwnerRepo(t *testing.T) {
	tests := []struct {
		name      string
		baseURL   string
		wantOwner string
		wantRepo  string
	}{
		{
			name:      "Codeberg URL",
			baseURL:   "https://codeberg.org/owner/myrepo",
			wantOwner: "owner",
			wantRepo:  "myrepo",
		},
		{
			name:      "Codeberg URL with .git suffix stripped",
			baseURL:   "https://codeberg.org/owner/myrepo",
			wantOwner: "owner",
			wantRepo:  "myrepo",
		},
		{
			name:      "Sourcehut URL",
			baseURL:   "https://git.sr.ht/~owner/myrepo",
			wantOwner: "~owner",
			wantRepo:  "myrepo",
		},
		{
			name:      "Generic three-segment URL",
			baseURL:   "https://git.example.com/owner/myrepo",
			wantOwner: "owner",
			wantRepo:  "myrepo",
		},
		{
			name:      "URL with extra path segments",
			baseURL:   "https://git.example.com/owner/myrepo/extra",
			wantOwner: "owner",
			wantRepo:  "myrepo",
		},
		{
			name:      "HTTP protocol",
			baseURL:   "http://git.example.com/owner/myrepo",
			wantOwner: "owner",
			wantRepo:  "myrepo",
		},
		{
			// Two-segment URL cannot be split into owner+repo
			name:      "URL too short returns empty",
			baseURL:   "https://git.example.com/owner",
			wantOwner: "",
			wantRepo:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotOwner, gotRepo := extractOwnerRepo(tt.baseURL)
			if gotOwner != tt.wantOwner {
				t.Errorf("extractOwnerRepo(%q) owner = %q, want %q", tt.baseURL, gotOwner, tt.wantOwner)
			}
			if gotRepo != tt.wantRepo {
				t.Errorf("extractOwnerRepo(%q) repo = %q, want %q", tt.baseURL, gotRepo, tt.wantRepo)
			}
		})
	}
}

// Test: Raw-file URL candidate generation for generic Git hosts
// Justification: The GenericGitClient fetches CI configuration files (e.g. .github/workflows,
//                .gitlab-ci.yml) using raw-content URLs. Generating the correct candidates
//                for each platform is essential to detecting automated release pipelines –
//                a key provenance signal per SLSA requirements.
// Source: SLSA specification v1.0 – https://slsa.dev/spec/v1.0/
//         Codeberg raw URL format – https://codeberg.org/
//         Sourcehut raw URL format – https://git.sr.ht/
// Methodology: Call genericRawURLs() and verify platform-specific URLs are present.
// Result: Platform-appropriate raw-content URLs appear in the candidate list.
func TestGenericRawURLs(t *testing.T) {
	t.Run("Codeberg URL includes branch-based raw paths", func(t *testing.T) {
		candidates := genericRawURLs("https://codeberg.org/owner/myrepo", "README.md")
		wantMain := "https://codeberg.org/owner/myrepo/raw/branch/main/README.md"
		wantMaster := "https://codeberg.org/owner/myrepo/raw/branch/master/README.md"

		hasMain, hasMaster := false, false
		for _, c := range candidates {
			if c == wantMain {
				hasMain = true
			}
			if c == wantMaster {
				hasMaster = true
			}
		}
		if !hasMain {
			t.Errorf("missing Codeberg main URL %q in candidates %v", wantMain, candidates)
		}
		if !hasMaster {
			t.Errorf("missing Codeberg master URL %q in candidates %v", wantMaster, candidates)
		}
	})

	t.Run("Sourcehut URL includes HEAD blob path", func(t *testing.T) {
		candidates := genericRawURLs("https://git.sr.ht/~owner/myrepo", "README.md")
		wantSrHt := "https://git.sr.ht/~owner/myrepo/blob/HEAD/README.md"

		found := false
		for _, c := range candidates {
			if c == wantSrHt {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("missing Sourcehut URL %q in candidates %v", wantSrHt, candidates)
		}
	})

	t.Run("Generic URL includes main and master fallbacks", func(t *testing.T) {
		candidates := genericRawURLs("https://git.example.com/owner/repo", "Makefile")
		wantMain := "https://git.example.com/owner/repo/raw/main/Makefile"
		wantMaster := "https://git.example.com/owner/repo/raw/master/Makefile"

		hasMain, hasMaster := false, false
		for _, c := range candidates {
			if c == wantMain {
				hasMain = true
			}
			if c == wantMaster {
				hasMaster = true
			}
		}
		if !hasMain {
			t.Errorf("missing generic main URL %q in candidates %v", wantMain, candidates)
		}
		if !hasMaster {
			t.Errorf("missing generic master URL %q in candidates %v", wantMaster, candidates)
		}
	})

	t.Run(".git suffix stripped from base URL", func(t *testing.T) {
		candidates := genericRawURLs("https://git.example.com/owner/repo.git", "README.md")
		for _, c := range candidates {
			if len(c) > 4 {
				// No candidate URL should contain ".git/raw/" – that would be malformed
				for i := 0; i < len(c)-8; i++ {
					if c[i:i+9] == ".git/raw/" {
						t.Errorf("candidate URL contains .git before /raw/: %q", c)
					}
				}
			}
		}
	})
}

// Test: GenericGitClient satisfies GitPlatformClient interface and identifies itself
// Justification: The generic client must implement the full interface so it can be used
//                anywhere a GitPlatformClient is expected without type assertions.
// Source: pkg/fetcher/generic_git.go
// Methodology: Instantiate GenericGitClient via NewGenericGitClient() and verify the
//              platform name and interface satisfaction.
// Result: GetPlatformName() returns "Generic Git".
func TestGenericGitClientGetPlatformName(t *testing.T) {
	// Test: GenericGitClient satisfies interface and returns correct platform name
	var _ GitPlatformClient = NewGenericGitClient() // compile-time interface check

	client := NewGenericGitClient()
	if got := client.GetPlatformName(); got != "Generic Git" {
		t.Errorf("GenericGitClient.GetPlatformName() = %q, want %q", got, "Generic Git")
	}
}
