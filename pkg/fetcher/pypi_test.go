package fetcher

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// Test: extractPyPIMaintainers extracts maintainers from all PyPI info fields
// Justification: Single-maintainer detection is the #1 supply chain risk signal.
//                Modern packages using pyproject.toml populate author_email instead of
//                author, causing 0 maintainers and missed single-maintainer detection.
// Source: PyPI JSON API docs; PEP 621 (pyproject.toml metadata)
// Methodology: Test with real-world PyPI field combinations (author, author_email,
//              maintainer, maintainer_email) including comma-separated lists
// Result: Correct maintainer count for all field combinations
func TestExtractPyPIMaintainers(t *testing.T) {
	tests := []struct {
		name      string
		info      PyPIInfo
		wantCount int
		wantFirst string
	}{
		{
			name: "author field only (legacy format, e.g. requests)",
			info: PyPIInfo{
				Author: "Kenneth Reitz",
			},
			wantCount: 1,
			wantFirst: "Kenneth Reitz",
		},
		{
			name: "author_email only (pyproject.toml format, e.g. colorama)",
			info: PyPIInfo{
				AuthorEmail: "Jonathan Hartley <tartley@tartley.com>",
			},
			wantCount: 1,
			wantFirst: "Jonathan Hartley <tartley@tartley.com>",
		},
		{
			name: "multiple authors in author_email (e.g. pydantic)",
			info: PyPIInfo{
				AuthorEmail: "Samuel Colvin <s@muelcolvin.com>, Eric Jolibois <em.jolibois@gmail.com>, Hasan Ramezani <hasan.r67@gmail.com>",
			},
			wantCount: 3,
			wantFirst: "Samuel Colvin <s@muelcolvin.com>",
		},
		{
			name: "maintainer_email only (e.g. flask)",
			info: PyPIInfo{
				MaintainerEmail: "Pallets <contact@palletsprojects.com>",
			},
			wantCount: 1,
			wantFirst: "Pallets <contact@palletsprojects.com>",
		},
		{
			name: "author_email without angle brackets (bare email)",
			info: PyPIInfo{
				AuthorEmail: "tom@example.com",
			},
			wantCount: 1,
			wantFirst: "tom@example.com",
		},
		{
			name: "both author and author_email (dedup by name)",
			info: PyPIInfo{
				Author:      "Tom Christie",
				AuthorEmail: "Tom Christie <tom@example.com>",
			},
			wantCount: 1,
			wantFirst: "Tom Christie",
		},
		{
			name: "maintainer takes priority, author adds extras",
			info: PyPIInfo{
				Maintainer:  "Maintainer One",
				AuthorEmail: "Author Two <a@b.com>",
			},
			wantCount: 2,
			wantFirst: "Maintainer One",
		},
		{
			name: "all fields empty",
			info: PyPIInfo{},
			wantCount: 0,
		},
		{
			name: "author_email with Django-style org email",
			info: PyPIInfo{
				AuthorEmail: "Django Software Foundation <foundation@djangoproject.com>",
			},
			wantCount: 1,
			wantFirst: "Django Software Foundation <foundation@djangoproject.com>",
		},
		{
			name: "comma-separated author field (e.g. pytest)",
			info: PyPIInfo{
				Author: "Holger Krekel, Bruno Oliveira, Ronny Pfannschmidt, Floris Bruynooghe, Brianna Laugher, Florian Bruhin, Others",
			},
			wantCount: 7,
			wantFirst: "Holger Krekel",
		},
		{
			name: "comma-separated maintainer field",
			info: PyPIInfo{
				Maintainer: "Alice, Bob",
			},
			wantCount: 2,
			wantFirst: "Alice",
		},
		{
			name: "comma-separated author with email-style author_email (dedup)",
			info: PyPIInfo{
				Author:      "Alice, Bob",
				AuthorEmail: "Alice <alice@example.com>, Charlie <charlie@example.com>",
			},
			wantCount: 3,
			wantFirst: "Alice",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractPyPIMaintainers(tt.info)
			if len(result) != tt.wantCount {
				t.Errorf("extractPyPIMaintainers() count = %d, want %d; got %v", len(result), tt.wantCount, result)
			}
			if tt.wantCount > 0 && len(result) > 0 && result[0] != tt.wantFirst {
				t.Errorf("extractPyPIMaintainers()[0] = %q, want %q", result[0], tt.wantFirst)
			}
		})
	}
}

// Test: splitEmailList correctly handles comma-separated email entries
// Justification: pyproject.toml author lists are serialized as comma-separated
//                "Name <email>, Name2 <email2>" strings in the PyPI JSON API.
//                Incorrect splitting would merge/lose maintainer entries.
// Source: PEP 621 (pyproject.toml authors format); PyPI JSON API response
// Methodology: Test various email list formats including edge cases
// Result: Each author correctly split into separate entries
func TestSplitEmailList(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  int
	}{
		{"single entry", "Tom <t@x.com>", 1},
		{"two entries", "Tom <t@x.com>, Jane <j@x.com>", 2},
		{"bare email", "tom@example.com", 1},
		{"mixed format", "Tom <t@x.com>, bob@y.com", 2},
		{"empty", "", 0},
		{"thirteen entries (pydantic-style)", "A <a@b.com>, B <b@c.com>, C <c@d.com>, D <d@e.com>, E <e@f.com>, F <f@g.com>, G <g@h.com>, H <h@i.com>, I <i@j.com>, J <j@k.com>, K <k@l.com>, L <l@m.com>, M <m@n.com>", 13},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := splitEmailList(tt.input)
			if len(result) != tt.want {
				t.Errorf("splitEmailList(%q) = %d entries, want %d; got %v", tt.input, len(result), tt.want, result)
			}
		})
	}
}

// Test: PyPI GetPackageInfo correctly populates maintainers from author_email
// Justification: End-to-end validation that the new extractPyPIMaintainers function
//                is correctly integrated into the PyPI data flow, so packages using
//                pyproject.toml (author_email) are correctly flagged for single-maintainer risk
// Source: Real-world PyPI API response formats (colorama, flask, pydantic)
// Methodology: Mock PyPI API with author_email instead of author field
// Result: Package metadata correctly reports maintainers from author_email
func TestGetPackageInfo_PyPI_AuthorEmail(t *testing.T) {
	response := PyPIResponse{
		Info: PyPIInfo{
			Name:        "colorama",
			Version:     "0.4.6",
			Author:      "", // Empty author (modern pyproject.toml format)
			AuthorEmail: "Jonathan Hartley <tartley@tartley.com>",
			License:     "BSD",
			ProjectURLs: map[string]string{
				"Source": "https://github.com/tartley/colorama",
			},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	client := &PyPIClient{
		httpClient: &http.Client{},
		baseURL:    server.URL,
	}

	pkg, err := client.GetPackageInfo("colorama")
	if err != nil {
		t.Fatalf("GetPackageInfo() error = %v", err)
	}

	if len(pkg.Maintainers) != 1 {
		t.Errorf("GetPackageInfo() maintainers count = %d, want 1; got %v", len(pkg.Maintainers), pkg.Maintainers)
	}

	if len(pkg.Maintainers) > 0 && pkg.Maintainers[0] != "Jonathan Hartley <tartley@tartley.com>" {
		t.Errorf("GetPackageInfo() maintainer = %q, want %q", pkg.Maintainers[0], "Jonathan Hartley <tartley@tartley.com>")
	}
}

// Test: PyPI GetPackageInfo with multiple authors from author_email
// Justification: Multi-author packages (e.g., pydantic with 13 authors) must correctly
//                count all maintainers to avoid false single-maintainer risk signals
// Source: Real-world PyPI response for pydantic (author_email with comma-separated list)
// Methodology: Mock PyPI API with multiple comma-separated author_email entries
// Result: All authors correctly counted as maintainers
func TestGetPackageInfo_PyPI_MultipleAuthorEmail(t *testing.T) {
	response := PyPIResponse{
		Info: PyPIInfo{
			Name:        "pydantic",
			Version:     "2.10.6",
			Author:      "", // Empty author
			AuthorEmail: "Samuel Colvin <s@muelcolvin.com>, Eric Jolibois <em.jolibois@gmail.com>, Hasan Ramezani <hasan.r67@gmail.com>",
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	client := &PyPIClient{
		httpClient: &http.Client{},
		baseURL:    server.URL,
	}

	pkg, err := client.GetPackageInfo("pydantic")
	if err != nil {
		t.Fatalf("GetPackageInfo() error = %v", err)
	}

	if len(pkg.Maintainers) != 3 {
		t.Errorf("GetPackageInfo() maintainers count = %d, want 3; got %v", len(pkg.Maintainers), pkg.Maintainers)
	}
}

// Test: extractPyPIRepoURL priority order for project_urls keys
// Justification: Correct repository URL extraction is critical for verifying
//                source code availability — the wrong URL leads to false
//                negatives in source verification checks
// Source: PyPI JSON API — project_urls is an arbitrary string→URL map
// Methodology: Test each priority level and case-insensitive matching
// Result: URLs are extracted in correct priority order
func TestExtractPyPIRepoURL(t *testing.T) {
	tests := []struct {
		name     string
		info     PyPIInfo
		expected string
	}{
		{
			name: "Source Code key (highest priority)",
			info: PyPIInfo{
				ProjectURLs: map[string]string{
					"Source Code": "https://github.com/example/repo",
					"Homepage":    "https://example.com",
				},
			},
			expected: "https://github.com/example/repo",
		},
		{
			name: "Source key",
			info: PyPIInfo{
				ProjectURLs: map[string]string{
					"Source": "https://github.com/example/repo2",
				},
			},
			expected: "https://github.com/example/repo2",
		},
		{
			name: "Repository key",
			info: PyPIInfo{
				ProjectURLs: map[string]string{
					"Repository": "https://gitlab.com/example/repo",
				},
			},
			expected: "https://gitlab.com/example/repo",
		},
		{
			name: "Code key",
			info: PyPIInfo{
				ProjectURLs: map[string]string{
					"Code": "https://github.com/example/repo3",
				},
			},
			expected: "https://github.com/example/repo3",
		},
		{
			name: "case insensitive matching",
			info: PyPIInfo{
				ProjectURLs: map[string]string{
					"source code": "https://github.com/example/lower",
				},
			},
			expected: "https://github.com/example/lower",
		},
		{
			name: "Homepage with GitHub domain (accepted)",
			info: PyPIInfo{
				ProjectURLs: map[string]string{
					"Homepage": "https://github.com/example/repo",
				},
			},
			expected: "https://github.com/example/repo",
		},
		{
			name: "Homepage with non-source domain (rejected)",
			info: PyPIInfo{
				ProjectURLs: map[string]string{
					"Homepage": "https://example.com",
				},
			},
			expected: "",
		},
		{
			name: "fallback to home_page field with GitHub domain",
			info: PyPIInfo{
				HomePage: "https://github.com/example/fallback",
			},
			expected: "https://github.com/example/fallback",
		},
		{
			name: "no URLs available",
			info: PyPIInfo{},
			expected: "",
		},
		{
			name: "GitHub key (e.g. packages using 'GitHub' as project_urls key)",
			info: PyPIInfo{
				ProjectURLs: map[string]string{
					"GitHub":        "https://github.com/example/repo",
					"Documentation": "https://docs.example.com",
				},
			},
			expected: "https://github.com/example/repo",
		},
		{
			name: "catch-all: repo URL extracted from Issue Tracker (sqlalchemy pattern)",
			info: PyPIInfo{
				ProjectURLs: map[string]string{
					"Documentation": "https://docs.sqlalchemy.org",
					"Homepage":      "https://www.sqlalchemy.org",
					"Issue Tracker": "https://github.com/sqlalchemy/sqlalchemy/",
				},
				HomePage: "https://www.sqlalchemy.org",
			},
			expected: "https://github.com/sqlalchemy/sqlalchemy",
		},
		{
			name: "catch-all: strips /issues suffix from bug tracker URL",
			info: PyPIInfo{
				ProjectURLs: map[string]string{
					"Bug Tracker": "https://github.com/example/repo/issues",
				},
			},
			expected: "https://github.com/example/repo",
		},
		{
			name: "heptapod URL in home_page field",
			info: PyPIInfo{
				HomePage: "https://foss.heptapod.net/python-libs/passlib",
			},
			expected: "https://foss.heptapod.net/python-libs/passlib",
		},
		{
			name: "heptapod URL in project_urls Homepage",
			info: PyPIInfo{
				ProjectURLs: map[string]string{
					"Homepage": "https://foss.heptapod.net/python-libs/passlib",
				},
			},
			expected: "https://foss.heptapod.net/python-libs/passlib",
		},
		{
			name: "Codeberg URL in Repository key",
			info: PyPIInfo{
				ProjectURLs: map[string]string{
					"Repository": "https://codeberg.org/example/repo",
				},
			},
			expected: "https://codeberg.org/example/repo",
		},
		{
			name: "priority keys preferred over catch-all",
			info: PyPIInfo{
				ProjectURLs: map[string]string{
					"Source":        "https://github.com/example/correct",
					"Issue Tracker": "https://github.com/example/issues-url/issues",
				},
			},
			expected: "https://github.com/example/correct",
		},
		{
			name: "home_page non-source domain (rejected)",
			info: PyPIInfo{
				HomePage: "https://example.readthedocs.io",
			},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractPyPIRepoURL(tt.info)
			if result != tt.expected {
				t.Errorf("extractPyPIRepoURL() = %q, want %q", result, tt.expected)
			}
		})
	}
}

// Test: stripRepoSubpageSuffix normalizes issue tracker / wiki URLs to base repo URLs
// Justification: When extracting repo URLs from non-standard project_urls keys
//                (e.g. "Issue Tracker"), subpage suffixes must be stripped so the
//                URL can be used for source code analysis
// Source: PyPI JSON API — project_urls values may point to subpages
// Methodology: Test various repo URL formats with and without subpage suffixes
// Result: Base repository URL is returned
func TestStripRepoSubpageSuffix(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"clean URL unchanged", "https://github.com/org/repo", "https://github.com/org/repo"},
		{"strips /issues", "https://github.com/org/repo/issues", "https://github.com/org/repo"},
		{"strips /wiki", "https://github.com/org/repo/wiki", "https://github.com/org/repo"},
		{"strips /pulls", "https://github.com/org/repo/pulls", "https://github.com/org/repo"},
		{"strips /actions", "https://github.com/org/repo/actions", "https://github.com/org/repo"},
		{"strips /releases", "https://github.com/org/repo/releases", "https://github.com/org/repo"},
		{"strips trailing slash", "https://github.com/org/repo/", "https://github.com/org/repo"},
		{"trailing slash + /issues", "https://github.com/org/repo/issues/", "https://github.com/org/repo"},
		{"GitLab issues", "https://gitlab.com/org/repo/issues", "https://gitlab.com/org/repo"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := stripRepoSubpageSuffix(tt.input)
			if result != tt.expected {
				t.Errorf("stripRepoSubpageSuffix(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

// Test: countRequiresDist excludes extras-only dependencies
// Justification: Accurate dependency count is essential for the Dependency
//                Sprawl risk category — extras should not inflate the count
// Source: PEP 508 — Dependency specification for Python packages
// Methodology: Pass requires_dist entries with and without extra markers
// Result: Only non-extra dependencies are counted
func TestCountRequiresDist(t *testing.T) {
	tests := []struct {
		name     string
		input    []string
		expected int
	}{
		{
			name:     "no dependencies",
			input:    nil,
			expected: 0,
		},
		{
			name: "all required",
			input: []string{
				"charset-normalizer (<4,>=2)",
				"idna (<4,>=2.5)",
				"urllib3 (<3,>=1.21.1)",
			},
			expected: 3,
		},
		{
			name: "mix of required and extras",
			input: []string{
				"charset-normalizer (<4,>=2)",
				"idna (<4,>=2.5)",
				"PySocks (!=1.5.7,>=1.5.6) ; extra == \"socks\"",
				"chardet (>=3.0.2,<6) ; extra == \"security\"",
			},
			expected: 2,
		},
		{
			name: "all extras",
			input: []string{
				"PySocks ; extra == \"socks\"",
				"win-inet-pton ; extra == \"socks\"",
			},
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := countRequiresDist(tt.input)
			if result != tt.expected {
				t.Errorf("countRequiresDist() = %d, want %d", result, tt.expected)
			}
		})
	}
}

// Test: GetOwnershipHistory with uploader fallback to info.Author
// Justification: PyPI's public JSON API does not expose per-file uploader —
//                the field is always "". Without fallback, all releases would
//                appear to have the same (empty) author, masking real transfers
// Source: PyPI JSON API behavior — uploader field is empty in public API
// Methodology: Mock releases with empty Uploader fields
// Result: Falls back to info.Author, still tracks stable ownership correctly
func TestGetOwnershipHistory_PyPI_EmptyUploader(t *testing.T) {
	response := PyPIFullResponse{
		Info: PyPIInfo{
			Name:   "test-package",
			Author: "alice",
		},
		Releases: map[string][]PyPIReleaseFile{
			"1.0.0": {
				{
					Filename:   "test-package-1.0.0.tar.gz",
					UploadTime: time.Now().AddDate(0, -12, 0),
					Uploader:   "", // Empty uploader (typical of public PyPI API)
				},
			},
			"2.0.0": {
				{
					Filename:   "test-package-2.0.0.tar.gz",
					UploadTime: time.Now().AddDate(0, -6, 0),
					Uploader:   "", // Empty uploader
				},
			},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	client := &PyPIClient{
		httpClient: &http.Client{},
		baseURL:    server.URL,
	}

	history, err := client.GetOwnershipHistory("test-package")
	if err != nil {
		t.Fatalf("GetOwnershipHistory() error = %v", err)
	}

	// With empty uploaders, both releases fall back to info.Author ("alice"),
	// so there should be 0 ownership changes
	if history.AuthorChanges != 0 {
		t.Errorf("GetOwnershipHistory() changes = %v, want 0 (empty uploaders should fall back to info.Author)", history.AuthorChanges)
	}

	if history.CurrentAuthor != "alice" {
		t.Errorf("GetOwnershipHistory() current author = %q, want %q", history.CurrentAuthor, "alice")
	}
}

func TestGetOwnershipHistory_PyPI(t *testing.T) {
	tests := []struct {
		name              string
		response          PyPIFullResponse
		wantChanges       int
		wantRecentTransfer bool
	}{
		{
			name: "stable ownership",
			response: PyPIFullResponse{
				Info: PyPIInfo{
					Name:   "test-package",
					Author: "alice",
				},
				Releases: map[string][]PyPIReleaseFile{
					"1.0.0": {
						{
							Filename:   "test-package-1.0.0.tar.gz",
							UploadTime: time.Now().AddDate(0, -12, 0),
							Uploader:   "alice",
						},
					},
					"1.1.0": {
						{
							Filename:   "test-package-1.1.0.tar.gz",
							UploadTime: time.Now().AddDate(0, -6, 0),
							Uploader:   "alice",
						},
					},
				},
			},
			wantChanges:       0,
			wantRecentTransfer: false,
		},
		{
			name: "recent ownership transfer",
			response: PyPIFullResponse{
				Info: PyPIInfo{
					Name:   "test-package",
					Author: "bob",
				},
				Releases: map[string][]PyPIReleaseFile{
					"1.0.0": {
						{
							Filename:   "test-package-1.0.0.tar.gz",
							UploadTime: time.Now().AddDate(0, -12, 0),
							Uploader:   "alice",
						},
					},
					"2.0.0": {
						{
							Filename:   "test-package-2.0.0.tar.gz",
							UploadTime: time.Now().AddDate(0, -2, 0),
							Uploader:   "bob",
						},
					},
				},
			},
			wantChanges:       1,
			wantRecentTransfer: true,
		},
		{
			name: "old ownership change",
			response: PyPIFullResponse{
				Info: PyPIInfo{
					Name:   "test-package",
					Author: "bob",
				},
				Releases: map[string][]PyPIReleaseFile{
					"1.0.0": {
						{
							Filename:   "test-package-1.0.0.tar.gz",
							UploadTime: time.Now().AddDate(-2, 0, 0),
							Uploader:   "alice",
						},
					},
					"2.0.0": {
						{
							Filename:   "test-package-2.0.0.tar.gz",
							UploadTime: time.Now().AddDate(-1, 0, 0),
							Uploader:   "bob",
						},
					},
				},
			},
			wantChanges:       1,
			wantRecentTransfer: false,
		},
		{
			name: "multiple author changes",
			response: PyPIFullResponse{
				Info: PyPIInfo{
					Name:   "test-package",
					Author: "charlie",
				},
				Releases: map[string][]PyPIReleaseFile{
					"1.0.0": {
						{
							Filename:   "test-package-1.0.0.tar.gz",
							UploadTime: time.Now().AddDate(-2, 0, 0),
							Uploader:   "alice",
						},
					},
					"2.0.0": {
						{
							Filename:   "test-package-2.0.0.tar.gz",
							UploadTime: time.Now().AddDate(-1, 0, 0),
							Uploader:   "bob",
						},
					},
					"3.0.0": {
						{
							Filename:   "test-package-3.0.0.tar.gz",
							UploadTime: time.Now().AddDate(0, -6, 0),
							Uploader:   "charlie",
						},
					},
				},
			},
			wantChanges:       2,
			wantRecentTransfer: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mock server
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(tt.response)
			}))
			defer server.Close()

			client := &PyPIClient{
				httpClient: &http.Client{},
				baseURL:    server.URL,
			}

			history, err := client.GetOwnershipHistory("test-package")
			if err != nil {
				t.Fatalf("GetOwnershipHistory() error = %v", err)
			}

			if history.AuthorChanges != tt.wantChanges {
				t.Errorf("GetOwnershipHistory() changes = %v, want %v", history.AuthorChanges, tt.wantChanges)
			}

			if history.RecentTransfer != tt.wantRecentTransfer {
				t.Errorf("GetOwnershipHistory() recent transfer = %v, want %v", history.RecentTransfer, tt.wantRecentTransfer)
			}
		})
	}
}

func TestGetOwnershipHistory_PyPI_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client := &PyPIClient{
		httpClient: &http.Client{},
		baseURL:    server.URL,
	}

	_, err := client.GetOwnershipHistory("nonexistent-package")
	if err == nil {
		t.Error("GetOwnershipHistory() expected error, got nil")
	}
}

func TestGetOwnershipHistory_PyPI_EmptyReleases(t *testing.T) {
	response := PyPIFullResponse{
		Info: PyPIInfo{
			Name:   "test-package",
			Author: "alice",
		},
		Releases: map[string][]PyPIReleaseFile{},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	client := &PyPIClient{
		httpClient: &http.Client{},
		baseURL:    server.URL,
	}

	history, err := client.GetOwnershipHistory("test-package")
	if err != nil {
		t.Fatalf("GetOwnershipHistory() error = %v", err)
	}

	if history.AuthorChanges != 0 {
		t.Errorf("GetOwnershipHistory() changes = %v, want 0", history.AuthorChanges)
	}

	if history.CurrentAuthor != "alice" {
		t.Errorf("GetOwnershipHistory() current author = %v, want alice", history.CurrentAuthor)
	}
}
