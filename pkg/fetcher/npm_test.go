package fetcher

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestGetOwnershipHistory_NPM(t *testing.T) {
	tests := []struct {
		name              string
		response          NPMRegistryResponse
		wantChanges       int
		wantRecentTransfer bool
	}{
		{
			name: "stable ownership",
			response: NPMRegistryResponse{
				Name: "test-package",
				Maintainers: []NPMMaintainer{
					{Name: "alice", Email: "alice@example.com"},
				},
				Versions: map[string]NPMVersionDetails{
					"1.0.0": {
						Version: "1.0.0",
						Maintainers: []NPMMaintainer{
							{Name: "alice", Email: "alice@example.com"},
						},
					},
					"1.1.0": {
						Version: "1.1.0",
						Maintainers: []NPMMaintainer{
							{Name: "alice", Email: "alice@example.com"},
						},
					},
				},
				Time: map[string]string{
					"1.0.0": time.Now().AddDate(0, -12, 0).Format(time.RFC3339),
					"1.1.0": time.Now().AddDate(0, -6, 0).Format(time.RFC3339),
				},
			},
			wantChanges:       0,
			wantRecentTransfer: false,
		},
		{
			name: "recent ownership transfer",
			response: NPMRegistryResponse{
				Name: "test-package",
				Maintainers: []NPMMaintainer{
					{Name: "bob", Email: "bob@example.com"},
				},
				Versions: map[string]NPMVersionDetails{
					"1.0.0": {
						Version: "1.0.0",
						Maintainers: []NPMMaintainer{
							{Name: "alice", Email: "alice@example.com"},
						},
					},
					"2.0.0": {
						Version: "2.0.0",
						Maintainers: []NPMMaintainer{
							{Name: "bob", Email: "bob@example.com"},
						},
					},
				},
				Time: map[string]string{
					"1.0.0": time.Now().AddDate(0, -12, 0).Format(time.RFC3339),
					"2.0.0": time.Now().AddDate(0, -1, 0).Format(time.RFC3339),
				},
			},
			wantChanges:       1,
			wantRecentTransfer: true,
		},
		{
			name: "old ownership change",
			response: NPMRegistryResponse{
				Name: "test-package",
				Maintainers: []NPMMaintainer{
					{Name: "bob", Email: "bob@example.com"},
				},
				Versions: map[string]NPMVersionDetails{
					"1.0.0": {
						Version: "1.0.0",
						Maintainers: []NPMMaintainer{
							{Name: "alice", Email: "alice@example.com"},
						},
					},
					"2.0.0": {
						Version: "2.0.0",
						Maintainers: []NPMMaintainer{
							{Name: "bob", Email: "bob@example.com"},
						},
					},
				},
				Time: map[string]string{
					"1.0.0": time.Now().AddDate(-2, 0, 0).Format(time.RFC3339),
					"2.0.0": time.Now().AddDate(-1, 0, 0).Format(time.RFC3339),
				},
			},
			wantChanges:       1,
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

			client := &NPMClient{
				httpClient: &http.Client{},
				baseURL:    server.URL,
			}

			history, err := client.GetOwnershipHistory("test-package")
			if err != nil {
				t.Fatalf("GetOwnershipHistory() error = %v", err)
			}

			if history.MaintainerChanges != tt.wantChanges {
				t.Errorf("GetOwnershipHistory() changes = %v, want %v", history.MaintainerChanges, tt.wantChanges)
			}

			if history.RecentTransfer != tt.wantRecentTransfer {
				t.Errorf("GetOwnershipHistory() recent transfer = %v, want %v", history.RecentTransfer, tt.wantRecentTransfer)
			}
		})
	}
}

// Test: GetPackageInfo handles polymorphic JSON field types without crashing
// Justification: npm registry returns "license" as string, object, or array, and
//                "repository" as object or string. Packages with non-standard types
//                (e.g. formidable with string repository, old packages with array
//                license) previously caused json.Decode to fail, returning a
//                misleading "Package Not Found" HIGH-risk result.
// Source: npm registry API documentation; observed in formidable, joi@1.x, etc.
// Methodology: Mock server returns JSON with polymorphic field types; verify decode succeeds.
// Result: GetPackageInfo returns valid package info regardless of field type variants.
func TestGetPackageInfo_PolymorphicFields(t *testing.T) {
	tests := []struct {
		name           string
		rawJSON        string
		wantLicense    string
		wantRepoURL    string
		wantErr        bool
	}{
		{
			name: "license as string, repository as object (standard)",
			rawJSON: `{
				"name":"test-pkg",
				"license":"MIT",
				"dist-tags":{"latest":"1.0.0"},
				"repository":{"type":"git","url":"git+https://github.com/test/test.git"},
				"maintainers":[{"name":"alice"}],
				"versions":{"1.0.0":{"version":"1.0.0"}},
				"time":{"1.0.0":"2024-01-01T00:00:00Z"}
			}`,
			wantLicense: "MIT",
			wantRepoURL: "https://github.com/test/test",
		},
		{
			name: "license as array of objects (old format, e.g. joi@1.x)",
			rawJSON: `{
				"name":"old-pkg",
				"license":[{"type":"BSD","url":"http://example.com/LICENSE"}],
				"dist-tags":{"latest":"1.0.0"},
				"repository":{"type":"git","url":"git://github.com/old/pkg.git"},
				"maintainers":[{"name":"bob"}],
				"versions":{"1.0.0":{"version":"1.0.0"}},
				"time":{"1.0.0":"2013-01-01T00:00:00Z"}
			}`,
			wantLicense: "BSD",
			wantRepoURL: "https://github.com/old/pkg",
		},
		{
			name: "license as object (rare format)",
			rawJSON: `{
				"name":"obj-lic-pkg",
				"license":{"type":"Apache-2.0","url":"http://example.com/LICENSE"},
				"dist-tags":{"latest":"2.0.0"},
				"repository":{"type":"git","url":"https://github.com/obj/lic.git"},
				"maintainers":[{"name":"carol"}],
				"versions":{"2.0.0":{"version":"2.0.0"}},
				"time":{"2.0.0":"2024-06-01T00:00:00Z"}
			}`,
			wantLicense: "Apache-2.0",
			wantRepoURL: "https://github.com/obj/lic",
		},
		{
			name: "repository as plain string (e.g. formidable)",
			rawJSON: `{
				"name":"formidable-like",
				"license":"MIT",
				"dist-tags":{"latest":"3.0.0"},
				"repository":"github:node-formidable/formidable",
				"maintainers":[{"name":"dave"}],
				"versions":{"3.0.0":{"version":"3.0.0"}},
				"time":{"3.0.0":"2024-03-01T00:00:00Z"}
			}`,
			wantLicense: "MIT",
			wantRepoURL: "", // string repo is stored in TypeString, normalised separately
		},
		{
			name: "license missing (null)",
			rawJSON: `{
				"name":"no-lic-pkg",
				"dist-tags":{"latest":"1.0.0"},
				"repository":{"type":"git","url":"https://github.com/no/lic.git"},
				"maintainers":[{"name":"eve"}],
				"versions":{"1.0.0":{"version":"1.0.0"}},
				"time":{"1.0.0":"2024-01-01T00:00:00Z"}
			}`,
			wantLicense: "",
			wantRepoURL: "https://github.com/no/lic",
		},
		{
			name: "scripts with nested objects (old joi)",
			rawJSON: `{
				"name":"joi-like",
				"license":"BSD-3-Clause",
				"dist-tags":{"latest":"1.0.0"},
				"repository":{"type":"git","url":"git://github.com/spumko/joi.git"},
				"maintainers":[{"name":"eran"}],
				"versions":{"1.0.0":{"version":"1.0.0","scripts":{"test":{"nested":"object"}}}},
				"time":{"1.0.0":"2013-01-01T00:00:00Z"}
			}`,
			wantLicense: "BSD-3-Clause",
			wantRepoURL: "https://github.com/spumko/joi",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(tt.rawJSON))
			}))
			defer server.Close()

			client := &NPMClient{
				httpClient: &http.Client{},
				baseURL:    server.URL,
			}

			pkg, err := client.GetPackageInfo("test")
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("GetPackageInfo() unexpected error: %v", err)
			}
			if pkg.License != tt.wantLicense {
				t.Errorf("License = %q, want %q", pkg.License, tt.wantLicense)
			}
			if tt.wantRepoURL != "" && pkg.RepositoryURL != tt.wantRepoURL {
				t.Errorf("RepositoryURL = %q, want %q", pkg.RepositoryURL, tt.wantRepoURL)
			}
		})
	}
}

// Test: GetPackageInfo uses "created" timestamp for PublishedAt, not the latest version time
// Justification: Package maturity scoring depends on when the package was first published.
//                Using the latest version's publish date makes old packages (e.g. Express,
//                first published 2010) appear "88 days old, very new", inflating risk scores.
// Source: npm registry API — the Time map includes a "created" key for original publish date
// Methodology: Mock server returns a Time map with distinct "created" and version timestamps;
//              verify PublishedAt matches "created", not the latest version.
// Result: PublishedAt reflects the package creation date, not the latest release date.
func TestGetPackageInfo_UsesCreatedDateForPublishedAt(t *testing.T) {
	createdDate := "2010-06-15T00:00:00Z"
	latestVersionDate := "2025-12-01T00:00:00Z"

	rawJSON := `{
		"name":"express",
		"license":"MIT",
		"dist-tags":{"latest":"5.0.0"},
		"repository":{"type":"git","url":"git+https://github.com/expressjs/express.git"},
		"maintainers":[{"name":"dougwilson"}],
		"versions":{"5.0.0":{"version":"5.0.0"}},
		"time":{
			"created":"` + createdDate + `",
			"modified":"2025-12-15T00:00:00Z",
			"5.0.0":"` + latestVersionDate + `"
		}
	}`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(rawJSON))
	}))
	defer server.Close()

	client := &NPMClient{
		httpClient: &http.Client{},
		baseURL:    server.URL,
	}

	pkg, err := client.GetPackageInfo("express")
	if err != nil {
		t.Fatalf("GetPackageInfo() unexpected error: %v", err)
	}

	expectedCreated, _ := time.Parse(time.RFC3339, createdDate)
	if !pkg.PublishedAt.Equal(expectedCreated) {
		t.Errorf("PublishedAt = %v, want %v (the created date, not the latest version date %s)",
			pkg.PublishedAt, expectedCreated, latestVersionDate)
	}

	// Verify the package age is measured in years, not days
	ageDays := time.Since(pkg.PublishedAt).Hours() / 24
	if ageDays < 365 {
		t.Errorf("Package age = %.0f days; Express (created 2010) should be years old, not days", ageDays)
	}
}

// Test: fetchWeeklyDownloadCount retrieves last-week download count
// Justification: Weekly download volume is used as a risk modifier for single-maintainer
//   packages. High-download packages (>1M/week) have greater community scrutiny,
//   which mitigates single-maintainer risk by reducing attacker dwell time.
// Source: npm downloads API — GET https://api.npmjs.org/downloads/point/last-week/{name}
// Methodology: Mock server returns download count JSON; verify client parses correctly.
// Result: WeeklyDownloads populated with correct count from API response.
func TestFetchWeeklyDownloadCount(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/downloads/point/last-week/express" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"downloads":5000000,"start":"2026-02-24","end":"2026-03-02","package":"express"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client := &NPMClient{
		httpClient:       &http.Client{},
		baseURL:          server.URL,
		downloadsBaseURL: server.URL,
	}

	count := client.fetchWeeklyDownloadCount("express")
	if count != 5_000_000 {
		t.Errorf("fetchWeeklyDownloadCount() = %d, want 5000000", count)
	}
}

// Test: fetchWeeklyDownloadCount returns 0 on error
// Justification: Download count is best-effort enrichment. API failures should not
//   block analysis or inflate risk scores — a zero download count means "unknown",
//   and the download volume modifier simply won't apply.
// Source: npm downloads API error handling
// Methodology: Mock server returns 404; verify client returns 0 gracefully.
// Result: Returns 0 without error, allowing analysis to continue.
func TestFetchWeeklyDownloadCount_Error(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client := &NPMClient{
		httpClient:       &http.Client{},
		baseURL:          server.URL,
		downloadsBaseURL: server.URL,
	}

	count := client.fetchWeeklyDownloadCount("nonexistent-package")
	if count != 0 {
		t.Errorf("fetchWeeklyDownloadCount() on error = %d, want 0", count)
	}
}

// Test: GetPackageInfo populates WeeklyDownloads from last-week API
// Justification: The WeeklyDownloads field must be populated during GetPackageInfo
//   so it flows through to PackageMetadata and the publisher control risk modifier.
// Source: npm downloads API — GET https://api.npmjs.org/downloads/point/last-week/{name}
// Methodology: Mock server returns both registry data and weekly download data;
//   verify WeeklyDownloads is populated in NPMPackage.
// Result: WeeklyDownloads field populated with weekly download count.
func TestGetPackageInfo_PopulatesWeeklyDownloads(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/downloads/point/last-week/test-pkg":
			_, _ = w.Write([]byte(`{"downloads":1500000,"package":"test-pkg"}`))
		case r.URL.Path == "/downloads/point/last-month/test-pkg":
			_, _ = w.Write([]byte(`{"downloads":6000000,"package":"test-pkg"}`))
		default:
			_, _ = w.Write([]byte(`{
				"name":"test-pkg",
				"license":"MIT",
				"dist-tags":{"latest":"1.0.0"},
				"maintainers":[{"name":"alice"}],
				"versions":{"1.0.0":{"version":"1.0.0"}},
				"time":{"created":"2020-01-01T00:00:00Z","1.0.0":"2025-12-01T00:00:00Z"}
			}`))
		}
	}))
	defer server.Close()

	client := &NPMClient{
		httpClient:       &http.Client{},
		baseURL:          server.URL,
		downloadsBaseURL: server.URL,
	}

	pkg, err := client.GetPackageInfo("test-pkg")
	if err != nil {
		t.Fatalf("GetPackageInfo() unexpected error: %v", err)
	}

	if pkg.WeeklyDownloads != 1_500_000 {
		t.Errorf("WeeklyDownloads = %d, want 1500000", pkg.WeeklyDownloads)
	}
	if pkg.Downloads != 6_000_000 {
		t.Errorf("Downloads (monthly) = %d, want 6000000", pkg.Downloads)
	}
}

func TestGetOwnershipHistory_NPM_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client := &NPMClient{
		httpClient: &http.Client{},
		baseURL:    server.URL,
	}

	_, err := client.GetOwnershipHistory("nonexistent-package")
	if err == nil {
		t.Error("GetOwnershipHistory() expected error, got nil")
	}
}
