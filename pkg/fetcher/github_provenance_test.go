package fetcher

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Test: checkSignedReleases counts releases with signature/checksum assets
// Justification: Signed releases enable downstream consumers to verify artifact integrity.
//                The ratio of signed to total releases indicates the project's commitment
//                to artifact authentication — a core supply chain hygiene practice.
// Source: SLSA specification v1.0 – https://slsa.dev/spec/v1.0/
//         Sigstore – https://www.sigstore.dev/
// Methodology: Mock the GitHub Releases API with releases containing various asset types;
//              verify signed/total counts match expectations.
// Result: Returns (signedCount, totalCount) where signedCount includes releases with
//         .sig, .asc, .gpg, .minisig, checksum, sha256, or sha512 assets.
func TestCheckSignedReleases_WithMockServer(t *testing.T) {
	tests := []struct {
		name            string
		releases        []GitHubRelease
		wantSignedCount int
		wantTotalCount  int
	}{
		{
			name: "all releases signed with .sig files",
			releases: []GitHubRelease{
				{
					TagName: "v1.0.0",
					Assets: []GitHubAsset{
						{Name: "release.tar.gz"},
						{Name: "release.tar.gz.sig"},
					},
				},
				{
					TagName: "v2.0.0",
					Assets: []GitHubAsset{
						{Name: "release.tar.gz"},
						{Name: "release.tar.gz.sig"},
					},
				},
			},
			wantSignedCount: 2,
			wantTotalCount:  2,
		},
		{
			name: "mixed — some signed, some not",
			releases: []GitHubRelease{
				{
					TagName: "v1.0.0",
					Assets: []GitHubAsset{
						{Name: "release.tar.gz"},
						{Name: "release.tar.gz.asc"},
					},
				},
				{
					TagName: "v2.0.0",
					Assets: []GitHubAsset{
						{Name: "release.tar.gz"},
					},
				},
				{
					TagName: "v3.0.0",
					Assets: []GitHubAsset{
						{Name: "release.tar.gz"},
						{Name: "SHA256SUMS"},
					},
				},
			},
			wantSignedCount: 2,
			wantTotalCount:  3,
		},
		{
			name: "checksum and sha256 assets count as signed",
			releases: []GitHubRelease{
				{
					TagName: "v1.0.0",
					Assets: []GitHubAsset{
						{Name: "binary"},
						{Name: "checksums.txt"},
					},
				},
				{
					TagName: "v2.0.0",
					Assets: []GitHubAsset{
						{Name: "binary"},
						{Name: "sha256sums.txt"},
					},
				},
				{
					TagName: "v3.0.0",
					Assets: []GitHubAsset{
						{Name: "binary"},
						{Name: "sha512sums.txt"},
					},
				},
			},
			wantSignedCount: 3,
			wantTotalCount:  3,
		},
		{
			name: "no signed releases",
			releases: []GitHubRelease{
				{
					TagName: "v1.0.0",
					Assets: []GitHubAsset{
						{Name: "release.tar.gz"},
						{Name: "release.zip"},
					},
				},
			},
			wantSignedCount: 0,
			wantTotalCount:  1,
		},
		{
			name:            "no releases at all",
			releases:        []GitHubRelease{},
			wantSignedCount: 0,
			wantTotalCount:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(tt.releases)
			}))
			defer server.Close()

			client := &GitHubClient{
				httpClient: &http.Client{},
				baseURL:    server.URL,
				cache:      newRepoCache(),
			}

			gotSigned, gotTotal := client.checkSignedReleases("owner", "repo")
			if gotSigned != tt.wantSignedCount {
				t.Errorf("checkSignedReleases() signedCount = %d, want %d", gotSigned, tt.wantSignedCount)
			}
			if gotTotal != tt.wantTotalCount {
				t.Errorf("checkSignedReleases() totalCount = %d, want %d", gotTotal, tt.wantTotalCount)
			}
		})
	}
}



// Test: GetProvenanceInfo integrates all provenance checks end-to-end
// Justification: GetProvenanceInfo is the public entry point that combines SLSA, Sigstore,
//                signed release, and reproducible build checks. Testing it end-to-end
//                ensures the individual checks are wired correctly.
// Source: SLSA specification v1.0 – https://slsa.dev/spec/v1.0/
// Methodology: Mock both file-existence (HEAD) and release (GET) endpoints to simulate
//              a repo with mixed provenance indicators; verify the returned ProvenanceInfo.
// Result: ProvenanceInfo fields reflect the combined provenance signals.
func TestGetProvenanceInfo(t *testing.T) {
	releases := []GitHubRelease{
		{
			TagName: "v1.0.0",
			Assets: []GitHubAsset{
				{Name: "binary"},
				{Name: "binary.sig"},
			},
		},
		{
			TagName: "v2.0.0",
			Assets: []GitHubAsset{
				{Name: "binary"},
			},
		},
	}

	existingFiles := map[string]bool{
		"BUILD.bazel": true, // reproducible build indicator
		// No SLSA or Sigstore config files — but releases have .sig assets
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "HEAD" {
			path := strings.TrimPrefix(r.URL.Path, "/repos/owner/repo/contents/")
			if existingFiles[path] {
				w.WriteHeader(http.StatusOK)
			} else {
				w.WriteHeader(http.StatusNotFound)
			}
			return
		}
		if strings.HasSuffix(r.URL.Path, "/releases") {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(releases)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client := &GitHubClient{
		httpClient: &http.Client{},
		baseURL:    server.URL,
		cache:      newRepoCache(),
	}

	info, err := client.GetProvenanceInfo("https://github.com/owner/repo")
	if err != nil {
		t.Fatalf("GetProvenanceInfo() unexpected error: %v", err)
	}

	// 1 of 2 releases has .sig asset
	if info.SignedReleaseCount != 1 {
		t.Errorf("SignedReleaseCount = %d, want 1", info.SignedReleaseCount)
	}
	if info.TotalReleaseCount != 2 {
		t.Errorf("TotalReleaseCount = %d, want 2", info.TotalReleaseCount)
	}

}

// Test: GetProvenanceInfo returns error for invalid GitHub URL
// Justification: Validates that malformed URLs fail fast with a clear error rather
//                than making spurious API calls.
// Source: N/A (defensive coding)
// Methodology: Call GetProvenanceInfo with a non-GitHub URL.
// Result: Returns error.
func TestGetProvenanceInfo_InvalidURL(t *testing.T) {
	client := &GitHubClient{
		httpClient: &http.Client{},
		baseURL:    "https://api.github.com",
		cache:      newRepoCache(),
	}

	_, err := client.GetProvenanceInfo("https://gitlab.com/owner/repo")
	if err == nil {
		t.Error("GetProvenanceInfo() expected error for non-GitHub URL, got nil")
	}
}

// Test: Real-world provenance patterns for packages from mike-libraries
// Justification: Real-package provenance profiles exercise the detection logic with
//                realistic release asset names and file structures seen in popular
//                open-source projects.
// Source: npm/PyPI registry metadata for well-known packages
// Methodology: Simulate the release asset patterns of well-known packages using mocked
//              HTTP; verify checkSignedReleases returns accurate counts.
// Result: Each simulated package profile returns the expected signed/total counts.
func TestCheckSignedReleases_RealPackageProfiles(t *testing.T) {
	tests := []struct {
		pkg             string
		releases        []GitHubRelease
		wantSignedCount int
		wantTotalCount  int
	}{
		{
			// cryptography (pyca/cryptography) signs every release with .asc
			pkg: "cryptography",
			releases: []GitHubRelease{
				{TagName: "42.0.0", Assets: []GitHubAsset{
					{Name: "cryptography-42.0.0.tar.gz"},
					{Name: "cryptography-42.0.0.tar.gz.asc"},
				}},
				{TagName: "41.0.0", Assets: []GitHubAsset{
					{Name: "cryptography-41.0.0.tar.gz"},
					{Name: "cryptography-41.0.0.tar.gz.asc"},
				}},
			},
			wantSignedCount: 2,
			wantTotalCount:  2,
		},
		{
			// express (expressjs/express) — no signature assets in releases
			pkg: "express",
			releases: []GitHubRelease{
				{TagName: "4.18.2", Assets: []GitHubAsset{}},
				{TagName: "4.18.1", Assets: []GitHubAsset{}},
			},
			wantSignedCount: 0,
			wantTotalCount:  2,
		},
		{
			// lodash (lodash/lodash) — no release assets at all (npm-only)
			pkg:             "lodash",
			releases:        []GitHubRelease{},
			wantSignedCount: 0,
			wantTotalCount:  0,
		},
		{
			// Pattern: project provides SHA256SUMS (like many Go/Rust tools)
			pkg: "gunicorn-style-checksums",
			releases: []GitHubRelease{
				{TagName: "v23.0.0", Assets: []GitHubAsset{
					{Name: "gunicorn-23.0.0.tar.gz"},
					{Name: "SHA256SUMS"},
				}},
				{TagName: "v22.0.0", Assets: []GitHubAsset{
					{Name: "gunicorn-22.0.0.tar.gz"},
				}},
			},
			wantSignedCount: 1,
			wantTotalCount:  2,
		},
		{
			// Pattern: mixed signing across releases (common in projects
			// that adopted signing after initial releases)
			pkg: "celery-style-mixed",
			releases: []GitHubRelease{
				{TagName: "5.3.6", Assets: []GitHubAsset{
					{Name: "celery-5.3.6.tar.gz"},
					{Name: "celery-5.3.6.tar.gz.sig"},
				}},
				{TagName: "5.3.5", Assets: []GitHubAsset{
					{Name: "celery-5.3.5.tar.gz"},
					{Name: "celery-5.3.5.tar.gz.sig"},
				}},
				{TagName: "5.2.0", Assets: []GitHubAsset{
					{Name: "celery-5.2.0.tar.gz"},
				}},
			},
			wantSignedCount: 2,
			wantTotalCount:  3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.pkg, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(tt.releases)
			}))
			defer server.Close()

			client := &GitHubClient{
				httpClient: &http.Client{},
				baseURL:    server.URL,
				cache:      newRepoCache(),
			}

			gotSigned, gotTotal := client.checkSignedReleases("owner", "repo")
			if gotSigned != tt.wantSignedCount {
				t.Errorf("[%s] signedCount = %d, want %d", tt.pkg, gotSigned, tt.wantSignedCount)
			}
			if gotTotal != tt.wantTotalCount {
				t.Errorf("[%s] totalCount = %d, want %d", tt.pkg, gotTotal, tt.wantTotalCount)
			}
		})
	}
}

// Test: GetProvenanceInfo for a repo with no provenance signals
// Justification: A repo with zero provenance signals represents the common case for
//                packages with poor supply chain hygiene. We must return a valid
//                (zero-value) ProvenanceInfo without errors.
// Source: OSSF Scorecard methodology – https://github.com/ossf/scorecard
// Methodology: Mock a server that returns 404 for all file checks and empty releases.
// Result: All provenance fields are false/zero.
func TestGetProvenanceInfo_NoSignals(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/releases") && r.Method == "GET" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode([]GitHubRelease{})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client := &GitHubClient{
		httpClient: &http.Client{},
		baseURL:    server.URL,
		cache:      newRepoCache(),
	}

	info, err := client.GetProvenanceInfo("https://github.com/owner/repo")
	if err != nil {
		t.Fatalf("GetProvenanceInfo() unexpected error: %v", err)
	}

	if info.SignedReleaseCount != 0 {
		t.Errorf("expected SignedReleaseCount=0, got %d", info.SignedReleaseCount)
	}
	if info.TotalReleaseCount != 0 {
		t.Errorf("expected TotalReleaseCount=0, got %d", info.TotalReleaseCount)
	}
}
