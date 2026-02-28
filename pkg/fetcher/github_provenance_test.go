package fetcher

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Test: checkSLSAAttestation detects SLSA workflow files in a repository
// Justification: SLSA attestations provide build provenance guarantees — a key signal
//                for supply chain integrity. Repos with SLSA provenance files have
//                cryptographically verifiable build chains, reducing compromise risk.
// Source: SLSA specification v1.0 – https://slsa.dev/spec/v1.0/
// Methodology: Mock the GitHub Contents API (HEAD requests) to simulate presence/absence
//              of known SLSA configuration file paths; verify detection outcome.
// Result: Returns (true, "SLSA_LEVEL_2") when any SLSA file exists, (false, "") otherwise.
func TestCheckSLSAAttestation(t *testing.T) {
	tests := []struct {
		name          string
		existingFiles map[string]bool // path -> exists
		wantFound     bool
		wantLevel     string
	}{
		{
			name: "SLSA provenance JSON file present",
			existingFiles: map[string]bool{
				".slsa-provenance.json": true,
			},
			wantFound: true,
			wantLevel: "SLSA_LEVEL_2",
		},
		{
			name: "SLSA generic generator workflow present",
			existingFiles: map[string]bool{
				".github/workflows/slsa-generic-generator.yml": true,
			},
			wantFound: true,
			wantLevel: "SLSA_LEVEL_2",
		},
		{
			name: "SLSA workflow present",
			existingFiles: map[string]bool{
				".github/workflows/slsa.yml": true,
			},
			wantFound: true,
			wantLevel: "SLSA_LEVEL_2",
		},
		{
			name:          "No SLSA files — workflows dir exists but no SLSA files",
			existingFiles: map[string]bool{
				".github/workflows": true,
			},
			wantFound: false,
			wantLevel: "",
		},
		{
			name:          "No files at all",
			existingFiles: map[string]bool{},
			wantFound:     false,
			wantLevel:     "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Extract file path from: /repos/owner/repo/contents/<path>
				path := strings.TrimPrefix(r.URL.Path, "/repos/owner/repo/contents/")
				if tt.existingFiles[path] {
					w.WriteHeader(http.StatusOK)
				} else {
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			defer server.Close()

			client := &GitHubClient{
				httpClient: &http.Client{},
				baseURL:    server.URL,
				cache:      newRepoCache(),
			}

			gotFound, gotLevel := client.checkSLSAAttestation("owner", "repo")
			if gotFound != tt.wantFound {
				t.Errorf("checkSLSAAttestation() found = %v, want %v", gotFound, tt.wantFound)
			}
			if gotLevel != tt.wantLevel {
				t.Errorf("checkSLSAAttestation() level = %q, want %q", gotLevel, tt.wantLevel)
			}
		})
	}
}

// Test: checkSLSAAttestation detects SLSA via workflow content analysis
// Justification: Most projects that generate SLSA provenance use GitHub Actions like
//                actions/attest-build-provenance or slsa-framework/slsa-github-generator
//                in generically-named workflows (release.yml, publish.yml), not in
//                workflows with "slsa" in the filename. Content-based detection catches
//                these common patterns.
// Source: SLSA specification v1.0 — https://slsa.dev/spec/v1.0/
//         GitHub attestation action — https://github.com/actions/attest-build-provenance
// Methodology: Mock workflow directory listing (GET) and workflow content
//              (via raw.githubusercontent.com pattern); verify detection.
// Result: Returns (true, "SLSA_BUILD_LEVEL_2") when attestation actions found in content.
func TestCheckSLSAAttestation_WorkflowContentDetection(t *testing.T) {
	tests := []struct {
		name          string
		workflows     []string
		workflowContent map[string]string // filename -> content
		wantFound     bool
		wantLevel     string
	}{
		{
			name:      "actions/attest-build-provenance in release.yml",
			workflows: []string{"release.yml", "ci.yml"},
			workflowContent: map[string]string{
				"release.yml": `
name: Release
on:
  push:
    tags: ['v*']
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/attest-build-provenance@v2
        with:
          subject-path: dist/
`,
			},
			wantFound: true,
			wantLevel: "SLSA_BUILD_LEVEL_2",
		},
		{
			name:      "slsa-framework/slsa-github-generator in publish.yml",
			workflows: []string{"publish.yml"},
			workflowContent: map[string]string{
				"publish.yml": `
name: Publish
on:
  release:
    types: [published]
jobs:
  provenance:
    uses: slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@v2.1.0
`,
			},
			wantFound: true,
			wantLevel: "SLSA_BUILD_LEVEL_2",
		},
		{
			name:      "npm publish --provenance in release.yml",
			workflows: []string{"release.yml"},
			workflowContent: map[string]string{
				"release.yml": `
name: Release
on:
  push:
    tags: ['v*']
jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm publish --provenance --access public
`,
			},
			wantFound: true,
			wantLevel: "SLSA_BUILD_LEVEL_2",
		},
		{
			name:      "no attestation actions in any workflow",
			workflows: []string{"ci.yml", "test.yml"},
			workflowContent: map[string]string{
				"ci.yml": `
name: CI
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm test
`,
				"test.yml": `
name: Tests
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: go test ./...
`,
			},
			wantFound: false,
			wantLevel: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// HEAD requests for file existence checks (tier 1)
				if r.Method == "HEAD" {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				// GET .github/workflows directory listing (tier 2)
				if strings.HasSuffix(r.URL.Path, "/contents/.github/workflows") {
					var files []GitHubContent
					for _, wf := range tt.workflows {
						files = append(files, GitHubContent{Name: wf})
					}
					w.Header().Set("Content-Type", "application/json")
					_ = json.NewEncoder(w).Encode(files)
					return
				}
				// GET workflow content via raw URL pattern
				// The test server URL doesn't match raw.githubusercontent.com,
				// but we serve content for the API path instead
				for wfName, content := range tt.workflowContent {
					if strings.HasSuffix(r.URL.Path, "/.github/workflows/"+wfName) {
						w.Header().Set("Content-Type", "text/plain")
						_, _ = w.Write([]byte(content))
						return
					}
				}
				w.WriteHeader(http.StatusNotFound)
			}))
			defer server.Close()

			client := &GitHubClient{
				httpClient: &http.Client{},
				baseURL:    server.URL,
				cache:      newRepoCache(),
			}

			gotFound, gotLevel := client.checkSLSAAttestation("owner", "repo")
			if gotFound != tt.wantFound {
				t.Errorf("checkSLSAAttestation() found = %v, want %v", gotFound, tt.wantFound)
			}
			if gotLevel != tt.wantLevel {
				t.Errorf("checkSLSAAttestation() level = %q, want %q", gotLevel, tt.wantLevel)
			}
		})
	}
}

// Test: checkSigstoreSignatures detects Sigstore/Cosign indicators
// Justification: Sigstore provides keyless signing and transparency for software artifacts.
//                Detecting .cosign, .sigstore, or .rekor directories, as well as .sig/.asc/.minisig
//                release assets, indicates the project uses cryptographic signing.
// Source: Sigstore – https://www.sigstore.dev/
// Methodology: Mock both HEAD requests (file existence) and GET requests (releases API)
//              to simulate various Sigstore indicator combinations.
// Result: Returns true if any Sigstore config file or signed release asset is found.
func TestCheckSigstoreSignatures(t *testing.T) {
	tests := []struct {
		name          string
		existingFiles map[string]bool
		releases      []GitHubRelease
		want          bool
	}{
		{
			name: "cosign config file present",
			existingFiles: map[string]bool{
				".cosign": true,
			},
			releases: nil,
			want:     true,
		},
		{
			name: "sigstore config file present",
			existingFiles: map[string]bool{
				".sigstore": true,
			},
			releases: nil,
			want:     true,
		},
		{
			name: "rekor config file present",
			existingFiles: map[string]bool{
				".rekor": true,
			},
			releases: nil,
			want:     true,
		},
		{
			name:          "release with .sig asset",
			existingFiles: map[string]bool{},
			releases: []GitHubRelease{
				{
					TagName: "v1.0.0",
					Assets: []GitHubAsset{
						{Name: "binary-linux-amd64"},
						{Name: "binary-linux-amd64.sig"},
					},
				},
			},
			want: true,
		},
		{
			name:          "release with .asc asset",
			existingFiles: map[string]bool{},
			releases: []GitHubRelease{
				{
					TagName: "v2.0.0",
					Assets: []GitHubAsset{
						{Name: "archive.tar.gz"},
						{Name: "archive.tar.gz.asc"},
					},
				},
			},
			want: true,
		},
		{
			name:          "release with .minisig asset",
			existingFiles: map[string]bool{},
			releases: []GitHubRelease{
				{
					TagName: "v3.0.0",
					Assets: []GitHubAsset{
						{Name: "release.zip"},
						{Name: "release.zip.minisig"},
					},
				},
			},
			want: true,
		},
		{
			name:          "no sigstore indicators at all",
			existingFiles: map[string]bool{},
			releases: []GitHubRelease{
				{
					TagName: "v1.0.0",
					Assets: []GitHubAsset{
						{Name: "binary-linux-amd64"},
						{Name: "checksums.txt"},
					},
				},
			},
			want: false,
		},
		{
			name:          "no files and no releases",
			existingFiles: map[string]bool{},
			releases:      []GitHubRelease{},
			want:          false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// HEAD requests check file existence
				if r.Method == "HEAD" {
					path := strings.TrimPrefix(r.URL.Path, "/repos/owner/repo/contents/")
					if tt.existingFiles[path] {
						w.WriteHeader(http.StatusOK)
					} else {
						w.WriteHeader(http.StatusNotFound)
					}
					return
				}
				// GET /repos/owner/repo/releases returns releases
				if strings.HasSuffix(r.URL.Path, "/releases") {
					releases := tt.releases
					if releases == nil {
						releases = []GitHubRelease{}
					}
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

			got := client.checkSigstoreSignatures("owner", "repo")
			if got != tt.want {
				t.Errorf("checkSigstoreSignatures() = %v, want %v", got, tt.want)
			}
		})
	}
}

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

	// No SLSA config files — should be false
	if info.HasSLSAAttestation {
		t.Errorf("HasSLSAAttestation = true, want false")
	}

	// .sig asset in releases — Sigstore detection picks this up
	if !info.HasSigstoreSignature {
		t.Errorf("HasSigstoreSignature = false, want true (releases have .sig assets)")
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

	if info.HasSLSAAttestation {
		t.Error("expected HasSLSAAttestation=false")
	}
	if info.SLSALevel != "" {
		t.Errorf("expected empty SLSALevel, got %q", info.SLSALevel)
	}
	if info.HasSigstoreSignature {
		t.Error("expected HasSigstoreSignature=false")
	}
	if info.SignedReleaseCount != 0 {
		t.Errorf("expected SignedReleaseCount=0, got %d", info.SignedReleaseCount)
	}
	if info.TotalReleaseCount != 0 {
		t.Errorf("expected TotalReleaseCount=0, got %d", info.TotalReleaseCount)
	}
}
