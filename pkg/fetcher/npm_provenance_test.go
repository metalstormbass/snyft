package fetcher

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Test: CheckNPMProvenance detects provenance attestation on latest version
// Justification: npm provenance attestations (via Sigstore) prove that a
//                published package was built from a specific source commit in
//                a trusted CI environment, which is the strongest supply chain
//                integrity signal available on npm
// Source: npm provenance documentation — https://docs.npmjs.com/generating-provenance-statements
//         SLSA specification v1.0 — https://slsa.dev/spec/v1.0/
// Methodology: Mock npm registry response with attestation fields on the
//              latest version's dist object; call CheckNPMProvenance
// Result: Returns true with the provenance URL
func TestCheckNPMProvenance_WithAttestation(t *testing.T) {
	npmResp := NPMRegistryResponse{
		Name: "sigstore-enabled-pkg",
		DistTags: NPMDistTags{
			Latest: "2.0.0",
		},
		Versions: map[string]NPMVersionDetails{
			"2.0.0": {
				Version: "2.0.0",
				Dist: NPMDist{
					Tarball:   "https://registry.npmjs.org/sigstore-enabled-pkg/-/sigstore-enabled-pkg-2.0.0.tgz",
					Shasum:    "abc123def456",
					Integrity: "sha512-AAAA",
					Attestations: &NPMAttestation{
						URL:           "https://registry.npmjs.org/-/npm/v1/attestations/sigstore-enabled-pkg@2.0.0",
						ProvenanceURL: "https://registry.npmjs.org/-/npm/v1/attestations/sigstore-enabled-pkg@2.0.0/provenance",
					},
				},
			},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(npmResp)
	}))
	defer server.Close()

	client := &NPMClient{
		httpClient: server.Client(),
		baseURL:    server.URL,
	}

	hasProvenance, provenanceURL, err := client.CheckNPMProvenance("sigstore-enabled-pkg")
	if err != nil {
		t.Fatalf("CheckNPMProvenance() error = %v", err)
	}

	if !hasProvenance {
		t.Error("CheckNPMProvenance() = false, want true for package with attestation")
	}

	expectedURL := "https://registry.npmjs.org/-/npm/v1/attestations/sigstore-enabled-pkg@2.0.0/provenance"
	if provenanceURL != expectedURL {
		t.Errorf("CheckNPMProvenance() provenanceURL = %q, want %q", provenanceURL, expectedURL)
	}
}

// Test: CheckNPMProvenance returns false when no attestation exists
// Justification: Packages without provenance attestations cannot be verified
//                as originating from a trusted CI build, which is a supply
//                chain integrity gap
// Source: npm provenance documentation — https://docs.npmjs.com/generating-provenance-statements
// Methodology: Mock npm registry response with nil Attestations field
// Result: Returns false with empty provenance URL, no error
func TestCheckNPMProvenance_NoAttestation(t *testing.T) {
	npmResp := NPMRegistryResponse{
		Name: "no-provenance-pkg",
		DistTags: NPMDistTags{
			Latest: "1.0.0",
		},
		Versions: map[string]NPMVersionDetails{
			"1.0.0": {
				Version: "1.0.0",
				Dist: NPMDist{
					Tarball:   "https://registry.npmjs.org/no-provenance-pkg/-/no-provenance-pkg-1.0.0.tgz",
					Shasum:    "aaa111",
					Integrity: "sha512-BBBB",
					// No Attestations field
				},
			},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(npmResp)
	}))
	defer server.Close()

	client := &NPMClient{
		httpClient: server.Client(),
		baseURL:    server.URL,
	}

	hasProvenance, provenanceURL, err := client.CheckNPMProvenance("no-provenance-pkg")
	if err != nil {
		t.Fatalf("CheckNPMProvenance() error = %v", err)
	}

	if hasProvenance {
		t.Error("CheckNPMProvenance() = true, want false for package without attestation")
	}

	if provenanceURL != "" {
		t.Errorf("CheckNPMProvenance() provenanceURL = %q, want empty string", provenanceURL)
	}
}

// Test: CheckNPMProvenance with attestation URL but empty provenance URL
// Justification: Some packages have partial attestation data — the attestation
//                object exists but the provenance_url field is empty, which
//                means provenance cannot be verified
// Source: npm registry API — attestations object structure
// Methodology: Mock response with non-nil Attestations but empty ProvenanceURL
// Result: Returns false — partial attestation without provenance URL is insufficient
func TestCheckNPMProvenance_AttestationWithoutProvenanceURL(t *testing.T) {
	npmResp := NPMRegistryResponse{
		Name: "partial-attest-pkg",
		DistTags: NPMDistTags{
			Latest: "1.0.0",
		},
		Versions: map[string]NPMVersionDetails{
			"1.0.0": {
				Version: "1.0.0",
				Dist: NPMDist{
					Tarball:   "https://registry.npmjs.org/partial-attest-pkg/-/partial-attest-pkg-1.0.0.tgz",
					Shasum:    "bbb222",
					Integrity: "sha512-CCCC",
					Attestations: &NPMAttestation{
						URL:           "https://registry.npmjs.org/-/npm/v1/attestations/partial-attest-pkg@1.0.0",
						ProvenanceURL: "", // Empty provenance URL
					},
				},
			},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(npmResp)
	}))
	defer server.Close()

	client := &NPMClient{
		httpClient: server.Client(),
		baseURL:    server.URL,
	}

	hasProvenance, provenanceURL, err := client.CheckNPMProvenance("partial-attest-pkg")
	if err != nil {
		t.Fatalf("CheckNPMProvenance() error = %v", err)
	}

	if hasProvenance {
		t.Error("CheckNPMProvenance() = true, want false when provenance URL is empty")
	}

	if provenanceURL != "" {
		t.Errorf("CheckNPMProvenance() provenanceURL = %q, want empty string", provenanceURL)
	}
}

// Test: CheckNPMProvenance returns error on server failure
// Justification: Registry unavailability must degrade gracefully — provenance
//                check failures should not silently report "no provenance"
// Source: SLSA v1.0 — build integrity checks must fail safely
// Methodology: Mock server returns 500 Internal Server Error
// Result: Returns error, does not falsely report no provenance
func TestCheckNPMProvenance_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	client := &NPMClient{
		httpClient: server.Client(),
		baseURL:    server.URL,
	}

	_, _, err := client.CheckNPMProvenance("any-package")
	if err == nil {
		t.Error("CheckNPMProvenance() expected error for 500 response, got nil")
	}
}

// Test: CheckNPMProvenance returns error on malformed JSON
// Justification: Corrupt or tampered API responses must be flagged rather
//                than silently parsed into zero-value structs
// Source: Defense-in-depth principle — untrusted input validation
// Methodology: Mock server returns invalid JSON body
// Result: Returns error indicating decode failure
func TestCheckNPMProvenance_MalformedJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{not valid json`))
	}))
	defer server.Close()

	client := &NPMClient{
		httpClient: server.Client(),
		baseURL:    server.URL,
	}

	_, _, err := client.CheckNPMProvenance("any-package")
	if err == nil {
		t.Error("CheckNPMProvenance() expected error for malformed JSON, got nil")
	}
}

// Test: CheckNPMProvenance when latest version is missing from versions map
// Justification: Registry inconsistency (dist-tags pointing to a version not
//                in the versions map) could indicate a yanked or corrupted entry
// Source: npm registry API — dist-tags.latest must reference an existing version
// Methodology: Mock response where dist-tags.latest references a version
//              not present in the versions map
// Result: Returns false with no error — graceful degradation
func TestCheckNPMProvenance_MissingLatestVersion(t *testing.T) {
	npmResp := NPMRegistryResponse{
		Name: "missing-latest-pkg",
		DistTags: NPMDistTags{
			Latest: "3.0.0", // Not in Versions map
		},
		Versions: map[string]NPMVersionDetails{
			"2.0.0": {
				Version: "2.0.0",
				Dist: NPMDist{
					Tarball: "https://registry.npmjs.org/missing-latest-pkg/-/missing-latest-pkg-2.0.0.tgz",
					Attestations: &NPMAttestation{
						URL:           "https://registry.npmjs.org/...",
						ProvenanceURL: "https://registry.npmjs.org/.../provenance",
					},
				},
			},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(npmResp)
	}))
	defer server.Close()

	client := &NPMClient{
		httpClient: server.Client(),
		baseURL:    server.URL,
	}

	hasProvenance, provenanceURL, err := client.CheckNPMProvenance("missing-latest-pkg")
	if err != nil {
		t.Fatalf("CheckNPMProvenance() unexpected error = %v", err)
	}

	if hasProvenance {
		t.Error("CheckNPMProvenance() = true, want false when latest version not in versions map")
	}

	if provenanceURL != "" {
		t.Errorf("CheckNPMProvenance() provenanceURL = %q, want empty string", provenanceURL)
	}
}

// Test: CheckNPMProvenance returns error for 404 not found
// Justification: Non-existent package names (e.g. typosquatting candidates)
//                must be clearly distinguished from packages without provenance
// Source: npm registry API — 404 for unknown packages
// Methodology: Mock server returns 404 Not Found
// Result: Returns error indicating package was not found
func TestCheckNPMProvenance_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error": "Not found"}`))
	}))
	defer server.Close()

	client := &NPMClient{
		httpClient: server.Client(),
		baseURL:    server.URL,
	}

	_, _, err := client.CheckNPMProvenance("nonexistent-package-zzz")
	if err == nil {
		t.Error("CheckNPMProvenance() expected error for 404, got nil")
	}
}
