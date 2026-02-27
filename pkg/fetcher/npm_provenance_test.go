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
// Result: Returns HasProvenance=true with the provenance URL and IsSLSA=true
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
						URL: "https://registry.npmjs.org/-/npm/v1/attestations/sigstore-enabled-pkg@2.0.0",
						Provenance: &NPMProvenanceInfo{
							PredicateType: "https://slsa.dev/provenance/v1",
						},
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

	result, err := client.CheckNPMProvenance("sigstore-enabled-pkg")
	if err != nil {
		t.Fatalf("CheckNPMProvenance() error = %v", err)
	}

	if !result.HasProvenance {
		t.Error("CheckNPMProvenance() HasProvenance = false, want true for package with attestation")
	}

	expectedURL := "https://registry.npmjs.org/-/npm/v1/attestations/sigstore-enabled-pkg@2.0.0"
	if result.ProvenanceURL != expectedURL {
		t.Errorf("CheckNPMProvenance() ProvenanceURL = %q, want %q", result.ProvenanceURL, expectedURL)
	}

	if !result.IsSLSA {
		t.Error("CheckNPMProvenance() IsSLSA = false, want true for SLSA predicate type")
	}
}

// Test: CheckNPMProvenance returns false when no attestation exists
// Justification: Packages without provenance attestations cannot be verified
//                as originating from a trusted CI build, which is a supply
//                chain integrity gap
// Source: npm provenance documentation — https://docs.npmjs.com/generating-provenance-statements
// Methodology: Mock npm registry response with nil Attestations field
// Result: Returns HasProvenance=false with empty provenance URL, no error
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

	result, err := client.CheckNPMProvenance("no-provenance-pkg")
	if err != nil {
		t.Fatalf("CheckNPMProvenance() error = %v", err)
	}

	if result.HasProvenance {
		t.Error("CheckNPMProvenance() HasProvenance = true, want false for package without attestation")
	}

	if result.ProvenanceURL != "" {
		t.Errorf("CheckNPMProvenance() ProvenanceURL = %q, want empty string", result.ProvenanceURL)
	}

	if result.IsSLSA {
		t.Error("CheckNPMProvenance() IsSLSA = true, want false for package without attestation")
	}
}

// Test: CheckNPMProvenance with empty attestation URL
// Justification: Some packages may have a malformed attestation object where
//                the URL field is empty, which means the attestation bundle
//                cannot be retrieved for verification
// Source: npm registry API — attestations object structure
// Methodology: Mock response with non-nil Attestations but empty URL
// Result: Returns HasProvenance=false — attestation without URL is insufficient
func TestCheckNPMProvenance_AttestationWithoutURL(t *testing.T) {
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
						URL: "", // Empty attestation URL
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

	result, err := client.CheckNPMProvenance("partial-attest-pkg")
	if err != nil {
		t.Fatalf("CheckNPMProvenance() error = %v", err)
	}

	if result.HasProvenance {
		t.Error("CheckNPMProvenance() HasProvenance = true, want false when attestation URL is empty")
	}

	if result.ProvenanceURL != "" {
		t.Errorf("CheckNPMProvenance() ProvenanceURL = %q, want empty string", result.ProvenanceURL)
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

	_, err := client.CheckNPMProvenance("any-package")
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

	_, err := client.CheckNPMProvenance("any-package")
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
// Result: Returns HasProvenance=false with no error — graceful degradation
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
						URL: "https://registry.npmjs.org/-/npm/v1/attestations/missing-latest-pkg@2.0.0",
						Provenance: &NPMProvenanceInfo{
							PredicateType: "https://slsa.dev/provenance/v1",
						},
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

	result, err := client.CheckNPMProvenance("missing-latest-pkg")
	if err != nil {
		t.Fatalf("CheckNPMProvenance() unexpected error = %v", err)
	}

	if result.HasProvenance {
		t.Error("CheckNPMProvenance() HasProvenance = true, want false when latest version not in versions map")
	}

	if result.ProvenanceURL != "" {
		t.Errorf("CheckNPMProvenance() ProvenanceURL = %q, want empty string", result.ProvenanceURL)
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

	_, err := client.CheckNPMProvenance("nonexistent-package-zzz")
	if err == nil {
		t.Error("CheckNPMProvenance() expected error for 404, got nil")
	}
}

// Test: CheckNPMProvenance detects non-SLSA attestation
// Justification: npm supports attestations with different predicate types.
//                A publish attestation (npm-specific) should be detected as
//                provenance but not flagged as SLSA
// Source: npm attestation spec — https://github.com/npm/attestation/tree/main/specs/publish
// Methodology: Mock registry response with attestation URL but npm publish
//              predicate (not SLSA)
// Result: HasProvenance=true, IsSLSA=false
func TestCheckNPMProvenance_NonSLSAAttestation(t *testing.T) {
	npmResp := NPMRegistryResponse{
		Name: "npm-attest-pkg",
		DistTags: NPMDistTags{
			Latest: "1.0.0",
		},
		Versions: map[string]NPMVersionDetails{
			"1.0.0": {
				Version: "1.0.0",
				Dist: NPMDist{
					Tarball:   "https://registry.npmjs.org/npm-attest-pkg/-/npm-attest-pkg-1.0.0.tgz",
					Shasum:    "ddd444",
					Integrity: "sha512-DDDD",
					Attestations: &NPMAttestation{
						URL: "https://registry.npmjs.org/-/npm/v1/attestations/npm-attest-pkg@1.0.0",
						Provenance: &NPMProvenanceInfo{
							PredicateType: "https://github.com/npm/attestation/tree/main/specs/publish/v0.1",
						},
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

	result, err := client.CheckNPMProvenance("npm-attest-pkg")
	if err != nil {
		t.Fatalf("CheckNPMProvenance() error = %v", err)
	}

	if !result.HasProvenance {
		t.Error("CheckNPMProvenance() HasProvenance = false, want true")
	}

	if result.IsSLSA {
		t.Error("CheckNPMProvenance() IsSLSA = true, want false for non-SLSA predicate type")
	}
}

// Test: CheckNPMProvenance with attestation but nil provenance object
// Justification: Some packages may have attestation URL but no provenance
//                object (predicate type unknown). Should still detect provenance
//                but not claim SLSA
// Source: npm registry API — attestations object structure
// Methodology: Mock with Attestations.URL set but Provenance=nil
// Result: HasProvenance=true, IsSLSA=false
func TestCheckNPMProvenance_AttestationWithoutProvenance(t *testing.T) {
	npmResp := NPMRegistryResponse{
		Name: "no-pred-pkg",
		DistTags: NPMDistTags{
			Latest: "1.0.0",
		},
		Versions: map[string]NPMVersionDetails{
			"1.0.0": {
				Version: "1.0.0",
				Dist: NPMDist{
					Tarball: "https://registry.npmjs.org/no-pred-pkg/-/no-pred-pkg-1.0.0.tgz",
					Attestations: &NPMAttestation{
						URL:        "https://registry.npmjs.org/-/npm/v1/attestations/no-pred-pkg@1.0.0",
						Provenance: nil, // No provenance predicate
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

	result, err := client.CheckNPMProvenance("no-pred-pkg")
	if err != nil {
		t.Fatalf("CheckNPMProvenance() error = %v", err)
	}

	if !result.HasProvenance {
		t.Error("CheckNPMProvenance() HasProvenance = false, want true (has URL)")
	}

	if result.IsSLSA {
		t.Error("CheckNPMProvenance() IsSLSA = true, want false (no provenance predicate)")
	}
}
