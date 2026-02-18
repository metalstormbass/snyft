package fetcher

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Test: CheckPyPISignatures with signed package files
// Justification: Packages without cryptographic signatures cannot be verified
//                as authentic, increasing risk of tampered distributions
// Source: SLSA specification v1.0 — https://slsa.dev/spec/v1.0/
// Methodology: Mock PyPI JSON API with has_sig and pgp_signature fields
// Result: Returns correct signed/total counts and hasSignatures flag
func TestCheckPyPISignatures_AllSigned(t *testing.T) {
	response := PyPIResponse{
		Info: PyPIInfo{
			Name:    "signed-package",
			Version: "1.0.0",
		},
		Urls: []PyPIURL{
			{
				Filename:     "signed-package-1.0.0.tar.gz",
				HasSignature: true,
				PGPSignature: "-----BEGIN PGP SIGNATURE-----\ntest\n-----END PGP SIGNATURE-----",
				Digests:      map[string]string{"sha256": "abc123"},
			},
			{
				Filename:     "signed_package-1.0.0-py3-none-any.whl",
				HasSignature: true,
				PGPSignature: "",
				Digests:      map[string]string{"sha256": "def456"},
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

	hasSignatures, signedCount, totalCount, err := client.CheckPyPISignatures("signed-package")
	if err != nil {
		t.Fatalf("CheckPyPISignatures() error = %v", err)
	}

	if !hasSignatures {
		t.Error("CheckPyPISignatures() hasSignatures = false, want true")
	}

	if signedCount != 2 {
		t.Errorf("CheckPyPISignatures() signedCount = %d, want 2", signedCount)
	}

	if totalCount != 2 {
		t.Errorf("CheckPyPISignatures() totalCount = %d, want 2", totalCount)
	}
}

// Test: CheckPyPISignatures with no signed files
// Justification: Most modern PyPI packages lack PGP signatures since PyPI
//                deprecated PGP upload support in May 2023
// Source: PyPI blog — "Removing PGP from PyPI" (2023-05-23)
// Methodology: Mock PyPI JSON API with has_sig=false on all files
// Result: Returns hasSignatures=false, signedCount=0
func TestCheckPyPISignatures_NoneSigned(t *testing.T) {
	response := PyPIResponse{
		Info: PyPIInfo{
			Name:    "unsigned-package",
			Version: "2.0.0",
		},
		Urls: []PyPIURL{
			{
				Filename:     "unsigned-package-2.0.0.tar.gz",
				HasSignature: false,
				Digests:      map[string]string{"sha256": "abc123"},
			},
			{
				Filename:     "unsigned_package-2.0.0-py3-none-any.whl",
				HasSignature: false,
				Digests:      map[string]string{"sha256": "def456"},
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

	hasSignatures, signedCount, totalCount, err := client.CheckPyPISignatures("unsigned-package")
	if err != nil {
		t.Fatalf("CheckPyPISignatures() error = %v", err)
	}

	if hasSignatures {
		t.Error("CheckPyPISignatures() hasSignatures = true, want false")
	}

	if signedCount != 0 {
		t.Errorf("CheckPyPISignatures() signedCount = %d, want 0", signedCount)
	}

	if totalCount != 2 {
		t.Errorf("CheckPyPISignatures() totalCount = %d, want 2", totalCount)
	}
}

// Test: CheckPyPISignatures with partial signature coverage
// Justification: Partial signing (e.g. only sdist signed, not wheels) leaves
//                a gap — attackers can replace unsigned distributions
// Source: "Backstabber's Knife Collection" (Ohm et al., 2020) —
//         https://arxiv.org/abs/2005.09535
// Methodology: Mock PyPI API returning mix of signed and unsigned files
// Result: Returns correct ratio of signed to total files
func TestCheckPyPISignatures_PartiallySigned(t *testing.T) {
	response := PyPIResponse{
		Info: PyPIInfo{
			Name:    "partial-package",
			Version: "1.0.0",
		},
		Urls: []PyPIURL{
			{
				Filename:     "partial-package-1.0.0.tar.gz",
				HasSignature: true,
				Digests:      map[string]string{"sha256": "abc123"},
			},
			{
				Filename:     "partial_package-1.0.0-py3-none-any.whl",
				HasSignature: false,
				Digests:      map[string]string{"sha256": "def456"},
			},
			{
				Filename:     "partial_package-1.0.0-cp39-cp39-manylinux1_x86_64.whl",
				HasSignature: false,
				Digests:      map[string]string{"sha256": "ghi789"},
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

	hasSignatures, signedCount, totalCount, err := client.CheckPyPISignatures("partial-package")
	if err != nil {
		t.Fatalf("CheckPyPISignatures() error = %v", err)
	}

	if !hasSignatures {
		t.Error("CheckPyPISignatures() hasSignatures = false, want true (at least one signed)")
	}

	if signedCount != 1 {
		t.Errorf("CheckPyPISignatures() signedCount = %d, want 1", signedCount)
	}

	if totalCount != 3 {
		t.Errorf("CheckPyPISignatures() totalCount = %d, want 3", totalCount)
	}
}

// Test: CheckPyPISignatures with no release files
// Justification: A package with no files at all is an edge case that could
//                indicate a yanked release or registry inconsistency
// Source: PyPI JSON API specification
// Methodology: Mock PyPI API returning empty urls array
// Result: Returns hasSignatures=false, counts at zero
func TestCheckPyPISignatures_NoFiles(t *testing.T) {
	response := PyPIResponse{
		Info: PyPIInfo{
			Name:    "empty-package",
			Version: "0.1.0",
		},
		Urls: []PyPIURL{},
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

	hasSignatures, signedCount, totalCount, err := client.CheckPyPISignatures("empty-package")
	if err != nil {
		t.Fatalf("CheckPyPISignatures() error = %v", err)
	}

	if hasSignatures {
		t.Error("CheckPyPISignatures() hasSignatures = true, want false")
	}

	if signedCount != 0 {
		t.Errorf("CheckPyPISignatures() signedCount = %d, want 0", signedCount)
	}

	if totalCount != 0 {
		t.Errorf("CheckPyPISignatures() totalCount = %d, want 0", totalCount)
	}
}

// Test: CheckPyPISignatures error handling for API failure
// Justification: Graceful degradation when PyPI API is unavailable
// Source: SLSA v1.0 — build integrity checks must fail safely
// Methodology: Mock server returns 500 Internal Server Error
// Result: Returns error, does not panic or return misleading data
func TestCheckPyPISignatures_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	client := &PyPIClient{
		httpClient: &http.Client{},
		baseURL:    server.URL,
	}

	_, _, _, err := client.CheckPyPISignatures("any-package")
	if err == nil {
		t.Error("CheckPyPISignatures() expected error for 500 response, got nil")
	}
}

// Test: CheckPyPISignatures with PGP signature field (no has_sig flag)
// Justification: Some older packages have pgp_signature field set without
//                has_sig=true; both should be detected
// Source: PyPI JSON API — has_sig and pgp_signature are independent fields
// Methodology: Mock file with pgp_signature but has_sig=false
// Result: File is counted as signed based on pgp_signature presence
func TestCheckPyPISignatures_PGPSignatureFieldOnly(t *testing.T) {
	response := PyPIResponse{
		Info: PyPIInfo{
			Name:    "pgp-only-package",
			Version: "1.0.0",
		},
		Urls: []PyPIURL{
			{
				Filename:     "pgp-only-package-1.0.0.tar.gz",
				HasSignature: false,
				PGPSignature: "-----BEGIN PGP SIGNATURE-----\ndata\n-----END PGP SIGNATURE-----",
				Digests:      map[string]string{"sha256": "abc"},
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

	hasSignatures, signedCount, _, err := client.CheckPyPISignatures("pgp-only-package")
	if err != nil {
		t.Fatalf("CheckPyPISignatures() error = %v", err)
	}

	if !hasSignatures {
		t.Error("CheckPyPISignatures() hasSignatures = false, want true (pgp_signature field set)")
	}

	if signedCount != 1 {
		t.Errorf("CheckPyPISignatures() signedCount = %d, want 1", signedCount)
	}
}

// Test: CheckPyPISignatures returns error for 404 not found
// Justification: Non-existent package names (e.g. typosquatting candidates)
//                must be clearly distinguished from packages without signatures
// Source: PyPI JSON API — 404 for unknown packages
// Methodology: Mock server returns 404 Not Found
// Result: Returns error indicating package was not found
func TestCheckPyPISignatures_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client := &PyPIClient{
		httpClient: &http.Client{},
		baseURL:    server.URL,
	}

	_, _, _, err := client.CheckPyPISignatures("nonexistent-package-zzz")
	if err == nil {
		t.Error("CheckPyPISignatures() expected error for 404, got nil")
	}
}

// Test: CheckPyPISignatures returns error for malformed JSON
// Justification: Corrupt or tampered API responses must be detected rather
//                than silently parsed into zero-value structs that would
//                falsely report "no signatures"
// Source: Defense-in-depth principle — untrusted input validation
// Methodology: Mock server returns invalid JSON body with 200 status
// Result: Returns error indicating JSON decode failure
func TestCheckPyPISignatures_MalformedJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{invalid json`))
	}))
	defer server.Close()

	client := &PyPIClient{
		httpClient: &http.Client{},
		baseURL:    server.URL,
	}

	_, _, _, err := client.CheckPyPISignatures("any-package")
	if err == nil {
		t.Error("CheckPyPISignatures() expected error for malformed JSON, got nil")
	}
}

// Test: CheckPyPISignatures returns error for 429 Too Many Requests
// Justification: Rate-limited responses should produce errors, not silently
//                report zero signatures (which would inflate risk scores)
// Source: PyPI service policies — rate limiting behavior
// Methodology: Mock server returns 429 status
// Result: Returns error with status code in message
func TestCheckPyPISignatures_RateLimited(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer server.Close()

	client := &PyPIClient{
		httpClient: &http.Client{},
		baseURL:    server.URL,
	}

	_, _, _, err := client.CheckPyPISignatures("any-package")
	if err == nil {
		t.Error("CheckPyPISignatures() expected error for 429, got nil")
	}
}
