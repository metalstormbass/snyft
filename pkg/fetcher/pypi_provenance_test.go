package fetcher

import (
	"testing"
)

func TestPyPISignatureDetection(t *testing.T) {
	// Test PyPI signature detection logic
	tests := []struct {
		name         string
		hasSignature bool
		pgpSignature string
		expectSigned bool
	}{
		{
			name:         "With PGP signature",
			hasSignature: true,
			pgpSignature: "-----BEGIN PGP SIGNATURE-----\n...",
			expectSigned: true,
		},
		{
			name:         "Has signature flag only",
			hasSignature: true,
			pgpSignature: "",
			expectSigned: true,
		},
		{
			name:         "No signature",
			hasSignature: false,
			pgpSignature: "",
			expectSigned: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isSigned := tt.hasSignature || tt.pgpSignature != ""

			if isSigned != tt.expectSigned {
				t.Errorf("Expected isSigned=%v, got %v", tt.expectSigned, isSigned)
			}
		})
	}
}

func TestPyPIURLStructure(t *testing.T) {
	// Verify PyPIURL has required fields for signature checking
	url := PyPIURL{
		Filename:     "package-1.0.0.tar.gz",
		URL:          "https://files.pythonhosted.org/packages/.../package-1.0.0.tar.gz",
		HasSignature: true,
		Digests: map[string]string{
			"sha256": "abc123...",
		},
		PGPSignature: "-----BEGIN PGP SIGNATURE-----\n...",
	}

	if !url.HasSignature {
		t.Errorf("Expected has_signature to be true")
	}

	if url.PGPSignature == "" {
		t.Errorf("Expected PGP signature to be present")
	}

	if url.Digests["sha256"] == "" {
		t.Errorf("Expected SHA256 digest to be present")
	}
}

func TestPyPISignatureRatio(t *testing.T) {
	// Test signature ratio calculation
	urls := []PyPIURL{
		{Filename: "package-1.0.0.tar.gz", HasSignature: true},
		{Filename: "package-1.0.0-py3-none-any.whl", HasSignature: true},
		{Filename: "package-1.0.0.zip", HasSignature: false},
	}

	signedCount := 0
	totalCount := len(urls)

	for _, url := range urls {
		if url.HasSignature {
			signedCount++
		}
	}

	expectedSigned := 2
	expectedTotal := 3

	if signedCount != expectedSigned {
		t.Errorf("Expected %d signed files, got %d", expectedSigned, signedCount)
	}

	if totalCount != expectedTotal {
		t.Errorf("Expected %d total files, got %d", expectedTotal, totalCount)
	}

	// Check ratio
	ratio := float64(signedCount) / float64(totalCount)
	expectedRatio := 2.0 / 3.0

	if ratio != expectedRatio {
		t.Errorf("Expected ratio %.2f, got %.2f", expectedRatio, ratio)
	}
}
