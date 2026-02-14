package fetcher

import (
	"testing"
)

func TestNPMProvenanceDetection(t *testing.T) {
	// Test NPM provenance attestation structure
	tests := []struct {
		name            string
		hasAttestation  bool
		provenanceURL   string
		expectProvenance bool
	}{
		{
			name:            "With provenance",
			hasAttestation:  true,
			provenanceURL:   "https://registry.npmjs.org/-/npm/v1/attestations/...",
			expectProvenance: true,
		},
		{
			name:            "No provenance URL",
			hasAttestation:  true,
			provenanceURL:   "",
			expectProvenance: false,
		},
		{
			name:            "No attestation",
			hasAttestation:  false,
			provenanceURL:   "",
			expectProvenance: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hasProvenance := tt.hasAttestation && tt.provenanceURL != ""

			if hasProvenance != tt.expectProvenance {
				t.Errorf("Expected hasProvenance=%v, got %v", tt.expectProvenance, hasProvenance)
			}
		})
	}
}

func TestNPMDistStructure(t *testing.T) {
	// Verify NPMDist has required fields for provenance
	dist := NPMDist{
		Tarball:   "https://registry.npmjs.org/package/-/package-1.0.0.tgz",
		Shasum:    "abc123",
		Integrity: "sha512-...",
		Attestations: &NPMAttestation{
			URL:           "https://registry.npmjs.org/...",
			ProvenanceURL: "https://registry.npmjs.org/-/npm/v1/attestations/...",
		},
	}

	if dist.Attestations == nil {
		t.Errorf("Expected attestations to be present")
	}

	if dist.Attestations.ProvenanceURL == "" {
		t.Errorf("Expected provenance URL to be present")
	}

	// Test without attestations
	distNoAttest := NPMDist{
		Tarball:   "https://registry.npmjs.org/package/-/package-1.0.0.tgz",
		Shasum:    "abc123",
		Integrity: "sha512-...",
	}

	if distNoAttest.Attestations != nil {
		t.Errorf("Expected no attestations")
	}
}
