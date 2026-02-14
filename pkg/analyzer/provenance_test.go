package analyzer

import (
	"testing"

	"github.com/metalstormbass/snyft/pkg/models"
)

func TestScoreProvenance_NoProvenance(t *testing.T) {
	a := NewAnalyzer()
	result := &models.AnalysisResult{
		Metadata: models.PackageMetadata{},
	}

	score := a.scoreProvenance(result)

	if score.RiskPoints != 2 {
		t.Errorf("Expected 2 risk points for no provenance, got %d", score.RiskPoints)
	}

	if score.Score != 0 {
		t.Errorf("Expected score 0 for no provenance, got %d", score.Score)
	}

	if score.Description != "No provenance evidence" {
		t.Errorf("Expected 'No provenance evidence', got '%s'", score.Description)
	}
}

func TestScoreProvenance_SLSAAttestation(t *testing.T) {
	a := NewAnalyzer()
	result := &models.AnalysisResult{
		Metadata: models.PackageMetadata{
			HasSLSAAttestation: true,
			SLSALevel:         "SLSA_LEVEL_3",
		},
	}

	score := a.scoreProvenance(result)

	if score.RiskPoints != 0 {
		t.Errorf("Expected 0 risk points with SLSA attestation, got %d", score.RiskPoints)
	}

	if score.Score != 2 {
		t.Errorf("Expected score 2 with SLSA attestation, got %d", score.Score)
	}

	if score.Description != "Full provenance with signatures" {
		t.Errorf("Expected 'Full provenance with signatures', got '%s'", score.Description)
	}
}

func TestScoreProvenance_SigstoreSignatures(t *testing.T) {
	a := NewAnalyzer()
	result := &models.AnalysisResult{
		Metadata: models.PackageMetadata{
			HasSigstoreSignature: true,
		},
	}

	score := a.scoreProvenance(result)

	if score.RiskPoints != 0 {
		t.Errorf("Expected 0 risk points with Sigstore signatures, got %d", score.RiskPoints)
	}

	if score.Score != 2 {
		t.Errorf("Expected score 2 with Sigstore signatures, got %d", score.Score)
	}
}

func TestScoreProvenance_NPMProvenance(t *testing.T) {
	a := NewAnalyzer()
	result := &models.AnalysisResult{
		Metadata: models.PackageMetadata{
			HasNPMProvenance: true,
		},
	}

	score := a.scoreProvenance(result)

	if score.RiskPoints != 0 {
		t.Errorf("Expected 0 risk points with npm provenance, got %d", score.RiskPoints)
	}

	if score.Score != 2 {
		t.Errorf("Expected score 2 with npm provenance, got %d", score.Score)
	}
}

func TestScoreProvenance_PyPISignatures(t *testing.T) {
	a := NewAnalyzer()
	result := &models.AnalysisResult{
		Metadata: models.PackageMetadata{
			HasPyPISignatures: true,
		},
	}

	score := a.scoreProvenance(result)

	if score.RiskPoints != 0 {
		t.Errorf("Expected 0 risk points with PyPI signatures, got %d", score.RiskPoints)
	}

	if score.Score != 2 {
		t.Errorf("Expected score 2 with PyPI signatures, got %d", score.Score)
	}
}

func TestScoreProvenance_PartialProvenance_SignedReleases(t *testing.T) {
	a := NewAnalyzer()
	result := &models.AnalysisResult{
		Metadata: models.PackageMetadata{
			SignedReleases: true,
		},
	}

	score := a.scoreProvenance(result)

	if score.RiskPoints != 1 {
		t.Errorf("Expected 1 risk point for partial provenance, got %d", score.RiskPoints)
	}

	if score.Score != 1 {
		t.Errorf("Expected score 1 for partial provenance, got %d", score.Score)
	}

	if score.Description != "Partial provenance" {
		t.Errorf("Expected 'Partial provenance', got '%s'", score.Description)
	}
}

func TestScoreProvenance_PartialProvenance_ReproducibleBuild(t *testing.T) {
	a := NewAnalyzer()
	result := &models.AnalysisResult{
		Metadata: models.PackageMetadata{
			ReproducibleBuild: true,
		},
	}

	score := a.scoreProvenance(result)

	if score.RiskPoints != 1 {
		t.Errorf("Expected 1 risk point for partial provenance, got %d", score.RiskPoints)
	}

	if score.Score != 1 {
		t.Errorf("Expected score 1 for partial provenance, got %d", score.Score)
	}
}

func TestScoreProvenance_PartialProvenance_Combined(t *testing.T) {
	a := NewAnalyzer()
	result := &models.AnalysisResult{
		Metadata: models.PackageMetadata{
			SignedReleases:    true,
			ReproducibleBuild: true,
		},
	}

	score := a.scoreProvenance(result)

	// Two weak indicators (1 point each) = full provenance (2 total)
	if score.RiskPoints != 0 {
		t.Errorf("Expected 0 risk points with two weak indicators, got %d", score.RiskPoints)
	}

	if score.Score != 2 {
		t.Errorf("Expected score 2 with two weak indicators, got %d", score.Score)
	}
}

func TestScoreProvenance_FullProvenance_Multiple(t *testing.T) {
	a := NewAnalyzer()
	result := &models.AnalysisResult{
		Metadata: models.PackageMetadata{
			HasSLSAAttestation:   true,
			SLSALevel:            "SLSA_LEVEL_3",
			HasSigstoreSignature: true,
			SignedReleases:       true,
			ReproducibleBuild:    true,
		},
	}

	score := a.scoreProvenance(result)

	if score.RiskPoints != 0 {
		t.Errorf("Expected 0 risk points with multiple strong indicators, got %d", score.RiskPoints)
	}

	if score.Score != 2 {
		t.Errorf("Expected score 2 with multiple strong indicators, got %d", score.Score)
	}

	if score.Description != "Full provenance with signatures" {
		t.Errorf("Expected 'Full provenance with signatures', got '%s'", score.Description)
	}
}

func TestScoreProvenance_OSSFScorecard(t *testing.T) {
	a := NewAnalyzer()
	result := &models.AnalysisResult{
		Metadata: models.PackageMetadata{
			OSSFChecks: map[string]int{
				"Signed-Releases": 8,
			},
		},
	}

	score := a.scoreProvenance(result)

	// OSSF score alone gives 1 point, which is partial provenance
	if score.RiskPoints != 1 {
		t.Errorf("Expected 1 risk point with OSSF signing score, got %d", score.RiskPoints)
	}

	if score.Score != 1 {
		t.Errorf("Expected score 1 with OSSF signing score, got %d", score.Score)
	}
}

func TestScoreProvenance_LowOSSFScorecard(t *testing.T) {
	a := NewAnalyzer()
	result := &models.AnalysisResult{
		Metadata: models.PackageMetadata{
			OSSFChecks: map[string]int{
				"Signed-Releases": 3,
			},
		},
	}

	score := a.scoreProvenance(result)

	// Low OSSF score doesn't contribute to provenance
	if score.RiskPoints != 2 {
		t.Errorf("Expected 2 risk points with low OSSF score, got %d", score.RiskPoints)
	}

	if score.Score != 0 {
		t.Errorf("Expected score 0 with low OSSF score, got %d", score.Score)
	}
}

func TestScoreProvenance_NPMWithSLSA(t *testing.T) {
	a := NewAnalyzer()
	result := &models.AnalysisResult{
		Metadata: models.PackageMetadata{
			HasNPMProvenance:   true,
			HasSLSAAttestation: true,
			SLSALevel:          "SLSA_LEVEL_2",
		},
	}

	score := a.scoreProvenance(result)

	// npm provenance + SLSA = strong provenance
	if score.RiskPoints != 0 {
		t.Errorf("Expected 0 risk points with npm provenance and SLSA, got %d", score.RiskPoints)
	}

	if score.Score != 2 {
		t.Errorf("Expected score 2 with npm provenance and SLSA, got %d", score.Score)
	}
}

func TestScoreProvenance_ProvenanceDetails(t *testing.T) {
	a := NewAnalyzer()
	result := &models.AnalysisResult{
		Metadata: models.PackageMetadata{
			HasNPMProvenance:   true,
			ProvenanceDetails: "npm provenance: https://registry.npmjs.org/...",
		},
	}

	score := a.scoreProvenance(result)

	if !contains(score.Evidence, "npm provenance: https://registry.npmjs.org/") {
		t.Errorf("Expected provenance details in evidence, got '%s'", score.Evidence)
	}
}

// Helper function to check if a string contains a substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) && containsSubstring(s, substr))
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
