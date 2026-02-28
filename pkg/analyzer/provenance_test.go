package analyzer

import (
	"testing"

	"github.com/metalstormbass/snyft/pkg/models"
)

// Test: scoreProvenance assigns maximum risk when no provenance signals exist
// Justification: Packages without any provenance evidence cannot be verified as
//                originating from their stated source, making them susceptible
//                to supply chain substitution attacks
// Source: SLSA specification v1.0 — https://slsa.dev/spec/v1.0/
//         "Backstabber's Knife Collection" (Ohm et al., 2020) — https://arxiv.org/abs/2005.09535
// Methodology: Call scoreProvenance with empty PackageMetadata (no provenance fields set)
// Result: 2 risk points, score 0, description "No provenance evidence"
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

// Test: scoreProvenance gives full credit for SLSA attestation
// Justification: SLSA attestations provide the strongest supply chain integrity
//                guarantee — cryptographic proof linking a package to its source
//                commit and build environment
// Source: SLSA specification v1.0 — https://slsa.dev/spec/v1.0/
// Methodology: Set HasSLSAAttestation=true with SLSA_LEVEL_3; call scoreProvenance
// Result: 0 risk points (full provenance), score 2
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

// Test: scoreProvenance gives full credit for Sigstore signatures
// Justification: Sigstore/Cosign provides keyless signing tied to OIDC
//                identities, enabling verification that releases were created
//                by authorized maintainers without managing long-lived keys
// Source: Sigstore documentation — https://www.sigstore.dev/
// Methodology: Set HasSigstoreSignature=true; call scoreProvenance
// Result: 0 risk points (full provenance), score 2
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

// Test: scoreProvenance gives full credit for npm provenance attestations
// Justification: npm provenance links published packages to specific GitHub
//                Actions workflow runs, proving the package was built from
//                a specific commit in a trusted CI environment
// Source: npm provenance documentation — https://docs.npmjs.com/generating-provenance-statements
// Methodology: Set HasNPMProvenance=true; call scoreProvenance
// Result: 0 risk points (full provenance), score 2
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

// Test: scoreProvenance gives full credit for PyPI cryptographic signatures
// Justification: PGP signatures on PyPI distributions allow verification that
//                the published files were created by the key holder, though
//                PyPI deprecated PGP upload support in May 2023
// Source: PyPI blog — "Removing PGP from PyPI" (2023-05-23)
// Methodology: Set HasPyPISignatures=true; call scoreProvenance
// Result: 0 risk points (full provenance), score 2
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

// Test: scoreProvenance assigns partial credit for signed releases alone
// Justification: Signed GitHub releases (GPG-signed tags) are a weaker
//                provenance signal than SLSA/Sigstore — they prove a maintainer
//                signed the release but don't verify the build process
// Source: OSSF Scorecard — Signed-Releases check
//         https://github.com/ossf/scorecard
// Methodology: Set only SignedReleases=true (weak indicator, 1 point)
// Result: 1 risk point (partial provenance), score 1
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

// Test: scoreProvenance gives full credit with multiple strong indicators
// Justification: Packages with overlapping provenance signals (SLSA + Sigstore
//                + signed releases) represent best-in-class supply chain hygiene;
//                score should not exceed maximum
// Source: SLSA specification v1.0 — defense in depth
// Methodology: Set all strong and weak provenance indicators simultaneously
// Result: 0 risk points (capped at full provenance), score 2
func TestScoreProvenance_FullProvenance_Multiple(t *testing.T) {
	a := NewAnalyzer()
	result := &models.AnalysisResult{
		Metadata: models.PackageMetadata{
			HasSLSAAttestation:   true,
			SLSALevel:            "SLSA_LEVEL_3",
			HasSigstoreSignature: true,
			SignedReleases:       true,
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

// Test: scoreProvenance counts high OSSF Signed-Releases score as weak indicator
// Justification: OSSF Scorecard's Signed-Releases check (score >= 7/10)
//                indicates consistent release signing practices, which is
//                a positive supply chain signal from an independent evaluator
// Source: OSSF Scorecard — Signed-Releases check
//         https://github.com/ossf/scorecard
// Methodology: Set OSSFChecks["Signed-Releases"]=8 (above 7 threshold)
// Result: 1 risk point (partial provenance — OSSF alone is a weak indicator)
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

// Test: scoreProvenance ignores low OSSF Signed-Releases score
// Justification: OSSF Signed-Releases scores below 7 indicate inconsistent
//                or absent release signing — not sufficient to serve as a
//                provenance indicator
// Source: OSSF Scorecard — Signed-Releases check threshold
// Methodology: Set OSSFChecks["Signed-Releases"]=3 (below 7 threshold)
// Result: 2 risk points (no provenance — low score is not counted)
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

// Test: scoreProvenance handles npm provenance combined with SLSA
// Justification: npm packages built via GitHub Actions can have both npm
//                provenance attestations and SLSA attestations — both should
//                be recognized without double-counting risk reduction
// Source: npm provenance documentation — https://docs.npmjs.com/generating-provenance-statements
//         SLSA specification v1.0 — https://slsa.dev/spec/v1.0/
// Methodology: Set HasNPMProvenance=true and HasSLSAAttestation=true together
// Result: 0 risk points (full provenance from either strong indicator)
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

// Test: scoreProvenance includes ProvenanceDetails in evidence output
// Justification: When provenance details are available (e.g. provenance URL),
//                they must appear in the evidence field so that analysts can
//                verify the provenance chain manually
// Source: SLSA specification v1.0 — transparency and auditability
// Methodology: Set HasNPMProvenance=true with a ProvenanceDetails string;
//              check that evidence field contains the details
// Result: Evidence string includes the provenance details content
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

// Test: scoreProvenance assigns 2 risk points when OSSF score is at boundary
// Justification: The threshold for OSSF Signed-Releases is >= 7; a score of
//                exactly 6 must not be counted as a provenance indicator
// Source: OSSF Scorecard — Signed-Releases check threshold
// Methodology: Set OSSFChecks["Signed-Releases"]=6 (just below 7 threshold)
// Result: 2 risk points (no provenance — score below threshold)
func TestScoreProvenance_OSSFBelowThreshold(t *testing.T) {
	a := NewAnalyzer()
	result := &models.AnalysisResult{
		Metadata: models.PackageMetadata{
			OSSFChecks: map[string]int{
				"Signed-Releases": 6,
			},
		},
	}

	score := a.scoreProvenance(result)

	if score.RiskPoints != 2 {
		t.Errorf("Expected 2 risk points with OSSF score 6 (below threshold), got %d", score.RiskPoints)
	}

	if score.Score != 0 {
		t.Errorf("Expected score 0 with OSSF score below threshold, got %d", score.Score)
	}
}

// Test: scoreProvenance assigns partial credit at exactly OSSF threshold of 7
// Justification: The threshold for OSSF Signed-Releases is >= 7; a score of
//                exactly 7 must be counted as a weak provenance indicator
// Source: OSSF Scorecard — Signed-Releases check threshold
// Methodology: Set OSSFChecks["Signed-Releases"]=7 (exactly at threshold)
// Result: 1 risk point (partial provenance — OSSF at boundary is counted)
func TestScoreProvenance_OSSFAtThreshold(t *testing.T) {
	a := NewAnalyzer()
	result := &models.AnalysisResult{
		Metadata: models.PackageMetadata{
			OSSFChecks: map[string]int{
				"Signed-Releases": 7,
			},
		},
	}

	score := a.scoreProvenance(result)

	if score.RiskPoints != 1 {
		t.Errorf("Expected 1 risk point with OSSF score exactly at threshold 7, got %d", score.RiskPoints)
	}

	if score.Score != 1 {
		t.Errorf("Expected score 1 with OSSF score at threshold, got %d", score.Score)
	}
}

// Test: scoreProvenance recognizes CI/CD pipeline as weak provenance indicator
// Justification: SLSA Level 1 requires "the build process to be documented" —
//                having a CI/CD pipeline demonstrates automated, repeatable builds
//                which is the baseline for supply chain hygiene
// Source: SLSA specification v1.0 — Level 1 requirements
//         https://slsa.dev/spec/v1.0/levels
// Methodology: Set only HasCI=true with no other provenance signals;
//              call scoreProvenance to check CI is counted as weak indicator
// Result: 1 risk point (partial provenance from CI baseline)
// Test: CI alone does not count as provenance
// Justification: CI presence indicates automated builds but does NOT provide any
//                cryptographic or verifiable provenance evidence. Provenance requires
//                attestations (SLSA, Sigstore, npm provenance) or signed releases.
//                CI without attestations leaves build integrity unverifiable.
// Source: SLSA specification v1.0 — CI is not a provenance level
// Methodology: Set HasCI=true with no attestation signals, verify no provenance credit
// Result: 2 risk points (no provenance evidence despite CI)
func TestScoreProvenance_CIAloneIsNotProvenance(t *testing.T) {
	a := NewAnalyzer()
	result := &models.AnalysisResult{
		Metadata: models.PackageMetadata{
			HasCI: true,
		},
	}

	score := a.scoreProvenance(result)

	if score.RiskPoints != 2 {
		t.Errorf("Expected 2 risk points with CI only (no attestations), got %d", score.RiskPoints)
	}

	if score.Score != 0 {
		t.Errorf("Expected score 0 with CI only (no attestations), got %d", score.Score)
	}

	if score.Description != "No provenance evidence" {
		t.Errorf("Expected 'No provenance evidence', got '%s'", score.Description)
	}
}

// Test: scoreProvenance does not double-count CI when stronger indicators exist
// Justification: CI is only added when provenanceScore is 0; when stronger
//                indicators (SLSA, Sigstore, etc.) already contribute points,
//                CI should not be counted again
// Source: SLSA specification v1.0 — higher levels subsume lower ones
// Methodology: Set HasCI=true AND HasSLSAAttestation=true; verify CI is not added
// Result: 0 risk points (full provenance from SLSA, CI not double-counted)
func TestScoreProvenance_CINotDoubleCountedWithStrongIndicator(t *testing.T) {
	a := NewAnalyzer()
	result := &models.AnalysisResult{
		Metadata: models.PackageMetadata{
			HasCI:              true,
			HasSLSAAttestation: true,
			SLSALevel:          "SLSA_LEVEL_2",
		},
	}

	score := a.scoreProvenance(result)

	if score.RiskPoints != 0 {
		t.Errorf("Expected 0 risk points with SLSA+CI, got %d", score.RiskPoints)
	}

	if score.Score != 2 {
		t.Errorf("Expected score 2 with SLSA+CI, got %d", score.Score)
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
