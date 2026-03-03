package analyzer

import (
	"strings"
	"testing"

	"github.com/metalstormbass/snyft/pkg/models"
)

// Test: scoreProvenance assigns moderate risk when source check not performed and no attestations
// Justification: When SourceVerification is nil, we couldn't check source availability —
//                this is unknown, not explicitly failed. Distinguish from verified-and-failed
//                (which gets 2 risk points). Unknown state gets 1 risk point (moderate).
// Source: SLSA specification v1.0 — https://slsa.dev/spec/v1.0/
//         "Backstabber's Knife Collection" (Ohm et al., 2020) — https://arxiv.org/abs/2005.09535
// Methodology: Call scoreProvenance with empty PackageMetadata (no provenance fields set,
//              nil SourceVerification)
// Result: 1 risk point (unknown source, no attestations), score 1
func TestScoreProvenance_NoProvenance(t *testing.T) {
	a := NewAnalyzer()
	result := &models.AnalysisResult{
		Metadata: models.PackageMetadata{},
	}

	score := a.scoreProvenance(result)

	if score.RiskPoints != 1 {
		t.Errorf("Expected 1 risk point for nil source verification (unknown, not failed), got %d", score.RiskPoints)
	}

	if score.Score != 1 {
		t.Errorf("Expected score 1 for nil source verification, got %d", score.Score)
	}

	if !strings.Contains(score.Description, "could not be determined") {
		t.Errorf("Description should explain source availability could not be determined, got '%s'", score.Description)
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

// Test: scoreProvenance gives full credit for Maven Central GPG signatures
// Justification: Maven Central has required GPG signing for all published
//                artifacts since 2010. This is a mandatory, enforced provenance
//                signal — not an optional best practice. It proves the publisher
//                holds the signing key and went through proper release procedures.
// Source: Maven Central publishing requirements — https://central.sonatype.org/publish/requirements/gpg/
// Methodology: Set HasMavenGPGSignature=true with Maven ecosystem; call scoreProvenance
// Result: 0 risk points (full provenance), score 2 — GPG signing is strong (+2 points)
func TestScoreProvenance_MavenGPGSignature(t *testing.T) {
	a := NewAnalyzer()
	result := &models.AnalysisResult{
		Dependency: models.Dependency{Ecosystem: models.EcosystemMaven},
		Metadata: models.PackageMetadata{
			HasMavenGPGSignature: true,
		},
	}

	score := a.scoreProvenance(result)

	if score.RiskPoints != 0 {
		t.Errorf("Expected 0 risk points with Maven GPG signature (strong provenance), got %d", score.RiskPoints)
	}

	if score.Score != 2 {
		t.Errorf("Expected score 2 with Maven GPG signature, got %d", score.Score)
	}

	if !strings.Contains(score.Evidence, "Maven Central GPG signature") {
		t.Errorf("Expected evidence to mention Maven Central GPG signature, got '%s'", score.Evidence)
	}
}

// Test: scoreProvenance assigns partial credit for signed releases alone
// Justification: Signed GitHub releases (GPG-signed tags) are a weaker
//                provenance signal — they prove a maintainer signed the
//                release but don't verify the build process
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

	if !strings.Contains(score.Description, "Partial provenance") || !strings.Contains(score.Description, "signed") {
		t.Errorf("Description should indicate partial provenance with signed releases, got '%s'", score.Description)
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
//                provenance indicator. With nil SourceVerification (unknown),
//                this gets moderate risk (1) not worst case (2).
// Source: OSSF Scorecard — Signed-Releases check threshold
// Methodology: Set OSSFChecks["Signed-Releases"]=3 (below 7 threshold)
// Result: 1 risk point (nil source verification + low OSSF not counted = unknown state)
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

	// Low OSSF score doesn't contribute to provenance; nil source → moderate risk
	if score.RiskPoints != 1 {
		t.Errorf("Expected 1 risk point with low OSSF score and nil source verification, got %d", score.RiskPoints)
	}

	if score.Score != 1 {
		t.Errorf("Expected score 1 with low OSSF score and nil source verification, got %d", score.Score)
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
			HasNPMProvenance:  true,
			ProvenanceDetails: "npm provenance: https://registry.npmjs.org/...",
		},
	}

	score := a.scoreProvenance(result)

	if !contains(score.Evidence, "npm provenance: https://registry.npmjs.org/") {
		t.Errorf("Expected provenance details in evidence, got '%s'", score.Evidence)
	}
}

// Test: scoreProvenance assigns moderate risk when OSSF score is at boundary
// Justification: The threshold for OSSF Signed-Releases is >= 7; a score of
//                exactly 6 must not be counted as a provenance indicator.
//                With nil SourceVerification (unknown), this gets moderate risk (1).
// Source: OSSF Scorecard — Signed-Releases check threshold
// Methodology: Set OSSFChecks["Signed-Releases"]=6 (just below 7 threshold)
// Result: 1 risk point (nil source verification + OSSF below threshold = unknown state)
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

	if score.RiskPoints != 1 {
		t.Errorf("Expected 1 risk point with OSSF score 6 and nil source verification, got %d", score.RiskPoints)
	}

	if score.Score != 1 {
		t.Errorf("Expected score 1 with OSSF score below threshold and nil source verification, got %d", score.Score)
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

// Test: CI alone does not count as provenance
// Justification: CI presence indicates automated builds but does NOT provide any
//                cryptographic or verifiable provenance evidence. Provenance requires
//                attestations (npm provenance, Maven GPG) or signed releases.
//                CI without attestations leaves build integrity unverifiable.
//                With nil SourceVerification (unknown), this gets moderate risk (1).
// Source: SLSA specification v1.0 — CI is not a provenance level
// Methodology: Set HasCI=true with no attestation signals, verify no provenance credit
// Result: 1 risk point (nil source verification + CI alone = unknown state)
func TestScoreProvenance_CIAloneIsNotProvenance(t *testing.T) {
	a := NewAnalyzer()
	result := &models.AnalysisResult{
		Metadata: models.PackageMetadata{
			HasCI: true,
		},
	}

	score := a.scoreProvenance(result)

	if score.RiskPoints != 1 {
		t.Errorf("Expected 1 risk point with CI only and nil source verification, got %d", score.RiskPoints)
	}

	if score.Score != 1 {
		t.Errorf("Expected score 1 with CI only and nil source verification, got %d", score.Score)
	}

	if !strings.Contains(score.Description, "could not be determined") {
		t.Errorf("Description should explain source could not be determined, got '%s'", score.Description)
	}
}

// Test: scoreProvenance does not double-count CI when stronger indicators exist
// Justification: CI is only added when provenanceScore is 0; when stronger
//                indicators (npm provenance, etc.) already contribute points,
//                CI should not be counted again
// Source: SLSA specification v1.0 — higher levels subsume lower ones
// Methodology: Set HasCI=true AND HasNPMProvenance=true; verify CI is not added
// Result: 0 risk points (full provenance from npm provenance, CI not double-counted)
func TestScoreProvenance_CINotDoubleCountedWithStrongIndicator(t *testing.T) {
	a := NewAnalyzer()
	result := &models.AnalysisResult{
		Metadata: models.PackageMetadata{
			HasCI:            true,
			HasNPMProvenance: true,
		},
	}

	score := a.scoreProvenance(result)

	if score.RiskPoints != 0 {
		t.Errorf("Expected 0 risk points with npm provenance+CI, got %d", score.RiskPoints)
	}

	if score.Score != 2 {
		t.Errorf("Expected score 2 with npm provenance+CI, got %d", score.Score)
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
