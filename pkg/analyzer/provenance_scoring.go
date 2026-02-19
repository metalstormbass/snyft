package analyzer

import (
	"fmt"
	"strings"

	"github.com/metalstormbass/snyft/pkg/models"
)

// scoreProvenance: source verification + reproducible/signed builds (0-2 pts)
//
// Source code verification is the primary gate for provenance scoring:
//   - Without verified source, you cannot validate what was attested, so attestations
//     alone cannot bring the score to 0 risk.
//   - With verified source + strong attestations = 0 risk (full provenance chain).
//   - With verified source but no attestations = 1 risk (source available but build
//     integrity unverifiable).
//   - Source explicitly NOT verified + no attestations = 2 risk (worst case).
//   - Source explicitly NOT verified + attestations = 1 risk (attestations exist but
//     cannot verify what was attested against source).
//   - SourceVerification nil (check not performed) = fall through to attestation-only
//     logic for backward compatibility.
//
// Scoring: 0=full provenance, 1=partial provenance, 2=no provenance
func (a *Analyzer) scoreProvenance(result *models.AnalysisResult) models.CategoryScore {
	evidence := []string{}
	provenanceScore := 0

	// --- Phase 1: Source verification (primary factor) ---
	//
	// Source verification status determines the ceiling for provenance scoring.
	// If SourceVerification is nil, the check was not performed (e.g., no repo URL
	// available or the check is not applicable), so we fall through to attestation-only
	// logic without penalizing.
	sourceVerified := false
	sourceExplicitlyFailed := false

	if result.SourceVerification != nil {
		if result.SourceVerification.Verified {
			sourceVerified = true
			evidence = append(evidence, "source code verified")
		} else {
			sourceExplicitlyFailed = true
			evidence = append(evidence, "source code NOT verified")
		}
	}

	// --- Phase 2: Attestation checks (existing logic) ---

	// Check for SLSA attestations (highest quality provenance)
	if result.Metadata.HasSLSAAttestation {
		provenanceScore += 2
		evidence = append(evidence, fmt.Sprintf("SLSA attestation (%s)", result.Metadata.SLSALevel))
	}

	// Check for Sigstore signatures
	if result.Metadata.HasSigstoreSignature {
		provenanceScore += 2
		evidence = append(evidence, "Sigstore/Cosign signatures")
	}

	// Check for ecosystem-specific provenance
	if result.Metadata.HasNPMProvenance {
		provenanceScore += 2
		evidence = append(evidence, "npm provenance attestations")
	}

	if result.Metadata.HasPyPISignatures {
		provenanceScore += 2
		evidence = append(evidence, "PyPI cryptographic signatures")
	}

	// Check for signed releases (GitHub releases with signatures)
	if result.Metadata.SignedReleases {
		provenanceScore += 1
		evidence = append(evidence, "signed GitHub releases")
	}

	// Check for reproducible builds
	if result.Metadata.ReproducibleBuild {
		provenanceScore += 1
		evidence = append(evidence, "reproducible build configuration")
	}

	// Check OSSF Scorecard for additional provenance indicators
	if result.Metadata.OSSFChecks != nil {
		if signingScore, exists := result.Metadata.OSSFChecks["Signed-Releases"]; exists && signingScore >= 7 {
			provenanceScore += 1
			evidence = append(evidence, fmt.Sprintf("OSSF Signed-Releases: %d/10", signingScore))
		}
	}

	// --- Phase 3: Compute final risk based on source verification + attestations ---
	//
	// Decision matrix:
	//
	//   SourceVerification  | Attestations | Risk
	//   --------------------|--------------|------
	//   verified            | strong (>=2) | 0 - full provenance chain
	//   verified            | weak/none    | 1 - source available but build unverifiable
	//   explicitly failed   | any          | 1 - can't verify what was attested
	//   explicitly failed   | none         | 2 - worst case: no source, no attestations
	//   nil (not checked)   | strong (>=2) | 0 - attestation-only (backward compat)
	//   nil (not checked)   | weak (1)     | 1 - partial provenance
	//   nil (not checked)   | none (0)     | 2 - no provenance evidence

	var riskPoints int
	var description string
	var score int

	switch {
	case sourceExplicitlyFailed && provenanceScore == 0:
		// Source NOT verified and no attestations at all: worst case
		riskPoints = 2
		score = 0
		description = "No provenance evidence; source code not verified"

	case sourceExplicitlyFailed:
		// Source NOT verified but has some attestations: capped at 1 risk
		// because attestations exist but we can't verify what was attested
		riskPoints = 1
		score = 1
		description = "Attestations present but source code not verified"

	case sourceVerified && provenanceScore >= 2:
		// Source verified AND strong attestations: best case
		riskPoints = 0
		score = 2
		description = "Full provenance with verified source and signatures"

	case sourceVerified:
		// Source verified but weak or no attestations
		riskPoints = 1
		score = 1
		description = "Source code verified but limited build attestations"

	default:
		// SourceVerification is nil (check not performed): fall through to
		// attestation-only logic for backward compatibility
		if provenanceScore >= 2 {
			riskPoints = 0
			score = 2
			description = "Full provenance with signatures"
		} else if provenanceScore >= 1 {
			riskPoints = 1
			score = 1
			description = "Partial provenance"
		} else {
			riskPoints = 2
			score = 0
			description = "No provenance evidence"
		}
	}

	evidenceStr := "No provenance data"
	if len(evidence) > 0 {
		evidenceStr = strings.Join(evidence, ", ")
	}

	// Add provenance details if available
	if result.Metadata.ProvenanceDetails != "" {
		evidenceStr = evidenceStr + "; " + result.Metadata.ProvenanceDetails
	}

	return models.CategoryScore{
		Score:       score,
		RiskPoints:  riskPoints,
		Description: description,
		Evidence:    evidenceStr,
		Verified:    len(evidence) > 0 || provenanceScore == 0,
	}
}
