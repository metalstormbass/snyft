package analyzer

import (
	"fmt"
	"strings"

	"github.com/metalstormbass/snyft/pkg/models"
)

// scoreProvenance: source availability + reproducible/signed builds (0-2 pts)
//
// Source availability is the primary factor for provenance scoring. A public, accessible
// source repository IS the meaningful signal — it means anyone can audit the code.
// Cryptographic tag matching is a nice-to-have, not a gate.
//
//   - Source available (repo URL or source package) + strong attestations = 0 risk
//   - Source available + no/weak attestations = 1 risk
//   - No source available + attestations = 1 risk
//   - No source available + no attestations = 2 risk (worst case)
//   - SourceVerification nil (check not performed) = fall through to attestation-only
//     logic for backward compatibility.
//
// Scoring: 0=full provenance, 1=partial provenance, 2=no provenance
func (a *Analyzer) scoreProvenance(result *models.AnalysisResult) models.CategoryScore {
	evidence := []string{}
	checks := []models.CheckResult{}
	provenanceScore := 0
	methodology := "Checked source code availability (source package in artifact and/or public repository URL). Checked for SLSA attestations, Sigstore/Cosign signatures, ecosystem-specific provenance (npm provenance, PyPI signatures, Maven Central GPG signatures), signed GitHub releases, reproducible build configuration, and OSSF Scorecard Signed-Releases check."

	// --- Phase 1: Source availability (primary factor) ---
	//
	// A public, accessible source repository is the meaningful signal for provenance.
	// If anyone can inspect the source code, that's what matters for supply chain risk.
	// We treat EITHER of these as "source available":
	//   - SourceVerification.HasSourcePackage (tarball contains source code)
	//   - result.RepositoryURL != "" (public repo exists to audit)
	//
	// We do NOT require HasMatchingGitTag — git tag format mismatches are common
	// and don't indicate compromise risk.
	sourceAvailable := false
	sourceExplicitlyFailed := false

	if result.SourceVerification != nil {
		if result.SourceVerification.HasSourcePackage || result.RepositoryURL != "" {
			sourceAvailable = true
			var detail string
			if result.SourceVerification.HasSourcePackage && result.RepositoryURL != "" {
				detail = "Source package present and repository URL available"
			} else if result.SourceVerification.HasSourcePackage {
				detail = "Source package present in published artifact"
			} else {
				detail = fmt.Sprintf("Public repository available: %s", result.RepositoryURL)
			}
			evidence = append(evidence, "source code available")
			checks = append(checks, models.CheckResult{Name: "Source code availability", Status: "PASS", Detail: detail})
		} else {
			sourceExplicitlyFailed = true
			evidence = append(evidence, "source code NOT available")
			detail := "No source package and no public repository URL"
			if len(result.SourceVerification.VerificationErrors) > 0 {
				detail = strings.Join(result.SourceVerification.VerificationErrors, "; ")
			}
			checks = append(checks, models.CheckResult{Name: "Source code availability", Status: "FAIL", Detail: detail})
		}
	} else if result.RepositoryURL != "" {
		// SourceVerification not performed, but we have a repo URL — source is available
		sourceAvailable = true
		evidence = append(evidence, "source code available")
		checks = append(checks, models.CheckResult{Name: "Source code availability", Status: "PASS", Detail: fmt.Sprintf("Public repository available: %s", result.RepositoryURL)})
	} else {
		checks = append(checks, models.CheckResult{Name: "Source code availability", Status: "SKIPPED", Detail: "No repository URL available or check not applicable"})
	}

	// --- Phase 2: Attestation checks (existing logic) ---

	// Check for SLSA attestations (highest quality provenance)
	if result.Metadata.HasSLSAAttestation {
		provenanceScore += 2
		evidence = append(evidence, fmt.Sprintf("SLSA attestation (%s)", result.Metadata.SLSALevel))
		checks = append(checks, models.CheckResult{Name: "SLSA attestation", Status: "PASS", Detail: fmt.Sprintf("SLSA level: %s", result.Metadata.SLSALevel)})
	} else {
		checks = append(checks, models.CheckResult{Name: "SLSA attestation", Status: "FAIL", Detail: "No SLSA attestation found"})
	}

	// Check for Sigstore signatures
	if result.Metadata.HasSigstoreSignature {
		provenanceScore += 2
		evidence = append(evidence, "Sigstore/Cosign signatures")
		checks = append(checks, models.CheckResult{Name: "Sigstore signatures", Status: "PASS", Detail: "Sigstore/Cosign signatures found"})
	} else {
		checks = append(checks, models.CheckResult{Name: "Sigstore signatures", Status: "FAIL", Detail: "No Sigstore/Cosign signatures found"})
	}

	// Check for ecosystem-specific provenance
	if result.Metadata.HasNPMProvenance {
		provenanceScore += 2
		evidence = append(evidence, "npm provenance attestations")
		checks = append(checks, models.CheckResult{Name: "npm provenance", Status: "PASS", Detail: "npm provenance attestations present"})
	} else if result.Dependency.Ecosystem == models.EcosystemNPM {
		checks = append(checks, models.CheckResult{Name: "npm provenance", Status: "FAIL", Detail: "No npm provenance attestations found"})
	}

	if result.Metadata.HasPyPISignatures {
		provenanceScore += 2
		evidence = append(evidence, "PyPI cryptographic signatures")
		checks = append(checks, models.CheckResult{Name: "PyPI signatures", Status: "PASS", Detail: "PyPI cryptographic signatures present"})
	} else if result.Dependency.Ecosystem == models.EcosystemPyPI {
		checks = append(checks, models.CheckResult{Name: "PyPI signatures", Status: "FAIL", Detail: "No PyPI cryptographic signatures found"})
	}

	// Check for Maven Central GPG signatures (.asc files)
	// Maven Central has required GPG signing since 2010. The presence of a .asc
	// file indicates the publisher followed proper release procedures.
	// Source: https://central.sonatype.org/publish/requirements/gpg/
	if result.Metadata.HasMavenGPGSignature {
		provenanceScore += 1
		evidence = append(evidence, "Maven Central GPG signature (.asc)")
		checks = append(checks, models.CheckResult{Name: "Maven GPG signature", Status: "PASS", Detail: "GPG signature (.asc) file found in Maven Central"})
	} else if result.Dependency.Ecosystem == models.EcosystemMaven {
		checks = append(checks, models.CheckResult{Name: "Maven GPG signature", Status: "FAIL", Detail: "No GPG signature (.asc) file found in Maven Central"})
	}

	// Check for signed releases (GitHub releases with signatures)
	if result.Metadata.SignedReleases {
		provenanceScore += 1
		evidence = append(evidence, "signed GitHub releases")
		checks = append(checks, models.CheckResult{Name: "Signed releases", Status: "PASS", Detail: "GitHub releases are signed"})
	} else {
		checks = append(checks, models.CheckResult{Name: "Signed releases", Status: "FAIL", Detail: "Releases are not cryptographically signed"})
	}

	// Check for reproducible builds
	if result.Metadata.ReproducibleBuild {
		provenanceScore += 1
		evidence = append(evidence, "reproducible build configuration")
		checks = append(checks, models.CheckResult{Name: "Reproducible build", Status: "PASS", Detail: "Reproducible build configuration found"})
	} else {
		checks = append(checks, models.CheckResult{Name: "Reproducible build", Status: "FAIL", Detail: "No reproducible build configuration detected"})
	}

	// Check OSSF Scorecard for additional provenance indicators
	if result.Metadata.OSSFChecks != nil {
		if signingScore, exists := result.Metadata.OSSFChecks["Signed-Releases"]; exists && signingScore >= 7 {
			provenanceScore += 1
			evidence = append(evidence, fmt.Sprintf("OSSF Signed-Releases: %d/10", signingScore))
			checks = append(checks, models.CheckResult{Name: "OSSF Signed-Releases", Status: "PASS", Detail: fmt.Sprintf("Score: %d/10", signingScore)})
		} else if signingScore, exists := result.Metadata.OSSFChecks["Signed-Releases"]; exists {
			checks = append(checks, models.CheckResult{Name: "OSSF Signed-Releases", Status: "FAIL", Detail: fmt.Sprintf("Score: %d/10 (below threshold of 7)", signingScore)})
		}
	}

	// --- Phase 3: Compute final risk based on source availability + attestations ---
	//
	// Decision matrix:
	//
	//   Source Available  | Attestations | Risk
	//   -----------------|--------------|------
	//   yes              | strong (>=2) | 0 - full provenance: auditable + verified
	//   yes              | weak/none    | 1 - source auditable but build unverifiable
	//   no (explicit)    | any          | 1 - attestations exist but can't audit source
	//   no (explicit)    | none         | 2 - worst case: no source, no attestations
	//   unknown          | strong (>=2) | 0 - attestation-only (backward compat)
	//   unknown          | weak (1)     | 1 - partial provenance
	//   unknown          | none (0)     | 2 - no provenance evidence

	var riskPoints int
	var description string
	var score int

	switch {
	case sourceExplicitlyFailed && provenanceScore == 0:
		// No source available and no attestations at all: worst case
		riskPoints = 2
		score = 0
		description = "No provenance evidence; source code not available"

	case sourceExplicitlyFailed:
		// No source available but has some attestations: capped at 1 risk
		riskPoints = 1
		score = 1
		description = "Attestations present but source code not available"

	case sourceAvailable && provenanceScore >= 2:
		// Source available AND strong attestations: best case
		riskPoints = 0
		score = 2
		description = "Full provenance with available source and signatures"

	case sourceAvailable:
		// Source available but no/weak attestations: partial provenance
		// Anyone can audit the code, but build integrity is unverifiable
		riskPoints = 1
		score = 1
		description = "Source code available but build provenance unverifiable"

	default:
		// SourceVerification is nil and no repo URL: fall through to
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
		Score:           score,
		RiskPoints:      riskPoints,
		Description:     description,
		Evidence:        evidenceStr,
		Verified:        len(evidence) > 0 || provenanceScore == 0,
		Methodology:     methodology,
		ChecksPerformed: checks,
	}
}
