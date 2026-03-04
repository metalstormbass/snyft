package analyzer

import (
	"strings"
	"testing"

	"github.com/metalstormbass/snyft/pkg/models"
)

// Test: Known compromised npm package is flagged
// Justification: Packages with documented supply chain compromises have proven
//                susceptibility to takeover — this is the highest-confidence
//                signal that a package carries supply chain risk.
// Source: "Backstabber's Knife Collection" (Ohm et al., 2020)
//         https://arxiv.org/abs/2005.09535
// Methodology: Match package name + ecosystem against static list of
//              documented supply chain attacks
// Result: HIGH finding with attack name, year, and reference URL
func TestCheckKnownCompromises_EventStream(t *testing.T) {
	result := &models.AnalysisResult{
		Dependency: models.Dependency{
			Name:      "event-stream",
			Ecosystem: models.EcosystemNPM,
		},
		Findings: []models.Finding{},
	}

	checkKnownCompromises(result)

	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}
	f := result.Findings[0]
	if f.Severity != "HIGH" {
		t.Errorf("expected HIGH severity, got %s", f.Severity)
	}
	if f.Category != "Known Supply Chain Compromise" {
		t.Errorf("expected 'Known Supply Chain Compromise' category, got %s", f.Category)
	}
	if f.Check != "Historical Compromise Database" {
		t.Errorf("expected 'Historical Compromise Database' check, got %s", f.Check)
	}
}

// Test: chalk is flagged as Shai-Hulud compromise
// Justification: chalk was compromised in the Sep 2025 Shai-Hulud coordinated
//                attack — account takeover leading to malicious npm publishes.
// Source: Phylum blog post on Shai-Hulud attack
// Methodology: Static list match
// Result: HIGH finding referencing Shai-Hulud attack (2025)
func TestCheckKnownCompromises_Chalk(t *testing.T) {
	result := &models.AnalysisResult{
		Dependency: models.Dependency{
			Name:      "chalk",
			Ecosystem: models.EcosystemNPM,
		},
		Findings: []models.Finding{},
	}

	checkKnownCompromises(result)

	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}
	f := result.Findings[0]
	if f.Severity != "HIGH" {
		t.Errorf("expected HIGH severity, got %s", f.Severity)
	}
	assertContains(t, f.Description, "Shai-Hulud")
	assertContains(t, f.Evidence, "2025")
}

// Test: debug is flagged as Shai-Hulud compromise
// Justification: debug was compromised alongside chalk in the Shai-Hulud
//                coordinated supply chain attack (Sep 2025).
// Source: Phylum blog post on Shai-Hulud attack
// Methodology: Static list match
// Result: HIGH finding referencing Shai-Hulud attack (2025)
func TestCheckKnownCompromises_Debug(t *testing.T) {
	result := &models.AnalysisResult{
		Dependency: models.Dependency{
			Name:      "debug",
			Ecosystem: models.EcosystemNPM,
		},
		Findings: []models.Finding{},
	}

	checkKnownCompromises(result)

	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}
	f := result.Findings[0]
	assertContains(t, f.Description, "Shai-Hulud")
}

// Test: Uncompromised package produces no finding
// Justification: False positives would erode trust in the tool. Packages not
//                in the known compromise list must produce zero findings from
//                this check.
// Source: N/A (negative test)
// Methodology: Check a package name not in the list
// Result: No findings added
func TestCheckKnownCompromises_SafePackage(t *testing.T) {
	result := &models.AnalysisResult{
		Dependency: models.Dependency{
			Name:      "express",
			Ecosystem: models.EcosystemNPM,
		},
		Findings: []models.Finding{},
	}

	checkKnownCompromises(result)

	if len(result.Findings) != 0 {
		t.Fatalf("expected 0 findings for safe package, got %d", len(result.Findings))
	}
}

// Test: Wrong ecosystem does not match
// Justification: event-stream is an npm compromise. A PyPI package with the
//                same name must NOT be flagged — ecosystem specificity prevents
//                false positives across registries.
// Source: N/A (boundary test)
// Methodology: Check npm-compromised name against PyPI ecosystem
// Result: No findings added
func TestCheckKnownCompromises_WrongEcosystem(t *testing.T) {
	result := &models.AnalysisResult{
		Dependency: models.Dependency{
			Name:      "event-stream",
			Ecosystem: models.EcosystemPyPI,
		},
		Findings: []models.Finding{},
	}

	checkKnownCompromises(result)

	if len(result.Findings) != 0 {
		t.Fatalf("expected 0 findings for wrong ecosystem, got %d", len(result.Findings))
	}
}

// Test: All known compromises are flagged
// Justification: Every entry in the static list must produce a finding when
//                matched — no silent gaps in coverage.
// Source: Static list validation
// Methodology: Iterate all entries, verify each produces exactly one finding
// Result: Each known compromise produces a HIGH finding
func TestCheckKnownCompromises_AllEntries(t *testing.T) {
	for _, c := range knownCompromises {
		t.Run(c.Name, func(t *testing.T) {
			result := &models.AnalysisResult{
				Dependency: models.Dependency{
					Name:      c.Name,
					Ecosystem: c.Ecosystem,
				},
				Findings: []models.Finding{},
			}

			checkKnownCompromises(result)

			if len(result.Findings) != 1 {
				t.Fatalf("expected 1 finding for %s, got %d", c.Name, len(result.Findings))
			}
			f := result.Findings[0]
			if f.Severity != "HIGH" {
				t.Errorf("expected HIGH severity for %s, got %s", c.Name, f.Severity)
			}
			if f.SourceURL == "" {
				t.Errorf("expected non-empty SourceURL for %s", c.Name)
			}
		})
	}
}

func assertContains(t *testing.T, s, substr string) {
	t.Helper()
	if !strings.Contains(s, substr) {
		t.Errorf("expected %q to contain %q", s, substr)
	}
}
