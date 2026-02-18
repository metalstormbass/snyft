package analyzer

import (
	"testing"

	"github.com/metalstormbass/snyft/pkg/models"
)

// Test: Levenshtein distance calculation
// Justification: Core algorithm for detecting single-character typosquatting variants
// Source: "Backstabber's Knife Collection" (Ohm et al., 2020) - Section 3.1
// Methodology: Unit test of edit distance computation
// Result: Verifies correct distance for known string pairs
func TestLevenshteinDistance(t *testing.T) {
	tests := []struct {
		name     string
		a        string
		b        string
		expected int
	}{
		{name: "identical strings", a: "lodash", b: "lodash", expected: 0},
		{name: "single insertion", a: "lodas", b: "lodash", expected: 1},
		{name: "single deletion", a: "lodash", b: "lodas", expected: 1},
		{name: "single substitution", a: "lodash", b: "lodesh", expected: 1},
		{name: "transposition", a: "lodash", b: "ldoash", expected: 2}, // Levenshtein counts transposition as 2
		{name: "completely different", a: "abc", b: "xyz", expected: 3},
		{name: "empty first", a: "", b: "abc", expected: 3},
		{name: "empty second", a: "abc", b: "", expected: 3},
		{name: "both empty", a: "", b: "", expected: 0},
		{name: "single char same", a: "a", b: "a", expected: 0},
		{name: "single char different", a: "a", b: "b", expected: 1},
		{name: "real typosquat crossenv", a: "crossenv", b: "cross-env", expected: 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := levenshteinDistance(tt.a, tt.b)
			if result != tt.expected {
				t.Errorf("levenshteinDistance(%q, %q) = %d, want %d", tt.a, tt.b, result, tt.expected)
			}
		})
	}
}

// Test: Character transposition detection
// Justification: Adjacent character swap is a common typo pattern exploited by attackers
// Source: "Backstabber's Knife Collection" (Ohm et al., 2020)
// Methodology: Unit test of transposition detection
// Result: Correctly identifies adjacent character swaps
func TestIsTransposition(t *testing.T) {
	tests := []struct {
		name     string
		a        string
		b        string
		expected bool
	}{
		{name: "adjacent swap", a: "reqeusts", b: "requests", expected: true},
		{name: "adjacent swap start", a: "erquest", b: "request", expected: true}, // same length, swap at positions 0-1
		{name: "no swap", a: "requests", b: "requests", expected: false},
		{name: "different lengths", a: "abc", b: "abcd", expected: false},
		{name: "non-adjacent diff", a: "abcd", b: "dbca", expected: false},
		{name: "swap at end", a: "axiso", b: "axios", expected: true},
		{name: "too short", a: "a", b: "b", expected: false},
		{name: "three diffs", a: "abcde", b: "edcba", expected: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isTransposition(tt.a, tt.b)
			if result != tt.expected {
				t.Errorf("isTransposition(%q, %q) = %v, want %v", tt.a, tt.b, result, tt.expected)
			}
		})
	}
}

// Test: Homoglyph substitution detection
// Justification: Visual similarity attacks exploit characters that look alike (l/1, O/0)
// Source: "Backstabber's Knife Collection" (Ohm et al., 2020) - Section 3.1.2
// Methodology: Unit test of homoglyph detection with known confusable character pairs
// Result: Correctly identifies homoglyph substitutions
func TestIsHomoglyphSubstitution(t *testing.T) {
	tests := []struct {
		name     string
		a        string
		b        string
		expected bool
	}{
		{name: "l to 1", a: "1odash", b: "lodash", expected: true},
		{name: "O to 0", a: "b0to3", b: "bOto3", expected: true},
		{name: "no homoglyph", a: "lodash", b: "lodash", expected: false},
		{name: "different lengths", a: "abc", b: "abcd", expected: false},
		{name: "non-homoglyph diff", a: "abc", b: "axc", expected: false},
		{name: "multiple homoglyphs", a: "100k", b: "lOOk", expected: true},
		{name: "i to 1", a: "p1p", b: "pip", expected: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isHomoglyphSubstitution(tt.a, tt.b)
			if result != tt.expected {
				t.Errorf("isHomoglyphSubstitution(%q, %q) = %v, want %v", tt.a, tt.b, result, tt.expected)
			}
		})
	}
}

// Test: Separator confusion detection
// Justification: Separator manipulation (cross-env vs crossenv vs cross_env) is a
//                documented attack technique. The crossenv malware (2017) used this exact pattern.
// Source: "Backstabber's Knife Collection" (Ohm et al., 2020) - Section 3.1
//         Real-world example: crossenv malware targeting cross-env
// Methodology: Unit test of separator stripping and comparison
// Result: Correctly identifies separator-based confusion
func TestIsSeparatorConfusion(t *testing.T) {
	tests := []struct {
		name     string
		a        string
		b        string
		expected bool
	}{
		{name: "hyphen removed", a: "crossenv", b: "cross-env", expected: true},
		{name: "underscore vs hyphen", a: "cross_env", b: "cross-env", expected: true},
		{name: "dot vs hyphen", a: "cross.env", b: "cross-env", expected: true},
		{name: "identical", a: "cross-env", b: "cross-env", expected: false},
		{name: "completely different", a: "lodash", b: "express", expected: false},
		{name: "no separators both", a: "lodash", b: "lodash", expected: false},
		{name: "separator in different place", a: "cro-ssenv", b: "cross-env", expected: true}, // strips to same "crossenv"
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isSeparatorConfusion(tt.a, tt.b)
			if result != tt.expected {
				t.Errorf("isSeparatorConfusion(%q, %q) = %v, want %v", tt.a, tt.b, result, tt.expected)
			}
		})
	}
}

// Test: npm scope confusion detection
// Justification: npm scoped packages can be used to impersonate popular packages
//                by creating @malicious-scope/popular-name
// Source: npm security advisories; "Backstabber's Knife Collection" (Ohm et al., 2020)
// Methodology: Unit test of scope extraction and comparison
// Result: Correctly identifies scope manipulation attempts
func TestIsScopeConfusion(t *testing.T) {
	tests := []struct {
		name     string
		pkg      string
		popular  string
		expected bool
	}{
		{name: "scope impersonation", pkg: "@evil/react", popular: "react", expected: true},
		{name: "different scope same base", pkg: "@malicious/lodash", popular: "lodash", expected: true},
		{name: "same scope same base", pkg: "@types/react", popular: "@types/react", expected: false},
		{name: "no scope", pkg: "react", popular: "react", expected: false},
		{name: "scoped vs scoped different base", pkg: "@evil/axios", popular: "@types/react", expected: false},
		{name: "scoped matching scoped", pkg: "@evil/core", popular: "@angular/core", expected: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isScopeConfusion(tt.pkg, tt.popular)
			if result != tt.expected {
				t.Errorf("isScopeConfusion(%q, %q) = %v, want %v", tt.pkg, tt.popular, result, tt.expected)
			}
		})
	}
}

// Test: Repeated character detection
// Justification: Doubling a character is a subtle typo that's hard to notice
//                (e.g., "expresss" vs "express", "reeact" vs "react")
// Source: "Towards Measuring Supply Chain Attacks" (NDSS 2020)
// Methodology: Unit test of repeated character detection
// Result: Correctly identifies character repetition variants
func TestIsRepeatedChar(t *testing.T) {
	tests := []struct {
		name     string
		a        string
		b        string
		expected bool
	}{
		{name: "repeated at end", a: "expresss", b: "express", expected: true},
		{name: "repeated at start", a: "rreact", b: "react", expected: true},
		{name: "repeated in middle", a: "reqquests", b: "requests", expected: true},
		{name: "no repetition", a: "express", b: "express", expected: false},
		{name: "different lengths by 2", a: "expresss", b: "expres", expected: false},
		{name: "different char added", a: "expresxs", b: "express", expected: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isRepeatedChar(tt.a, tt.b)
			if result != tt.expected {
				t.Errorf("isRepeatedChar(%q, %q) = %v, want %v", tt.a, tt.b, result, tt.expected)
			}
		})
	}
}

// Test: normalizeName strips ecosystem-specific prefixes
// Justification: Package names must be normalized before comparison to avoid
//                false negatives from scope prefixes and group IDs
// Source: Package manager naming conventions (npm, Maven)
// Methodology: Unit test of name normalization per ecosystem
// Result: Correctly strips scope/group prefixes
func TestNormalizeName(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		ecosystem models.Ecosystem
		expected  string
	}{
		{name: "npm scoped", input: "@types/react", ecosystem: models.EcosystemNPM, expected: "react"},
		{name: "npm unscoped", input: "lodash", ecosystem: models.EcosystemNPM, expected: "lodash"},
		{name: "maven full", input: "com.google.guava:guava", ecosystem: models.EcosystemMaven, expected: "guava"},
		{name: "pypi simple", input: "Requests", ecosystem: models.EcosystemPyPI, expected: "requests"},
		{name: "uppercase to lower", input: "LODASH", ecosystem: models.EcosystemNPM, expected: "lodash"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := normalizeName(tt.input, tt.ecosystem)
			if result != tt.expected {
				t.Errorf("normalizeName(%q, %q) = %q, want %q", tt.input, tt.ecosystem, result, tt.expected)
			}
		})
	}
}

// Test: End-to-end typosquatting detection via checkTyposquatting
// Justification: Integration test ensuring the full detection pipeline correctly
//                identifies known typosquatting patterns and doesn't flag legitimate packages
// Source: "Backstabber's Knife Collection" (Ohm et al., 2020)
//         Real-world attacks: crossenv (2017), event-stream (2018)
// Methodology: Run checkTyposquatting against known malicious and legitimate package names
// Result: Malicious-looking names produce findings; legitimate names produce none
func TestCheckTyposquatting_KnownPatterns(t *testing.T) {
	tests := []struct {
		name            string
		dep             models.Dependency
		expectFindings  bool
		expectTechnique string
	}{
		{
			name: "crossenv typosquat of cross-env",
			dep: models.Dependency{
				Name:      "crossenv",
				Ecosystem: models.EcosystemNPM,
			},
			expectFindings:  true,
			expectTechnique: "separator confusion",
		},
		{
			name: "lodas missing char from lodash",
			dep: models.Dependency{
				Name:      "lodas",
				Ecosystem: models.EcosystemNPM,
			},
			expectFindings:  true,
			expectTechnique: "character omission",
		},
		{
			name: "expresss repeated char",
			dep: models.Dependency{
				Name:      "expresss",
				Ecosystem: models.EcosystemNPM,
			},
			expectFindings:  true,
			expectTechnique: "repeated character",
		},
		{
			name: "scope confusion @evil/react",
			dep: models.Dependency{
				Name:      "@evil/react",
				Ecosystem: models.EcosystemNPM,
			},
			expectFindings:  true,
			expectTechnique: "scope/namespace manipulation",
		},
		{
			name: "1odash homoglyph of lodash",
			dep: models.Dependency{
				Name:      "1odash",
				Ecosystem: models.EcosystemNPM,
			},
			expectFindings:  true,
			expectTechnique: "homoglyph",
		},
		{
			name: "reqeusts transposition of requests",
			dep: models.Dependency{
				Name:      "reqeusts",
				Ecosystem: models.EcosystemPyPI,
			},
			expectFindings:  true,
			expectTechnique: "adjacent character transposition",
		},
		{
			name: "legitimate package lodash",
			dep: models.Dependency{
				Name:      "lodash",
				Ecosystem: models.EcosystemNPM,
			},
			expectFindings: false,
		},
		{
			name: "legitimate package requests",
			dep: models.Dependency{
				Name:      "requests",
				Ecosystem: models.EcosystemPyPI,
			},
			expectFindings: false,
		},
		{
			name: "legitimate package express",
			dep: models.Dependency{
				Name:      "express",
				Ecosystem: models.EcosystemNPM,
			},
			expectFindings: false,
		},
		{
			name: "completely different name",
			dep: models.Dependency{
				Name:      "my-unique-package",
				Ecosystem: models.EcosystemNPM,
			},
			expectFindings: false,
		},
		{
			name: "pypi separator confusion request_s",
			dep: models.Dependency{
				Name:      "request-s",
				Ecosystem: models.EcosystemPyPI,
			},
			expectFindings:  true,
			expectTechnique: "separator confusion",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := &models.AnalysisResult{
				Findings:    []models.Finding{},
				RiskFactors: []string{},
			}

			checkTyposquatting(result, tt.dep)

			if tt.expectFindings && len(result.Findings) == 0 {
				t.Errorf("expected typosquatting findings for %q, got none", tt.dep.Name)
			}
			if !tt.expectFindings && len(result.Findings) > 0 {
				t.Errorf("expected no typosquatting findings for %q, got: %v",
					tt.dep.Name, result.Findings[0].Description)
			}

			if tt.expectFindings && len(result.Findings) > 0 {
				// Verify the finding has the right category
				f := result.Findings[0]
				if f.Category != "Typosquatting Risk" {
					t.Errorf("expected category 'Typosquatting Risk', got %q", f.Category)
				}
				// Verify the finding mentions the expected technique
				if tt.expectTechnique != "" {
					if !containsSubstring(f.Description, tt.expectTechnique) &&
						!containsSubstring(f.Evidence, tt.expectTechnique) {
						t.Errorf("expected finding to mention technique %q, got description=%q evidence=%q",
							tt.expectTechnique, f.Description, f.Evidence)
					}
				}
				// Verify risk factors were added
				if len(result.RiskFactors) == 0 {
					t.Error("expected risk factors to be added")
				}
			}
		})
	}
}

// Test: Unknown ecosystem returns no findings
// Justification: Graceful handling of unsupported ecosystems
// Source: Defensive programming practice
// Methodology: Pass ecosystem not in popularPackages map
// Result: No findings, no panic
func TestCheckTyposquatting_UnknownEcosystem(t *testing.T) {
	result := &models.AnalysisResult{
		Findings:    []models.Finding{},
		RiskFactors: []string{},
	}

	dep := models.Dependency{
		Name:      "something",
		Ecosystem: models.Ecosystem("cargo"), // Not in popular packages
	}

	checkTyposquatting(result, dep)

	if len(result.Findings) > 0 {
		t.Errorf("expected no findings for unknown ecosystem, got %d", len(result.Findings))
	}
}

// Test: detectTyposquatting returns nil for clearly different names
// Justification: Avoid false positives on names with high edit distance
// Source: Standard edit distance thresholds from academic literature
// Methodology: Test with names that differ significantly
// Result: No match returned
func TestDetectTyposquatting_NoMatch(t *testing.T) {
	result := detectTyposquatting("completely-different", "lodash", "completely-different", "lodash")
	if result != nil {
		t.Errorf("expected nil for clearly different names, got %+v", result)
	}
}

// Test: detectTyposquatting correctly classifies edit distance 1 variants
// Justification: Single-character differences are the most common typosquatting technique
// Source: npm security incident data; "Backstabber's Knife Collection" (Ohm et al., 2020)
// Methodology: Test insertion, deletion, and substitution at edit distance 1
// Result: HIGH confidence match with correct technique classification
func TestDetectTyposquatting_EditDistance1(t *testing.T) {
	tests := []struct {
		name      string
		pkg       string
		popular   string
		technique string
	}{
		{name: "extra char", pkg: "lodashx", popular: "lodash", technique: "extra character insertion"},
		{name: "missing char", pkg: "lodas", popular: "lodash", technique: "character omission"},
		{name: "substitution", pkg: "lodesh", popular: "lodash", technique: "character substitution"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detectTyposquatting(tt.pkg, tt.popular, tt.pkg, tt.popular)
			if result == nil {
				t.Fatalf("expected match for %q vs %q, got nil", tt.pkg, tt.popular)
			}
			if result.Confidence != "HIGH" {
				t.Errorf("expected HIGH confidence, got %q", result.Confidence)
			}
			if result.Technique != tt.technique {
				t.Errorf("expected technique %q, got %q", tt.technique, result.Technique)
			}
			if result.EditDistance != 1 {
				t.Errorf("expected edit distance 1, got %d", result.EditDistance)
			}
		})
	}
}

// Test: Short package name with edit distance 2 is flagged as MEDIUM
// Justification: Short package names are more vulnerable to typosquatting because
//                a larger proportion of the name changes, making detection harder
// Source: "Towards Measuring Supply Chain Attacks" (NDSS 2020)
// Methodology: Test with short popular names and edit distance 2
// Result: MEDIUM confidence match for short names
func TestDetectTyposquatting_ShortNameEditDistance2(t *testing.T) {
	// "glob" is 4 chars, need true edit distance 2 without homoglyph match
	// "glab" vs "glob" = distance 2 (l->l, a->o, b->b -- wait, let me compute)
	// Actually use "gxyb" vs "glob" = g->g, x->l, y->o, b->b = distance 2
	result := detectTyposquatting("gxyb", "glob", "gxyb", "glob")
	if result == nil {
		t.Fatal("expected match for short name with edit distance 2")
	}
	if result.Confidence != "MEDIUM" {
		t.Errorf("expected MEDIUM confidence for short name ed=2, got %q", result.Confidence)
	}
}

// Test: Long package name with edit distance 2 is NOT flagged
// Justification: For longer names, edit distance 2 is too common to be meaningful
// Source: Standard edit distance thresholds
// Methodology: Test with long popular names and edit distance 2
// Result: No match returned
func TestDetectTyposquatting_LongNameEditDistance2(t *testing.T) {
	// "typescript" is 10 chars, need true edit distance 2
	result := detectTyposquatting("typxscxipt", "typescript", "typxscxipt", "typescript")
	if result != nil {
		t.Errorf("expected no match for long name with edit distance 2, got %+v", result)
	}
}

// Test: Maven ecosystem typosquatting detection
// Justification: Maven packages use groupId:artifactId format, which must be
//                normalized before comparison
// Source: Maven Central naming conventions
// Methodology: Test typosquatting against normalized Maven artifact IDs
// Result: Correctly detects typosquats of Maven packages after normalization
func TestCheckTyposquatting_Maven(t *testing.T) {
	result := &models.AnalysisResult{
		Findings:    []models.Finding{},
		RiskFactors: []string{},
	}

	// "guavaa" should match against "com.google.guava:guava" after normalization
	dep := models.Dependency{
		Name:      "com.evil:guavaa",
		Ecosystem: models.EcosystemMaven,
	}

	checkTyposquatting(result, dep)

	if len(result.Findings) == 0 {
		t.Error("expected typosquatting finding for 'guavaa' (similar to 'guava')")
	}
}

// Note: containsSubstring helper is defined in provenance_test.go (same package)
