package analyzer

import (
	"strings"
	"testing"

	"github.com/anthropics/anthropic-sdk-go"
)

// ===== AI Evidence Quality Tests =====
// These tests verify that AI-generated findings always include specific, verifiable
// academic citations and concrete evidence - never vague placeholders.

// Test: parseAttackPatternResponse extracts real evidence from AI response text
// Justification: Vague evidence like "Pattern mentioned in AI analysis: Account Takeover"
//                provides no value to security teams reviewing findings. Evidence must
//                include the AI's actual reasoning about why a pattern applies.
// Source: Project requirement - CLAUDE.md: "Every risk point assigned must have clear
//         justification, academic source citation, methodology documentation"
// Methodology: Construct mock Claude API responses with known attack pattern mentions
//              and verify the parser extracts surrounding context as evidence.
// Result: Evidence array should contain actual context, not generic placeholders.
func TestParseAttackPatternResponse_ExtractsRealEvidence(t *testing.T) {
	analyzer := NewAnalyzer()

	// Simulate a Claude response that mentions Account Takeover with specific reasoning
	responseText := `## Pattern Matching Analysis

Based on the package profile, the following attack patterns are relevant:

**Account Takeover**: This package has a single maintainer with no 2FA enforcement, making it vulnerable to credential-based account takeover. The single maintainer pattern matches the eslint-scope (2018) and ua-parser-js (2021) incidents where compromised credentials led to malicious package versions.

**Build Chain Compromise**: The package is published locally without CI/CD automation, matching the SLSA threat model for build integrity gaps. No signed releases or attestations are present.`

	message := &anthropic.Message{
		Content: []anthropic.ContentBlockUnion{
			{
				Type: "text",
				Text: responseText,
			},
		},
	}

	patterns := analyzer.parseAttackPatternResponse(message)

	if len(patterns) < 2 {
		t.Fatalf("Expected at least 2 patterns, got %d", len(patterns))
	}

	// Find the Account Takeover pattern
	var accountTakeover *struct {
		evidence       []string
		academicSource string
		indicators     []string
	}

	for _, p := range patterns {
		if p.PatternName == "Account Takeover" {
			accountTakeover = &struct {
				evidence       []string
				academicSource string
				indicators     []string
			}{
				evidence:       p.Evidence,
				academicSource: p.AcademicSource,
				indicators:     p.Indicators,
			}
			break
		}
	}

	if accountTakeover == nil {
		t.Fatal("Account Takeover pattern not found in results")
	}

	// Verify evidence is NOT the old vague format
	for _, ev := range accountTakeover.evidence {
		if strings.Contains(ev, "Pattern mentioned in AI analysis") {
			t.Errorf("Evidence should not contain vague 'Pattern mentioned in AI analysis' placeholder, got: %s", ev)
		}
	}

	// Verify evidence contains actual substance from the AI response
	hasSubstantiveEvidence := false
	for _, ev := range accountTakeover.evidence {
		if len(ev) > 30 {
			hasSubstantiveEvidence = true
			break
		}
	}
	if !hasSubstantiveEvidence {
		t.Error("Evidence should contain substantive content from the AI response, not just short labels")
	}

	// Verify academic source is present and specific
	if accountTakeover.academicSource == "" {
		t.Error("Academic source must not be empty")
	}
	if accountTakeover.academicSource == "Supply chain security research" {
		t.Error("Academic source must be specific, not the vague fallback 'Supply chain security research'")
	}
	if !strings.Contains(accountTakeover.academicSource, "Ohm") && !strings.Contains(accountTakeover.academicSource, "arxiv") {
		t.Errorf("Account Takeover source should cite Ohm et al. or arxiv, got: %s", accountTakeover.academicSource)
	}
}

// Test: parseAttackPatternResponse handles response with no pattern mentions gracefully
// Justification: When AI analysis doesn't identify any attack patterns, the parser should
//                return an empty slice without errors, not generate phantom findings.
// Source: Defensive programming best practice
// Methodology: Pass a Claude response with no attack pattern keywords
// Result: Empty patterns slice returned
func TestParseAttackPatternResponse_EmptyResponse(t *testing.T) {
	analyzer := NewAnalyzer()

	message := &anthropic.Message{
		Content: []anthropic.ContentBlockUnion{
			{
				Type: "text",
				Text: "This package shows good security practices with no concerning patterns.",
			},
		},
	}

	patterns := analyzer.parseAttackPatternResponse(message)

	if len(patterns) != 0 {
		t.Errorf("Expected 0 patterns for benign response, got %d", len(patterns))
	}
}

// Test: parseAttackPatternResponse handles empty message content
// Justification: API responses may be empty due to rate limits or errors
// Source: Defensive programming best practice
// Methodology: Pass empty message content
// Result: Empty patterns slice returned
func TestParseAttackPatternResponse_EmptyContent(t *testing.T) {
	analyzer := NewAnalyzer()

	message := &anthropic.Message{
		Content: []anthropic.ContentBlockUnion{},
	}

	patterns := analyzer.parseAttackPatternResponse(message)

	if len(patterns) != 0 {
		t.Errorf("Expected 0 patterns for empty content, got %d", len(patterns))
	}
}

// Test: getAcademicSourceForPattern returns specific citations for all known patterns
// Justification: Every AI-generated finding must cite a specific, verifiable source -
//                an academic paper, a specification, or a documented attack pattern.
//                Vague references like "Various security advisories" or
//                "Supply chain security research" are not acceptable.
// Source: Project CLAUDE.md: "All risk assessments must be justified by peer-reviewed
//         academic research, official security specifications (SLSA, OSSF)"
// Methodology: Call getAcademicSourceForPattern for every known pattern and verify
//              each returns a specific, verifiable citation.
// Result: All patterns return citations with author names or specification names and URLs.
func TestGetAcademicSourceForPattern_AllPatternsHaveSpecificCitations(t *testing.T) {
	analyzer := NewAnalyzer()

	knownPatterns := []string{
		"Typosquatting",
		"Account Takeover",
		"Dependency Confusion",
		"Malicious Install Script",
		"Abandoned Package Takeover",
		"Build Chain Compromise",
		"Transitive Dependency Poisoning",
		"Subdomain Takeover",
	}

	vagueSourcePatterns := []string{
		"Various security advisories",
		"Supply chain security research",
		"various",
		"general",
		"multiple sources",
	}

	for _, pattern := range knownPatterns {
		source := analyzer.getAcademicSourceForPattern(pattern)

		// Source must not be empty
		if source == "" {
			t.Errorf("Pattern %q has empty academic source", pattern)
			continue
		}

		// Source must not be vague
		for _, vague := range vagueSourcePatterns {
			if strings.EqualFold(source, vague) || strings.Contains(strings.ToLower(source), strings.ToLower(vague)) {
				t.Errorf("Pattern %q has vague academic source: %q", pattern, source)
			}
		}

		// Source must contain at least one of: author name, specification name, or URL
		hasAuthorOrSpec := strings.Contains(source, "Ohm") ||
			strings.Contains(source, "Zimmermann") ||
			strings.Contains(source, "Birsan") ||
			strings.Contains(source, "SLSA") ||
			strings.Contains(source, "NDSS") ||
			strings.Contains(source, "arxiv") ||
			strings.Contains(source, "https://")

		if !hasAuthorOrSpec {
			t.Errorf("Pattern %q source should contain author name, specification, or URL: %q", pattern, source)
		}
	}
}

// Test: getAcademicSourceForPattern fallback is specific, not vague
// Justification: Even unknown patterns should fall back to a specific reference
//                that security teams can verify, not a generic placeholder.
// Source: Project CLAUDE.md requirements for evidence-based scoring
// Methodology: Call with an unknown pattern name and verify fallback is specific
// Result: Fallback citation includes author and URL
func TestGetAcademicSourceForPattern_FallbackIsSpecific(t *testing.T) {
	analyzer := NewAnalyzer()

	// Use an unknown pattern to trigger the fallback
	source := analyzer.getAcademicSourceForPattern("Unknown Pattern That Does Not Exist")

	if source == "" {
		t.Error("Fallback source must not be empty")
	}

	if source == "Supply chain security research" {
		t.Error("Fallback source must not be the vague 'Supply chain security research'")
	}

	if !strings.Contains(source, "https://") {
		t.Errorf("Fallback source should include a verifiable URL, got: %s", source)
	}
}

// Test: splitIntoSentences correctly handles bullet points, numbered lists, and paragraphs
// Justification: Proper sentence splitting is required to extract meaningful evidence
//                from AI response text rather than truncated fragments.
// Source: Internal implementation requirement
// Methodology: Pass text with various formatting and verify sentence boundaries
// Result: Each bullet point and paragraph becomes a separate sentence
func TestSplitIntoSentences(t *testing.T) {
	text := `This is a paragraph about security.

- First bullet point about Account Takeover risk
- Second bullet about single maintainer
* Star-style bullet about Build Chain Compromise

1. Numbered item about dependency risk
2. Another numbered item

Final paragraph with a conclusion.`

	sentences := splitIntoSentences(text)

	if len(sentences) < 7 {
		t.Errorf("Expected at least 7 sentences, got %d: %v", len(sentences), sentences)
	}

	// Verify bullet points are preserved as individual items
	hasBullet := false
	for _, s := range sentences {
		if strings.Contains(s, "First bullet") {
			hasBullet = true
			break
		}
	}
	if !hasBullet {
		t.Error("Bullet points should be preserved as individual sentences")
	}
}

// Test: extractEvidenceForPattern finds relevant context, not generic labels
// Justification: Evidence extraction must pull actual AI reasoning from the response,
//                not just acknowledge that a pattern name was mentioned.
// Source: Project requirement for substantive evidence
// Methodology: Provide sentences with pattern mentions and verify extraction
// Result: Extracted evidence contains the full context sentence
func TestExtractEvidenceForPattern(t *testing.T) {
	sentences := []string{
		"This package shows good practices.",
		"The Account Takeover risk is elevated due to single maintainer with no 2FA.",
		"Only one person controls package publishing credentials.",
		"The package uses CI/CD for releases.",
	}

	evidence := extractEvidenceForPattern(sentences, "Account Takeover")

	if len(evidence) == 0 {
		t.Fatal("Expected at least one evidence item")
	}

	// Evidence should contain the actual reasoning
	foundRelevant := false
	for _, ev := range evidence {
		if strings.Contains(ev, "single maintainer") || strings.Contains(ev, "no 2FA") {
			foundRelevant = true
			break
		}
	}
	if !foundRelevant {
		t.Errorf("Evidence should contain specific reasoning about the pattern, got: %v", evidence)
	}

	// Evidence should NOT be the vague placeholder
	for _, ev := range evidence {
		if strings.Contains(ev, "Pattern mentioned in AI analysis") {
			t.Errorf("Evidence must not be a vague placeholder, got: %s", ev)
		}
	}
}

// Test: extractEvidenceForPattern returns structured fallback when no context found
// Justification: When the AI mentions a pattern name without surrounding context,
//                the fallback evidence should still be more descriptive than
//                "Pattern mentioned in AI analysis: X"
// Source: Project requirement for meaningful evidence
// Methodology: Provide sentences where pattern is only in a short header
// Result: Fallback evidence references the attack vector, not just the pattern name
func TestExtractEvidenceForPattern_FallbackIsDescriptive(t *testing.T) {
	sentences := []string{
		"Typosquatting",
		"Analysis complete.",
	}

	evidence := extractEvidenceForPattern(sentences, "Typosquatting")

	if len(evidence) == 0 {
		t.Fatal("Expected fallback evidence")
	}

	// Fallback should mention the attack vector and supply chain context
	if strings.HasPrefix(evidence[0], "Pattern mentioned") {
		t.Errorf("Fallback evidence should not start with 'Pattern mentioned', got: %s", evidence[0])
	}

	if !strings.Contains(evidence[0], "Typosquatting") {
		t.Errorf("Fallback evidence should reference the attack pattern name, got: %s", evidence[0])
	}
}
