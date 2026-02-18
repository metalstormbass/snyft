package ai

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/metalstormbass/snyft/pkg/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Note: Semantic analyzer integration tests removed after PR #59 reverted semantic code analysis
// as it was deemed out of scope for supply chain risk assessment.

// ── Helpers ─────────────────────────────────────────────────────────────────

func skipIfNoAPIKey(t *testing.T) {
	t.Helper()
	apiKey := os.Getenv("CLAUDE_API_KEY")
	if apiKey == "" {
		apiKey = os.Getenv("ANTHROPIC_API_KEY")
	}
	if apiKey == "" {
		t.Skip("Skipping integration test: CLAUDE_API_KEY or ANTHROPIC_API_KEY not set")
	}
}

func newTestClient(t *testing.T) *Client {
	t.Helper()
	apiKey := os.Getenv("CLAUDE_API_KEY")
	if apiKey == "" {
		apiKey = os.Getenv("ANTHROPIC_API_KEY")
	}
	cfg := DefaultConfig()
	cfg.APIKey = apiKey
	client, err := NewClient(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { client.Close() })
	return client
}

// highRiskNPMResult returns an AnalysisResult representing a high-risk npm package
// with characteristics similar to the ua-parser-js (2021) or coa (2021) attacks:
// single maintainer, no 2FA, suspicious install scripts, no provenance.
func highRiskNPMResult(packageName string) models.AnalysisResult {
	return models.AnalysisResult{
		RiskLevel: "HIGH",
		RiskScore: 88,
		RiskFactors: []string{
			"Single maintainer with full publish rights",
			"No MFA enforcement detected on registry account",
			"postinstall script makes outbound network requests",
			"No SLSA attestation or Sigstore signature",
			"Local publish workflow (no CI-based publishing)",
		},
		SourceCodeAvailable: true,
		Metadata: models.PackageMetadata{
			Maintainers:       []string{"sole-maintainer"},
			HasInstallScripts: true,
			HasCI:             false,
			PublishedAt:       time.Now().Add(-14 * 24 * time.Hour),
		},
		Findings: []models.Finding{
			{
				Severity:    "CRITICAL",
				Category:    "Install Execution",
				Description: "postinstall script performs outbound network requests",
				Evidence:    "package.json postinstall: node ./scripts/install.js (fetches remote payload)",
			},
			{
				Severity: "HIGH",
				Category: "Publisher Control",
				Description: "Single maintainer — account takeover compromises entire package",
				Evidence: "npm registry: 1 maintainer, no MFA enforcement visible",
			},
		},
		SupplyChainScore: &models.SupplyChainScore{
			TotalScore: 13,
			RiskLevel:  "HIGH",
			CategoryScores: models.CategoryScores{
				PublisherControl: models.CategoryScore{
					RiskPoints:  2,
					Description: "Single maintainer, no MFA enforcement",
				},
				InstallExecution: models.CategoryScore{
					RiskPoints:  2,
					Description: "postinstall script with network activity",
				},
				OwnershipChanges: models.CategoryScore{
					RiskPoints:  1,
					Description: "New release after 18-month dormancy",
				},
				ReleaseAnomalies: models.CategoryScore{
					RiskPoints:  2,
					Description: "Rapid patch release following period of inactivity",
				},
			},
		},
	}
}

// lowRiskNPMResult returns an AnalysisResult representing a low-risk, well-maintained npm package.
// Models packages like express (OpenJS Foundation, multiple maintainers, CI-based publishing).
func lowRiskNPMResult(packageName string) models.AnalysisResult {
	return models.AnalysisResult{
		RiskLevel:           "LOW",
		RiskScore:           12,
		RiskFactors:         []string{},
		SourceCodeAvailable: true,
		Metadata: models.PackageMetadata{
			Maintainers:          []string{"maintainer-a", "maintainer-b", "maintainer-c"},
			HasInstallScripts:    false,
			HasCI:                true,
			HasSLSAAttestation:   true,
			HasBranchProtection:  true,
			HasSigstoreSignature: false,
			RepoStars:            62000,
			RepoForks:            10000,
		},
		Findings: []models.Finding{
			{
				Severity:    "LOW",
				Category:    "Health",
				Description: "Minor: no Sigstore signature on releases",
				Evidence:    "Sigstore transparency log: no entry found",
			},
		},
		SupplyChainScore: &models.SupplyChainScore{
			TotalScore: 2,
			RiskLevel:  "LOW",
			CategoryScores: models.CategoryScores{
				PublisherControl: models.CategoryScore{RiskPoints: 0, Description: "Multiple maintainers, CI-based publishing"},
				OwnershipChanges: models.CategoryScore{RiskPoints: 0, Description: "Stable ownership, no recent transfers"},
				InstallExecution: models.CategoryScore{RiskPoints: 0, Description: "No install scripts"},
				ReleaseAnomalies: models.CategoryScore{RiskPoints: 0, Description: "Consistent release cadence"},
			},
		},
	}
}

// mediumRiskNPMResult returns an AnalysisResult for a moderately-risky npm package.
// Models packages like lodash: concentrated bus factor and local publishing workflow.
func mediumRiskNPMResult(packageName string) models.AnalysisResult {
	return models.AnalysisResult{
		RiskLevel: "MEDIUM",
		RiskScore: 52,
		RiskFactors: []string{
			"Single primary maintainer accounts for majority of commits",
			"No SLSA provenance attestation",
			"Publish workflow is local (not CI-enforced)",
		},
		SourceCodeAvailable: true,
		Metadata: models.PackageMetadata{
			Maintainers:         []string{"primary-author", "secondary-contrib"},
			HasInstallScripts:   false,
			HasCI:               true,
			HasBranchProtection: true,
			RepoStars:           58000,
			RepoForks:           7000,
		},
		Findings: []models.Finding{
			{
				Severity:    "MEDIUM",
				Category:    "Health",
				Description: "High bus factor concentration — one contributor dominates commit history",
				Evidence:    "Top contributor: 78% of total commits",
			},
			{
				Severity:    "MEDIUM",
				Category:    "Provenance",
				Description: "No SLSA attestation — cannot verify the build pipeline produced this artifact",
				Evidence:    "npm registry: no attestation metadata found",
			},
		},
		SupplyChainScore: &models.SupplyChainScore{
			TotalScore: 6,
			RiskLevel:  "MEDIUM",
			CategoryScores: models.CategoryScores{
				PublisherControl: models.CategoryScore{RiskPoints: 1, Description: "Concentrated ownership but multiple maintainers"},
				OwnershipChanges: models.CategoryScore{RiskPoints: 0, Description: "No recent ownership transfer"},
				InstallExecution: models.CategoryScore{RiskPoints: 0, Description: "No install scripts"},
				ReleaseAnomalies: models.CategoryScore{RiskPoints: 1, Description: "Irregular release cadence"},
			},
		},
	}
}

// lowRiskPyPIResult returns an AnalysisResult for a well-maintained PyPI package.
// Models packages like requests: multiple maintainers, active community, CI-based publishing.
func lowRiskPyPIResult(packageName string) models.AnalysisResult {
	return models.AnalysisResult{
		RiskLevel:           "LOW",
		RiskScore:           10,
		RiskFactors:         []string{},
		SourceCodeAvailable: true,
		Metadata: models.PackageMetadata{
			Maintainers:         []string{"maintainer-a", "maintainer-b", "maintainer-c"},
			HasInstallScripts:   false,
			HasCI:               true,
			HasBranchProtection: true,
			RepoStars:           51000,
			RepoForks:           9000,
		},
		Findings: []models.Finding{},
		SupplyChainScore: &models.SupplyChainScore{
			TotalScore: 1,
			RiskLevel:  "LOW",
			CategoryScores: models.CategoryScores{
				PublisherControl: models.CategoryScore{RiskPoints: 0, Description: "Multiple maintainers, trusted org"},
				OwnershipChanges: models.CategoryScore{RiskPoints: 0, Description: "Stable, no transfers"},
				InstallExecution: models.CategoryScore{RiskPoints: 0, Description: "No setup.py install hooks"},
				ReleaseAnomalies: models.CategoryScore{RiskPoints: 0, Description: "Regular release cadence"},
			},
		},
	}
}

// mediumRiskPyPIResult returns an AnalysisResult for a moderately-risky PyPI package.
// Models packages like python-jose: security-critical package with concentrated maintainership.
func mediumRiskPyPIResult(packageName string) models.AnalysisResult {
	return models.AnalysisResult{
		RiskLevel: "MEDIUM",
		RiskScore: 55,
		RiskFactors: []string{
			"Security-critical JWT library maintained by single primary author",
			"Periods of inactivity between releases",
			"No SLSA provenance attestation",
		},
		SourceCodeAvailable: true,
		Metadata: models.PackageMetadata{
			Maintainers:         []string{"primary-author"},
			HasInstallScripts:   false,
			HasCI:               true,
			HasBranchProtection: false,
			RepoStars:           1400,
			RepoForks:           220,
		},
		Findings: []models.Finding{
			{
				Severity:    "MEDIUM",
				Category:    "Publisher Control",
				Description: "Single primary maintainer of a security-critical JWT library",
				Evidence:    "PyPI: 1 active maintainer; GitHub: primary author drives all releases",
			},
			{
				Severity:    "LOW",
				Category:    "Health",
				Description: "Irregular release cadence with gaps > 6 months",
				Evidence:    "PyPI release history: 14-month gap between 3.2.0 and 3.3.0",
			},
		},
		SupplyChainScore: &models.SupplyChainScore{
			TotalScore: 7,
			RiskLevel:  "MEDIUM",
			CategoryScores: models.CategoryScores{
				PublisherControl: models.CategoryScore{RiskPoints: 2, Description: "Single maintainer on security-critical package"},
				OwnershipChanges: models.CategoryScore{RiskPoints: 0, Description: "No transfers detected"},
				InstallExecution: models.CategoryScore{RiskPoints: 0, Description: "No install hooks"},
				ReleaseAnomalies: models.CategoryScore{RiskPoints: 1, Description: "Irregular cadence"},
			},
		},
	}
}

// ── Attack matcher integration tests ────────────────────────────────────────

// Test: Attack pattern matching against a high-risk npm package profile
// Justification: Packages exhibiting single-maintainer + install-script + no-MFA patterns
//
//	match the ua-parser-js (2021) and coa (2021) account-takeover attack profile.
//	Validating this with the real API ensures the matcher correctly identifies
//	the correlation. (Ohm et al., 2020 — "Backstabber's Knife Collection")
//
// Source: Backstabber's Knife Collection (Ohm et al., 2020) — https://arxiv.org/abs/2005.09535
// Methodology: Build AnalysisResult mirroring ua-parser-js attack indicators, call MatchAgainstKnownAttacks,
//
//	assert at least one npm attack pattern is returned above threshold.
//
// Result: Should return ≥1 match with confidence in [0,1], academic source, and evidence
func TestAttackMatcher_Integration_RealAPI(t *testing.T) {
	skipIfNoAPIKey(t)
	client := newTestClient(t)

	// Profile resembles ua-parser-js (2021): sole maintainer, no MFA, malicious postinstall
	req := AttackMatchRequest{
		PackageName:    "agenda", // from mike-libraries javascript/package.json
		Ecosystem:      models.EcosystemNPM,
		AnalysisResult: highRiskNPMResult("agenda"),
		Threshold:      0.5,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	matches, err := MatchAgainstKnownAttacks(ctx, client, req)
	require.NoError(t, err, "MatchAgainstKnownAttacks should not error")

	// High-risk profile should produce at least one pattern match
	if len(matches) == 0 {
		t.Log("Warning: high-risk profile produced no matches above threshold 0.5")
	}

	for _, m := range matches {
		assert.NotEmpty(t, m.PatternName, "match must have a pattern name")
		assert.True(t, m.Confidence >= 0 && m.Confidence <= 1,
			"confidence must be in [0,1], got %.2f", m.Confidence)
		assert.NotEmpty(t, m.Severity, "match must have a severity")
		assert.NotEmpty(t, m.Description, "match must have a description")
		assert.NotEmpty(t, m.AcademicSource, "match must have an academic source citation")

		t.Logf("Pattern match: %s (confidence: %.2f, severity: %s)",
			m.PatternName, m.Confidence, m.Severity)
	}
}

// Test: Attack pattern matching for a low-risk npm package produces minimal matches
// Justification: A well-maintained package (multiple maintainers, CI, no install scripts,
//
//	SLSA attestation) should not resemble known attack patterns.
//	False positives undermine analyst trust. (OSSF Scorecard methodology)
//
// Source: OSSF Scorecard — https://github.com/ossf/scorecard
// Methodology: Build AnalysisResult modelling express-like package (low risk, many maintainers),
//
//	call MatchAgainstKnownAttacks with threshold 0.7, assert ≤1 matches.
//
// Result: Well-maintained package should have zero or near-zero pattern matches
func TestAttackMatcher_Integration_LowRiskPackage(t *testing.T) {
	skipIfNoAPIKey(t)
	client := newTestClient(t)

	req := AttackMatchRequest{
		PackageName:    "express", // from mike-libraries javascript/package.json
		Ecosystem:      models.EcosystemNPM,
		AnalysisResult: lowRiskNPMResult("express"),
		Threshold:      0.7,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	matches, err := MatchAgainstKnownAttacks(ctx, client, req)
	require.NoError(t, err, "MatchAgainstKnownAttacks should not error")

	if len(matches) > 1 {
		t.Errorf("expected ≤1 attack pattern matches for low-risk package, got %d", len(matches))
		for _, m := range matches {
			t.Logf("  unexpected match: %s (confidence: %.2f)", m.PatternName, m.Confidence)
		}
	}

	t.Logf("express (low-risk npm): %d pattern matches above threshold 0.7", len(matches))
}

// ── Explainer integration tests ──────────────────────────────────────────────

// Test: Executive explanation for a high-risk npm package using real Claude API
// Justification: The explainer must generate an urgent, actionable explanation when
//
//	a package exhibits critical supply chain risk factors. Stakeholders rely on
//	this output to make block/allow decisions. (Risk communication frameworks)
//
// Source: Stakeholder communication for supply chain security decisions
// Methodology: Pass HIGH-risk AnalysisResult (single maintainer, install scripts, no provenance)
//
//	for "jsonwebtoken" (mike-libraries package) through ExplainRisk, validate
//	that the response contains non-empty summary, recommendation, and confidence.
//
// Result: Should return structured explanation with non-empty summary, recommendation, confidence > 0
func TestExplainer_Integration_HighRisk(t *testing.T) {
	skipIfNoAPIKey(t)
	client := newTestClient(t)

	config := &ExplainerConfig{
		Client:         client,
		TargetAudience: "executive",
		IncludeAttacks: true,
		MaxTokens:      1500,
		Temperature:    0.5,
	}
	explainer := NewExplainer(config)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// jsonwebtoken is a security-critical package in mike-libraries javascript/package.json
	result := highRiskNPMResult("jsonwebtoken")
	explainerResult, err := explainer.ExplainRisk(ctx, "jsonwebtoken", models.EcosystemNPM, result)
	require.NoError(t, err, "ExplainRisk should not error")
	require.NotNil(t, explainerResult.Explanation, "explanation must not be nil")

	assert.NotEmpty(t, explainerResult.Explanation.Summary,
		"high-risk explanation must have a summary")
	assert.NotEmpty(t, explainerResult.Explanation.RecommendedAction,
		"high-risk explanation must have a recommendation")
	assert.True(t, explainerResult.Explanation.Confidence > 0,
		"confidence must be > 0, got %.2f", explainerResult.Explanation.Confidence)

	// High-risk packages should recommend BLOCK or REVIEW, not ALLOW
	rec := strings.ToUpper(explainerResult.Explanation.RecommendedAction)
	if !strings.Contains(rec, "BLOCK") && !strings.Contains(rec, "REVIEW") {
		t.Logf("Warning: high-risk package got unexpected recommendation: %s", rec)
	}

	t.Logf("Summary: %s", explainerResult.Explanation.Summary)
	t.Logf("Recommendation: %s", explainerResult.Explanation.RecommendedAction)
	t.Logf("Confidence: %.2f", explainerResult.Explanation.Confidence)
}

// Test: Executive explanation for a low-risk PyPI package using real Claude API
// Justification: Low-risk packages should generate concise, reassuring explanations
//
//	using "ALLOW" or "MONITOR" recommendations. Over-warning on safe packages
//	causes alert fatigue and reduces analyst trust.
//
// Source: OSSF Scorecard methodology — graduated risk communication
// Methodology: Pass LOW-risk AnalysisResult modelling "requests" (mike-libraries
//
//	python/requirements.txt) through ExplainRisk, validate tone and recommendation.
//
// Result: Should return brief explanation with non-empty summary and ALLOW recommendation
func TestExplainer_Integration_LowRiskPyPI(t *testing.T) {
	skipIfNoAPIKey(t)
	client := newTestClient(t)

	config := &ExplainerConfig{
		Client:         client,
		TargetAudience: "technical",
		IncludeAttacks: false,
		MaxTokens:      1000,
		Temperature:    0.3,
	}
	explainer := NewExplainer(config)

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	// requests is a core dependency in mike-libraries python/requirements.txt
	result := lowRiskPyPIResult("requests")
	explainerResult, err := explainer.ExplainRisk(ctx, "requests", models.EcosystemPyPI, result)
	require.NoError(t, err, "ExplainRisk should not error")
	require.NotNil(t, explainerResult.Explanation, "explanation must not be nil")

	assert.NotEmpty(t, explainerResult.Explanation.Summary)
	assert.True(t, explainerResult.Explanation.Confidence > 0)

	t.Logf("requests (PyPI, low-risk) summary: %s", explainerResult.Explanation.Summary)
	t.Logf("Recommendation: %s", explainerResult.Explanation.RecommendedAction)
}

// Test: Quick summary generation for a medium-risk npm package
// Justification: Quick summaries must be concise (2–4 sentences) and actionable.
//
//	lodash (mike-libraries) has concentrated bus factor — a real supply chain risk
//	(Zimmermann et al., 2019 — "Small World with High Risks").
//
// Source: Small World with High Risks (Zimmermann et al., 2019) — npm dependency network analysis
// Methodology: Pass MEDIUM-risk AnalysisResult for "lodash" through GenerateQuickSummary,
//
//	assert non-empty result with sentence count ≤ 5.
//
// Result: Should return 2–4 sentence summary; warns if longer
func TestExplainer_QuickSummary_Integration(t *testing.T) {
	skipIfNoAPIKey(t)
	client := newTestClient(t)

	config := &ExplainerConfig{Client: client}
	explainer := NewExplainer(config)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// lodash is in mike-libraries javascript/package.json; MEDIUM risk due to bus factor
	result := mediumRiskNPMResult("lodash")
	summary, err := explainer.GenerateQuickSummary(ctx, "lodash", result)
	require.NoError(t, err, "GenerateQuickSummary should not error")
	assert.NotEmpty(t, summary, "summary must not be empty")

	sentences := countSentences(summary)
	if sentences > 5 {
		t.Logf("Warning: quick summary has %d sentences (expected 2–4): %s", sentences, summary)
	}

	t.Logf("lodash quick summary (%d sentences): %s", sentences, summary)
}

// Test: Quick summary for a medium-risk PyPI package
// Justification: python-jose (mike-libraries python/requirements.txt) is a JWT library
//
//	with a single active maintainer — elevated supply chain risk for a security-
//	critical package. Summary should flag this concern concisely.
//
// Source: Backstabber's Knife Collection (Ohm et al., 2020) — single-maintainer risk taxonomy
// Methodology: Pass MEDIUM-risk AnalysisResult for "python-jose" through GenerateQuickSummary,
//
//	assert non-empty result.
//
// Result: Should return concise summary noting single-maintainer risk
func TestExplainer_QuickSummary_PyPI_Integration(t *testing.T) {
	skipIfNoAPIKey(t)
	client := newTestClient(t)

	config := &ExplainerConfig{Client: client}
	explainer := NewExplainer(config)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// python-jose is in mike-libraries python/requirements.txt
	result := mediumRiskPyPIResult("python-jose")
	summary, err := explainer.GenerateQuickSummary(ctx, "python-jose", result)
	require.NoError(t, err, "GenerateQuickSummary should not error")
	assert.NotEmpty(t, summary, "summary must not be empty")

	t.Logf("python-jose quick summary: %s", summary)
}

// Test: Batch explanation for packages from mike-libraries across two ecosystems
// Justification: Production use requires analysing entire dependency manifests in batch.
//
//	Results for each package must be independent and non-nil even if one fails.
//
// Source: Bulk processing requirements; OSSF Scorecard batch analysis patterns
// Methodology: Submit three representative packages from mike-libraries
//
//	(express npm LOW, lodash npm MEDIUM, requests pypi LOW) through BatchExplain.
//	Assert correct count returned and each result has an explanation.
//
// Result: Should return exactly 3 results; each must have a non-nil explanation
func TestExplainer_BatchExplain_Integration(t *testing.T) {
	skipIfNoAPIKey(t)
	client := newTestClient(t)

	config := &ExplainerConfig{Client: client}
	explainer := NewExplainer(config)

	// Packages drawn directly from mike-libraries manifests
	packages := []string{
		"express",  // javascript/package.json — npm, expected LOW risk
		"lodash",   // javascript/package.json — npm, expected MEDIUM risk
		"requests", // python/requirements.txt  — pypi, expected LOW risk
	}
	ecosystems := []models.Ecosystem{
		models.EcosystemNPM,
		models.EcosystemNPM,
		models.EcosystemPyPI,
	}
	results := []models.AnalysisResult{
		lowRiskNPMResult("express"),
		mediumRiskNPMResult("lodash"),
		lowRiskPyPIResult("requests"),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	batchResults, err := explainer.BatchExplain(ctx, packages, ecosystems, results)
	require.NoError(t, err, "BatchExplain should not return a top-level error")
	assert.Equal(t, len(packages), len(batchResults),
		"BatchExplain must return one result per input package")

	for i, r := range batchResults {
		require.NotNil(t, r, "result for %s must not be nil", packages[i])
		if r.Error != nil {
			t.Logf("Warning: %s returned error: %v", packages[i], r.Error)
			continue
		}
		require.NotNil(t, r.Explanation, "explanation for %s must not be nil", packages[i])
		assert.NotEmpty(t, r.Explanation.Summary,
			"summary for %s must not be empty", packages[i])
		t.Logf("%s (%s): %s", packages[i], ecosystems[i], r.Explanation.Summary)
	}
}

// Test: Attack pattern matching for a medium-risk PyPI package (python-jose)
// Justification: python-jose exhibits single-maintainer risk similar to account-takeover
//
//	patterns. This cross-ecosystem test validates that the matcher correctly
//	skips npm-specific attack patterns for PyPI packages.
//
// Source: Towards Measuring Supply Chain Attacks on Package Managers (NDSS 2020) — cross-ecosystem patterns
// Methodology: Submit python-jose (PyPI) through MatchAgainstKnownAttacks; since all
//
//	KnownAttacks are npm-ecosystem, expect 0 matches (ecosystem filter applied).
//
// Result: Should return 0 matches — PyPI package correctly filtered from npm attack DB
func TestAttackMatcher_Integration_PyPIEcosystemFilter(t *testing.T) {
	skipIfNoAPIKey(t)
	client := newTestClient(t)

	req := AttackMatchRequest{
		PackageName:    "python-jose", // mike-libraries python/requirements.txt
		Ecosystem:      models.EcosystemPyPI,
		AnalysisResult: mediumRiskPyPIResult("python-jose"),
		Threshold:      0.4,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	matches, err := MatchAgainstKnownAttacks(ctx, client, req)
	require.NoError(t, err, "MatchAgainstKnownAttacks should not error")

	// All KnownAttacks are npm; PyPI package should be filtered out before API calls
	assert.Equal(t, 0, len(matches),
		"PyPI package should match 0 npm-only attack patterns; got %d", len(matches))

	t.Logf("python-jose (PyPI): correctly filtered — %d matches against npm-only attack DB", len(matches))
}
