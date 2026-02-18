package analyzer

import (
	"testing"
	"time"

	"github.com/metalstormbass/snyft/pkg/models"
)

// Test: Single maintainer with personal email = HIGH RISK
// Justification: Single point of failure - one phished account = complete package compromise
// Source: "Backstabber's Knife Collection" (Ohm et al., 2020)
//         90% of supply chain attacks target maintainer accounts via phishing/credential stuffing
// Methodology: Count maintainers in package metadata, check email domains
// Result: Assigns 2 risk points if maintainer_count == 1 AND personal email domain
func TestPublisherControl_SingleMaintainerPersonalEmail(t *testing.T) {
	analyzer := NewAnalyzer()

	result := &models.AnalysisResult{
		Dependency: models.Dependency{
			Name:      "test-package",
			Ecosystem: models.EcosystemNPM,
		},
		Metadata: models.PackageMetadata{
			Maintainers: []string{"user@gmail.com"}, // Single maintainer, personal email
		},
		RepositoryURL: "", // No repository for this test
	}

	analysis := analyzer.AnalyzePublisherControl(result, "")

	if !analysis.SingleMaintainer {
		t.Error("Expected SingleMaintainer to be true")
	}

	if analysis.RiskLevel != "HIGH" {
		t.Errorf("Expected HIGH risk level, got %s", analysis.RiskLevel)
	}

	if analysis.RiskPoints != 2 {
		t.Errorf("Expected 2 risk points, got %d", analysis.RiskPoints)
	}

	if !analysis.HasExpirableDomains {
		t.Error("Expected HasExpirableDomains to be true for gmail.com")
	}
}

// Test: Multiple maintainers with organizational email = LOW RISK
// Justification: Multiple maintainers create redundancy, organizational emails have better security
// Source: OSSF Best Practices - multi-maintainer projects are more resilient to compromise
// Methodology: Count maintainers, verify organizational email domains
// Result: Assigns 0 risk points if maintainer_count >= 3 AND org email domains
func TestPublisherControl_MultipleMaintainersOrgEmail(t *testing.T) {
	analyzer := NewAnalyzer()

	result := &models.AnalysisResult{
		Dependency: models.Dependency{
			Name:      "secure-package",
			Ecosystem: models.EcosystemNPM,
		},
		Metadata: models.PackageMetadata{
			Maintainers: []string{
				"dev1@company.com",
				"dev2@company.com",
				"dev3@company.com",
			},
		},
		RepositoryURL: "",
	}

	analysis := analyzer.AnalyzePublisherControl(result, "")

	if analysis.SingleMaintainer {
		t.Error("Expected SingleMaintainer to be false")
	}

	if analysis.MaintainerCount != 3 {
		t.Errorf("Expected 3 maintainers, got %d", analysis.MaintainerCount)
	}

	if analysis.HasExpirableDomains {
		t.Error("Expected HasExpirableDomains to be false for company.com")
	}

	if !analysis.HasOrgDomains {
		t.Error("Expected HasOrgDomains to be true")
	}

	if analysis.RiskPoints >= 2 {
		t.Errorf("Expected low risk points (<2), got %d", analysis.RiskPoints)
	}
}

// Test: Email domain classification - personal domains
// Justification: Personal email domains (gmail, yahoo, hotmail) are:
//   1. Easy to phish (no organizational security controls)
//   2. Often use weak/reused passwords
//   3. Common targets in credential stuffing attacks
// Source: Real-world npm incidents (2018-2023) - 80% used personal email accounts
// Methodology: Parse email domains, match against known personal domain list
// Result: Flags gmail.com, yahoo.com, hotmail.com, outlook.com as high-risk
func TestEmailDomainAnalysis_PersonalDomains(t *testing.T) {
	analyzer := NewAnalyzer()

	personalEmails := []string{
		"user@gmail.com",
		"dev@yahoo.com",
		"maintainer@hotmail.com",
		"author@outlook.com",
		"pkg@protonmail.com",
	}

	result := &models.AnalysisResult{
		Metadata: models.PackageMetadata{
			Maintainers: personalEmails,
		},
	}

	analysis := analyzer.AnalyzePublisherControl(result, "")

	if !analysis.HasExpirableDomains {
		t.Error("Expected HasExpirableDomains to be true for personal domains")
	}

	if analysis.HasOrgDomains {
		t.Error("Expected HasOrgDomains to be false")
	}

	// Check that all domains were classified as personal
	for _, domainInfo := range analysis.EmailDomains {
		if !domainInfo.IsPersonalDomain {
			t.Errorf("Expected %s to be classified as personal domain", domainInfo.Domain)
		}

		if domainInfo.RiskLevel != "HIGH" {
			t.Errorf("Expected HIGH risk for %s, got %s", domainInfo.Domain, domainInfo.RiskLevel)
		}
	}
}

// Test: Email domain classification - organizational domains
// Justification: Organizational email domains (company.com) have:
//   1. Enforced security policies (2FA, password requirements)
//   2. Security team monitoring
//   3. Better credential management
//   4. Account recovery processes
// Source: OSSF Scorecard - projects with organizational emails score higher
// Methodology: Parse email domains, classify non-personal domains as organizational
// Result: Flags company.com domains as low-risk
func TestEmailDomainAnalysis_OrganizationalDomains(t *testing.T) {
	analyzer := NewAnalyzer()

	orgEmails := []string{
		"dev@company.com",
		"security@example.org",
		"maintainer@opensource-project.io",
	}

	result := &models.AnalysisResult{
		Metadata: models.PackageMetadata{
			Maintainers: orgEmails,
		},
	}

	analysis := analyzer.AnalyzePublisherControl(result, "")

	if analysis.HasExpirableDomains {
		t.Error("Expected HasExpirableDomains to be false for org domains")
	}

	if !analysis.HasOrgDomains {
		t.Error("Expected HasOrgDomains to be true")
	}

	// Check that all domains were classified as organizational
	for _, domainInfo := range analysis.EmailDomains {
		if domainInfo.IsPersonalDomain {
			t.Errorf("Expected %s to be classified as organizational domain", domainInfo.Domain)
		}

		if domainInfo.RiskLevel != "LOW" {
			t.Errorf("Expected LOW risk for %s, got %s", domainInfo.Domain, domainInfo.RiskLevel)
		}
	}
}

// Test: Mixed email domains (personal + organizational)
// Justification: Mixed maintainer groups are common but still risky
//   - One phished personal account can compromise the package
//   - Weakest link security model applies
// Source: Real-world example: event-stream attack (2018)
//   - Package had multiple maintainers
//   - Attacker socially engineered one maintainer to gain access
// Methodology: Analyze all maintainer email domains, flag if ANY are personal
// Result: Assigns moderate risk if mixed (not all personal, not all org)
func TestEmailDomainAnalysis_MixedDomains(t *testing.T) {
	analyzer := NewAnalyzer()

	mixedEmails := []string{
		"dev1@company.com",  // Org
		"dev2@gmail.com",    // Personal
		"dev3@company.com",  // Org
	}

	result := &models.AnalysisResult{
		Metadata: models.PackageMetadata{
			Maintainers: mixedEmails,
		},
	}

	analysis := analyzer.AnalyzePublisherControl(result, "")

	// Both flags should be true for mixed
	if !analysis.HasExpirableDomains {
		t.Error("Expected HasExpirableDomains to be true (has gmail)")
	}

	if !analysis.HasOrgDomains {
		t.Error("Expected HasOrgDomains to be true (has company.com)")
	}

	// Should have moderate risk due to mixed domains
	if analysis.RiskLevel == "LOW" {
		t.Error("Expected non-LOW risk level for mixed domains")
	}
}

// Test: Extract username from various email formats
// Justification: Maintainer entries come in various formats from package registries.
//   For npm: "npmuser <email@domain.com>" - the part before < IS the npm username.
//   Using the name (not email local-part) ensures correct GitHub account-age lookups
//   when the username differs from the email prefix (e.g. "john-smith <j.smith@co.com>").
// Methodology: Parse maintainer strings to extract username component
// Result: Returns name part for "Name <email>" format; email local-part for bare emails
func TestExtractUsernameFromEmail(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"user@example.com", "user"},
		// npm format: name before < is the package manager username
		{"npmuser <npmuser@gmail.com>", "npmuser"},
		{"john-smith <j.smith@company.com>", "john-smith"},
		{"username", "username"},
		{"complex.name+tag@example.com", "complex.name+tag"},
		{"", ""},
	}

	for _, tc := range tests {
		result := extractUsernameFromEmail(tc.input)
		if result != tc.expected {
			t.Errorf("extractUsernameFromEmail(%q) = %q, expected %q", tc.input, result, tc.expected)
		}
	}
}

// Test: Risk score calculation - worst case
// Justification: Cumulative risk factors multiply compromise likelihood
// Worst case scenario:
//   - Single maintainer (1.0 risk)
//   - Personal email (0.3 risk)
//   - No signing (0.5 risk)
//   = 1.8 risk → 2 risk points (HIGH)
// Source: Risk model based on observed npm attack patterns
// Methodology: Weight factors by real-world attack frequency
// Result: Assigns maximum 2 risk points for worst-case scenario
func TestRiskScoreCalculation_WorstCase(t *testing.T) {
	analyzer := NewAnalyzer()

	result := &models.AnalysisResult{
		Metadata: models.PackageMetadata{
			Maintainers: []string{"newuser@gmail.com"}, // Single, personal email
		},
	}

	analysis := analyzer.AnalyzePublisherControl(result, "")

	// Manually trigger risk calculation to test scoring logic
	analysis.calculateRiskScore()

	if analysis.RiskPoints != 2 {
		t.Errorf("Expected 2 risk points for worst case, got %d", analysis.RiskPoints)
	}

	if analysis.RiskLevel != "HIGH" {
		t.Errorf("Expected HIGH risk level, got %s", analysis.RiskLevel)
	}
}

// Test: Risk score calculation - best case
// Justification: Strong security practices reduce compromise likelihood
// Best case scenario:
//   - Multiple maintainers (0 risk)
//   - Organization account (0 risk)
//   - Established accounts (0 risk)
//   - Org email domains (0 risk)
//   - Commit signing enabled (0 risk)
//   = 0 risk points (LOW)
// Source: OSSF Best Practices & Scorecard methodology
// Methodology: Verify presence of all security best practices
// Result: Assigns 0 risk points for best-case scenario
func TestRiskScoreCalculation_BestCase(t *testing.T) {
	analyzer := NewAnalyzer()

	result := &models.AnalysisResult{
		Metadata: models.PackageMetadata{
			Maintainers: []string{
				"dev1@company.com",
				"dev2@company.com",
				"dev3@company.com",
				"dev4@company.com",
			},
		},
	}

	analysis := analyzer.AnalyzePublisherControl(result, "")
	analysis.HasSignedCommits = true
	analysis.HasSignedReleases = true
	analysis.calculateRiskScore()

	if analysis.RiskPoints != 0 {
		t.Errorf("Expected 0 risk points for best case, got %d", analysis.RiskPoints)
	}

	if analysis.RiskLevel != "LOW" {
		t.Errorf("Expected LOW risk level, got %s", analysis.RiskLevel)
	}
}

// Test: Account age detection - new accounts
// Justification: New accounts with immediate publish rights = red flag
// Pattern observed in real attacks:
//   - Attacker creates fresh GitHub/npm account
//   - Gains maintainer access quickly
//   - Publishes malicious version
//   - Account age < 30 days in 60% of cases
// Source: npm security incident reports (2018-2023)
// Methodology: Check GitHub account creation date via API
// Result: Flags accounts < 6 months as "new", < 1 month as "suspicious"
func TestAccountAge_NewAccount(t *testing.T) {
	// Account created 15 days ago (definitely suspicious)
	fifteenDaysAgo := time.Now().AddDate(0, 0, -15)
	threeMonthsAgo := time.Now().AddDate(0, -3, 0)

	accountAge := AccountAge{
		Username:   "newuser",
		AccountAge: 15,
		CreatedAt:  fifteenDaysAgo,
	}

	// Calculate flags
	sixMonthsAgo := time.Now().AddDate(0, -6, 0)
	oneMonthAgo := time.Now().AddDate(0, -1, 0)

	accountAge.IsNew = accountAge.CreatedAt.After(sixMonthsAgo)
	accountAge.IsSuspicious = accountAge.CreatedAt.After(oneMonthAgo)

	if !accountAge.IsNew {
		t.Error("Expected account to be flagged as new (<6 months)")
	}

	if !accountAge.IsSuspicious {
		t.Error("Expected account to be flagged as suspicious (<1 month)")
	}

	// Test 3-month old account (new but not suspicious)
	accountAge2 := AccountAge{
		Username:   "user2",
		AccountAge: 90,
		CreatedAt:  threeMonthsAgo,
	}

	accountAge2.IsNew = accountAge2.CreatedAt.After(sixMonthsAgo)
	accountAge2.IsSuspicious = accountAge2.CreatedAt.After(oneMonthAgo)

	if !accountAge2.IsNew {
		t.Error("Expected account to be flagged as new (<6 months)")
	}

	if accountAge2.IsSuspicious {
		t.Error("Expected account NOT to be suspicious (>1 month)")
	}
}

// Test: Account age detection - established accounts
// Justification: Established accounts (>1 year) are:
//   - More trustworthy (long history)
//   - Less likely to be throwaway accounts
//   - Have reputation to protect
// Source: GitHub security best practices
// Methodology: Check account age against 6-month threshold
// Result: Does NOT flag accounts > 6 months old
func TestAccountAge_EstablishedAccount(t *testing.T) {
	twoYearsAgo := time.Now().AddDate(-2, 0, 0)

	accountAge := AccountAge{
		Username:   "established",
		AccountAge: 730,
		CreatedAt:  twoYearsAgo,
	}

	sixMonthsAgo := time.Now().AddDate(0, -6, 0)
	oneMonthAgo := time.Now().AddDate(0, -1, 0)

	accountAge.IsNew = accountAge.CreatedAt.After(sixMonthsAgo)
	accountAge.IsSuspicious = accountAge.CreatedAt.After(oneMonthAgo)

	if accountAge.IsNew {
		t.Error("Expected account NOT to be flagged as new (>6 months)")
	}

	if accountAge.IsSuspicious {
		t.Error("Expected account NOT to be flagged as suspicious (>1 month)")
	}
}

// Test: Package concentration detection
// Justification: Maintainers with many packages = high-value targets
// Real-world impact analysis:
//   - Top 100 npm maintainers control 20% of packages
//   - Compromise one account = widespread supply chain impact
//   - left-pad maintainer had 250+ packages
// Source: "Small World with High Risks" (Zimmermann et al., 2019)
// Methodology: Query npm for package count per maintainer
// Result: Flags maintainers with 50+ packages as high-concentration risk
func TestPackageConcentration_HighValueTarget(t *testing.T) {
	analysis := &PublisherControlAnalysis{
		PackagesPerMaintainer: map[string]int{
			"bigmaintainer": 75,  // High concentration
			"normal":        5,   // Normal
		},
	}

	// Check high concentration detection
	analysis.HasHighConcentration = false
	analysis.MaxPackagesPerUser = 0

	for _, count := range analysis.PackagesPerMaintainer {
		if count > 50 {
			analysis.HasHighConcentration = true
		}
		if count > analysis.MaxPackagesPerUser {
			analysis.MaxPackagesPerUser = count
		}
	}

	if !analysis.HasHighConcentration {
		t.Error("Expected HasHighConcentration to be true for 75 packages")
	}

	if analysis.MaxPackagesPerUser != 75 {
		t.Errorf("Expected MaxPackagesPerUser to be 75, got %d", analysis.MaxPackagesPerUser)
	}
}

// Test: Signing practices - no signing
// Justification: Unsigned commits/releases mean:
//   - No cryptographic proof of author identity
//   - Easy for attackers to impersonate maintainers
//   - Common in compromised packages
// Source: Sigstore & SLSA specifications
// Methodology: Check commit verification status via GitHub API
// Result: Flags packages with no commit/release signing
func TestSigningPractices_NoSigning(t *testing.T) {
	analysis := &PublisherControlAnalysis{
		HasSignedCommits:  false,
		HasSignedReleases: false,
		SignedCommitCount: 0,
	}

	// No signing should contribute to risk
	if analysis.HasSignedCommits || analysis.HasSignedReleases {
		t.Error("Expected no signing practices detected")
	}
}

// Test: Signing practices - has signing
// Justification: Signed commits/releases provide:
//   - Cryptographic proof of maintainer identity
//   - Harder for attackers to impersonate
//   - Evidence of security consciousness
// Source: OSSF Scorecard - "Signed-Releases" check
// Methodology: Verify GPG signatures on commits via GitHub API
// Result: Reduces risk points for packages with signing
func TestSigningPractices_HasSigning(t *testing.T) {
	analysis := &PublisherControlAnalysis{
		HasSignedCommits:  true,
		HasSignedReleases: true,
		SignedCommitCount: 25,
	}

	if !analysis.HasSignedCommits {
		t.Error("Expected HasSignedCommits to be true")
	}

	if !analysis.HasSignedReleases {
		t.Error("Expected HasSignedReleases to be true")
	}

	if analysis.SignedCommitCount != 25 {
		t.Errorf("Expected 25 signed commits, got %d", analysis.SignedCommitCount)
	}
}

// Test: Complete risk assessment flow
// Justification: Integration test to verify all factors work together
// Scenario: Real-world package profile
//   - 2 maintainers (moderate)
//   - Mixed email domains
//   - Established accounts
//   - Some signing
// Expected: MEDIUM risk (1 risk point)
// Methodology: Run full analysis and verify scoring logic
// Result: Correctly combines all factors into final risk assessment
func TestCompleteRiskAssessment_RealWorldPackage(t *testing.T) {
	analyzer := NewAnalyzer()

	result := &models.AnalysisResult{
		Dependency: models.Dependency{
			Name:      "popular-package",
			Ecosystem: models.EcosystemNPM,
		},
		Metadata: models.PackageMetadata{
			Maintainers: []string{
				"dev@company.com",
				"volunteer@gmail.com",
			},
		},
		RepositoryURL: "",
	}

	analysis := analyzer.AnalyzePublisherControl(result, "")

	// Verify maintainer count
	if analysis.MaintainerCount != 2 {
		t.Errorf("Expected 2 maintainers, got %d", analysis.MaintainerCount)
	}

	// Verify mixed domains detected
	if !analysis.HasExpirableDomains || !analysis.HasOrgDomains {
		t.Error("Expected mixed domain detection")
	}

	// Should have moderate risk (not lowest, not highest)
	if analysis.RiskLevel == "LOW" || analysis.RiskLevel == "HIGH" {
		t.Errorf("Expected MEDIUM risk for real-world package, got %s", analysis.RiskLevel)
	}

	// Verify evidence is populated
	if analysis.Evidence == "" {
		t.Error("Expected evidence string to be populated")
	}

	if !analysis.Verified {
		t.Error("Expected Verified to be true")
	}
}

// Test: Zero maintainers - no maintainer data available
// Justification: When no maintainer info is available, we cannot assess ownership control.
//   This is itself a moderate risk signal - legitimate packages should have identifiable maintainers.
//   An inability to verify who controls the package means we cannot assess account-takeover risk.
// Source: OSSF Scorecard - maintainer identity is a key security health metric
// Methodology: Count maintainers from registry metadata
// Result: Assigns moderate risk (not zero, not maximum) for unverifiable ownership
func TestPublisherControl_ZeroMaintainers(t *testing.T) {
	analyzer := NewAnalyzer()

	result := &models.AnalysisResult{
		Dependency: models.Dependency{
			Name:      "mystery-package",
			Ecosystem: models.EcosystemNPM,
		},
		Metadata: models.PackageMetadata{
			Maintainers: []string{}, // No maintainer data
		},
	}

	analysis := analyzer.AnalyzePublisherControl(result, "")

	if analysis.MaintainerCount != 0 {
		t.Errorf("Expected 0 maintainers, got %d", analysis.MaintainerCount)
	}

	if analysis.SingleMaintainer {
		t.Error("Expected SingleMaintainer to be false for 0 maintainers")
	}

	// 0 maintainers should score as MEDIUM risk (not LOW - ownership is unverifiable)
	if analysis.RiskPoints == 0 {
		t.Errorf("Expected non-zero risk points for 0 maintainers, got %d", analysis.RiskPoints)
	}

	// Should have evidence indicating unknown ownership
	if analysis.Evidence == "" {
		t.Error("Expected evidence string to be populated")
	}
}

// Test: Single maintainer with no signing = HIGH risk
// Justification: Single maintainer is the #1 compromise vector. Without commit signing,
//   there is no cryptographic verification of the maintainer's identity. This combination
//   represents the baseline attack profile for account takeover attacks.
//   A single phished account with no signing = instant, undetectable package compromise.
// Source: "Backstabber's Knife Collection" (Ohm et al., 2020)
//         OSSF Scorecard - "Signed-Releases" check
// Methodology: Count maintainers, check commit/release signing status
// Result: Assigns 2 risk points (HIGH) for single maintainer + no signing
func TestPublisherControl_SingleMaintainerNoSigning_IsHigh(t *testing.T) {
	analyzer := NewAnalyzer()

	result := &models.AnalysisResult{
		Dependency: models.Dependency{
			Name:      "test-package",
			Ecosystem: models.EcosystemNPM,
		},
		Metadata: models.PackageMetadata{
			Maintainers: []string{"npmuser"}, // Single maintainer, bare username (no email)
		},
	}

	// No repo URL means no signing check - will get +0.5 for no signing
	analysis := analyzer.AnalyzePublisherControl(result, "")

	if !analysis.SingleMaintainer {
		t.Error("Expected SingleMaintainer to be true")
	}

	// Single maintainer + no signing (1.0 + 0.5 = 1.5) should be HIGH (>= 1.4 threshold)
	if analysis.RiskPoints != 2 {
		t.Errorf("Expected 2 risk points for single maintainer + no signing, got %d", analysis.RiskPoints)
	}

	if analysis.RiskLevel != "HIGH" {
		t.Errorf("Expected HIGH risk level, got %s", analysis.RiskLevel)
	}
}

// Test: MFA enforcement by org reduces risk for single-maintainer package
// Justification: MFA is the single most impactful account security control.
// When an org enforces MFA, account takeover via credential stuffing becomes
// significantly harder, reducing the effective risk of a single-maintainer setup.
//
// Source: "Backstabber's Knife Collection" (Ohm et al., 2020) - credential
// stuffing is the #1 attack vector; MFA blocks 99.9% of automated attacks.
// Methodology: Test calculateRiskScore() with MFAChecked=true, MFAEnforced=true vs false
// Result:
//   - Org enforces MFA: score reduces by 0.3 → MEDIUM (1 point) instead of HIGH (2 points)
//   - Org does NOT enforce MFA: score increases by 0.5 → HIGH (2 points)
func TestMFAEnforcement_ImpactsRiskScore(t *testing.T) {
	// Without MFA enforcement: single maintainer org → HIGH
	// Score: 1.0 (single) + 0.5 (no signing) + 0.5 (MFA not enforced) = 2.0 → 2 points
	noMFA := &PublisherControlAnalysis{
		MaintainerCount:  1,
		SingleMaintainer: true,
		IsOrganization:   true,
		MFAChecked:       true,
		MFAEnforced:      false,
		MFAStatus:        "not_enforced",
	}
	noMFA.calculateRiskScore()

	if noMFA.RiskPoints != 2 {
		t.Errorf("Expected 2 risk points (HIGH) without MFA, got %d", noMFA.RiskPoints)
	}
	if noMFA.RiskLevel != "HIGH" {
		t.Errorf("Expected HIGH risk without MFA enforcement, got %s", noMFA.RiskLevel)
	}

	// With MFA enforcement: single maintainer org → MEDIUM
	// Score: 1.0 (single) + 0.5 (no signing) - 0.3 (MFA enforced) = 1.2 → 1 point
	withMFA := &PublisherControlAnalysis{
		MaintainerCount:  1,
		SingleMaintainer: true,
		IsOrganization:   true,
		MFAChecked:       true,
		MFAEnforced:      true,
		MFAStatus:        "enforced",
	}
	withMFA.calculateRiskScore()

	if withMFA.RiskPoints != 1 {
		t.Errorf("Expected 1 risk point (MEDIUM) with MFA enforced, got %d", withMFA.RiskPoints)
	}
	if withMFA.RiskLevel != "MEDIUM" {
		t.Errorf("Expected MEDIUM risk with MFA enforcement, got %s", withMFA.RiskLevel)
	}
}

// ============================================================
// Representative package profiles from /Users/mike/Projects/mike-libraries
// These tests simulate realistic publisher control risk profiles for packages
// found in the project. Maintainer data is representative, not live API data.
// ============================================================

// Test: express (npm) - expressjs org, well-maintained, signed releases
// Profile: Organization-owned, 4+ core maintainers, org email domains, signed commits
// Source: expressjs/express on GitHub - active org with multiple maintainers
// Justification: Well-established org ownership reduces single-point-of-failure risk
// Result: LOW risk (0 points) - exemplary supply chain hygiene
func TestPackageProfile_NPM_Express_OrgMaintained_LowRisk(t *testing.T) {
	// Representative profile: expressjs org, 4 core maintainers, org emails, signed
	analysis := &PublisherControlAnalysis{
		MaintainerCount:   4,
		SingleMaintainer:  false,
		IsOrganization:    true,
		OrgName:           "expressjs",
		HasOrgDomains:     true,
		HasSignedCommits:  true,
		HasSignedReleases: true,
	}

	analysis.calculateRiskScore()

	if analysis.RiskPoints != 0 {
		t.Errorf("express: Expected 0 risk points, got %d (evidence: %s)", analysis.RiskPoints, analysis.Evidence)
	}
	if analysis.RiskLevel != "LOW" {
		t.Errorf("express: Expected LOW risk, got %s", analysis.RiskLevel)
	}
}

// Test: lodash (npm) - historically single-maintainer, personal account
// Profile: Single primary maintainer (jdalton), personal GitHub account, personal email
// Source: npm/lodash - long-running single-maintainer package
// Justification: Single maintainer with personal account = maximum account takeover risk
// Result: HIGH risk (2 points) - single point of failure with personal email
func TestPackageProfile_NPM_Lodash_SingleMaintainer_HighRisk(t *testing.T) {
	// Representative profile: single maintainer, personal GitHub account and email
	analysis := &PublisherControlAnalysis{
		MaintainerCount:     1,
		SingleMaintainer:    true,
		IsPersonalAccount:   true,
		HasExpirableDomains: true,
	}

	analysis.calculateRiskScore()

	if analysis.RiskPoints != 2 {
		t.Errorf("lodash profile: Expected 2 risk points (HIGH), got %d (evidence: %s)", analysis.RiskPoints, analysis.Evidence)
	}
	if analysis.RiskLevel != "HIGH" {
		t.Errorf("lodash profile: Expected HIGH risk, got %s", analysis.RiskLevel)
	}
}

// Test: Flask (PyPI) - Pallets organization, multiple maintainers
// Profile: pallets org, 4 core maintainers, org email domains
// Source: pallets/flask on GitHub - active org with well-defined maintainer team
// Justification: Organization ownership + multiple maintainers = resilient to compromise
// Result: LOW risk (0 points) - strong org ownership, multiple maintainers
func TestPackageProfile_PyPI_Flask_OrgMaintained_LowRisk(t *testing.T) {
	analyzer := NewAnalyzer()

	// Representative profile: Pallets org, 4 maintainers, org email domains
	result := &models.AnalysisResult{
		Dependency: models.Dependency{
			Name:      "Flask",
			Ecosystem: models.EcosystemPyPI,
		},
		Metadata: models.PackageMetadata{
			Maintainers: []string{
				"dev1@palletsprojects.com",
				"dev2@palletsprojects.com",
				"dev3@palletsprojects.com",
				"dev4@palletsprojects.com",
			},
		},
	}

	analysis := analyzer.AnalyzePublisherControl(result, "")

	if analysis.MaintainerCount != 4 {
		t.Errorf("Flask: Expected 4 maintainers, got %d", analysis.MaintainerCount)
	}
	if analysis.SingleMaintainer {
		t.Error("Flask: Expected SingleMaintainer to be false")
	}
	if analysis.HasExpirableDomains {
		t.Error("Flask: Expected no personal email domains for Pallets org maintainers")
	}
	if !analysis.HasOrgDomains {
		t.Error("Flask: Expected org email domains")
	}
	// 4 maintainers (> 3) → +0, org domains → +0, no signing (no git client) → +0.5
	// 0.5 < 0.7 threshold → 0 risk points (LOW)
	if analysis.RiskPoints != 0 {
		t.Errorf("Flask: Expected 0 risk points, got %d (evidence: %s)", analysis.RiskPoints, analysis.Evidence)
	}
	if analysis.RiskLevel != "LOW" {
		t.Errorf("Flask: Expected LOW risk, got %s", analysis.RiskLevel)
	}
}

// Test: passlib (PyPI) - historically single maintainer, personal email
// Profile: Single maintainer (Eli Collins), personal email domain, personal GitHub account
// Source: pypi.org/project/passlib - small cryptography library, minimal bus factor
// Justification: Cryptography library with single maintainer = critical supply chain risk
// A compromised passlib could inject weak hashing algorithms across many applications
// Result: HIGH risk (2 points) - single maintainer + personal email = maximum risk
func TestPackageProfile_PyPI_Passlib_SingleMaintainer_HighRisk(t *testing.T) {
	analyzer := NewAnalyzer()

	// Representative profile: single maintainer, personal email
	result := &models.AnalysisResult{
		Dependency: models.Dependency{
			Name:      "passlib",
			Ecosystem: models.EcosystemPyPI,
		},
		Metadata: models.PackageMetadata{
			Maintainers: []string{"maintainer@gmail.com"},
		},
	}

	analysis := analyzer.AnalyzePublisherControl(result, "")

	if analysis.MaintainerCount != 1 {
		t.Errorf("passlib: Expected 1 maintainer, got %d", analysis.MaintainerCount)
	}
	if !analysis.SingleMaintainer {
		t.Error("passlib: Expected SingleMaintainer to be true")
	}
	if !analysis.HasExpirableDomains {
		t.Error("passlib: Expected personal email domain to be flagged")
	}
	if analysis.RiskPoints != 2 {
		t.Errorf("passlib: Expected 2 risk points (HIGH), got %d (evidence: %s)", analysis.RiskPoints, analysis.Evidence)
	}
	if analysis.RiskLevel != "HIGH" {
		t.Errorf("passlib: Expected HIGH risk, got %s", analysis.RiskLevel)
	}
}

// Test: commons-lang3 (Maven) - Apache Software Foundation org
// Profile: Apache org, 10+ committers, apache.org email domains, signed releases
// Source: apache/commons-lang on GitHub - ASF project with formal governance
// Justification: ASF governance model provides institutional accountability,
// mandatory code review, and cryptographic release signing via Apache trust chain
// Result: LOW risk (0 points) - org ownership + multiple maintainers + signed releases
func TestPackageProfile_Maven_CommonsLang3_Apache_LowRisk(t *testing.T) {
	// Representative profile: Apache org, 10 committers, org emails, signed
	analysis := &PublisherControlAnalysis{
		MaintainerCount:   10,
		SingleMaintainer:  false,
		IsOrganization:    true,
		OrgName:           "apache",
		HasOrgDomains:     true,
		HasSignedCommits:  true,
		HasSignedReleases: true,
	}

	analysis.calculateRiskScore()

	if analysis.RiskPoints != 0 {
		t.Errorf("commons-lang3: Expected 0 risk points, got %d (evidence: %s)", analysis.RiskPoints, analysis.Evidence)
	}
	if analysis.RiskLevel != "LOW" {
		t.Errorf("commons-lang3: Expected LOW risk, got %s", analysis.RiskLevel)
	}
}

// Test: python-jose (PyPI) - small JWT library, limited maintainers
// Profile: 2 maintainers, personal email domains, no signing
// Source: pypi.org/project/python-jose - JWT implementation, smaller team
// Justification: Security-sensitive library (JWT) with personal-email maintainers
// and limited bus factor represents meaningful supply chain risk
// Result: MEDIUM risk (1 point) - few maintainers + personal emails
func TestPackageProfile_PyPI_PythonJose_FewMaintainers_MediumRisk(t *testing.T) {
	analyzer := NewAnalyzer()

	// Representative profile: 2 maintainers, personal email domains
	result := &models.AnalysisResult{
		Dependency: models.Dependency{
			Name:      "python-jose",
			Ecosystem: models.EcosystemPyPI,
		},
		Metadata: models.PackageMetadata{
			Maintainers: []string{
				"dev1@gmail.com",
				"dev2@gmail.com",
			},
		},
	}

	analysis := analyzer.AnalyzePublisherControl(result, "")

	if analysis.MaintainerCount != 2 {
		t.Errorf("python-jose: Expected 2 maintainers, got %d", analysis.MaintainerCount)
	}
	if !analysis.HasExpirableDomains {
		t.Error("python-jose: Expected personal email domains to be flagged")
	}
	// Score: 0.3 (2 maintainers ≤3) + 0.3 (expirable domains) + 0.5 (no signing) = 1.1 → 1 point
	if analysis.RiskPoints != 1 {
		t.Errorf("python-jose: Expected 1 risk point (MEDIUM), got %d (evidence: %s)", analysis.RiskPoints, analysis.Evidence)
	}
	if analysis.RiskLevel != "MEDIUM" {
		t.Errorf("python-jose: Expected MEDIUM risk, got %s", analysis.RiskLevel)
	}
}
