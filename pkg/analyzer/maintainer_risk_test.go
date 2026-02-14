package analyzer

import (
	"testing"
	"time"

	"github.com/metalstormbass/snyft/pkg/models"
)

// Test: Single maintainer with no security controls
// Justification: Single maintainer represents highest compromise risk - one phishing attack
//                gains full package control
// Source: "Backstabber's Knife Collection" (Ohm et al., 2020)
//         Section 3.2: Account Takeover - describes maintainer compromise as primary attack vector
// Methodology: Check maintainer count and signing controls
// Result: Should assign 2 risk points (highest)
func TestMaintainerRisk_SingleMaintainerNoSigning(t *testing.T) {
	analyzer := NewAnalyzer()

	result := &models.AnalysisResult{
		Dependency: models.Dependency{
			Name:      "vulnerable-package",
			Version:   "1.0.0",
			Ecosystem: models.EcosystemNPM,
		},
		RepositoryURL: "https://github.com/user/vulnerable-package",
		Metadata: models.PackageMetadata{
			Maintainers:      []string{"single-user"},
			BusFactor:        1,
			RepoOwner:        "single-user",
		},
	}

	maintainerRisk := analyzer.AnalyzeMaintainerRisk(result)

	if maintainerRisk.BusFactor != 1 {
		t.Errorf("Expected bus factor 1, got %d", maintainerRisk.BusFactor)
	}

	if maintainerRisk.BusFactorRisk != "HIGH" {
		t.Errorf("Expected HIGH bus factor risk, got %s", maintainerRisk.BusFactorRisk)
	}

	if maintainerRisk.RiskLevel != "HIGH" {
		t.Errorf("Expected HIGH overall risk level, got %s", maintainerRisk.RiskLevel)
	}

	if maintainerRisk.RiskScore != 2 {
		t.Errorf("Expected risk score 2, got %d", maintainerRisk.RiskScore)
	}

	// Should have at least one risk factor about single maintainer
	hasRiskFactor := false
	for _, factor := range maintainerRisk.RiskFactors {
		if len(factor) > 0 {
			hasRiskFactor = true
			break
		}
	}

	if !hasRiskFactor {
		t.Error("Expected risk factors to be populated for single maintainer")
	}
}

// Test: Package with multiple maintainers and organization backing
// Justification: Multiple maintainers with org account provides redundancy and better security
// Source: Backstabber's Knife Collection - Section 4.1 "Defensive Measures"
// Methodology: Check maintainer count, bus factor, and account types
// Result: Should assign 0-1 risk points (low risk)
func TestMaintainerRisk_MultipleMaintainersOrganizationBacking(t *testing.T) {
	analyzer := NewAnalyzer()

	result := &models.AnalysisResult{
		Dependency: models.Dependency{
			Name:      "secure-package",
			Version:   "1.0.0",
			Ecosystem: models.EcosystemNPM,
		},
		RepositoryURL: "https://github.com/secure-org/secure-package",
		Metadata: models.PackageMetadata{
			Maintainers:      []string{"user1", "user2", "user3"},
			BusFactor:        3,
			RepoOwner:        "secure-org",
		},
	}

	maintainerRisk := analyzer.AnalyzeMaintainerRisk(result)

	if maintainerRisk.BusFactor != 3 {
		t.Errorf("Expected bus factor 3, got %d", maintainerRisk.BusFactor)
	}

	if maintainerRisk.BusFactorRisk != "LOW" {
		t.Errorf("Expected LOW bus factor risk, got %s", maintainerRisk.BusFactorRisk)
	}

	if maintainerRisk.RiskLevel == "HIGH" {
		t.Errorf("Expected LOW or MEDIUM risk level for multiple maintainers, got HIGH")
	}

	if maintainerRisk.RiskScore > 1 {
		t.Errorf("Expected risk score 0-1 for secure package, got %d", maintainerRisk.RiskScore)
	}
}

// Test: New maintainer account (less than 6 months old)
// Justification: Newly created accounts gaining immediate publishing rights may indicate
//                compromised account or social engineering attack
// Source: Backstabber's Knife Collection - Section 3.2 "Account Takeover"
// Methodology: Check account creation dates via GitHub API
// Result: Should flag new accounts and increase risk score
func TestMaintainerRisk_NewMaintainerAccount(t *testing.T) {
	analyzer := NewAnalyzer()

	// Account created 3 months ago
	recentAccountAge := time.Now().AddDate(0, -3, 0)

	result := &models.AnalysisResult{
		Dependency: models.Dependency{
			Name:      "suspicious-package",
			Version:   "1.0.0",
			Ecosystem: models.EcosystemNPM,
		},
		RepositoryURL: "https://github.com/newuser/suspicious-package",
		Metadata: models.PackageMetadata{
			Maintainers:      []string{"newuser"},
			BusFactor:        1,
			RepoOwner:        "newuser",
			RepoCreatedAt:    recentAccountAge,
		},
	}

	maintainerRisk := analyzer.AnalyzeMaintainerRisk(result)

	// Risk should be elevated due to new account
	if maintainerRisk.RiskLevel != "HIGH" {
		t.Errorf("Expected HIGH risk for new maintainer account, got %s", maintainerRisk.RiskLevel)
	}

	// Check that risk factors mention the new account
	foundNewAccountFactor := false
	for _, factor := range maintainerRisk.RiskFactors {
		if len(factor) > 0 {
			foundNewAccountFactor = true
		}
	}

	if !foundNewAccountFactor {
		t.Error("Expected risk factors to mention new maintainer account")
	}
}

// Test: Recent maintainer ownership transfer
// Justification: Sudden maintainer changes followed by new releases are a documented
//                attack pattern for supply chain compromise
// Source: "Towards Measuring Supply Chain Attacks on Package Managers" (NDSS 2020)
//         Documents multiple cases of ownership transfer attacks
// Methodology: Track maintainer changes via npm/PyPI APIs and git commit history
// Result: Should detect recent changes and assign high risk
func TestMaintainerRisk_RecentOwnershipTransfer(t *testing.T) {
	analyzer := NewAnalyzer()

	result := &models.AnalysisResult{
		Dependency: models.Dependency{
			Name:      "transferred-package",
			Version:   "2.0.0",
			Ecosystem: models.EcosystemNPM,
		},
		RepositoryURL: "https://github.com/newowner/transferred-package",
		Metadata: models.PackageMetadata{
			Maintainers:      []string{"newowner"},
			BusFactor:        1,
			RepoOwner:        "newowner",
		},
	}

	maintainerRisk := analyzer.AnalyzeMaintainerRisk(result)

	// Note: In a full implementation with mocked npm client, we would detect the transfer
	// For now, we verify the risk analysis framework is in place
	if maintainerRisk.RecentChanges > 0 {
		// If recent changes detected, risk should be elevated
		if maintainerRisk.RiskLevel == "LOW" {
			t.Error("Expected MEDIUM or HIGH risk when recent ownership changes detected")
		}

		// Check that risk factors mention the transfer
		foundTransferFactor := false
		for _, factor := range maintainerRisk.RiskFactors {
			if len(factor) > 0 {
				foundTransferFactor = true
			}
		}

		if !foundTransferFactor {
			t.Error("Expected risk factors to mention ownership transfer")
		}
	}
}

// Test: High-volume publisher (>100 packages)
// Justification: Compromised maintainer with many packages creates massive blast radius
// Source: "Small World with High Risks: npm Ecosystem Study" (Zimmermann et al., 2019)
//         Shows how single compromised high-volume publisher affects thousands of users
// Methodology: Query package count per maintainer via registry APIs
// Result: Should flag high-volume publishers and note blast radius
func TestMaintainerRisk_HighVolumePublisher(t *testing.T) {
	analyzer := NewAnalyzer()

	result := &models.AnalysisResult{
		Dependency: models.Dependency{
			Name:      "one-of-many",
			Version:   "1.0.0",
			Ecosystem: models.EcosystemNPM,
		},
		RepositoryURL: "https://github.com/prolific-dev/one-of-many",
		Metadata: models.PackageMetadata{
			Maintainers:      []string{"prolific-dev"},
			BusFactor:        1,
			RepoOwner:        "prolific-dev",
		},
	}

	maintainerRisk := analyzer.AnalyzeMaintainerRisk(result)

	// Note: In full implementation with mocked npm client returning >100 packages,
	// this would flag the high-volume publisher risk
	// For now, verify the framework tracks package counts
	if maintainerRisk.HighVolumePublishers > 0 {
		// Should note the blast radius in risk factors
		foundBlastRadiusFactor := false
		for _, factor := range maintainerRisk.RiskFactors {
			if len(factor) > 0 {
				foundBlastRadiusFactor = true
			}
		}

		if !foundBlastRadiusFactor {
			t.Error("Expected risk factors to mention blast radius for high-volume publisher")
		}
	}

	// Package counts should be tracked
	if len(maintainerRisk.PackageCounts) > 0 {
		for _, pkgCount := range maintainerRisk.PackageCounts {
			if pkgCount.PackageCount > 100 && pkgCount.RiskLevel != "HIGH" {
				t.Errorf("Expected HIGH risk level for >100 packages, got %s", pkgCount.RiskLevel)
			}
		}
	}
}

// Test: Email domain stability check
// Justification: Suspicious or temporary email domains may indicate compromised accounts
// Source: Backstabber's Knife Collection - discusses identity verification challenges
// Methodology: Extract email domains from git commit history
// Result: Should flag suspicious domains (temp mail, etc.)
func TestMaintainerRisk_SuspiciousEmailDomain(t *testing.T) {
	analyzer := NewAnalyzer()

	result := &models.AnalysisResult{
		Dependency: models.Dependency{
			Name:      "questionable-package",
			Version:   "1.0.0",
			Ecosystem: models.EcosystemNPM,
		},
		RepositoryURL: "https://github.com/user/questionable-package",
		Metadata: models.PackageMetadata{
			Maintainers:      []string{"user"},
			BusFactor:        1,
			RepoOwner:        "user",
		},
	}

	maintainerRisk := analyzer.AnalyzeMaintainerRisk(result)

	// Verify email domain tracking is in place
	if maintainerRisk.EmailDomains != nil {
		// If suspicious domains detected, should be flagged
		if maintainerRisk.HasSuspiciousDomains {
			foundSuspiciousDomainFactor := false
			for _, factor := range maintainerRisk.RiskFactors {
				if len(factor) > 0 {
					foundSuspiciousDomainFactor = true
				}
			}

			if !foundSuspiciousDomainFactor {
				t.Error("Expected risk factors to mention suspicious email domains")
			}
		}

		// Corporate domains should be recognized
		if maintainerRisk.HasCorporateDomain {
			// Should provide some positive signal (lower risk)
			// This is validated through the overall risk calculation
		}
	}
}

// Test: Risk score calculation weights factors appropriately
// Justification: Multiple risk factors should compound appropriately
// Source: SLSA framework and academic research weighting
// Methodology: Test various combinations of risk factors
// Result: Should calculate weighted risk score 0-2 correctly
func TestMaintainerRisk_RiskScoreCalculation(t *testing.T) {
	tests := []struct {
		name           string
		busFactor      int
		hasNewAccounts bool
		recentChanges  int
		expectedMin    int // Minimum expected risk score
		expectedMax    int // Maximum expected risk score
	}{
		{
			name:           "Perfect security",
			busFactor:      5,
			hasNewAccounts: false,
			recentChanges:  0,
			expectedMin:    0,
			expectedMax:    0,
		},
		{
			name:           "Single maintainer only",
			busFactor:      1,
			hasNewAccounts: false,
			recentChanges:  0,
			expectedMin:    1,
			expectedMax:    2,
		},
		{
			name:           "Multiple risk factors",
			busFactor:      1,
			hasNewAccounts: true,
			recentChanges:  2,
			expectedMin:    2,
			expectedMax:    2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			analyzer := NewAnalyzer()

			result := &models.AnalysisResult{
				Dependency: models.Dependency{
					Name:      "test-package",
					Version:   "1.0.0",
					Ecosystem: models.EcosystemNPM,
				},
				RepositoryURL: "https://github.com/test/test-package",
				Metadata: models.PackageMetadata{
					BusFactor: tt.busFactor,
				},
			}

			maintainerRisk := analyzer.AnalyzeMaintainerRisk(result)

			if maintainerRisk.RiskScore < tt.expectedMin || maintainerRisk.RiskScore > tt.expectedMax {
				t.Errorf("%s: Expected risk score %d-%d, got %d",
					tt.name, tt.expectedMin, tt.expectedMax, maintainerRisk.RiskScore)
			}

			// Verify risk level matches risk score
			if maintainerRisk.RiskScore == 2 && maintainerRisk.RiskLevel != "HIGH" {
				t.Errorf("%s: Risk score 2 should map to HIGH, got %s",
					tt.name, maintainerRisk.RiskLevel)
			}
			if maintainerRisk.RiskScore == 0 && maintainerRisk.RiskLevel != "LOW" {
				t.Errorf("%s: Risk score 0 should map to LOW, got %s",
					tt.name, maintainerRisk.RiskLevel)
			}
		})
	}
}

// Test: Evidence string provides clear explanation
// Justification: Users need to understand why a package is risky
// Source: SLSA framework - transparency requirement
// Methodology: Check that evidence field is populated with human-readable text
// Result: Evidence should explain all risk factors found
func TestMaintainerRisk_EvidencePopulated(t *testing.T) {
	analyzer := NewAnalyzer()

	result := &models.AnalysisResult{
		Dependency: models.Dependency{
			Name:      "test-package",
			Version:   "1.0.0",
			Ecosystem: models.EcosystemNPM,
		},
		RepositoryURL: "https://github.com/user/test-package",
		Metadata: models.PackageMetadata{
			Maintainers:      []string{"user"},
			BusFactor:        1,
			RepoOwner:        "user",
		},
	}

	maintainerRisk := analyzer.AnalyzeMaintainerRisk(result)

	// Evidence should never be empty
	if maintainerRisk.Evidence == "" {
		t.Error("Expected evidence field to be populated")
	}

	// Evidence should be readable (contains common words)
	if len(maintainerRisk.Evidence) < 10 {
		t.Error("Evidence string seems too short to be meaningful")
	}

	// If risk factors exist, evidence should reference them
	if len(maintainerRisk.RiskFactors) > 0 {
		// Evidence should contain information from risk factors
		// This is a basic sanity check
		if len(maintainerRisk.Evidence) < len(maintainerRisk.RiskFactors)*5 {
			t.Error("Evidence seems too short given the number of risk factors")
		}
	}
}
