package analyzer

import (
	"fmt"
	"strings"
	"time"

	"github.com/metalstormbass/snyft/pkg/models"
)

// MaintainerRiskAnalysis contains detailed maintainer risk assessment
// Test: Enhanced maintainer risk scoring
// Justification: Maintainer account compromise is the primary attack vector for supply chain attacks.
//                Single points of failure, new accounts, and high package counts indicate elevated risk.
// Source: "Backstabber's Knife Collection: A Review of Open Source Software Supply Chain Attacks"
//         (Ohm et al., 2020) - https://arxiv.org/abs/2005.09535
//         Section 3.2: "Account Takeover" - describes how attackers compromise maintainer accounts
//         via phishing, credential stuffing, or social engineering to inject malicious code
// Methodology: Multi-factor maintainer assessment across 6 dimensions
type MaintainerRiskAnalysis struct {
	// Bus Factor: Number of maintainers needed for 50% of development
	// Risk: bus_factor=1 means single point of failure
	BusFactor          int                    `json:"bus_factor"`
	BusFactorRisk      string                 `json:"bus_factor_risk"`      // HIGH, MEDIUM, LOW

	// Account Type: Organization vs Personal accounts
	// Risk: Personal accounts easier to compromise than org accounts with 2FA
	AccountTypes       []MaintainerAccountType `json:"account_types"`
	HasOrgAccount      bool                   `json:"has_org_account"`
	AllPersonalAccounts bool                  `json:"all_personal_accounts"`

	// Account Age: How long have maintainer accounts existed
	// Risk: New accounts (<6 months) may indicate fresh account takeover
	MaintainerAges     []MaintainerAge        `json:"maintainer_ages"`
	HasNewMaintainers  bool                   `json:"has_new_maintainers"`   // Any maintainer <6 months old
	AverageAccountAge  float64                `json:"average_account_age"`   // In years

	// Recent Changes: Maintainer turnover in last 90 days
	// Risk: Sudden maintainer changes may indicate hostile takeover
	RecentChanges      int                    `json:"recent_changes"`
	RecentAdditions    []string               `json:"recent_additions"`
	RecentRemovals     []string               `json:"recent_removals"`

	// Email Domain Stability: Maintainer email domain consistency
	// Risk: Mixed or suspicious domains (temp email, free providers for critical packages)
	EmailDomains       map[string]int         `json:"email_domains"`         // domain -> count
	HasCorporateDomain bool                   `json:"has_corporate_domain"`
	HasSuspiciousDomains bool                 `json:"has_suspicious_domains"`

	// Packages Per Maintainer: Number of packages each maintainer publishes
	// Risk: Compromised maintainer with many packages = large blast radius
	PackageCounts      []MaintainerPackageCount `json:"package_counts"`
	HighVolumePublishers int                   `json:"high_volume_publishers"` // Maintainers with >50 packages

	// Overall Risk Assessment
	RiskScore          int                    `json:"risk_score"`            // 0-2 (0=best, 2=worst)
	RiskLevel          string                 `json:"risk_level"`            // LOW, MEDIUM, HIGH
	RiskFactors        []string               `json:"risk_factors"`
	Evidence           string                 `json:"evidence"`
}

// MaintainerAccountType describes the account type of a maintainer
type MaintainerAccountType struct {
	Username    string `json:"username"`
	AccountType string `json:"account_type"` // "organization", "user"
	Platform    string `json:"platform"`     // "github", "npm", "pypi"
}

// MaintainerAge describes how long a maintainer account has existed
type MaintainerAge struct {
	Username   string    `json:"username"`
	CreatedAt  time.Time `json:"created_at"`
	AgeYears   float64   `json:"age_years"`
	Platform   string    `json:"platform"`
}

// MaintainerPackageCount describes how many packages a maintainer publishes
type MaintainerPackageCount struct {
	Username     string `json:"username"`
	PackageCount int    `json:"package_count"`
	Platform     string `json:"platform"`
	RiskLevel    string `json:"risk_level"` // HIGH (>100), MEDIUM (50-100), LOW (<50)
}

// AnalyzeMaintainerRisk performs comprehensive maintainer risk assessment
// This implements the 30% weight enhancement to Category 1 (Publisher Control)
func (a *Analyzer) AnalyzeMaintainerRisk(result *models.AnalysisResult) *MaintainerRiskAnalysis {
	analysis := &MaintainerRiskAnalysis{
		AccountTypes:    []MaintainerAccountType{},
		MaintainerAges:  []MaintainerAge{},
		PackageCounts:   []MaintainerPackageCount{},
		EmailDomains:    make(map[string]int),
		RiskFactors:     []string{},
	}

	// 1. Check Bus Factor (from existing health metrics)
	analysis.BusFactor = result.Metadata.BusFactor
	if analysis.BusFactor == 0 {
		// Fallback to maintainer count
		analysis.BusFactor = len(result.Metadata.Maintainers)
	}

	if analysis.BusFactor == 1 {
		analysis.BusFactorRisk = "HIGH"
		analysis.RiskFactors = append(analysis.RiskFactors, "Single maintainer (bus factor=1)")
	} else if analysis.BusFactor == 2 {
		analysis.BusFactorRisk = "MEDIUM"
		analysis.RiskFactors = append(analysis.RiskFactors, "Only 2 maintainers (limited redundancy)")
	} else if analysis.BusFactor >= 3 {
		analysis.BusFactorRisk = "LOW"
	}

	// 2. Check Organization vs Personal Accounts
	if result.RepositoryURL != "" {
		a.analyzeAccountTypes(result, analysis)
	}

	// 3. Check Maintainer Account Ages
	if result.RepositoryURL != "" {
		a.analyzeMaintainerAges(result, analysis)
	}

	// 4. Check Recent Maintainer Changes (leverage existing ownership change detection)
	a.analyzeRecentMaintainerChanges(result, analysis)

	// 5. Check Email Domain Stability
	a.analyzeEmailDomains(result, analysis)

	// 6. Check Packages Per Maintainer
	a.analyzePackagesPerMaintainer(result, analysis)

	// Calculate overall risk score based on accumulated factors
	analysis.calculateRiskScore()

	return analysis
}

// analyzeAccountTypes checks if maintainers are organizations or personal accounts
// Justification: Organization accounts typically have better security controls (2FA enforcement,
//                audit logs, multiple admins) compared to personal accounts
// Source: Backstabber's Knife Collection - Section 4.1 "Defensive Measures"
func (a *Analyzer) analyzeAccountTypes(result *models.AnalysisResult, analysis *MaintainerRiskAnalysis) {
	gitClient := a.getGitClient(result.RepositoryURL)

	// Check repository owner type
	if result.Metadata.RepoOwner != "" {
		accountType := gitClient.GetAccountType(result.RepositoryURL, result.Metadata.RepoOwner)
		analysis.AccountTypes = append(analysis.AccountTypes, MaintainerAccountType{
			Username:    result.Metadata.RepoOwner,
			AccountType: accountType,
			Platform:    "github",
		})

		if accountType == "organization" {
			analysis.HasOrgAccount = true
		}
	}

	// Check if all accounts are personal
	personalCount := 0
	for _, acct := range analysis.AccountTypes {
		if acct.AccountType == "user" {
			personalCount++
		}
	}

	analysis.AllPersonalAccounts = (personalCount == len(analysis.AccountTypes) && len(analysis.AccountTypes) > 0)

	if analysis.AllPersonalAccounts {
		analysis.RiskFactors = append(analysis.RiskFactors, "All personal accounts (easier to compromise)")
	} else if analysis.HasOrgAccount {
		// Positive signal - org accounts have better security
		analysis.RiskFactors = append(analysis.RiskFactors, "Organization account (stronger security controls)")
	}
}

// analyzeMaintainerAges checks how long maintainer accounts have existed
// Justification: Newly created accounts that immediately gain package control may indicate
//                account takeover or social engineering attacks
// Source: Backstabber's Knife Collection - Section 3.2 "Account Takeover"
//         "Attackers create new accounts or compromise existing ones to gain publishing rights"
func (a *Analyzer) analyzeMaintainerAges(result *models.AnalysisResult, analysis *MaintainerRiskAnalysis) {
	gitClient := a.getGitClient(result.RepositoryURL)

	// Check repository owner account age
	if result.Metadata.RepoOwner != "" {
		createdAt := gitClient.GetAccountCreationDate(result.RepositoryURL, result.Metadata.RepoOwner)
		if !createdAt.IsZero() {
			ageYears := time.Since(createdAt).Hours() / 24 / 365
			analysis.MaintainerAges = append(analysis.MaintainerAges, MaintainerAge{
				Username:  result.Metadata.RepoOwner,
				CreatedAt: createdAt,
				AgeYears:  ageYears,
				Platform:  "github",
			})

			// Flag accounts less than 6 months old as concerning
			if ageYears < 0.5 {
				analysis.HasNewMaintainers = true
				analysis.RiskFactors = append(analysis.RiskFactors,
					fmt.Sprintf("New maintainer account: %s (%.1f months old)",
						result.Metadata.RepoOwner, ageYears*12))
			}
		}
	}

	// Calculate average account age
	if len(analysis.MaintainerAges) > 0 {
		totalAge := 0.0
		for _, age := range analysis.MaintainerAges {
			totalAge += age.AgeYears
		}
		analysis.AverageAccountAge = totalAge / float64(len(analysis.MaintainerAges))

		// Very young average age is concerning
		if analysis.AverageAccountAge < 1.0 {
			analysis.RiskFactors = append(analysis.RiskFactors,
				fmt.Sprintf("Low average account age (%.1f years)", analysis.AverageAccountAge))
		}
	}
}

// analyzeRecentMaintainerChanges detects maintainer turnover in last 90 days
// Justification: Sudden maintainer changes, especially combined with immediate releases,
//                are a common attack pattern
// Source: "Towards Measuring Supply Chain Attacks on Package Managers for Interpreted Languages"
//         (NDSS 2020) - Documents multiple cases where attackers gained maintainer access
//         and immediately pushed malicious updates
func (a *Analyzer) analyzeRecentMaintainerChanges(result *models.AnalysisResult, analysis *MaintainerRiskAnalysis) {
	gitClient := a.getGitClient(result.RepositoryURL)
	if gitClient == nil || result.RepositoryURL == "" {
		return
	}

	// Get commit author changes (reuse existing logic)
	commitStats, err := gitClient.GetCommitAuthors(result.RepositoryURL)
	if err != nil || commitStats == nil {
		return
	}

	// Detect new authors in last 90 days
	if len(commitStats.RecentAuthors) > 0 && len(commitStats.HistoricalAuthors) > 0 {
		historicalSet := make(map[string]bool)
		for _, author := range commitStats.HistoricalAuthors {
			historicalSet[author] = true
		}

		for _, author := range commitStats.RecentAuthors {
			if !historicalSet[author] {
				analysis.RecentAdditions = append(analysis.RecentAdditions, author)
				analysis.RecentChanges++
			}
		}

		// High turnover is suspicious
		if analysis.RecentChanges >= 2 {
			analysis.RiskFactors = append(analysis.RiskFactors,
				fmt.Sprintf("%d new maintainers in last 90 days", analysis.RecentChanges))
		}
	}

	// Check npm/pypi ownership history for more detailed tracking
	switch result.Dependency.Ecosystem {
	case models.EcosystemNPM:
		npmHistory, err := a.npmClient.GetOwnershipHistory(result.Dependency.Name)
		if err == nil && npmHistory != nil && npmHistory.RecentTransfer {
			analysis.RecentChanges++
			analysis.RiskFactors = append(analysis.RiskFactors, "Recent npm ownership transfer")
		}

	case models.EcosystemPyPI:
		pypiHistory, err := a.pypiClient.GetOwnershipHistory(result.Dependency.Name)
		if err == nil && pypiHistory != nil && pypiHistory.RecentTransfer {
			analysis.RecentChanges++
			analysis.RiskFactors = append(analysis.RiskFactors, "Recent PyPI ownership transfer")
		}
	}
}

// analyzeEmailDomains checks maintainer email domain stability and legitimacy
// Justification: Email domains reveal maintainer identity verification. Corporate domains
//                indicate organizational backing. Temporary/disposable email domains or
//                inconsistent domains may indicate compromised or suspicious accounts.
// Source: Backstabber's Knife Collection - discusses identity verification challenges
//         in package ecosystems and lack of maintainer authentication
func (a *Analyzer) analyzeEmailDomains(result *models.AnalysisResult, analysis *MaintainerRiskAnalysis) {
	gitClient := a.getGitClient(result.RepositoryURL)
	if gitClient == nil || result.RepositoryURL == "" {
		return
	}

	// Get maintainer email domains from recent commits
	commitStats, err := gitClient.GetCommitAuthors(result.RepositoryURL)
	if err != nil || commitStats == nil {
		return
	}

	// Extract domains from commit author emails
	for email := range commitStats.AuthorEmails {
		domain := extractEmailDomain(email)
		if domain != "" {
			analysis.EmailDomains[domain]++

			// Check for corporate domains
			if isCorporateDomain(domain) {
				analysis.HasCorporateDomain = true
			}

			// Check for suspicious domains
			if isSuspiciousDomain(domain) {
				analysis.HasSuspiciousDomains = true
			}
		}
	}

	// Multiple unrelated domains may indicate instability
	if len(analysis.EmailDomains) > 3 && !analysis.HasCorporateDomain {
		analysis.RiskFactors = append(analysis.RiskFactors,
			fmt.Sprintf("Many different email domains (%d), no corporate backing", len(analysis.EmailDomains)))
	}

	if analysis.HasSuspiciousDomains {
		analysis.RiskFactors = append(analysis.RiskFactors, "Suspicious email domains detected")
	}
}

// analyzePackagesPerMaintainer checks how many packages each maintainer publishes
// Justification: Compromised maintainer with many packages creates large blast radius.
//                High-volume publishers (>100 packages) are attractive targets for attackers.
// Source: "Small World with High Risks: A Study of Security Threats in the npm Ecosystem"
//         (Zimmermann et al., 2019) - Analyzes impact of compromised maintainers with
//         multiple popular packages. A single compromise can affect thousands of downstream users.
func (a *Analyzer) analyzePackagesPerMaintainer(result *models.AnalysisResult, analysis *MaintainerRiskAnalysis) {
	// Check ecosystem-specific package counts
	switch result.Dependency.Ecosystem {
	case models.EcosystemNPM:
		for _, maintainer := range result.Metadata.Maintainers {
			count, err := a.npmClient.GetMaintainerPackageCount(maintainer)
			if err == nil {
				riskLevel := "LOW"
				if count > 100 {
					riskLevel = "HIGH"
					analysis.HighVolumePublishers++
				} else if count > 50 {
					riskLevel = "MEDIUM"
				}

				analysis.PackageCounts = append(analysis.PackageCounts, MaintainerPackageCount{
					Username:     maintainer,
					PackageCount: count,
					Platform:     "npm",
					RiskLevel:    riskLevel,
				})
			}
		}

	case models.EcosystemPyPI:
		for _, maintainer := range result.Metadata.Maintainers {
			count, err := a.pypiClient.GetMaintainerPackageCount(maintainer)
			if err == nil {
				riskLevel := "LOW"
				if count > 100 {
					riskLevel = "HIGH"
					analysis.HighVolumePublishers++
				} else if count > 50 {
					riskLevel = "MEDIUM"
				}

				analysis.PackageCounts = append(analysis.PackageCounts, MaintainerPackageCount{
					Username:     maintainer,
					PackageCount: count,
					Platform:     "pypi",
					RiskLevel:    riskLevel,
				})
			}
		}
	}

	if analysis.HighVolumePublishers > 0 {
		analysis.RiskFactors = append(analysis.RiskFactors,
			fmt.Sprintf("%d high-volume publishers (>100 packages) - large blast radius if compromised",
				analysis.HighVolumePublishers))
	}
}

// calculateRiskScore computes final 0-2 risk score based on accumulated factors
func (m *MaintainerRiskAnalysis) calculateRiskScore() {
	riskPoints := 0

	// Bus factor contributes heavily
	if m.BusFactor == 1 {
		riskPoints += 2
	} else if m.BusFactor == 2 {
		riskPoints += 1
	}

	// All personal accounts
	if m.AllPersonalAccounts {
		riskPoints += 1
	}

	// New maintainers
	if m.HasNewMaintainers {
		riskPoints += 2
	}

	// Recent ownership changes
	if m.RecentChanges >= 2 {
		riskPoints += 2
	} else if m.RecentChanges == 1 {
		riskPoints += 1
	}

	// Suspicious email domains
	if m.HasSuspiciousDomains {
		riskPoints += 1
	}

	// High-volume publishers increase blast radius
	if m.HighVolumePublishers > 0 {
		riskPoints += 1
	}

	// Cap at 2 for the category score
	if riskPoints > 2 {
		m.RiskScore = 2
		m.RiskLevel = "HIGH"
	} else if riskPoints == 2 {
		m.RiskScore = 2
		m.RiskLevel = "HIGH"
	} else if riskPoints == 1 {
		m.RiskScore = 1
		m.RiskLevel = "MEDIUM"
	} else {
		m.RiskScore = 0
		m.RiskLevel = "LOW"
	}

	// Build evidence summary
	m.Evidence = strings.Join(m.RiskFactors, "; ")
	if m.Evidence == "" {
		m.Evidence = "No significant maintainer risk factors detected"
	}
}

// Helper functions

func extractEmailDomain(email string) string {
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(parts[1]))
}

func isCorporateDomain(domain string) bool {
	// Known corporate/trusted domains
	corporateDomains := map[string]bool{
		"google.com":    true,
		"microsoft.com": true,
		"facebook.com":  true,
		"meta.com":      true,
		"amazon.com":    true,
		"apple.com":     true,
		"ibm.com":       true,
		"oracle.com":    true,
		"redhat.com":    true,
		"mozilla.org":   true,
		"cloudflare.com": true,
		"github.com":    true,
		"gitlab.com":    true,
	}

	return corporateDomains[domain]
}

func isSuspiciousDomain(domain string) bool {
	// Suspicious/temporary email domains
	suspiciousDomains := map[string]bool{
		"tempmail.com":     true,
		"guerrillamail.com": true,
		"10minutemail.com": true,
		"throwaway.email":  true,
		"temp-mail.org":    true,
		"mailinator.com":   true,
		"maildrop.cc":      true,
	}

	// Also check for generic free providers for critical packages
	// (not necessarily suspicious, but worth noting)
	freeProviders := map[string]bool{
		"gmail.com":   false, // Common but legitimate
		"yahoo.com":   false,
		"hotmail.com": false,
		"outlook.com": false,
	}

	if suspiciousDomains[domain] {
		return true
	}

	// Free providers are only suspicious if combined with other factors
	_ = freeProviders

	return false
}
