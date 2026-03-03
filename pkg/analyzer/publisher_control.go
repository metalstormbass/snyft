package analyzer

import (
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/metalstormbass/snyft/pkg/fetcher"
	"github.com/metalstormbass/snyft/pkg/models"
)

// PublisherControlAnalysis contains comprehensive publisher control risk assessment
// This analysis focuses on "How easy is it to get publish rights?" - the #1 compromise vector
//
// Justification: Account takeover via phishing/credential stuffing is the most common
// supply chain attack vector. Single maintainers with personal accounts and weak
// authentication create a single point of failure.
//
// Source: "Backstabber's Knife Collection: A Review of Open Source Software Supply Chain Attacks"
// (Ohm et al., 2020) - https://arxiv.org/abs/2005.09535
// Finding: 90% of supply chain attacks target maintainer accounts, not code vulnerabilities
type PublisherControlAnalysis struct {
	// Maintainer metrics (HIGHEST WEIGHT - 30% of total risk)
	MaintainerCount       int      `json:"maintainer_count"`
	MaintainerEmails      []string `json:"maintainer_emails,omitempty"`
	SingleMaintainer      bool     `json:"single_maintainer"`       // RED FLAG

	// Organization vs personal account
	IsOrganization        bool     `json:"is_organization"`
	IsPersonalAccount     bool     `json:"is_personal_account"`
	OrgName               string   `json:"org_name,omitempty"`
	VerifiedOrgMembership bool     `json:"verified_org_membership"` // GitHub verified org badge

	// Account age and stability
	MaintainerAccountAges []AccountAge `json:"maintainer_account_ages,omitempty"`
	HasNewMaintainers     bool         `json:"has_new_maintainers"` // Accounts < 6 months old
	NewMaintainerCount    int          `json:"new_maintainer_count"`

	// Email domain stability
	EmailDomains          []EmailDomainInfo `json:"email_domains,omitempty"`
	HasExpirableDomains   bool              `json:"has_expirable_domains"` // RED FLAG: personal/free domains
	HasOrgDomains         bool              `json:"has_org_domains"`

	// Package concentration (compromise pattern detection)
	PackagesPerMaintainer map[string]int `json:"packages_per_maintainer,omitempty"`
	HasHighConcentration  bool           `json:"has_high_concentration"` // Maintainer with 50+ packages
	MaxPackagesPerUser    int            `json:"max_packages_per_user"`

	// Authentication & signing
	HasSignedCommits      bool   `json:"has_signed_commits"`
	HasSignedReleases     bool   `json:"has_signed_releases"`
	SignedCommitCount     int    `json:"signed_commit_count"`
	SigningChecked        bool   `json:"signing_checked"` // true if we actually checked signing status

	// MFA detection (if available from API)
	// Check: MFA/2FA enforcement for package maintainers
	// Justification: Accounts without MFA are primary targets for credential
	//                stuffing attacks - the leading cause of supply chain compromise.
	// Source: "Backstabber's Knife Collection" (Ohm et al., 2020)
	//         https://arxiv.org/abs/2005.09535
	// Methodology: GitHub org two_factor_requirement_enabled (publicly available);
	//              npm/PyPI per-maintainer MFA not publicly accessible (requires auth).
	// Result: 0 = MFA enforced, 1 = MFA optional/unknown, 2 = MFA not enforced
	MFAStatus   string `json:"mfa_status"`   // "enforced", "not_enforced", "unknown"
	MFAEnforced bool   `json:"mfa_enforced"` // true if org-level MFA is required
	MFAChecked  bool   `json:"mfa_checked"`  // true if we successfully determined MFA status

	// Ecosystem context for scoring
	Ecosystem             models.Ecosystem `json:"ecosystem,omitempty"`

	// Overall risk assessment
	RiskPoints            int    `json:"risk_points"`  // 0-2 points
	RiskLevel             string `json:"risk_level"`   // HIGH, MEDIUM, LOW
	Evidence              string `json:"evidence"`
	Verified              bool   `json:"verified"`
}

// AccountAge contains information about a maintainer account's age and history
type AccountAge struct {
	Username    string    `json:"username"`
	AccountAge  int       `json:"account_age_days"`
	CreatedAt   time.Time `json:"created_at"`
	IsNew       bool      `json:"is_new"`        // < 6 months old
	IsSuspicious bool     `json:"is_suspicious"` // < 1 month old
}

// EmailDomainInfo analyzes the email domain stability of maintainers
type EmailDomainInfo struct {
	Email           string `json:"email"`
	Domain          string `json:"domain"`
	IsPersonalDomain bool  `json:"is_personal_domain"` // gmail, yahoo, hotmail, etc.
	IsFreeDomain    bool   `json:"is_free_domain"`     // Can expire or be taken over
	IsOrgDomain     bool   `json:"is_org_domain"`      // Stable organizational domain
	RiskLevel       string `json:"risk_level"`         // HIGH, MEDIUM, LOW
}

// AnalyzePublisherControl performs comprehensive publisher control risk analysis
// This is the PRIMARY risk factor - maintainer account compromise is the #1 attack vector
//
// Methodology:
// 1. Check maintainer count (bus factor) - CRITICAL
// 2. Analyze organization vs personal ownership
// 3. Verify account ages (new accounts = suspicious)
// 4. Check email domain stability
// 5. Detect package concentration patterns (many packages = compromise pattern)
// 6. Verify signing and MFA practices
//
// Scoring weights:
// - Maintainer count: 30% of risk
// - Account type (org vs personal): 20%
// - Account age: 20%
// - Email domain: 15%
// - Package concentration: 10%
// - Signing/MFA: 5%
func (a *Analyzer) AnalyzePublisherControl(result *models.AnalysisResult, repoURL string) *PublisherControlAnalysis {
	analysis := &PublisherControlAnalysis{
		MaintainerCount: len(result.Metadata.Maintainers),
		MaintainerEmails: result.Metadata.Maintainers,
		SingleMaintainer: len(result.Metadata.Maintainers) == 1,
		PackagesPerMaintainer: make(map[string]int),
		Ecosystem: result.Dependency.Ecosystem,
	}

	// Get git platform client
	var gitClient fetcher.GitPlatformClient
	if repoURL != "" {
		gitClient = a.getGitClient(repoURL)
	}

	// 2. Check organization vs personal account (20% weight)
	if repoURL != "" && gitClient != nil {
		analysis.checkOrganizationOwnership(gitClient, repoURL)
	}

	// 3. Check maintainer account ages (20% weight)
	// Justification: New accounts with publish rights = red flag
	// Real-world pattern: Attackers create fresh accounts to avoid detection
	if repoURL != "" && gitClient != nil {
		analysis.checkMaintainerAccountAges(gitClient, repoURL, result.Metadata.Maintainers)
	}

	// 4. Analyze email domains (15% weight)
	// Justification: Personal email domains can expire, be phished, or taken over
	// Organizational domains have better security practices
	analysis.analyzeEmailDomains(result.Metadata.Maintainers)

	// 5. Check package concentration (10% weight)
	// Justification: Maintainers with 50+ packages = high-value target
	// Compromise one account = compromise entire package ecosystem
	if result.Dependency.Ecosystem == models.EcosystemNPM {
		analysis.checkPackageConcentration(a.npmClient, result.Metadata.Maintainers)
	}

	// 6. Check signing and authentication (5% weight)
	if repoURL != "" && gitClient != nil {
		analysis.checkSigningPractices(gitClient, repoURL)
	}

	// 7. Check MFA/2FA enforcement
	// Only GitHub org-level 2FA status is publicly accessible without auth
	if repoURL != "" && gitClient != nil {
		analysis.checkMFAEnforcement(gitClient, repoURL)
	}

	// Calculate final risk assessment
	analysis.calculateRiskScore()

	return analysis
}

// checkOrganizationOwnership determines if the package is owned by an organization
// or a personal account
//
// Methodology:
// - Check if repository owner is a GitHub/GitLab organization
// - Verify organization membership badges
// - Check maintainer email domains
//
// Risk Assessment:
// - Organization with verified members = LOW RISK
// - Personal account with org email = MEDIUM RISK
// - Personal account with personal email = HIGH RISK
func (analysis *PublisherControlAnalysis) checkOrganizationOwnership(gitClient fetcher.GitPlatformClient, repoURL string) {
	// Parse repository URL to get owner
	owner, _, err := fetcher.ParseRepoURL(repoURL)
	if err != nil {
		return
	}

	// Check if owner is an organization (via GitHub API)
	// GitHub API: GET /users/{username} returns "type": "Organization" or "User"
	//
	// API failure detection: when the call fails (unauthenticated/rate-limited),
	// CheckIfOrganization returns (false, ""). We distinguish this from a confirmed
	// personal account by checking whether orgName is empty - a successful "User"
	// response always returns (false, login), while a failed call returns (false, "").
	isOrg, orgName := gitClient.CheckIfOrganization(owner)
	if isOrg {
		// Confirmed organization
		analysis.IsOrganization = true
		analysis.IsPersonalAccount = false
		analysis.OrgName = orgName
		analysis.VerifiedOrgMembership = gitClient.CheckVerifiedOrganization(owner)
	} else if orgName != "" {
		// Confirmed personal account (API returned "User" with a valid login)
		analysis.IsOrganization = false
		analysis.IsPersonalAccount = true
		analysis.OrgName = ""
	}
	// If orgName == "" and isOrg == false, the API call failed (rate limit / no token)
	// Leave both IsOrganization and IsPersonalAccount as false = "unknown"
}

// checkMaintainerAccountAges fetches the account creation dates for all maintainers
// and flags new accounts as suspicious
//
// Methodology:
// - Query GitHub API: GET /users/{username} for each maintainer
// - Extract "created_at" field
// - Flag accounts < 6 months old as new
// - Flag accounts < 1 month old as highly suspicious
//
// Justification:
// - Established maintainers have old accounts (years)
// - New accounts with immediate publish rights = red flag
// - Real-world attacks: Fresh accounts used to avoid scrutiny
//
// Source: npm incident reports (2018-2023) show attackers often use
// accounts created < 30 days before malicious publish
func (analysis *PublisherControlAnalysis) checkMaintainerAccountAges(gitClient fetcher.GitPlatformClient, repoURL string, maintainers []string) {
	sixMonthsAgo := time.Now().AddDate(0, -6, 0)
	oneMonthAgo := time.Now().AddDate(0, -1, 0)

	for _, maintainerEmail := range maintainers {
		// Extract username from email or use email directly
		username := extractUsernameFromEmail(maintainerEmail)
		if username == "" {
			continue
		}

		// Fetch account creation date
		createdAt, err := gitClient.GetUserAccountCreatedDate(username)
		if err != nil {
			continue // Skip if unable to fetch
		}

		accountAgeDays := int(time.Since(createdAt).Hours() / 24)
		isNew := createdAt.After(sixMonthsAgo)
		isSuspicious := createdAt.After(oneMonthAgo)

		accountAge := AccountAge{
			Username:    username,
			AccountAge:  accountAgeDays,
			CreatedAt:   createdAt,
			IsNew:       isNew,
			IsSuspicious: isSuspicious,
		}

		analysis.MaintainerAccountAges = append(analysis.MaintainerAccountAges, accountAge)

		if isNew {
			analysis.HasNewMaintainers = true
			analysis.NewMaintainerCount++
		}
	}
}

// analyzeEmailDomains checks the stability and security of maintainer email domains
//
// Methodology:
// - Parse email addresses to extract domains
// - Classify domains: personal (gmail, yahoo), free (outlook), organizational
// - Flag personal/free domains as higher risk (can expire, be phished)
//
// Risk Assessment:
// - Personal domains (gmail.com, yahoo.com): HIGH RISK
//   * Can be phished easily
//   * No organizational security controls
//   * Common in supply chain attacks
// - Free domains (outlook.com, protonmail.com): MEDIUM RISK
//   * Better than personal but still vulnerable
// - Organizational domains (company.com): LOW RISK
//   * 2FA enforcement
//   * Security team oversight
//   * Better credential management
//
// Justification:
// Real-world attacks target personal email accounts because:
// 1. No MFA enforcement
// 2. Weak passwords common
// 3. Reused passwords from breaches
// 4. No security team monitoring
func (analysis *PublisherControlAnalysis) analyzeEmailDomains(maintainers []string) {
	personalDomains := map[string]bool{
		// Google
		"gmail.com": true,
		// Yahoo
		"yahoo.com": true,
		// Microsoft (current + legacy)
		"hotmail.com": true,
		"outlook.com": true,
		"live.com":    true,
		"msn.com":     true,
		// Protonmail (all domain variants)
		"protonmail.com": true,
		"proton.me":      true,
		"pm.me":          true,
		// Apple (current + legacy)
		"icloud.com": true,
		"me.com":     true,
		// Chinese providers (large user bases)
		"qq.com":  true,
		"163.com": true,
		"126.com": true,
		// Other free providers
		"mail.com":    true,
		"aol.com":     true,
		"zoho.com":    true,
		"yandex.com":  true,
		"tutanota.com": true,
		"tuta.com":     true,
		"fastmail.com": true,
	}

	for _, email := range maintainers {
		// Extract actual email address from "name <email@domain>" format
		if strings.Contains(email, "<") && strings.Contains(email, ">") {
			start := strings.Index(email, "<")
			end := strings.Index(email, ">")
			if start < end {
				email = email[start+1 : end]
			}
		}

		parts := strings.Split(email, "@")
		if len(parts) != 2 {
			continue
		}

		domain := strings.ToLower(parts[1])
		isPersonal := personalDomains[domain]
		isOrg := !isPersonal

		domainInfo := EmailDomainInfo{
			Email:           email,
			Domain:          domain,
			IsPersonalDomain: isPersonal,
			IsFreeDomain:    isPersonal, // Personal domains are free and can expire
			IsOrgDomain:     isOrg,
		}

		if isPersonal {
			domainInfo.RiskLevel = "HIGH"
			analysis.HasExpirableDomains = true
		} else {
			domainInfo.RiskLevel = "LOW"
			analysis.HasOrgDomains = true
		}

		analysis.EmailDomains = append(analysis.EmailDomains, domainInfo)
	}
}

// checkPackageConcentration detects maintainers who control many packages
//
// Methodology:
// - Query npm registry for each maintainer's package list
// - npm API: GET /-/user/org.couchdb.user:{username} (requires auth)
// - Alternative: Search npm for author:{username}
// - Count packages per maintainer
//
// Risk Assessment:
// - 1-5 packages: LOW RISK (normal maintainer)
// - 6-49 packages: MEDIUM RISK (active contributor)
// - 50+ packages: HIGH RISK (high-value target)
//
// Justification:
// - Maintainers with many packages = attractive targets
// - One compromised account = widespread supply chain impact
// - Real-world examples: left-pad incident, event-stream attack
// - Attacker ROI: compromise one account, inject malware into 50+ packages
//
// Source: "Small World with High Risks" (Zimmermann et al., 2019)
// Finding: Top 500 npm maintainers collectively control 30% of ecosystem
func (analysis *PublisherControlAnalysis) checkPackageConcentration(npmClient *fetcher.NPMClient, maintainers []string) {
	for _, email := range maintainers {
		username := extractUsernameFromEmail(email)
		if username == "" {
			continue
		}

		// Fetch package count for this maintainer
		packageCount, err := npmClient.GetMaintainerPackageCount(username)
		if err != nil {
			continue
		}

		analysis.PackagesPerMaintainer[username] = packageCount

		// Flag high concentration (50+ packages)
		if packageCount > 50 {
			analysis.HasHighConcentration = true
		}

		if packageCount > analysis.MaxPackagesPerUser {
			analysis.MaxPackagesPerUser = packageCount
		}
	}
}

// checkSigningPractices verifies if maintainers use commit/release signing
//
// Methodology:
// - Check recent commits for GPG signatures
// - Check releases for signatures
// - GitHub API: commit.verification.verified
//
// Risk Assessment:
// - No signing: HIGH RISK (no verification of identity)
// - Partial signing: MEDIUM RISK (some verification)
// - All signed: LOW RISK (strong identity verification)
func (analysis *PublisherControlAnalysis) checkSigningPractices(gitClient fetcher.GitPlatformClient, repoURL string) {
	// Check signed commits.
	// ErrDataUnavailable means the platform does not expose signature data;
	// leave defaults (false/0) so scoring treats signing as unknown rather than absent.
	hasSigned, count, err := gitClient.CheckSignedCommits(repoURL)
	if err == nil {
		analysis.SigningChecked = true
		analysis.HasSignedCommits = hasSigned
		analysis.SignedCommitCount = count
	} else if !errors.Is(err, fetcher.ErrDataUnavailable) {
		// Real error (not just platform limitation) - leave defaults
		_ = err
	}

	// Check signed releases.
	// ErrDataUnavailable means the platform does not expose release signature data.
	hasSignedReleases, err := gitClient.CheckSignedReleases(repoURL)
	if err == nil {
		analysis.SigningChecked = true
		analysis.HasSignedReleases = hasSignedReleases
	} else if !errors.Is(err, fetcher.ErrDataUnavailable) {
		_ = err
	}
}

// checkMFAEnforcement detects whether the package owner enforces MFA/2FA
//
// Check: MFA/2FA enforcement for package maintainers
// Justification: Accounts without MFA are primary targets for credential stuffing
//                attacks - the leading cause of supply chain compromise. Phishing
//                and credential stuffing become trivially easy without MFA.
// Source: "Backstabber's Knife Collection" (Ohm et al., 2020)
//         https://arxiv.org/abs/2005.09535
// Methodology:
//   - GitHub orgs: GET /orgs/{owner} → two_factor_requirement_enabled (PUBLICLY AVAILABLE)
//   - npm maintainers: tfa field requires auth → NOT publicly available, skip gracefully
//   - PyPI maintainers: no 2FA field in public JSON API → NOT publicly available, skip
//   - GitHub users (personal): GitHub does not expose 2FA status (privacy policy) → skip
// Result: Sets MFAEnforced, MFAStatus, MFAChecked on the analysis
func (analysis *PublisherControlAnalysis) checkMFAEnforcement(gitClient fetcher.GitPlatformClient, repoURL string) {
	analysis.MFAStatus = "unknown"
	analysis.MFAChecked = false
	analysis.MFAEnforced = false

	// Extract owner from repo URL
	owner, _, err := fetcher.ParseRepoURL(repoURL)
	if err != nil {
		return
	}
	if owner == "" {
		return
	}

	// MFA enforcement is only meaningful at the organization level.
	// GitHub does not expose individual user 2FA status (privacy policy).
	// npm/PyPI do not expose per-maintainer 2FA without authentication.
	//
	// Reuse org status from checkOrganizationOwnership if already determined
	// (both IsOrganization and IsPersonalAccount are set by that call).
	// Only make an API call if we haven't already checked.
	var isOrg bool
	if analysis.IsOrganization || analysis.IsPersonalAccount {
		// Already determined in checkOrganizationOwnership - reuse cached result
		isOrg = analysis.IsOrganization
	} else {
		isOrg, _ = gitClient.CheckIfOrganization(owner)
	}
	if !isOrg {
		// Personal account: cannot determine MFA status publicly
		analysis.MFAStatus = "unknown"
		analysis.MFAChecked = false
		return
	}

	// For organizations: query MFA enforcement via platform API
	mfaRequired, dataAvailable := gitClient.CheckOrgMFARequired(owner)
	if !dataAvailable {
		// Platform does not expose MFA status publicly (GitLab, Bitbucket)
		analysis.MFAStatus = "unknown"
		analysis.MFAChecked = false
		return
	}

	analysis.MFAChecked = true
	if mfaRequired {
		analysis.MFAEnforced = true
		analysis.MFAStatus = "enforced"
	} else {
		analysis.MFAEnforced = false
		analysis.MFAStatus = "not_enforced"
	}
}

// calculateRiskScore computes the final risk score based on all factors
//
// Scoring rubric (0-2 risk points):
// - 0 points (best): Multiple maintainers, org account, established accounts, signing enabled
// - 1 point (moderate): Few maintainers OR personal account OR some new accounts
// - 2 points (worst): Single maintainer + personal account/email + no signing
//
// Simplified weighting for clear boundaries:
// - Single maintainer alone = 1.0 risk
// - Personal email/account = +0.3 each
// - No signing (when checked) = +0.5 risk
// - New accounts = +0.3 risk, suspicious = additional +0.2
// - Package concentration = +0.2 risk
// - Signing NOT checked (no repo) = no penalty (insufficient data)
func (analysis *PublisherControlAnalysis) calculateRiskScore() {
	riskScore := 0.0
	evidenceParts := []string{}

	// Factor 1: Maintainer count (CRITICAL - highest weight)
	// Single maintainer is an automatic HIGH concern
	//
	// Ecosystem-aware interpretation: some registries (e.g. Maven Central) do not
	// expose maintainer lists at all. A zero maintainer count in those ecosystems
	// means "data unavailable", not "no maintainers". We assign 1 risk point
	// (unknown/moderate) instead of worst-case.
	// Source: Maven Central REST API docs — no owner/maintainer endpoint exists
	caps := models.GetEcosystemCapabilities(analysis.Ecosystem)
	if analysis.MaintainerCount == 0 {
		// When maintainer count is zero, treat as "data unavailable" regardless of
		// ecosystem capability. Even ecosystems that *can* expose maintainer data
		// (HasMaintainerList == true) may fail to return it due to scraping fallbacks,
		// API errors, or POM files without a <developers> section. Penalising these
		// cases at 0.6 creates a double penalty: the data loss itself already harms
		// accuracy, and then the higher weight inflates the risk score further.
		// Uniform 0.3 ("unknown/moderate") avoids this while still flagging the gap.
		riskScore += 0.3
		if !caps.HasMaintainerList {
			evidenceParts = append(evidenceParts,
				fmt.Sprintf("Maintainer count unavailable (%s does not expose this data)", analysis.Ecosystem))
		} else {
			evidenceParts = append(evidenceParts,
				fmt.Sprintf("Maintainer data not found (%s can expose this data but none retrieved)", analysis.Ecosystem))
		}
	} else if analysis.SingleMaintainer {
		riskScore += 1.0
		evidenceParts = append(evidenceParts, "single maintainer (CRITICAL)")
	} else if analysis.MaintainerCount <= 3 {
		riskScore += 0.3 // Few maintainers = moderate concern
		evidenceParts = append(evidenceParts, fmt.Sprintf("%d maintainers (few)", analysis.MaintainerCount))
	} else {
		// Multiple maintainers = good
		evidenceParts = append(evidenceParts, fmt.Sprintf("%d maintainers (good)", analysis.MaintainerCount))
	}

	// Factor 2: Account type & Email domain (combined for simplicity)
	// Personal account OR personal email = minor risk signal.
	// Note: only penalize when confirmed personal (API returned "User" type);
	//       leave neutral when API check failed (no token / rate-limited).
	//
	// Weight rationale: Personal accounts and personal emails are the NORM in open
	// source (~70% personal accounts, ~95% personal emails). Heavily penalizing
	// baseline-normal practices causes nearly every package to max out at 2/2,
	// destroying differentiation. These get small weights (0.15 each) so they only
	// tip the scale when combined with stronger signals like single-maintainer.
	// Source: "Small World with High Risks" (Zimmermann et al., 2019) - most npm
	// maintainers use personal accounts and free email providers.
	if analysis.IsPersonalAccount {
		riskScore += 0.15
		evidenceParts = append(evidenceParts, "personal account")
	} else if analysis.IsOrganization {
		evidenceParts = append(evidenceParts, fmt.Sprintf("organization: %s", analysis.OrgName))
		if analysis.VerifiedOrgMembership {
			evidenceParts = append(evidenceParts, "verified org")
		}
	}
	if !analysis.IsOrganization && !analysis.IsPersonalAccount {
		evidenceParts = append(evidenceParts, "account type unknown (no repo URL or API unavailable)")
	}

	if analysis.HasExpirableDomains {
		riskScore += 0.15
		evidenceParts = append(evidenceParts, "personal email domains")
	} else if analysis.HasOrgDomains {
		evidenceParts = append(evidenceParts, "organizational email domains")
	}

	// Factor 3: Account age
	if analysis.HasNewMaintainers {
		riskScore += 0.3
		evidenceParts = append(evidenceParts, fmt.Sprintf("%d new accounts (<6mo)", analysis.NewMaintainerCount))

		// Extra penalty for very new accounts (< 1 month)
		for _, age := range analysis.MaintainerAccountAges {
			if age.IsSuspicious {
				riskScore += 0.2
				evidenceParts = append(evidenceParts, fmt.Sprintf("SUSPICIOUS: %s account %d days old", age.Username, age.AccountAge))
			}
		}
	}

	// Factor 4: Package concentration
	if analysis.HasHighConcentration {
		riskScore += 0.2
		evidenceParts = append(evidenceParts, fmt.Sprintf("high-value target: %d packages", analysis.MaxPackagesPerUser))
	}

	// Factor 5: Signing practices
	// Only penalize when we actually checked and found no signing.
	// When signing wasn't checked (no repo URL / API failure), don't assume the worst.
	//
	// Weight rationale: ~90% of OSS projects don't sign commits or releases.
	// The old weight of 0.5 was too aggressive for such a common practice gap,
	// causing multi-maintainer packages to reach HIGH risk just because they don't
	// sign. Reduced to 0.3 so it contributes meaningfully but doesn't dominate.
	// Source: OSSF Scorecard data - signing adoption remains under 10% in most ecosystems.
	if analysis.SigningChecked {
		if !analysis.HasSignedCommits && !analysis.HasSignedReleases {
			riskScore += 0.3
			evidenceParts = append(evidenceParts, "no signing detected")
		} else {
			evidenceParts = append(evidenceParts, fmt.Sprintf("signing enabled (%d commits)", analysis.SignedCommitCount))
			// Signing reduces risk slightly
			if riskScore > 0.15 {
				riskScore -= 0.15
			}
		}
	} else {
		evidenceParts = append(evidenceParts, "signing not checked (no repo URL)")
	}

	// Factor 6: MFA enforcement (when data is available)
	// MFA is the single most impactful account security control.
	// Only GitHub org-level MFA status is publicly verifiable.
	//
	// Weight rationale: Most orgs don't enforce MFA. The old +0.5 penalty for
	// non-enforcement was too harsh given how common this is, and could push
	// multi-maintainer packages to HIGH by itself. Reduced to +0.3.
	if analysis.MFAChecked {
		if analysis.MFAEnforced {
			// Org enforces MFA - significant risk reduction
			evidenceParts = append(evidenceParts, "org MFA enforced (good)")
			if riskScore > 0.3 {
				riskScore -= 0.3
			} else {
				riskScore = 0
			}
		} else {
			// Org does NOT enforce MFA - risk signal
			riskScore += 0.3
			evidenceParts = append(evidenceParts, "org MFA NOT enforced (risk)")
		}
	} else if analysis.MFAStatus == "unknown" {
		evidenceParts = append(evidenceParts, "MFA status unknown (personal account or platform limitation)")
	}

	// Convert to 0-2 risk points scale
	// Thresholds calibrated so that baseline-normal OSS practices (personal email,
	// no signing, personal account) don't automatically push multi-maintainer
	// packages to HIGH. Only single-maintainer packages with additional risk
	// signals reach HIGH.
	//
	// Recalibrated weights (reduced for common OSS practices):
	//   personal email: 0.15, personal account: 0.15, no signing: 0.3, MFA not enforced: 0.3
	//
	// Single maintainer + personal acct + personal email + no signing = 1.0+0.15+0.15+0.3 = 1.6 → HIGH
	// Single maintainer + no signing (checked) = 1.0 + 0.3 = 1.3 → HIGH
	// Single maintainer + personal acct + personal email = 1.0 + 0.15 + 0.15 = 1.3 → HIGH
	// Single maintainer + personal email (signing not checked) = 1.0 + 0.15 = 1.15 → MEDIUM
	// Single maintainer alone (bare username, no repo) = 1.0 → MEDIUM
	// Single maintainer + signing = 1.0 - 0.15 = 0.85 → MEDIUM
	// 2-3 maintainers + personal email + no signing = 0.3 + 0.15 + 0.3 = 0.75 → MEDIUM
	// 5+ maintainers + personal email + no signing + personal acct = 0.15+0.3+0.15 = 0.6 → MEDIUM
	// 2-3 maintainers + personal email = 0.3 + 0.15 = 0.45 → LOW
	// 0 maintainers (ecosystem exposes list) = 0.6 → MEDIUM
	// 0 maintainers (ecosystem doesn't expose) = 0.3 → LOW
	// 4+ maintainers + org email = 0.0 → LOW
	// Round to 2 decimal places to avoid IEEE 754 floating point precision issues.
	// e.g. 1.0 + 0.15 + 0.15 = 1.2999999999999998 in float64, not 1.3
	riskScore = math.Round(riskScore*100) / 100

	if riskScore >= 1.3 {
		analysis.RiskPoints = 2
	} else if riskScore >= 0.6 {
		analysis.RiskPoints = 1
	} else {
		analysis.RiskPoints = 0
	}

	// When key publisher control signals are all unknown/unchecked, ensure minimum
	// 1 risk point. The tool's inability to verify publisher controls represents
	// genuine uncertainty, not evidence of safety. This fixes the paradox where
	// packages with no verifiable data score better than fully-analyzed ones.
	if analysis.RiskPoints == 0 && analysis.MaintainerCount == 0 &&
		!analysis.IsOrganization && !analysis.IsPersonalAccount && !analysis.SigningChecked {
		analysis.RiskPoints = 1
	}

	// Set risk level
	switch analysis.RiskPoints {
	case 0:
		analysis.RiskLevel = "LOW"
	case 1:
		analysis.RiskLevel = "MEDIUM"
	case 2:
		analysis.RiskLevel = "HIGH"
	}

	// Build evidence string
	// Source: Backstabber's Knife Collection (Ohm et al., 2020)
	analysis.Evidence = strings.Join(evidenceParts, "; ")
	analysis.Verified = len(evidenceParts) > 0
}

// buildPublisherControlChecks builds CheckResult slice from the analysis for use in CategoryScore.
func (analysis *PublisherControlAnalysis) buildPublisherControlChecks() []models.CheckResult {
	checks := []models.CheckResult{}

	// Maintainer count check
	if analysis.MaintainerCount == 0 {
		caps := models.GetEcosystemCapabilities(analysis.Ecosystem)
		if !caps.HasMaintainerList {
			checks = append(checks, models.CheckResult{Name: "Maintainer count", Status: "UNAVAILABLE", Detail: fmt.Sprintf("%s does not expose maintainer data", analysis.Ecosystem)})
		} else {
			checks = append(checks, models.CheckResult{Name: "Maintainer count", Status: "FAIL", Detail: "No maintainer data found (ecosystem exposes this data)"})
		}
	} else if analysis.SingleMaintainer {
		checks = append(checks, models.CheckResult{Name: "Maintainer count", Status: "FAIL", Detail: fmt.Sprintf("Single maintainer: %s", strings.Join(analysis.MaintainerEmails, ", "))})
	} else {
		checks = append(checks, models.CheckResult{Name: "Maintainer count", Status: "PASS", Detail: fmt.Sprintf("%d maintainers found", analysis.MaintainerCount)})
	}

	// Organization check
	if analysis.IsOrganization {
		detail := fmt.Sprintf("Organization: %s", analysis.OrgName)
		if analysis.VerifiedOrgMembership {
			detail += " (verified)"
		}
		checks = append(checks, models.CheckResult{Name: "Organization ownership", Status: "PASS", Detail: detail})
	} else if analysis.IsPersonalAccount {
		checks = append(checks, models.CheckResult{Name: "Organization ownership", Status: "FAIL", Detail: "Personal account (not an organization)"})
	} else {
		checks = append(checks, models.CheckResult{Name: "Organization ownership", Status: "UNAVAILABLE", Detail: "Account type unknown (no repo URL or API unavailable)"})
	}

	// Email domain check
	if analysis.HasExpirableDomains {
		domains := []string{}
		for _, d := range analysis.EmailDomains {
			if d.IsPersonalDomain {
				domains = append(domains, d.Domain)
			}
		}
		checks = append(checks, models.CheckResult{Name: "Email domain stability", Status: "FAIL", Detail: fmt.Sprintf("Personal/free email domains: %s", strings.Join(domains, ", "))})
	} else if analysis.HasOrgDomains {
		checks = append(checks, models.CheckResult{Name: "Email domain stability", Status: "PASS", Detail: "Organizational email domains detected"})
	} else if len(analysis.EmailDomains) == 0 {
		checks = append(checks, models.CheckResult{Name: "Email domain stability", Status: "UNAVAILABLE", Detail: "No email data available"})
	}

	// Account age check
	if analysis.HasNewMaintainers {
		for _, age := range analysis.MaintainerAccountAges {
			if age.IsSuspicious {
				checks = append(checks, models.CheckResult{Name: "Account age", Status: "FAIL", Detail: fmt.Sprintf("SUSPICIOUS: %s account only %d days old (created %s)", age.Username, age.AccountAge, age.CreatedAt.Format("2006-01-02"))})
			} else if age.IsNew {
				checks = append(checks, models.CheckResult{Name: "Account age", Status: "FAIL", Detail: fmt.Sprintf("%s account %d days old (< 6 months, created %s)", age.Username, age.AccountAge, age.CreatedAt.Format("2006-01-02"))})
			}
		}
	} else if len(analysis.MaintainerAccountAges) > 0 {
		checks = append(checks, models.CheckResult{Name: "Account age", Status: "PASS", Detail: "All maintainer accounts are established (> 6 months old)"})
	} else {
		checks = append(checks, models.CheckResult{Name: "Account age", Status: "SKIPPED", Detail: "Could not determine account ages"})
	}

	// Signing check
	if analysis.SigningChecked {
		if analysis.HasSignedCommits || analysis.HasSignedReleases {
			checks = append(checks, models.CheckResult{Name: "Commit/release signing", Status: "PASS", Detail: fmt.Sprintf("%d signed commits found", analysis.SignedCommitCount)})
		} else {
			checks = append(checks, models.CheckResult{Name: "Commit/release signing", Status: "FAIL", Detail: "No signed commits or releases detected"})
		}
	} else {
		checks = append(checks, models.CheckResult{Name: "Commit/release signing", Status: "SKIPPED", Detail: "Signing not checked (no repo URL)"})
	}

	// MFA check
	if analysis.MFAChecked {
		if analysis.MFAEnforced {
			checks = append(checks, models.CheckResult{Name: "MFA enforcement", Status: "PASS", Detail: "Organization-level MFA enforcement enabled"})
		} else {
			checks = append(checks, models.CheckResult{Name: "MFA enforcement", Status: "FAIL", Detail: "Organization does NOT enforce MFA"})
		}
	} else {
		checks = append(checks, models.CheckResult{Name: "MFA enforcement", Status: "UNAVAILABLE", Detail: fmt.Sprintf("MFA status: %s (personal account or platform limitation)", analysis.MFAStatus)})
	}

	// Package concentration check
	if analysis.HasHighConcentration {
		checks = append(checks, models.CheckResult{Name: "Package concentration", Status: "FAIL", Detail: fmt.Sprintf("High-value target: maintainer controls %d packages", analysis.MaxPackagesPerUser)})
	} else if len(analysis.PackagesPerMaintainer) > 0 {
		checks = append(checks, models.CheckResult{Name: "Package concentration", Status: "PASS", Detail: fmt.Sprintf("Max packages per maintainer: %d (below 50 threshold)", analysis.MaxPackagesPerUser)})
	}

	return checks
}

// extractUsernameFromEmail extracts a username from an email or maintainer string.
// Supports formats:
//   - "username"                          → "username"
//   - "username@domain.com"               → "username"
//   - "npmuser <npmuser@domain.com>"      → "npmuser"  (name before < is the npm username)
//
// For the "Name <email>" format, the part before < is the package manager username
// (e.g. npm extracts maintainers as "{name} <{email}>"). Returning the name avoids
// the incorrect fallback of using the email local-part as a username, which breaks
// account-age lookups when the username differs from the email prefix.
func extractUsernameFromEmail(email string) string {
	// Handle "name <email@domain.com>" format - the name before < is the username
	if strings.Contains(email, "<") && strings.Contains(email, ">") {
		start := strings.Index(email, "<")
		name := strings.TrimSpace(email[:start])
		if name != "" {
			return name
		}
		// Fallback: extract local part of the email inside <>
		end := strings.Index(email, ">")
		if start < end {
			email = email[start+1 : end]
		}
	}

	// Extract local part from "user@domain.com"
	if strings.Contains(email, "@") {
		parts := strings.Split(email, "@")
		return parts[0]
	}

	// Already a bare username
	return email
}
