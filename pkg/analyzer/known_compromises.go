package analyzer

import (
	"fmt"
	"strings"

	"github.com/metalstormbass/snyft/pkg/models"
)

// KnownCompromise represents a historically documented supply chain attack
// on a specific package. This is NOT a CVE database — these are confirmed
// supply chain compromises where the package distribution itself was hijacked.
type KnownCompromise struct {
	// Package identity
	Name      string
	Ecosystem models.Ecosystem

	// Attack details
	AttackName  string // e.g. "event-stream incident"
	Year        int
	Description string

	// Academic/industry reference
	Reference string
}

// knownCompromises is a static list of historically documented supply chain
// attacks. Each entry represents a confirmed case where a package's
// distribution channel was compromised — the package itself was weaponized.
//
// This is fundamentally different from CVE tracking:
//   - CVEs document vulnerabilities in code (bugs, logic errors)
//   - These entries document compromised supply chains (malicious takeovers,
//     hijacked accounts, injected payloads)
//
// Source: "Backstabber's Knife Collection" (Ohm et al., 2020)
//
//	https://arxiv.org/abs/2005.09535
//
// Source: "Towards Measuring Supply Chain Attacks on Package Managers"
//
//	(NDSS 2020)
var knownCompromises = []KnownCompromise{
	{
		Name:        "event-stream",
		Ecosystem:   models.EcosystemNPM,
		AttackName:  "event-stream incident",
		Year:        2018,
		Description: "Maintainer social-engineered into transferring ownership; attacker injected flatmap-stream dependency targeting cryptocurrency wallets",
		Reference:   "https://blog.npmjs.org/post/180565383195/details-about-the-event-stream-incident",
	},
	{
		Name:        "ua-parser-js",
		Ecosystem:   models.EcosystemNPM,
		AttackName:  "ua-parser-js hijack",
		Year:        2021,
		Description: "Maintainer npm account compromised; malicious versions published with cryptominer and credential stealer payloads",
		Reference:   "https://github.com/nicedayto/ua-parser-js/issues/536",
	},
	{
		Name:        "colors",
		Ecosystem:   models.EcosystemNPM,
		AttackName:  "colors/faker protest sabotage",
		Year:        2022,
		Description: "Maintainer intentionally sabotaged package by pushing infinite loop (protestware); demonstrated single-maintainer supply chain risk",
		Reference:   "https://snyk.io/blog/open-source-npm-packages-colors-702",
	},
	{
		Name:        "faker",
		Ecosystem:   models.EcosystemNPM,
		AttackName:  "colors/faker protest sabotage",
		Year:        2022,
		Description: "Maintainer intentionally sabotaged package alongside colors; demonstrated single-maintainer supply chain risk",
		Reference:   "https://snyk.io/blog/open-source-npm-packages-colors-702",
	},
	{
		Name:        "chalk",
		Ecosystem:   models.EcosystemNPM,
		AttackName:  "Shai-Hulud attack",
		Year:        2025,
		Description: "npm account compromised in coordinated Shai-Hulud supply chain attack; malicious versions published to npm",
		Reference:   "https://blog.phylum.io/shai-hulud-npm-supply-chain-attack/",
	},
	{
		Name:        "debug",
		Ecosystem:   models.EcosystemNPM,
		AttackName:  "Shai-Hulud attack",
		Year:        2025,
		Description: "npm account compromised in coordinated Shai-Hulud supply chain attack; malicious versions published to npm",
		Reference:   "https://blog.phylum.io/shai-hulud-npm-supply-chain-attack/",
	},
}

// checkKnownCompromises checks whether the given dependency matches any
// historically compromised package and adds a HIGH finding if so.
//
// Test: Package matches known supply chain compromise
// Justification: A package with a documented history of supply chain compromise
//
//	has proven susceptibility to takeover, hijacking, or sabotage —
//	the exact risk Snyft exists to surface.
//
// Source: "Backstabber's Knife Collection" (Ohm et al., 2020)
//
//	https://arxiv.org/abs/2005.09535
//
// Methodology: Static list match against package name + ecosystem
// Result: HIGH finding with attack details and reference
func checkKnownCompromises(result *models.AnalysisResult) {
	dep := result.Dependency
	nameLower := strings.ToLower(dep.Name)

	for _, c := range knownCompromises {
		if strings.ToLower(c.Name) == nameLower && c.Ecosystem == dep.Ecosystem {
			result.Findings = append(result.Findings, models.Finding{
				Severity: "HIGH",
				Category: "Known Supply Chain Compromise",
				Description: fmt.Sprintf(
					"This package was compromised in the %s (%d). %s",
					c.AttackName, c.Year, c.Description,
				),
				Check:       "Historical Compromise Database",
				Evidence:    fmt.Sprintf("Attack: %s (%d)", c.AttackName, c.Year),
				Methodology: "Matched against curated list of documented supply chain attacks (not CVEs)",
				SourceURL:   c.Reference,
			})
			return
		}
	}
}
