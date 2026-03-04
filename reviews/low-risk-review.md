# Snyft Report Review: 10 Lowest-Risk Packages

**Reviewer:** review-low (automated supply chain risk validation)
**Report Date:** Mar 3, 2026
**Review Date:** Mar 3, 2026

## Summary

| # | Package | Score | Verdict | Concerns |
|---|---------|-------|---------|----------|
| 1 | axios@1.6.5 | 3/20 | ACCURATE | Minor CI/CD gaps correctly flagged |
| 2 | numpy@1.26.3 | 3/20 | ACCURATE | Well-governed, findings fair |
| 3 | stripe@14.10.0 | 3/20 | FALSE POSITIVE on Publisher Control | "Single maintainer" is misleading for corporate package |
| 4 | **passlib@1.7.4** | **4/20** | **MISLEADING - ACTUALLY DANGEROUS** | **Abandoned since 2020, active typosquatting, missing data inflated score** |
| 5 | agenda@5.0.0 | 4/20 | ACCURATE | Findings reasonable |
| 6 | cors@2.8.5 | 4/20 | ACCURATE | Findings fair |
| 7 | lodash@4.17.21 | 4/20 | ACCURATE but incomplete | Dormancy period and prototype pollution history missed |
| 8 | redis@4.6.12 | 4/20 | ACCURATE | Findings reasonable |
| 9 | stripe@7.11.0 | 4/20 | FALSE POSITIVE on Publisher Control | Same issue as stripe@14.10.0 — corporate entity, not truly single-maintainer |
| 10 | mongoose@8.1.0 | 5/20 | ACCURATE but incomplete | Recent critical RCE CVEs represent supply chain pattern risk |

---

## FLAGGED PACKAGES

### passlib@1.7.4 — Score 4/20 LOW — ACTUALLY DANGEROUS

**This is the most problematic low-score package in the report. The low score masks serious risks because missing data defaulted to passing scores.**

**Report Findings:**
- Source: **Unavailable** (no repo URL found)
- Provenance: 1/2 (no build attestations)
- Governance: 1/2 (couldn't check — no repo)
- Release Security: 1/2 (couldn't check — no repo)
- Package Maturity: 1/2 (irregular cadence)
- Publisher Control: **2/2** (full score)
- All other categories: **2/2** (full score)

**Reality:**
1. **ABANDONED since 2020.** Last release was v1.7.4 in late 2020. No commits, no maintenance for 5+ years.
2. **Incompatible with Python 3.13.** passlib uses the deprecated `crypt` module which was removed in Python 3.13. Multiple downstream projects (cloud-init, Ansible, FastAPI) have documented this breakage.
3. **Active typosquatting attack.** A malicious package `psslib` was published on PyPI by threat actor "umaraq" that typosquats passlib. It forces Windows system shutdowns when incorrect passwords are entered. As of research date, it was still active on PyPI.
4. **No repository URL** means Snyft couldn't check governance, CI/CD, release security, or branch protection — all of which **defaulted to passing or partial scores** rather than flagging the gap.
5. **Single maintainer** (Eli Collins) — the report gave 2/2 on Publisher Control, which appears incorrect for a single-maintainer package.
6. **FastAPI has officially dropped it** from documentation examples, recommending `pwdlib` instead. Arch Linux is considering switching to a maintained fork.

**Finding-by-Finding Assessment:**
| Finding | Verdict |
|---------|---------|
| "No repository URL found" (HIGH) | **ACCURATE** — correct, but the *impact* is understated |
| "No strong build attestations" (MEDIUM) | **ACCURATE** |
| "Unable to check governance" (MEDIUM) | **MISLEADING** — should penalize more heavily when data is entirely missing |
| "Unable to check release security" (MEDIUM) | **MISLEADING** — same issue |
| "Irregular release cadence CV=1.3" (MEDIUM) | **MISLEADING** — framed as "irregular cadence" when the package is actually dead |

**Missed Risks:**
- Package is abandoned (5+ years, no maintenance)
- Active typosquatting campaign targeting this package
- Python 3.13 incompatibility (broken, not just deprecated)
- Single maintainer who is no longer active
- Major projects actively migrating away from it

**Recommendation:** This package should score **12-14/20 MEDIUM** minimum. The current 4/20 is dangerously low and gives false assurance.

---

## Detailed Package Reviews

### 1. axios@1.6.5 — Score 3/20 LOW

**Maintainer:** Jay (jasonsaayman) is the primary maintainer. The axios GitHub org has multiple contributors. 4 npm maintainers.
**Last Release:** v1.13.6 (4 days before report date). Actively maintained.
**Ever Compromised:** No. axios was NOT among the 18 packages compromised in the September 2025 npm supply chain attack (which hit chalk, debug, etc.).
**Known Supply Chain Concerns:** None. A DoS vulnerability (CVE-related to data handle abuse) was found but is a code vulnerability, not supply chain.

**Finding-by-Finding Assessment:**
| Finding | Verdict |
|---------|---------|
| "Overly broad permissions in GitHub Actions" (MEDIUM) | **ACCURATE** — valid CI/CD hygiene concern |
| "2 unpinned actions in GitHub Actions" (MEDIUM) | **ACCURATE** — tag hijacking is a real risk vector |
| "Publish workflow lacks environment protection" (MEDIUM) | **ACCURATE** — no manual approval gate is a valid concern |
| "4 maintainers, missing signing/MFA" (MEDIUM) | **ACCURATE** — reasonable finding |
| "Release security gaps" (MEDIUM) | **ACCURATE** — branch protection 3/10, no signed releases |
| "Irregular release cadence CV=1.0" (MEDIUM) | **ACCURATE** — minor concern, avg 19 days between releases is reasonable |

**Missed Risks:** None significant. axios is genuinely low-risk from a supply chain perspective.
**Overall Verdict:** **ACCURATE** — 3/20 is appropriate.

---

### 2. numpy@1.26.3 — Score 3/20 LOW

**Maintainer:** NumPy Developers (collective). Part of the NumPy organization on GitHub/PyPI. Well-governed under NumFOCUS fiscal sponsorship.
**Last Release:** v2.4.1 (January 10, 2026). Actively maintained.
**Ever Compromised:** No direct compromise. numpy has been the target of numerous typosquatting attempts (e.g., `nurnpy`, `numpy-financial` impersonators) but the official package has never been compromised.
**Known Supply Chain Concerns:** PyPI lists only 2 maintainers with publish rights, which is noted correctly by the report.

**Finding-by-Finding Assessment:**
| Finding | Verdict |
|---------|---------|
| "2 maintainers found" (MEDIUM) | **ACCURATE** — PyPI shows 2 maintainers with publish rights. However, this understates the broader contributor base (500+ contributors) |
| "No strong build attestations, 0/139 releases signed" (MEDIUM) | **ACCURATE** — numpy does not sign GitHub releases |
| "Branch-Protection 3/10, releases not signed" (MEDIUM) | **ACCURATE** — valid concern for such a critical package |

**Missed Risks:** numpy is a very high-value target (massive install base). Typosquatting attacks are frequent but not flagged in the report. The narrow maintainer count on PyPI (2) for such a critical package is a genuine concern.
**Overall Verdict:** **ACCURATE** — 3/20 is fair. numpy has strong governance despite narrow PyPI publish access.

---

### 3. stripe@14.10.0 — Score 3/20 LOW

**Maintainer:** Stripe Inc. (official corporate SDK). Published by Stripe's engineering team.
**Last Release:** v20.4.0 (6 days before report). Actively maintained.
**Ever Compromised:** No. A typosquatting attack hit NuGet (`StripeApi.Net`) in February 2025 but NOT npm/PyPI.
**Known Supply Chain Concerns:** A "pwn request" vulnerability was found in a Stripe repo's GitHub Actions workflow (StepSecurity disclosed it) but this did not affect published packages.

**Finding-by-Finding Assessment:**
| Finding | Verdict |
|---------|---------|
| "Single maintainer, no signing" (HIGH) | **FALSE POSITIVE** — The npm package shows a single publish account, but this is Stripe Inc., a $50B+ company with internal security controls. A corporate entity using a single npm publish bot account is fundamentally different from a solo developer. The "single maintainer" framing is misleading. |
| "12 unpinned actions in GitHub Actions" (MEDIUM) | **ACCURATE** — valid CI/CD concern |
| "Publish workflow lacks environment protection" (MEDIUM) | **ACCURATE** — valid concern |
| "Release security gaps" (MEDIUM) | **ACCURATE** but context matters — Branch-Protection 8/10, 100% PR review rate is excellent |

**Missed Risks:** None significant. Stripe is genuinely one of the safest packages to depend on.
**Overall Verdict:** **ACCURATE** score, but the **HIGH severity "single maintainer" finding is a FALSE POSITIVE** for a corporate package.

---

### 4. passlib@1.7.4 — Score 4/20 LOW — SEE FLAGGED SECTION ABOVE

---

### 5. agenda@5.0.0 — Score 4/20 LOW

**Maintainer:** Multiple maintainers (10 on npm). Published by koresar. Originally by rschmukler. vkarpov15 (Mongoose maintainer) is also listed.
**Last Release:** v6.2.3 (12 days before report). Version 5.0.0 is ~3 years old.
**Ever Compromised:** No known supply chain compromise.
**Known Supply Chain Concerns:** Snyk classifies it as "inactive" despite recent v6.x releases. A community fork (Pulse) exists due to perceived inactivity.

**Finding-by-Finding Assessment:**
| Finding | Verdict |
|---------|---------|
| "Release security: 0/2" (HIGH) | **ACCURATE** — no branch protection data, no signed releases, no required reviews |
| "Overly broad GitHub Actions permissions" (MEDIUM) | **ACCURATE** |
| "4 unpinned actions" (MEDIUM) | **ACCURATE** |
| "No environment protection on publish" (MEDIUM) | **ACCURATE** |
| "10 maintainers, missing signing/MFA" (MEDIUM) | **ACCURATE** — large team but no signing |
| "Irregular release cadence CV=1.7" (MEDIUM) | **ACCURATE** — highly irregular |

**Missed Risks:** The "inactive" classification by Snyk and existence of community forks suggest potential future abandonment risk.
**Overall Verdict:** **ACCURATE** — 4/20 is reasonable.

---

### 6. cors@2.8.5 — Score 4/20 LOW

**Maintainer:** Part of the expressjs organization. Maintained by troygoode, dougwilson, ulisesgascon.
**Last Release:** v2.8.6 (recent). Version 2.8.5 was the previous stable.
**Ever Compromised:** No known supply chain compromise.
**Known Supply Chain Concerns:** None identified.

**Finding-by-Finding Assessment:**
| Finding | Verdict |
|---------|---------|
| "3 maintainers, small team" (MEDIUM) | **ACCURATE** |
| "No npm provenance, 0/1 releases signed" (MEDIUM) | **ACCURATE** |
| "Partial governance" (MEDIUM) | **ACCURATE** — has security policy but partial |
| "Release security gaps" (MEDIUM) | **ACCURATE** — branch protection unavailable |

**Missed Risks:** None significant. cors is a simple, stable middleware backed by the Express organization.
**Overall Verdict:** **ACCURATE** — 4/20 is fair.

---

### 7. lodash@4.17.21 — Score 4/20 LOW

**Maintainer:** John-David Dalton (jdalton), now at Socket.dev. Other maintainers: mathias, bnjmnt4n. Recently moved to Technical Steering Committee governance with OpenJS Foundation and Sovereign Tech Agency funding.
**Last Release:** v4.17.21 (Feb 2021) was the last release for ~4 years. v4.17.23 recently released as part of "security reset."
**Ever Compromised:** No direct supply chain compromise. However, lodash has had a significant history of prototype pollution vulnerabilities (CVE-2019-10744, CVE-2020-8203, CVE-2020-28500, CVE-2021-23337).
**Known Supply Chain Concerns:** The long dormancy period (2021-2025) was a significant bus factor risk that has since been partially addressed by the governance restructuring.

**Finding-by-Finding Assessment:**
| Finding | Verdict |
|---------|---------|
| "3 maintainers, small team" (MEDIUM) | **ACCURATE** |
| "No npm provenance, 0/2 releases signed" (MEDIUM) | **ACCURATE** |
| "Bus factor: 1 (85% of commits from top contributor)" (MEDIUM) | **ACCURATE** — this is a real concern |
| "Release security gaps" (MEDIUM) | **ACCURATE** |

**Missed Risks:**
- The ~4 year dormancy period between v4.17.21 and recent activity represents a significant supply chain risk that the report does not adequately capture
- Historical prototype pollution vulnerabilities show the package has been a repeated attack target
- The "security reset" by Socket.dev is positive but very recent

**Overall Verdict:** **ACCURATE** score, but **incomplete** — the dormancy period and vulnerability history are supply chain risk signals that were missed.

---

### 8. redis@4.6.12 — Score 4/20 LOW

**Maintainer:** Redis organization (official Node.js client). Multiple contributors including nkaradzhov, PavelPoshov, elena-kolevska.
**Last Release:** v5.11.0 (February 2026). Actively maintained.
**Ever Compromised:** No. The Redis npm client has never been compromised. (Note: Redis server has had CVEs like CVE-2025-49844 and CVE-2025-21605, but those are server-side, not the client package.)
**Known Supply Chain Concerns:** None for the npm client.

**Finding-by-Finding Assessment:**
| Finding | Verdict |
|---------|---------|
| "No verifiable source code for this exact version" (HIGH) | **ACCURATE** — valid concern for artifact verification |
| "Overly broad GitHub Actions permissions" (MEDIUM) | **ACCURATE** |
| "2 unpinned actions" (MEDIUM) | **ACCURATE** |
| "No environment protection on publish" (MEDIUM) | **ACCURATE** |
| "5 maintainers, missing signing/MFA" (MEDIUM) | **ACCURATE** |
| "No npm provenance, 0/157 releases signed" (MEDIUM) | **ACCURATE** |
| "Branch-Protection 6/10, releases not signed" (MEDIUM) | **ACCURATE** |
| "Irregular release cadence CV=1.0" (MEDIUM) | **ACCURATE** — minor concern |

**Missed Risks:** None significant. redis is well-maintained by an established organization.
**Overall Verdict:** **ACCURATE** — 4/20 is fair.

---

### 9. stripe@7.11.0 — Score 4/20 LOW

**Maintainer:** Stripe Inc. (official Python SDK). Published by Stripe's engineering team.
**Last Release:** Active (Python stripe package regularly updated).
**Ever Compromised:** No. Same as stripe@14.10.0 — NuGet typosquatting only.
**Known Supply Chain Concerns:** None.

**Finding-by-Finding Assessment:**
| Finding | Verdict |
|---------|---------|
| "Single maintainer, no signing" (HIGH) | **FALSE POSITIVE** — Same issue as stripe@14.10.0. This is Stripe Inc., a major corporation. "Single maintainer" refers to publish rights, not actual organizational control. |
| "14 unpinned actions" (MEDIUM) | **ACCURATE** |
| "Publish workflow lacks environment protection" (MEDIUM) | **ACCURATE** |
| "0/383 releases signed" (MEDIUM) | **ACCURATE** — valid concern |
| "Release security gaps" (MEDIUM) | **ACCURATE** but context matters — 8/10 branch protection, 100% review rate |

**Missed Risks:** None significant.
**Overall Verdict:** **ACCURATE** score, but the **HIGH "single maintainer" finding is a FALSE POSITIVE** for a corporate package.

---

### 10. mongoose@8.1.0 — Score 5/20 LOW

**Maintainer:** Automattic organization. Primary maintainer is vkarpov15 (Val Karpov). 400+ contributors. Commercial support via Tidelift.
**Last Release:** v9.2.3 (March 2026). Actively maintained.
**Ever Compromised:** No direct supply chain compromise. However, two critical RCE vulnerabilities were discovered in late 2024/early 2025:
  - **CVE-2024-53900** (CVSS 9.1): MongoDB operator injection via `$where` allowing arbitrary JS execution. Affected <8.8.3.
  - **CVE-2025-23061** (CVSS 9.0): Bypass of the CVE-2024-53900 fix using `$or` nesting. Affected <8.9.5.
  - **Version 8.1.0 is vulnerable to BOTH CVEs.**
**Known Supply Chain Concerns:** The patch-bypass pattern (initial fix was insufficient, requiring a second patch) is concerning from a supply chain integrity perspective.

**Finding-by-Finding Assessment:**
| Finding | Verdict |
|---------|---------|
| "Release security: 0/2" (HIGH) | **ACCURATE** — no branch protection data, no signed releases, no required reviews |
| "2 unpinned actions" (MEDIUM) | **ACCURATE** |
| "No environment protection on publish" (MEDIUM) | **ACCURATE** |
| "4 maintainers, missing signing/MFA" (MEDIUM) | **ACCURATE** |
| "6 direct dependencies" (MEDIUM) | **ACCURATE** |
| "Bus factor: 1" (MEDIUM) | **ACCURATE** — vkarpov15 dominates commits |

**Missed Risks:**
- Two critical CVSS 9.0+ RCE vulnerabilities in recent versions (not CVE tracking per se, but the patch-bypass pattern is a supply chain integrity signal)
- Version 8.1.0 is significantly outdated and missing critical security patches
- Bus factor 1 combined with critical vulnerability history is a compound risk

**Overall Verdict:** **ACCURATE** score but **incomplete** — the version-specific vulnerability exposure and patch-bypass pattern are relevant supply chain signals.

---

## Data Collection Context (from fancy-eagle)

Per fancy-eagle's analysis of Snyft's data collection limitations:

- **Most categories default to 1/2 (MODERATE) when data is unavailable** — unknown != unsafe
- **Install Execution defaults to 0/2** when no scripts found (absence of scripts = low risk)
- **Theoretical worst-case with NO data: ~11/20 (MEDIUM)**
- **Low-risk scores (0-8) are generally MORE reliable** — they mean data WAS available and scored well
- npm provenance is the only actively validated attestation; Maven GPG only checks file existence
- Branch protection 403/404 gets benefit of the doubt

**Impact on this review:**

This context **strengthens the passlib concern**. fancy-eagle confirms most missing-data categories should default to 1/2 — but passlib scored 2/2 on Publisher Control, Ownership Changes, Release Anomalies, Install Execution, Dependency Sprawl, and Health. Some of these (Publisher Control, Ownership Changes, Release Anomalies, Dependency Sprawl) could plausibly come from registry-only data. But **Health at 2/2 is suspect** — bus factor and code review checks require a source repo, which passlib lacks. This suggests a scoring bug or inappropriate default for the Health category.

Additionally, fancy-eagle notes the theoretical worst-case with zero data is ~11/20. passlib at 4/20 with no source repo is well below this floor, confirming that the scoring system is not properly penalizing the data gap.

---

## Systemic Issues Identified

### 1. Missing Data Inflates Scores (Critical)
passlib@1.7.4 demonstrates a systemic flaw: when Snyft cannot find source data (no repo URL, no CI/CD, no governance info), several categories default to passing or partial scores rather than penalizing the gap. **Packages with missing data should not receive low risk scores** — the inability to verify supply chain integrity IS a risk signal.

### 2. "Single Maintainer" for Corporate Packages (False Positive Pattern)
Both stripe packages are flagged with HIGH-severity "single maintainer" findings. For corporate packages where a single npm/PyPI account is used as a publish bot, this is standard practice and not a genuine single-maintainer risk. Snyft should differentiate between a solo developer and a corporate org using a single publish account.

### 3. Abandoned Packages Not Adequately Penalized
passlib (dead since 2020) and lodash (dormant 2021-2025) demonstrate that long-term inactivity is not adequately weighted. A package that hasn't been updated in 5 years with a single maintainer who is no longer active should score significantly higher on the risk scale.

### 4. Typosquatting Attacks Not Tracked
passlib has an active typosquatting campaign (psslib) on PyPI. This is a direct supply chain risk signal that Snyft does not currently track.

---

## Final Assessment

**8 of 10 packages** are genuinely low-risk with accurate or reasonable scores.

**1 package (passlib@1.7.4) is DANGEROUSLY underscored** at 4/20 — it should be 12-14/20 MEDIUM. Its low score is primarily due to missing data defaulting to passing scores rather than genuine supply chain safety. This is the most critical finding: **an abandoned, typosquatted, Python 3.13-incompatible package with no visible source code is rated as one of the safest packages in the report.**

**2 packages (stripe@14.10.0, stripe@7.11.0)** have FALSE POSITIVE findings on Publisher Control that overstate risk for what are actually corporate-backed packages.
