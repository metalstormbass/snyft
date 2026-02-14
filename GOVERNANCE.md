# Project Governance

This document describes the governance model for the snyft project.

## Overview

Snyft is an open-source supply chain security analyzer currently maintained under an **individual maintainer model**. This document establishes the framework for project governance, decision-making, and contribution processes.

## Project Mission

To provide a free, open-source tool that helps developers and security teams assess supply chain security risks in their dependencies across multiple package ecosystems.

## Core Values

- **Security First:** Security is paramount in design and implementation
- **Transparency:** Open development, public roadmap, clear communication
- **Community-Driven:** Welcome contributions from all experience levels
- **Quality Over Speed:** Careful, tested changes over rapid but buggy development
- **Responsible Disclosure:** Coordinated vulnerability disclosure protects users

## Governance Structure

### Current Model: Individual Maintainer

The project currently operates under a single-maintainer model:
- One lead maintainer has administrative control
- Contributors submit pull requests for review
- Maintainer has final decision authority

**Status:** 🟡 Single maintainer (seeking additional maintainers)

**Future Goal:** Transition to multi-maintainer model for improved resilience and shared workload.

### Roles and Responsibilities

#### 1. Lead Maintainer
**Current:** Michael Braun (@metalstormbass)

**Responsibilities:**
- Set project direction and roadmap
- Review and merge pull requests
- Manage releases
- Respond to security issues
- Make final decisions on disputes
- Recruit and onboard new maintainers

**Authority:**
- Merge access to main branch
- Release creation
- Repository administration
- Grant maintainer status to contributors

#### 2. Maintainers
**Current:** (Seeking additional maintainers)

**Responsibilities:**
- Review pull requests
- Triage and respond to issues
- Participate in technical decisions
- Help with releases
- Support community members

**Authority:**
- Merge access to main branch
- Issue/PR labeling and triage
- Participate in consensus decisions

**How to become a maintainer:** See [MAINTAINERS.md](MAINTAINERS.md)

#### 3. Contributors
**Status:** Open to all

**How to contribute:** See [CONTRIBUTING.md](CONTRIBUTING.md)

**Responsibilities:**
- Follow code of conduct
- Write quality, tested code
- Participate constructively in discussions
- Help other contributors

**Recognition:**
- Listed in release notes
- Credited in git history
- Mentioned in project acknowledgments

#### 4. Users
**Everyone who uses snyft**

**Rights:**
- Report bugs and request features
- Participate in discussions
- Use the software according to MIT License
- Report security vulnerabilities privately

## Decision-Making Process

### Types of Decisions

#### Routine Decisions (Individual Maintainer)
Examples:
- Merging bug fixes and small improvements
- Labeling and triaging issues
- Updating documentation
- Responding to questions

**Process:**
- Individual maintainer makes decision
- Use best judgment aligned with project goals
- No formal approval needed

#### Significant Decisions (Consensus)
Examples:
- Breaking API changes
- Major new features
- Architecture changes
- Dependency additions
- Governance changes

**Process:**
1. Propose change via GitHub Discussion or Issue
2. Allow 1 week for community feedback
3. Maintainers discuss and seek consensus
4. If consensus reached → proceed
5. If no consensus → lead maintainer makes final decision

**Consensus Definition:**
- All maintainers support or accept the decision
- No maintainer strongly objects (blocking concern)
- Silence after 1 week = consent

#### Emergency Decisions (Rapid Response)
Examples:
- Security vulnerabilities
- Critical bugs in production
- Service outages affecting users

**Process:**
1. Most available maintainer makes decision
2. Document decision and rationale
3. Inform other maintainers within 24 hours
4. Review decision post-incident

### Conflict Resolution

If maintainers disagree:

1. **Discussion:** Try to understand all perspectives
2. **Compromise:** Look for middle-ground solutions
3. **Data:** Gather information to inform decision
4. **Vote:** If needed, maintainers vote (simple majority)
5. **Final Decision:** Lead maintainer breaks ties

### Proposal Template

For significant changes, use this template:

```markdown
## Proposal: [Title]

**Author:** [Your name]
**Date:** [YYYY-MM-DD]
**Status:** [Proposed / Accepted / Rejected / Implemented]

### Problem
[What problem does this solve?]

### Proposal
[What is the proposed solution?]

### Alternatives Considered
[What other approaches did you consider?]

### Impact
- Breaking changes: [Yes/No - describe]
- Performance impact: [Describe]
- Security implications: [Describe]
- Documentation needed: [List]

### Implementation Plan
1. [Step 1]
2. [Step 2]
...

### Open Questions
- [Question 1?]
- [Question 2?]
```

## Release Process

### Versioning

Snyft uses **Semantic Versioning** (https://semver.org):
- **MAJOR** (1.0.0): Breaking changes
- **MINOR** (0.1.0): New features, backwards-compatible
- **PATCH** (0.0.1): Bug fixes, backwards-compatible

**Current status:** Pre-1.0 development (0.x.x)
- Breaking changes may occur in minor versions during 0.x
- After 1.0, strict semver adherence

### Release Authority

**Who can release:**
- Lead maintainer (current: @metalstormbass)
- Future: Any maintainer with release privileges

**Release checklist:** See [CONTRIBUTING.md](CONTRIBUTING.md) lines 376-384

### Release Types

#### Regular Releases
- Scheduled: When significant features are ready
- Process:
  1. All tests passing
  2. CHANGELOG.md updated
  3. Version bumped
  4. Git tag created and signed
  5. GitHub release with notes
  6. Announcement (if significant)

#### Security Releases
- Unscheduled: When security patches are ready
- Process:
  1. Security fix merged
  2. Patch version bumped
  3. Immediate release
  4. Security advisory published
  5. Coordinated disclosure with reporter

#### Hotfix Releases
- Unscheduled: Critical bug fixes
- Process: Same as regular release, expedited

## Code Review Process

### Pull Request Requirements

**All PRs must:**
- [ ] Pass all CI tests
- [ ] Include tests for new functionality
- [ ] Update documentation if needed
- [ ] Follow code style guidelines
- [ ] Have clear, descriptive commit messages

**PR Review:**
- At least 1 maintainer review required (when multiple maintainers exist)
- Current: Single maintainer reviews and merges
- Constructive feedback expected
- Address review comments or discuss respectfully

### Review Timeline

- **Goal:** Initial response within 1 week
- **Complex PRs:** May take longer, maintainer will communicate
- **Stale PRs:** Closed after 60 days of inactivity (can be reopened)

## Security Governance

### Security Response Team

**Current:** Lead maintainer handles security issues
**Future:** Dedicated security response team

### Security Incident Response

See [SECURITY.md](SECURITY.md) for full details.

**Process:**
1. **Report received** → Acknowledge within 48 hours
2. **Validation** → Confirm and assess (7 days)
3. **Fix development** → Develop patch (14-30 days)
4. **Coordinated release** → Work with reporter on timing
5. **Public disclosure** → Advisory + patched release

**Authority:**
- Lead maintainer coordinates response
- Emergency patches can be released without normal review process
- Embargo periods respected

## Communication Channels

### Official Channels

| Channel | Purpose | Response Time |
|---------|---------|---------------|
| **GitHub Issues** | Bug reports, feature requests | 1 week |
| **GitHub Discussions** | Questions, ideas, community chat | Best effort |
| **GitHub Pull Requests** | Code contributions | 1 week |
| **Security Email** | Vulnerability reports | 48 hours |

### Announcements

- **Releases:** GitHub Releases + (future: mailing list)
- **Security:** GitHub Security Advisories
- **Governance:** GitHub Discussions

## Project Assets

### Repository Access

**Current:**
- Repository: https://github.com/metalstormbass/snyft
- Owner: @metalstormbass (Individual account)
- **Recommendation:** Transfer to organization for better governance

**Future:**
- Consider organizational account for:
  - Team-based access control
  - Better succession planning
  - Enhanced security features

### Domain Names
- None currently

### Package Registries
- None currently (no published packages yet)

### Social Media
- None currently

## Succession Planning

### Maintainer Unavailability

**Current Risk:** Single maintainer = single point of failure

**Mitigation:**
1. Recruit additional maintainers (in progress)
2. Document all processes (this governance model)
3. Consider organization ownership
4. Keep contact information current

### Repository Ownership Transfer

**Triggers for transfer:**
- Original maintainer requests transfer
- Original maintainer unresponsive for 6+ months
- Project grows to need organizational structure

**Process:**
1. Consensus among active maintainers
2. Notify community of intent
3. Transfer to organization or new lead maintainer
4. Update all documentation and contacts

## Code of Conduct

### Current

Basic code of conduct in [CONTRIBUTING.md](CONTRIBUTING.md):
> "Be respectful, inclusive, and collaborative. We're all here to build better security tools."

### Future

Consider adopting formal Code of Conduct when project grows:
- [Contributor Covenant](https://www.contributor-covenant.org/)
- [Django Code of Conduct](https://www.djangoproject.com/conduct/)

### Enforcement

**Current:** Lead maintainer handles violations
**Process:**
1. Warning for first minor violation
2. Temporary ban for repeated or serious violations
3. Permanent ban for severe violations
4. Maintainers decide enforcement actions

## Intellectual Property

### License

**Project License:** MIT License (see [LICENSE](LICENSE))

**Contributor Rights:**
- Contributors retain copyright on their contributions
- MIT License applies to all contributions
- No CLA (Contributor License Agreement) required

### Trademarks

**Project Name:** "Snyft"
- No registered trademark currently
- Consider trademark registration if project grows

## Amendments to Governance

This governance document can be amended:

**Who can propose:** Anyone (maintainers, contributors, users)
**Who decides:** Maintainers (consensus)

**Process:**
1. Open a pull request with proposed changes to GOVERNANCE.md
2. Discuss in PR comments
3. Allow 2 weeks for feedback
4. Maintainers reach consensus
5. Merge if approved

**Version History:**
- v1.0 - 2026-02-14 - Initial governance document

## Questions?

- **Governance questions:** Open a GitHub Discussion
- **Maintainer nominations:** See [MAINTAINERS.md](MAINTAINERS.md)
- **Security reports:** See [SECURITY.md](SECURITY.md)

---

**Acknowledgment:** This governance model is inspired by successful open-source projects including Kubernetes, Django, and Rust. As snyft grows, this governance will evolve to meet the community's needs.
