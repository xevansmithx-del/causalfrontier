# Governance

## Current model

CausalFrontier is an early, single-maintainer research-software project. The
repository owner currently acts as maintainer and release manager. This document
describes the process; it does not imply a community, institution, or independent
governance body that does not yet exist.

## Decisions

- User-facing and trust-boundary changes should begin with a focused public
  issue or pull request.
- Decisions are recorded in pull-request discussion, architecture records, the
  changelog, or an explicitly versioned protocol document.
- Compatibility may break during pre-alpha development, but the break and
  migration path must be documented.
- Security reports follow [SECURITY.md](SECURITY.md), not a public issue.

## Review and release

Every release candidate must pass the supported Python matrix, offline tests,
normal/optimized replay comparisons, source-manifest verification, privacy
scanning, static analysis, package checks, and installed-artifact smoke tests.
Release artifacts must be bound to one reviewed commit and accompanied by
checksums.

The maintainer may release software, but cannot unilaterally convert a structural
software result into a scientific claim. Claims about calibration, superiority,
biological validity, prospective performance, or impact require the independent
evidence and adjudication declared by the applicable protocol.

## Contributions and credit

Contributions are reviewed under [CONTRIBUTING.md](CONTRIBUTING.md). Authorship,
acknowledgment, and citation credit should reflect actual intellectual and
technical contributions and must be agreed by the people named. Automated or AI
systems are not authors.

## Conflicts and appeals

Contributors should disclose material conflicts relevant to a proposed
benchmark, case, comparator, review, or release. A contested scientific gate
stays closed until a documented, conflict-aware review resolves it. Ordinary
maintainer decisions may be challenged in a focused issue with reproducible
evidence.

## Sustainability

No response-time or long-term support guarantee is currently offered. A stable
support window, backup maintainer, contributor succession process, and external
governance roles are publication-readiness gates, not present facts.
