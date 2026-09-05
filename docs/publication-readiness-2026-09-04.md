# Publication-readiness assessment — 2026-09-04

**Policy clarification:** 2026-09-05 UTC. The engineering and adoption evidence
below retains the original assessment's scope. This clarification adds no new
scientific result, external reproduction, or journal submission.

## Decision

CausalFrontier is **not submission-ready** as a research-software paper or a
biomedical methods paper. Its local software-engineering evidence is strong for
a pre-alpha project, but the decisive publication gaps are external research
use, authenticated independent release reproduction, real-world semantic
validation, executed comparators, and public development history. Copyediting
cannot close those gaps.

The appropriate next move is to mature and test CausalFrontier, not to replace
it with another new repository. A replacement would reset the development,
adoption, and validation clocks while leaving the same evidence bottleneck.

The software-engine evidence in this assessment applies to development commit
`1995cf7379523c952dc19f56fdc01b15a9212583` (`0.1.0a5`). That commit is not a
stable or archived release. This document is a planning record, not peer review,
editorial advice, or a prediction of acceptance.

## Current evidence

| Area | Current state | Publication interpretation |
|---|---|---|
| License and access | Public Apache-2.0 repository with a public issue tracker | Meets a basic open-source prerequisite |
| Packaging | Reproducible wheel and source distribution checks; latest packaged release is `v0.1.0a2` | Strong engineering evidence, but development source and release are not yet aligned |
| Verification | 873 tests passed on Python 3.13 and 3.14 in the V2 review; CI covers Python 3.10–3.14 | Supports structural correctness claims only |
| Security and provenance | CodeQL, dependency, privacy, source-freeze, hostile-input, and replay checks | Does not authenticate biological assertions, custody, or external independence |
| Inputs | Public-aggregate or synthetic boundary; current calibration is known-hindsight | Safe for development, insufficient for empirical utility claims |
| Semantic controls | Positive, failed-translation, and ambiguous controls are structurally present; semantically verified controls = 0 | Scientific scoring must remain disabled |
| Adoption | No documented independent installation, research workflow, external contribution, or reproduced result | No defensible realized-impact claim |
| Benchmark | Required real-world scientific benchmark executions for expert, retrieval, graph, random, and simple-rule comparators are absent; synthetic comparator plumbing is not counted | No comparative-performance or tenfold claim |
| Maturity | Pre-alpha; public repository created in late August 2026 | Too early for venues that require sustained public development |

Repository traffic is not counted as adoption. Automated builds, dependency
services, scanners, and maintainer activity can all create clones or downloads.
Only attributable, consented, independently reproducible use should enter the
adoption record.

## Venue gates

The policies below were reviewed on 2026-09-04 and rechecked during the
2026-09-05 UTC clarification. Journal policies can change and must be rechecked
before submission.

| Venue | Relevant current gate | Verdict now |
|---|---|---|
| [Journal of Open Source Software](https://joss.readthedocs.io/en/latest/submitting.html) | Feature-complete research software, demonstrated research use, good open-source practice, and more than six months of active public development; the [paper format](https://joss.readthedocs.io/en/latest/paper.html) also requires sections on the need, field, design, impact, and AI use | **No-go.** Public history is about one week, the software is pre-alpha, demonstrated research use is absent, and no paper exists. Under the current JOSS workflow, a tagged archive and DOI are acceptance-stage deliverables, not today's pre-review blocker. A conservative earliest time-gate date is 2027-03-01, contingent on active public development and demonstrated use—not merely waiting. |
| [Nature Methods](https://www.nature.com/nmeth/submission-guidelines/about/aims) | Novel methods with immediate practical relevance and potential to advance biological applications; central code must satisfy the journal's [software and code guidance](https://www.nature.com/documents/GuidelinesCodePublication.pdf) | **No-go.** No real biological application, documented testing by colleagues unfamiliar with the tool, state-of-the-art performance comparison, or generalizability evidence exists. |
| [PLOS Computational Biology](https://journals.plos.org/ploscompbiol/s/submission-guidelines) Software article | Broad utility and a significant advance providing biological insight, plus wide adoption or credible promise of it; the [sharing policy](https://journals.plos.org/ploscompbiol/s/materials-and-software-sharing) requires a well-established project with an open repository available for an extended period | **No-go.** Biological insight, broad utility, adoption promise, and sufficient development history remain unestablished. Deposit source, license, documentation, test data, and parameters for reproducible review; the exact submission version must be supplied as supporting information and linked. Wet-lab validation and a DOI are not categorical requirements of this route. |
| [Bioinformatics](https://academic.oup.com/bioinformatics/pages/author-guidelines) Application Note or Original Paper | Original Papers require actual biological data except extremely well-justified simulation-only cases. Application Notes require anonymous stable review access, exact software/test-data archival, two-year availability, broad machine compatibility, and low installation burden | **No-go for either route.** Realistic validated use and relevant empirical comparisons are absent. The Application Note availability commitment and the Original Paper biological-data requirement remain open. Article type and subject category determine the applicable comparison and availability rules. |

The [AI-use record](../AI_USAGE.md) leaves accountable-human review pending.
JOSS requires disclosure of systems, versions, and scope, plus human confirmation
of review, editing, validation, and core design decisions. Its author
conversations with editors and reviewers exclude AI assistance except
translation. See the [JOSS policy](https://joss.readthedocs.io/en/latest/submitting.html#ai-usage-policy).

Bioinformatics permits accountable code and documentation assistance but bars
prompt-generated manuscript text, figures, tables, and references: researchers
must write the paper. Permitted use still needs detailed disclosure under the
[author guidelines](https://academic.oup.com/BIOINFORMATICS/pages/author-guidelines).
The present planning document is not a manuscript or an attestation that these
requirements have been met.

## Evidence-first publication ladder

Advance only when the prior rung is independently checkable.

1. **Source-tree reproduction pilot.** Before a current stable release exists,
   at least three self-declared users outside the development workflow reproduce
   the exact identified development commit. Treat these as documentation and
   usability pilots—not release validation, authenticated independence,
   adoption, or scientific evidence. Repeat the exercise against the exact
   archived release once one exists.
2. **Semantic calibration.** An externally authenticated, phase-separated
   review adjudicates the precommitted positive, failed-translation, and
   ambiguous controls. All three are required before any score.
3. **Real-world public cases.** Independently encode public, aggregate cases in
   at least three biomedical domains. Measure pre-reconciliation agreement and
   publish every critical disagreement.
4. **Comparator execution.** Run expert, retrieval, graph, random, and a
   predeclared simple rule on identical inputs with audited time, compute,
   service cost, coverage, selective risk, and abstention.
5. **Prospective validation.** Commit the evidence cutoff, actions, branches,
   scoring, and custody before outcome access; then obtain independent reveal
   and adjudication. Historical replays remain calibration-only.
6. **Human review and venue-specific paper.** Accountable human authors review
   and validate the code, evidence, and claims; document their core design
   decisions; and supply verified affiliations, contributions, competing
   interests, funding, availability statements, references, and AI disclosures.
   For Bioinformatics, researchers must write the manuscript. Follow the
   [human correspondence gate](dynamic-workflow.md#journal-correspondence-gate)
   for JOSS. Submit only claims supported by the completed evidence steps.
7. **Venue-specific release identity.** Align source and package versions and
   document the support window. For JOSS, submit the feature-complete candidate
   and paper first, then tag and archive the exact reviewed revision with a DOI
   after successful review. Other venues may require an exact archive at
   submission; follow their sequence. Independently reproduce the exact release
   before claiming release reproduction or scientific performance.

## Go, pivot, or stop

As an interim engineering continuation criterion—not a publication or
tenfold-claim gate—continue CausalFrontier if external users can reproduce the
source tree and, once one exists, authenticated independent users can reproduce
the reviewed release; external reviewers can agree on the case representation
without hidden outcome access; and it beats at least one meaningful comparator
without sacrificing calibrated abstention or safety boundaries.

Beating one comparator cannot satisfy the fixed program claim; that still
requires the complete domain × expert/retrieval/graph/random/simple-rule
conjunction in the [goal–claim contract](goal-claim-contract-v1.md).

Redesign the representation if independent encoders cannot reach the
predeclared agreement threshold, the residual makes every action
non-discriminating, or simple rules match the compiler across the full control
set. Stop the software-paper track if no real research workflow adopts the tool
after a sustained public evaluation period.

## Claims that remain unavailable

This repository does not yet establish novelty, superiority, calibration,
causal correctness, biological discovery, clinical utility, tenfold
acceleration, broad adoption, journal suitability, health benefit, or lives
saved. A journal cover or acceptance cannot be forecast from repository quality.
