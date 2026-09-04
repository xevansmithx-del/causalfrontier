# Publication-readiness assessment — 2026-09-04

## Decision

CausalFrontier is **not submission-ready** as a research-software paper or a
biomedical methods paper. Its local software-engineering evidence is strong for
a pre-alpha project, but the decisive publication gaps are external research
use, independent reproduction, real-world semantic validation, executed
comparators, and public development history. Copyediting cannot close those
gaps.

The appropriate next move is to mature and test CausalFrontier, not to replace
it with another new repository. A replacement would reset the development,
adoption, and validation clocks while leaving the same evidence bottleneck.

This assessment applies to development commit
`1995cf7379523c952dc19f56fdc01b15a9212583` (`0.1.0a5`). It is a planning
record, not peer review, editorial advice, or a prediction of acceptance.

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
| Benchmark | Required expert, retrieval, graph, random, and simple-rule executions are absent | No comparative-performance or tenfold claim |
| Maturity | Pre-alpha; public repository created in late August 2026 | Too early for venues that require sustained public development |

Repository traffic is not counted as adoption. Automated builds, dependency
services, scanners, and maintainer activity can all create clones or downloads.
Only attributable, consented, independently reproducible use should enter the
adoption record.

## Venue gates

The policies below were accessed on 2026-09-04. Journal policies can change and
must be rechecked before submission.

| Venue | Relevant current gate | Verdict now |
|---|---|---|
| [Journal of Open Source Software](https://joss.readthedocs.io/en/latest/submitting.html) | Feature-complete research software, demonstrated research use, good open-source practice, and more than six months of active public development; the [paper format](https://joss.readthedocs.io/en/latest/paper.html) also requires sections on the need, field, design, impact, and AI use | **No-go.** Public history is about one week, the software is pre-alpha, demonstrated research use is absent, and no paper or archived DOI exists. A conservative earliest time-gate date is 2027-03-01, contingent on real iterative use and development—not merely waiting. |
| [Nature Methods](https://www.nature.com/nmeth/submission-guidelines/about/aims) | Novel methods with immediate practical relevance and potential to advance biological applications; central code must satisfy the journal's [software and code guidance](https://www.nature.com/documents/GuidelinesCodePublication.pdf) | **No-go.** No real biological application, independent user study, state-of-the-art performance comparison, or generalizability evidence exists. |
| [PLOS Computational Biology](https://journals.plos.org/ploscompbiol/s/journal-information) Software article | Outstanding software of broad utility that can provide new biological insight, with reproducible code/data and the [required software sharing](https://journals.plos.org/ploscompbiol/s/materials-and-software-sharing) | **No-go.** No real-world biological insight, broad-utility evidence, or independent adoption is established. Wet-lab validation is not categorically required, but qualifying real-world evidence is. |
| [Bioinformatics](https://academic.oup.com/bioinformatics/pages/author-guidelines) Application Note or Original Paper | Nontrivial software, stable availability, realistic biological use, and appropriate comparison on common or actual biological data | **No-go.** The repository lacks a realistic validated use case, common-dataset comparison, and a reviewed support commitment. |

## Evidence-first publication ladder

Advance only when the prior rung is independently checkable.

1. **Independent reproduction.** At least three people outside the development
   workflow install the exact release and complete the
   [reproduction walkthrough](independent-reproduction.md). Record failures as
   first-class results.
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
6. **Stable release and archive.** Align source and package versions, document a
   support window, create a reviewed release, and archive the exact release with
   a DOI.
7. **Venue-specific paper.** Add verified author affiliations, contributions,
   competing interests, funding, data/code availability, references, and a
   complete AI-use disclosure. Submit only the claims supported by rungs 1–6.

## Go, pivot, or stop

Continue CausalFrontier if independent users can reproduce it, external
reviewers can agree on the case representation without hidden outcome access,
and it beats at least one meaningful comparator without sacrificing calibrated
abstention or safety boundaries.

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
