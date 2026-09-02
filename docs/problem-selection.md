# Moonshot problem-selection record

**Decision date:** 2026-08-28  
**Fixed parameter:** `OPEN_MACHINE_VERIFIABLE_TRANSLATION_FROM_FRAGMENTED_BIOMEDICAL_EVIDENCE_TO_NEXT_FALSIFIABLE_ACTION`

## Decision

Build a provenance-bound compiler that turns a time-frozen evidence set, explicit competing causal worlds, and predeclared outcome branches into the next structurally discriminating experiment or an explicit abstention.

The breakthrough hypothesis is not that this pre-alpha already performs causal discovery. It is that a public, leakage-resistant challenge and receipt format could make evidence-to-experiment translation measurable, composable, and progressively learnable. The first deliverable is the measurement and falsification substrate; learned proposal systems can compete behind that boundary later.

## Why this problem

AlphaFold's significance depended on more than a powerful model: protein structure prediction had a sharp output contract and a blind community benchmark. CASP14 used structures unavailable to participants, and AlphaFold demonstrated accuracy competitive with experimental structures on a majority of cases ([Jumper et al., 2021](https://www.nature.com/articles/s41586-021-03819-2)). Causal biomedical translation lacks an equivalent broadly adopted contract for “given only evidence available by date *t*, which experiment should be run next, what outcomes would discriminate the live explanations, and what would force abstention?”

The ingredients already exist but solve neighboring problems:

- Open Targets integrates diverse target–disease evidence, while PrimeKG integrates millions of biomedical relations across scales ([Open Targets Platform](https://pubmed.ncbi.nlm.nih.gov/39657122/); [PrimeKG](https://doi.org/10.1038/s41597-023-01960-3)). They are evidence substrates, not precommitted experiment-selection ledgers.
- TxGNN ranks drug-repurposing candidates and exposes graph rationales ([Huang et al., 2024](https://www.nature.com/articles/s41591-024-03233-x)). Candidate ranking is different from compiling a total, falsifiable outcome contract with failure and contradiction branches.
- Budgeted causal-discovery research formalizes experiment selection under explicit assumptions ([Agrawal et al., 2019](https://proceedings.mlr.press/v89/agrawal19b.html)). CausalFrontier tests how to bind those choices to heterogeneous biomedical receipts and open-world abstention.
- Human genetic support is associated with higher clinical-development success, but it does not remove translation failures or establish a particular intervention's efficacy ([Minikel et al., 2024](https://www.nature.com/articles/s41586-024-07316-0)).
- Generalizing perturbation predictions remains an open benchmark problem; recent studies show important context failures and cases where simple baselines match complex models ([Systema](https://www.nature.com/articles/s41587-025-02777-8); [Nature Methods benchmark](https://www.nature.com/articles/s41592-025-02980-0)).

These observations motivate an orchestration and evaluation layer rather than another ungrounded universal predictor.

## Competitive update — 2026-09-02

[Elicit's BioDecisionBench](https://elicit.com/blog/biodecisionbench-evals) materially overlaps this problem framing: it evaluates evidence-grounded biomedical decisions under ambiguity across target selection, study and trial design, and indication selection, with rubrics for both research process and answer quality. It therefore invalidates any novelty claim based merely on “benchmarking biomedical decisions,” reasoning from fragmented evidence, or evaluating what a biomedical team should do next. LifeSciBench, FrontierScience, LAB-Bench and BixBench also cover realistic expert scientific work, while CACHE and CASP establish precedents for prospective experimental validation and blind independent assessment. This is a bounded comparison, not an exhaustive survey or a novelty opinion.

CausalFrontier's still-unvalidated distinct hypothesis is narrower: machine-verifiable pre-outcome commitments to admissible evidence, candidate actions, complete outcome branches, scoring, and calibrated abstention; independent custody and reveal; and a measured reduction in fully loaded real time and cost to the next decision-relevant falsification against predeclared baselines. The conjunction may be worth testing, but its distinctiveness, feasibility, effect size, and value have not been demonstrated. See the [2026-09-02 competitive landscape](competitive-landscape-2026-09-02.md).

The same-day [public adoption audit](adoption-audit-2026-09-02.md) found no
defensible evidence of meaningful external scientific use for GraceGraph,
GraceLoop, or CausalFrontier. Clone counts cannot distinguish scientists from
maintainer, CI, scanner, or automation traffic. Independent novice installation
and one observed end-to-end read-only task are therefore empirical program gates,
not marketing afterthoughts.

## Alternatives considered

| Direction | Upside | Why it is not the first wedge |
|---|---|---|
| Whole-cell or patient digital twin | Direct prediction could be transformative | Validation targets are underspecified, context shift is severe, and patient-level use would exceed the current authority and privacy boundary |
| End-to-end drug generator | Large therapeutic upside | Requires chemistry, safety, manufacturability, and prospective biology; existing molecule/structure systems are components rather than sufficient causal validation |
| Universal biomedical knowledge graph | Broad reusable substrate | Strong public systems already exist; graph aggregation alone does not decide which observation would falsify competing explanations |
| Single-cell perturbation foundation model | Large, benchmarkable datasets | Generalization remains unstable and model outputs do not by themselves create a trustworthy evidence-to-action contract |
| AMR intervention planner | Acute global-health relevance | Pathogen and material execution raise dual-use and operational risks; begin with read-only historical evidence instead |
| Causal evidence-to-experiment compiler | Cross-domain leverage; supports explicit abstention; prospectively testable | Authored worlds and branches are subjective until independent encoders, executable classifiers, and blind benchmarks pass |

## What would count as a breakthrough

CausalFrontier earns a strong claim only after all of the following, not because the repository exists:

1. A public challenge set is frozen prospectively, with immutable evidence-availability receipts and held-out outcomes.
2. Independent encoders achieve reproducible world, branch, and gate contracts or make disagreements machine-auditable.
3. Executable, digest-bound classifiers map evidence to exactly one predeclared branch and pass disjoint/exhaustive property tests.
4. On positive, failed-translation, and ambiguous controls, the system improves experiment-selection quality over expert, retrieval, graph-ranking, random, and simple-rule baselines without time leakage.
5. Prospective domain-expert trials show that its selected experiments reduce decision-relevant uncertainty faster or more safely than the baselines.
6. Independent groups reproduce the result and document failures.

Until then the accurate claim is: **a structural pre-alpha for authoring and replaying falsification plans**.

## First challenge ladder

1. Positive historical control: PCSK9 inhibition before the FOURIER outcome trial.
2. Failed-translation control: a target with compelling preclinical or surrogate evidence but a later null efficacy outcome.
3. Ambiguous control: a case whose later evidence should preserve defer rather than reward a confident choice.
4. Cross-domain controls in genetics, perturbation biology, and pharmacovigilance.
5. Only after historical leakage tests pass, prospectively commit a small expert-reviewed challenge.

## Two-week kill gates

Stop or redesign this representation if any gate fails:

- temporal receipts cannot prove that inputs existed before the cutoff;
- two independent encoders cannot reach 80% exact cell agreement before reconciliation;
- simple baselines match the compiler's selection on every historical control;
- the residual makes every proposed experiment non-discriminating;
- outcome classifiers cannot be made executable and total;
- rollback, post-hoc branch creation, or source omission escapes hostile review; or
- domain reviewers consistently interpret structural admissibility as biological or clinical authority.

The billion-life aspiration is a direction for choosing leverage, not a measured result, forecast, or release claim.
