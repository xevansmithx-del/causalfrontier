# Scientific-decision challenge network: a candidate zero-to-one wedge

**Decision date:** 2026-09-01
**Status:** local, unreleased structural preflight; scientific scoring disabled
**Fixed parameter:** `OPEN_MACHINE_VERIFIABLE_TRANSLATION_FROM_FRAGMENTED_BIOMEDICAL_EVIDENCE_TO_NEXT_FALSIFIABLE_ACTION`

## Decision

Do not build another general literature agent, hypothesis chatbot, or autonomous-scientist wrapper. Build the open, model-neutral proving ground that can tell whether any human or agent chose a next action that produced the correct decision-state transition with less audited resource.

The long-range target combines the recurring blind assessment of [CASP](https://predictioncenter.org/) with the prospective compound selection and organizer-run testing of [CACHE](https://cache-challenge.org/critical-assessment-computational-hit-finding-experiments), generalized across scientific domains. Partner laboratories would contribute real decision points before outcomes exist. At `t0`, an independent steward would freeze the evidence, decision target, competing worlds, outcome branches, stopping rule, primary resource estimand, baselines, and analysis plan. Outcomes would be opened only after the authorized laboratory obtains them.

This is a benchmark, governance, and epistemic-compiler layer—not another closed agent. ToolUniverse, Biomni, Google Co-Scientist, Kosmos, Robin, Sakana AI Scientist, POPPER, or a human team could be entrants or execution substrates.

## Why this direction survived

| Candidate | Leverage | Collision | Decision |
|---|---|---|---|
| General autonomous scientist on ToolUniverse | Broad execution | A crowded field already covers retrieval, analysis, hypothesis generation, and tool use | Reject as the first wedge |
| Paper-to-falsification compiler | Useful interface for early-career scientists | Easy to demo but difficult to validate against live outcomes | Defer until the challenge contract exists |
| Cross-domain scientific-decision challenge network | Could improve every compatible human and agent workflow by making downstream decision impact measurable | CACHE, POPPER, and simulation benchmarks cover important parts, but not the complete cross-domain contract | Select, with a deliberately narrow novelty claim |

This selection is a documented search result, not proof that no obscure, private, or later system overlaps.

## Primary-source update, 2026-09-01

- [CASP17](https://predictioncenter.org/) is active in 2026, preserving recurring blind
  target release and independent assessment. This strengthens the case for durable
  community governance; it does not evaluate cross-domain next-action resource savings.
- [CACHE](https://cache-challenge.org/) now describes active retrospective-to-prospective
  PGK2 work and additional target-specific challenges, with organizer experimental
  testing and later open results. This remains the closest empirical precedent and makes
  cross-domain generalization—not prospective compound testing—a necessary novelty limit.
- [LifeSciBench](https://openai.com/index/introducing-life-sci-bench/) launched in June
  2026 with 750 expert-authored tasks and explicitly says that real acceleration requires
  longer, live, iterative workflow studies. Its own limitation statement aligns with the
  outcome-linked proving-ground gap; task-level rubric performance is not downstream
  research impact.
- [POPPER](https://cs.stanford.edu/people/jure/pubs/auto-hypothesis-validation-icml25.pdf)
  remains a mandatory sequential-falsification baseline and already reports a tenfold
  time comparison. Neither sequential falsification nor an unqualified “10x” is available
  as a CausalFrontier novelty claim.
- [RFC 3161](https://www.rfc-editor.org/rfc/rfc3161) defines signed proof that a datum
  existed before a time but leaves TSA trust policy to relying parties. Current
  [Sigstore timestamp guidance](https://docs.sigstore.dev/cosign/verifying/timestamps/)
  also warns that Rekor v1 integrated time is not externally verifiable. These sources
  motivated the separate caller-pinned RFC 3161 verifier and its explicit refusal to
  infer source availability or witness independence.

This update found no primary-source basis for broadening the novelty or impact claim.

## Prior-art boundary

- [CACHE](https://cache-challenge.org/critical-assessment-computational-hit-finding-experiments) is the closest live precedent found: participants select compounds, organizers procure and test them, and later rounds can use experimental feedback. CausalFrontier must credit and learn from this design.
- [POPPER](https://cs.stanford.edu/people/jure/pubs/auto-hypothesis-validation-icml25.pdf) already implements sequential computational falsification and reports a roughly tenfold time reduction against a small human-expert comparison. “Sequential falsification” and “10x” are therefore not novelty claims.
- [LifeSciBench](https://openai.com/index/introducing-life-sci-bench/) includes 750 expert-authored life-science tasks, including experiment design and what-to-do-next questions. Its reported scope does not establish downstream live, iterative research impact.
- [Petri-bench](https://petri-labs.org/bench/report) evaluates experiment selection, rigor, calibration, and efficiency in hidden causal worlds; its report shows simple informed experimental strategies can beat frontier agents. Those strategies are mandatory baselines, not straw opponents.
- [CASP](https://predictioncenter.org/) demonstrates durable blind target release and independent assessment, but it evaluates structure prediction rather than the cost of a scientific decision transition.
- [W3C PROV](https://www.w3.org/TR/prov-overview/), [RO-Crate](https://www.researchobject.org/ro-crate/specification.html), and [OSF registrations](https://help.osf.io/article/330-welcome-to-registrations) supply provenance, packaging, and preregistration components. They do not by themselves implement this evaluation protocol.
- [ToolUniverse](https://github.com/mims-harvard/ToolUniverse) is an open scientific execution plane. Execution breadth does not certify evidence dates, causal adequacy, or the next action.

The defensible white-space hypothesis is narrow: generalize CACHE-like prospective evaluation across domains while binding temporal evidence, decision-equivalence worlds, total outcome branches, resource accounting, calibrated abstention, and append-only successor state. The local code does not prove that hypothesis.

## Challenge-lock v1 contract

The local `preflight-challenge` command requires:

1. a caller-supplied manifest digest and positive sequence, plus a structurally continuous predecessor field;
2. a closed inventory of exact regular-file bytes with no symlinks, hard links, surplus files, duplicate JSON keys, floating-point JSON, obvious private paths, credentials, or prohibited patient fields;
3. actual receipt sets and payloads, replayed rather than trusted through a summary;
4. direct byte-identity linkage from every frozen dossier source to a replayed raw receipt payload; derived transforms are unsupported in v1;
5. receipt freezes no later than the challenge lock and synthetic-only evidence in synthetic protocol scope;
6. the fixed no-clinical, no-human-decision, no-material-execution alpha boundary;
7. declared positive, failed-translation, and ambiguous control roles before any scoring path;
8. exactly two organization-distinct, self-declared encodings of the same evidence and decision dossier for each case;
9. an author-declared residual-containing world partition and a machine-checked total world-by-outcome contract for every encoding; software does not establish semantic exhaustiveness or mutual exclusivity;
10. schema-bound, explicitly unexecuted specifications for all 15 required baseline families;
11. a named domain-separated reveal-commitment scheme; and
12. the provisional v1 metric contract.

The 15 exact baseline families are:

```text
LAB_ACTUAL_CHOICE
CURRENT_STANDARDIZED_WORKFLOW
INDEPENDENT_EXPERT
HUMAN_PLUS_AGENT
FRONTIER_GENERAL_AGENT
POPPER_SEQUENTIAL_FALSIFICATION
RETRIEVAL_ONLY
GRAPH_ONLY
RANDOM
DO_NOTHING_OR_ABSTAIN
BLIND_OFAT
INFORMED_OFAT
BAYESIAN_DESIGN
COST_AWARE_EXPECTED_INFORMATION_GAIN
ORACLE_REPLAY_ONLY
```

Challenge-lock v1 accepts only 3–7 cases and exactly two encoders per case. The larger empirical target requires a future protocol and schema; v1 cannot represent or test it.

The immutable v1 metric is also insufficient for the program goal: it requires
tenfold improvement only versus `CURRENT_STANDARDIZED_WORKFLOW`, noninferiority
otherwise, and has no explicit `SIMPLE_RULE_PREDECLARED` family. It remains
preserved for artifact compatibility. The separate
[goal-claim contract](goal-claim-contract-v1.md) is the mandatory successor gate;
a v1 preflight can never be promoted into successor-goal compliance.

## Hard empirical target

The primary endpoint is the first **correct predeclared decision-state transition sustained on the required replication**, not the first cheap falsification. A domain must predeclare one primary resource estimand; post-hoc choice between time and cost is forbidden. Raw world counts are not an endpoint because authors can inflate them; decision-equivalence classes and externally adjudicated decision loss are required.

The program-level target is:

> In an independently administered, preregistered, parallel or randomized evaluation across at least 30 decision points from at least six laboratories and three domains, reach the correct predeclared decision-state transition using at most 10% of the audited primary resource required by each independently implemented expert, retrieval-only, graph-only, random, and predeclared simple-rule comparator in every domain, under simultaneous uncertainty control, with no increase in false exclusions or authority violations and full independent reproduction.

This is a falsifiable target, not a result. Counterfactual comparisons are admissible only when actions run in parallel, are randomized across sites, or use a complete replay oracle. The analysis must be intention-to-treat and report calendar time, human time, compute, direct cost, assay failure, censoring, repeated seeds, uncertainty, calibration, replication, and authority violations without a composite leaderboard score.

## What the implementation proves—and refuses to prove

A valid bundle exits `3` with `STRUCTURALLY_BOUND_AND_REPLAYED_SCIENTIFIC_SCORING_DISABLED`.

Structural passes establish exact local byte binding, closed inventories, direct receipt-to-dossier digest matches, receipt-report replay, baseline-schema conformance, total authored branches, and immutable in-process alpha policies. They do not establish scientific truth.

The gate vector preserves `NO_CALL` for:

- independent temporal attestation and historical admissibility;
- external currentness or monotonicity of the caller-supplied checkpoint;
- control validity and domain identity beyond author labels;
- encoder independence and blinded field-level agreement;
- privacy certification beyond narrow pattern screening;
- baseline execution or adequacy;
- reveal opening and independent timestamping;
- model-training contamination and historical blinding; and
- outcome adjudication, replication, scientific scoring, biological validity, clinical utility, or health impact.

No patient, human-decision, biological, material, or clinical authority is granted.

## Governance required before scientific scoring

- An independent steward and explicit separation of sponsor, case author, encoder, laboratory, adjudicator, and entrant roles.
- Public registration and version history, statistical analysis plan, power rationale, ranking uncertainty, appeals, and publication of failures.
- Frozen model/version and training-data policies, sealed execution logs, contamination audits, and disclosure of organizer access.
- Lab quality control, assay-failure, replication, stopping, and resource-accounting rules.
- Conflict-of-interest, funding, IP/licensing, embargo, negative-result, privacy, ethics, and data-governance policies.

Self-declared organization IDs, control labels, or domain strings are not substitutes for this governance.

## Usage

Prepare a closed challenge directory, preserve its raw manifest digest and sequence outside the directory, then run:

```bash
causalfrontier preflight-challenge CHALLENGE_ROOT \
  --expected-manifest-sha256 EXTERNALLY_PRESERVED_SHA256 \
  --expected-sequence EXTERNALLY_PRESERVED_POSITIVE_INTEGER
```

Successful structural validation emits canonical JSON and exits `3` because scientific scoring remains disabled. Invalid structure or bytes exit `2`.

## Next gates

1. Publish normative schemas and a generated synthetic challenge bundle after separate release review.
2. Continue the [complete-matrix successor](horse-race-v1.md) from a synthetic
   structural rehearsal to a policy-neutral input tier with fully loaded metering,
   independent terminal truth, and durable external event checkpoints.
3. Implement the applicable locked comparators honestly; never relabel a structural proxy as expert, Bayesian, POPPER, retrieval, graph, laboratory, or current-workflow execution.
4. Run the first score-eligible budget-matched synthetic/replay horse race only after the mandatory comparator set is executable and counterfactual outcomes are complete. The current 36-episode matrix is descriptive only.
5. Kill or redesign the metric if rankings change under reasonable equivalent encodings or a simple strategy matches CausalFrontier.
6. Add independently anchored registration receipts and prove successor continuity against two stores.
7. Implement blinded, field-level encoding comparison with label-invariant alignment and preregistered critical-disagreement rules.
8. Secure at least two external laboratory commitments and establish independent governance before any live case.
9. Keep PCSK9 as known-hindsight calibration only; lock a failed-translation and ambiguous control before any historical score.
10. Only under separate reviewed authorization, register a small read-only live pilot before outcomes exist.

Stop if an outcome-provider network cannot be formed, independent encoders cannot reproduce decision-critical structure, simple baselines match the system, temporal receipts cannot exclude future evidence, counterfactual resources are not identifiable, or users repeatedly mistake structural admissibility for scientific or clinical authority.
