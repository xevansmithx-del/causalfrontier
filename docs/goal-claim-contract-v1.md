# Goal-claim contract v1 — local, unreleased claim firewall

## What changed

The repository's preserved `causalfrontier.challenge-lock.v1` metric does not encode the
program-level goal. It requires tenfold improvement only against the current standardized
workflow and mere noninferiority to the strongest computational baseline; it also has no
explicit simple-rule family. A future green result under that metric could therefore miss
the stated objective.

This successor does **not** alter challenge v1 or reinterpret its artifacts. It adds a
separate immutable contract and a strict, pre-outcome plan preflight:

```text
causalfrontier.goal-claim-contract.v1
  -> causalfrontier.goal-claim-plan.v1
  -> exact caller checkpoint
  -> preflight-goal-claim-plan
  -> GOAL_CONFORMANT_CLAIM_PLAN_BOUND_OUTCOMES_AND_SCORING_DISABLED
```

The output is a structural `NO_CALL`. It machine-verifies the closed plan shape, exact
checkpoint, and required digest relationships for the harder comparison. It does not prove
that a comparator semantically conforms to its named family, that any benchmark case,
laboratory, controller, or implementation is independent or prospective, that any system was
executed, or that a tenfold result exists.

## Immutable success conjunction

The contract fixes the primary endpoint as the first correct, predeclared,
decision-relevant falsification that excludes at least one live decision-equivalence class
and is sustained on required replication. The resource ratio is always:

```text
comparator primary resource / candidate primary resource
```

The claimed threshold is at least `10 / 1`. It must hold as a simultaneous one-sided lower
confidence bound for every declared scientific domain crossed with every mandatory family,
as well as the pooled claims:

1. `INDEPENDENT_EXPERT`
2. `RETRIEVAL_ONLY`
3. `GRAPH_ONLY`
4. `RANDOM`
5. `SIMPLE_RULE_PREDECLARED`

`BLIND_OFAT`, `INFORMED_OFAT`, or `CURRENT_STANDARDIZED_WORKFLOW` cannot be renamed into the
simple-rule coordinate. The contract requires at least three domains, at least ten
primary decision points and two case-linked laboratories in every domain, and therefore
at least thirty primary decision points and six laboratories globally. Every primary case has exactly one
declared laboratory assignment, and every laboratory declared within a domain must be used
by at least one primary case. Those identifiers and assignments are necessary plan fields,
not software proof of domain, laboratory, or controller independence.

The plan must use exactly one primary resource per domain—calendar minutes or fully loaded
cost in standardized USD minor units—before outcome access. Preprocessing, retrieval, model and tool calls,
retries, human labor, compute, calendar time, and direct cost remain in scope. Synthetic
tariffs and same-process telemetry cannot support the program claim. A v1 cost domain must bind
`USD` and an exact `YYYY-MM-DD` price-basis date; a
calendar-minute domain must set both fields to `null`. Every domain binds a positive common
horizon in minutes plus resource-basis, complete-ledger, and common-horizon contract digests.

The plan selects exactly one execution design before outcome access:
`PARALLEL_RANDOMIZED` or `COMPLETE_REPLAY_ORACLE`. The execution section must repeat the
top-level common-input digest exactly. The candidate and all five comparators must bind the
same resource-meter contract, and the execution resource-parity digest must equal that meter
digest. These equalities prevent a structurally different input or meter from being smuggled
into one arm; they do not validate the meter's scientific or economic adequacy.

## Failure, censoring, and uncertainty

The firewall freezes rules that otherwise create easy post-hoc wins:

- every precommitted primary-case × candidate/comparator cell stays intention-to-treat;
- no best domain, case, seed, expert, model, or comparator may be selected;
- a candidate that does not reach the endpoint fails every affected claim cell;
- an unreached comparator supports only a right-censored lower bound backed by a complete
  resource ledger through the precommitted common horizon that already proves the threshold;
  otherwise the result is `NO_CALL`;
- a missing or incomplete resource ledger is `NO_CALL`, never favorable censoring, and
  failed, censored, or expensive runs cannot be favorably omitted;
- resource values must be strictly positive; zero never becomes infinity;
- one Bonferroni-adjusted 95% familywise-error budget covers every acceleration,
  false-exclusion, coverage, and selective-risk bound across every required domain and pooled
  cell; success requires the complete intersection, not separate 95% families;
- laboratory and domain clustering must be represented by the frozen analysis
  implementation;
- false exclusion uses `candidate - matched comparator` false-exclusion rate, with a zero
  margin and global-family-adjusted one-sided upper bounds at or below zero in every domain
  and pooled;
- every authority violation invalidates the affected run and blocks the claim; and
- calibrated abstention must, in every domain, pass global-family-adjusted one-sided lower
  bounds of at least 50% coverage and upper bounds of at most 5% selective risk.

The preflight accepts declarations for analysis, power, abstention, and false-exclusion
implementation digests but does not receive their preimage bytes or review their statistical
correctness. The corresponding report gate is structural-rule-literals only, not an
implementation pass. Independent artifact review remains required.

## Prospective and calibration separation

Primary performance cases must be declared `PROSPECTIVE_BLIND_ONLY`. Known-hindsight cases
are `CALIBRATION_ONLY_NEVER_PRIMARY_PERFORMANCE`. Each domain must contain exactly one unique
calibration case for each role, in canonical order: `POSITIVE`, `FAILED_TRANSLATION`, and
`AMBIGUOUS`. Calibration and primary IDs are disjoint within and across domains. Calibration
cases never count toward the thirty primary decision points or the execution matrix. In
particular, PCSK9 before FOURIER is a method-recovery control, not a prospective discovery.

The separate top-level calibration contract fixes what each role must demonstrate:

1. `POSITIVE` passes a predeclared method-recovery criterion.
2. `FAILED_TRANSLATION` passes a predeclared failed-translation rejection criterion.
3. `AMBIGUOUS` passes a predeclared ambiguity-abstention criterion.

It also binds the control-oracle commitment, control-scoring protocol and implementation,
and semantic-validity review protocol. Any required control failure in any domain blocks
primary scoring and yields `NO_CALL`; calibration controls never enter primary effect
estimation. The plan must set current control semantic validity false. Digests and role labels
do not establish that a historical case is a valid control.

The current three historical examples remain useful role archetypes:

- PCSK9 → FOURIER as the bounded-positive calibration;
- BACE1/verubecestat → EPOCH and APECS as failed translation; and
- remdesivir → ACTT-1 and final WHO Solidarity as an ambiguous, context-dependent result.

One archetype in a different domain for each role perfectly confounds control role with
scientific domain. The three-case set can exercise ingestion, temporal separation, branch
totality, and abstention only; it cannot satisfy this successor schema or be scored. At the
minimum three domains, the structural plan therefore contains nine calibration cases: all
three roles in every domain. Modern models also know these historical outcomes, so balancing
roles or renaming entities does not make them leakage-resistant or prospective.

## Closed plan shape

Every object has an exact key set. There are no extension dictionaries or arbitrary prose
fields. The top-level plan binds:

| Section | Required content |
|---|---|
| Identity | schema, status, plan ID, sequence, fixed parameter, exact boundary, contract digest, semantic plan digest |
| Cohort | exact cohort checkpoint; at least three sorted domains; exactly one positive, failed-translation, and ambiguous calibration per domain; sorted primary cases and laboratories; complete primary-case-to-laboratory assignments; knowledge cutoff; and explicit resource/currency/date/horizon fields and digests |
| Calibration | canonical recovery, failed-translation, and ambiguity-abstention criteria; oracle commitment; scoring protocol and implementation; semantic-review protocol; any-control-failure `NO_CALL`; strict separation from primary effects; current semantic validity fixed false |
| Candidate | public source tree/archive, dependency lock, build recipe, implementation, environment, protocol, common resource meter, controller disclosure, independence protocol, and domain-separated binding |
| Comparators | exactly one canonically ordered declaration for each mandatory family, with policy, family-conformance protocol and implementation, environment, common meter, controller disclosure, independence protocol, and binding digests; selected structural digests must not alias |
| Execution | one selected allowed design, exact shared-input equality, assignment, total endpoint adjudication, exact common-meter resource parity, and complete primary-case × six-policy and domain/pooled claim-cell counts |
| Analysis | endpoint, ratio, threshold, domain conjunction, ITT, one global Bonferroni family over acceleration, false exclusion, coverage, and risk, clustering, missingness, censoring, zero-resource, numeric abstention and false-exclusion inference, and no-best-selection rules |
| Leakage | prospective-blind primary timing, calibration-only hindsight, frozen model/tool inventory, network policy, temporal audit, training-contamination review, and no post-cutoff access |
| Privacy/authority | only public aggregate or synthetic data, no patient-level data, exact fixed boundary, zero authority violations, and a review protocol |
| Provenance | evidence-receipt, exact source-inventory, transformation-lineage, execution-trace, analysis-artifact-lineage, and independent-witness protocol digests; exact required state `EXACT_END_TO_END_PROVENANCE_PASS_BEFORE_OUTCOME_ACCESS_OR_CLAIM_NO_CALL`; current verification fixed false |
| Gates | temporal, provenance, privacy, authority, branch totality, rollback/equivocation, hostile input, common-input parity, oracle totality, real-resource accounting, and role separation |
| Reproduction | one controller-disjoint independent organization/reproducer, clean build, byte-identical artifacts, complete matrix and analysis replay, plus an independent holdout bound to this exact goal-contract digest and the complete domain × comparator conjunction; current verification fixed false |
| Usability | a bound population definition and study protocol; twelve non-contributor early-career participants from at least two independent organizations and three domains; at least 80% unaided completion; median at most 120 minutes; zero authority errors; current verification fixed false |
| Openness | public Apache-2.0 source, public/synthetic data only, reproducible build, publication-plan digest, and no publication authority |

Except for the exact caller-checkpointed plan bytes and hashes deterministically recomputed
from the contract, plan, candidate/comparator declaration objects, and preflight report, all
referenced non-checkpoint artifact hashes are digest declarations. Their preimage bytes are
not supplied to this interface, opened, or independently verified.

The usability numbers are an intentionally difficult program criterion, not an observed
result. They should receive external methodological review before any public benchmark is
registered.

Primary and calibration case IDs are globally unique and disjoint. Primary IDs contribute
to the thirty-case minimum and complete execution matrix; calibration IDs never do. Every
domain binds the complete case/laboratory geometry and one predeclared resource definition.
The acceleration cell set contains five comparator cells per domain plus five pooled cells;
at the three-domain minimum that is twenty acceleration cells, not fifteen. The single global
inferential family additionally includes every required false-exclusion, coverage, and
selective-risk bound.

## Command and exit semantics

Preserve the exact plan bytes and compute their SHA-256 outside the tool, then run:

```bash
causalfrontier preflight-goal-claim-plan GOAL_CLAIM_PLAN.json \
  --expected-plan-checkpoint-sha256 EXACT_RAW_PLAN_SHA256
```

A valid structural plan emits canonical JSON and exits `3`, the project's abstention code.
Invalid bytes, schemas, bindings, thresholds, counts, gates, authority boundaries, result
fields, or checkpoints emit no JSON and exit `2`.

The API exposes:

```python
from causalfrontier import (
    goal_claim_contract,
    goal_claim_contract_sha256,
    preflight_goal_claim_plan,
)
```

`goal_claim_contract()` returns a fresh copy. Mutating that copy cannot change validation.
The CLI deterministically rebuilds the preflight from the exact plan before emission, so a
coherently rehashed but altered report is rejected.

## Hostile boundary

The validator rejects duplicate keys, floats, non-finite numbers, all-zero placeholder
digests, unknown fields, reordered or duplicate identifiers, symlinks, hard links,
checkpoint mismatch, semantic-hash mismatch, and a second-read substitution. It recursively
rejects named outcome, result, winner, ranking, score, reveal, oracle-opening, effect,
confidence-interval, and p-value fields. Inputs are screened for private paths and credential
patterns.

The forbidden-key screen is not semantic leakage detection. Opaque IDs and referenced
artifacts can still encode outcomes or known hindsight. Equal input or meter digests do not
prove semantic symmetry or correct accounting. Distinct system IDs and nonaliased implementation,
policy, controller-disclosure, independence-protocol, family-conformance, and binding
digests prove only structural separation of declarations. They do not inspect executable
behavior, prove that `RANDOM` is random, establish expert or controller independence, or
verify semantic conformance to any named comparator family. The preflight therefore reports
domain semantic validity, cohort admission, generator independence, control semantic
validity, comparator-family conformance, controller independence, and provenance
verification false. The domain geometry gate verifies only declared counts and assignments.
The model/tool freeze, temporal witness, steward-only oracle,
provenance witness, privacy review, and hostile-input protocols remain external gates and are
reported unverified.

Normal Python, optimized Python (`-O`), and different hash seeds must produce identical
contract and preflight bytes. CI runs the assertion-independent probe in all of those modes.

## Nonclaims

Passing preflight does not establish:

- scientific or domain validity;
- cohort admission or generator independence;
- prospective timing, leakage resistance, or independent custody;
- calibration-control semantic validity or successful control behavior;
- semantic comparator-family conformance, executable distinctness, or correct randomness;
- authorship, laboratory, expert, organization, implementation, or controller independence;
- privacy certification or patient-data absence outside the bound plan;
- executed or independently witnessed end-to-end provenance;
- complete oracle truth or correct statistics;
- real-resource measurement;
- comparator execution, a winner, or tenfold acceleration;
- independent reproduction or early-career usability;
- biological, clinical, patient, material, safety, efficacy, or health impact; or
- publication, release, wet-lab, human-decision, or clinical authority.

Those are future evidence requirements. The purpose of this tool is narrower and essential:
make it impossible for the project to answer an easier question while believing it answered
the legacy goal.
