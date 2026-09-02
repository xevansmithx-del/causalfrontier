# First-slice benchmark contract

## Purpose

The bundled `synthetic-aggregate` fixture tests software behavior, not biology. It represents a tiny aggregate perturbation-response table with three contexts, two interventions, one response index, and one negative-control index. All values are invented integers. There are no people, samples, sequences, compounds, pathogens, or material instructions.

The evidence file is frozen at:

```text
evidence/aggregate_response.tsv
SHA-256 e0035faad7a9ade27d6d6e259e338208d68cec0ce4211361ad9b92e9b3dea627
```

## Declared worlds

The fixture contains three operationally exclusive worlds:

1. the aggregate response is invariant enough to keep a mechanism-oriented read-only check eligible;
2. the response is primarily explained by context-linked confounding; and
3. a residual explanation outside the named model set.

The residual maps only to defer. The other worlds map to one substantive read-only lane plus defer.

These relations are authored declarations. The compiler binds and analyzes them but does not derive them from the table.

## Discriminators

| Identifier | Read-only protocol | Resource distinction | Expected status |
|---|---|---|---|
| `experiment:held-out-invariance` | Apply an authored frozen contrast rule to the held-out row | Shorter, one external dependency | Structural Pareto/conditional-minimax co-winner |
| `experiment:negative-control` | Apply an authored control/context rule | Longer, zero external dependencies | Structural Pareto/conditional-minimax co-winner |
| `experiment:global-recompute` | Recompute all context contrasts | More expensive on every dimension than held-out check | Dominated |

Every discriminator has two informative branches plus contradiction, execution failure, and no-call. Its prediction matrix has exactly 15 cells: three worlds by five outcomes.

## Frozen expected result

With CausalFrontier `0.1.0a2`, the exact baseline run identifier is:

```text
0a28022c6e31be13d09a57a3d5bdddfc644962740e032183f441827572faf7c0
```

The structurally-admissible-unexecuted and conditional-scientific-structure Pareto frontiers both contain:

```text
experiment:held-out-invariance
experiment:negative-control
```

Both are informative-branch-conditional minimax co-winners. The held-out experiment is displayed first only because its identifier sorts first. No scientific preference is inferred from that ordering. Each classifier is executable and digest-bound for this synthetic TSV, but its thresholds and mapping remain authored and have no biological calibration.

## Hostile benchmark cases

The automated suite must continue to reject or detect:

- duplicate JSON keys and floating-point fields;
- prior, posterior, and observed-outcome leakage;
- an edited branch plan under an old digest;
- a missing outcome class or prediction cell;
- an informative branch that removes the residual;
- a failure branch that changes world state;
- a contradiction that removes the open residual or regenerates the invalidated frontier;
- multiple residual worlds;
- clinical authority inside the alpha boundary;
- source digest drift and unmanifested files;
- source semantic/data-class mismatches and omitted gate or source authorities;
- post-hoc outcome identifiers;
- capsule analysis tampering;
- removed ledger append-only triggers; and
- a locally rolled-back ledger checked against an independently preserved head;
- a forged or discontinuous counterfactual branch path; and
- decision-selection changes caused only by duplicating an equivalent world;
- an attempt to overwrite an existing capsule.

The normal and `python -O` probes must produce the same run identifier and frontier. The probe contains no `assert` statements, so optimization cannot erase its checks.

## Benchmark ladder after the first slice

The next evaluation should add, in order:

1. three independently encoded public-aggregate biomedical cases;
2. duplicate blinded encodings to measure author-dependence;
3. extend the digest-bound executable classifier contract from the completed synthetic slice to independently attested public evidence;
4. adversarial case authors attempting post-hoc leakage;
5. versioned corrections that supersede rather than mutate old cases; and
6. a prospectively hash-committed historical challenge with a positive, failed-translation, and ambiguous control; and
7. only after those pass, a prospective benchmark designed and reviewed by domain experts.

No step in this ladder grants clinical authority. Any real biological or health-impact claim requires separate empirical validation and governance.

The local unreleased [scientific-decision challenge](scientific-decision-challenge.md) turns this ladder into a machine-enforced cohort preflight. It requires all three declared control roles, two organization-distinct encodings per case, replayed receipt-to-dossier byte and acquisition-semantic binding, one shared dossier/gate/action contract, and 15 schema-bound comparator families. Encoder worlds and prediction relations remain separate sensitivity strata. Scientific scoring remains disabled, with explicit `NO_CALL` gates for control validity, independence, temporal admissibility, privacy certification, checkpoint monotonicity, baseline execution, reveal opening, and adjudication.

Challenge-lock v1 does not encode the full program objective: its tenfold rule
targets current standardized workflow and only requires noninferiority otherwise.
The [goal-claim contract](goal-claim-contract-v1.md) therefore precedes any future
scoring registration and requires tenfold simultaneous lower bounds for every
declared domain × independent-expert/retrieval/graph/random/predeclared-simple-rule
cell plus all five pooled cells. One global familywise error budget covers those
acceleration bounds together with false-exclusion, abstention-coverage, and
selective-risk bounds. Each domain must bind at least ten primary cases, two
case-linked laboratories, and all three calibration roles; any control failure is
`NO_CALL`, and controls never enter primary effects. Comparator, control,
provenance, reproduction, and usability artifact digests remain declarations until
their preimage bytes and execution are independently verified. Historical hindsight
controls remain calibration-only.

The local unreleased [calibration tripwire v1](calibration-tripwire-v1.md)
executes the first inseparable positive/failed-translation/ambiguous plumbing
check without enabling benchmark scoring. Its checked-in biomedical pilot is a
negative result: CausalFrontier emits `NO_CALL` for every input and therefore
matches only the ambiguous role label, while the always-advance simple rule
matches only the positive role. Both are 1/3 diagnostics; neither is a winner.
Because the output is only a three-way label, action semantics, total branches,
independent adjudication, calibrated abstention, temporal custody, real resource
measurement, and cross-domain generality remain unverified. This does not
complete ladder step 6 or supply any primary benchmark case.

The hostile challenge suite additionally rejects forged receipt summaries, malformed receipt reason types, unrelated receipt and dossier capsules, receipt/case acquisition-semantic disagreement, post-lock receipt freezes, missing or oversized case sources, cross-encoding decision or action-contract drift, arbitrary or mislabeled baseline JSON, role/media mismatches, synthetic-scope relabeling, policy-set mutation, and external sequence or predecessor inconsistency. These are software-integrity tests, not adjudication of declared controls, domains, evidence dates, encoder world agreement, or scientific correctness.

The separate [synthetic protocol exercise](protocol-exercise-v1.md) locks three deterministic reference selections before reveal and verifies a total committed case/action/replicate branch table afterward. It does not derive outcomes from hidden observation bytes, execute the 15 required scientific baselines, audit resources, or compute an acceleration result.

## Local unreleased neutral ordering fixture

The separate [neutral baseline substrate](neutral-baselines-v1.md) uses a local
synthetic factor/action fixture to exercise common-input parity and ordering. The
current fixture has two factors, one exact common baseline, three authorized
single-factor actions covering every nonbaseline value, and one authorized interaction
action. Three 32-byte seeds are each committed in the context of the authorized
action-universe digest, then each orders all four authorized actions. Blind and informed
OFAT each order the three proved single-factor actions; the interaction is deliberately
outside OFAT geometry. The shared synthetic budget funds three reset/action pairs after
one full four-action selection scan, so random traces retain an explicit budget skip
rather than silently changing the universe.

The neutral hostile/regression file contains 17 tests, and the focused public API/CLI
plus neutral slice contains 29 tests. Its assertion-independent normal, `python -O`,
and alternate-hash-seed probes are byte-identical; SHA-256 of each exact emitted JSON
stream, including the terminal newline, is:

```text
b4ea90ee210fbb046d32273845b84dc4611cb972aa0740c1664b34665c326bc0
```

This fixture is protocol plumbing, not an additional scientific benchmark or an
execution of any required scientific baseline family. It reads no outcome and supports
no semantic-neutrality, scientific-validity, real-resource, impact, 10x, currentness,
or rollback-protection claim.
