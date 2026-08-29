# CausalFrontier

CausalFrontier is a pre-alpha compiler for one narrow but potentially important scientific task: turn a frozen evidence package and explicit competing causal worlds into an auditable frontier of next falsification checks.

The long-range idea is a public causal challenge network in which biomedical claims become replayable, adversarially testable objects instead of prose conclusions. This repository is only the first software slice. It shows that a small authored case can be file-bound, open-world through a residual, branch-complete through failure and contradiction, compared without priors, and replayed with checkpointed local memory.

It does **not** discover a drug, infer a causal effect, validate a biological mechanism, recommend care, or save lives. Those goals require independent evidence and validation far beyond this prototype.

## What the prototype does

Given a case directory, the compiler:

1. verifies an exact inventory of public-aggregate or synthetic source files and their SHA-256 digests;
2. validates a *declared* mutually exclusive causal-world partition with exactly one open-world residual;
3. requires every discriminator to predeclare informative, contradiction, execution-failure, and no-call branches;
4. requires a complete world-by-outcome relation matrix plus a closed, digest-bound classifier contract;
5. enforces declared gates, source authority, and a fixed no-clinical/no-material alpha boundary;
6. removes dominated discriminators with a prior-free Pareto comparison over decision-equivalence classes;
7. identifies informative-branch-conditional minimax co-winners without scalarizing resource trade-offs;
8. executes the registered TSV/integer classifier against the exact frozen input and seals its result in the capsule;
9. creates a no-clobber capsule containing frozen inputs, replayable analysis, classifier results, an immutable manifest, and a hash-chained SQLite ledger; and
10. rejects post-hoc branches, requires an independently stored ledger-head checkpoint for every append, and records linked counterfactual branch paths as rehearsals, never observations.

Structural analysis labels an unblocked discriminator `STRUCTURALLY_ADMISSIBLE_UNEXECUTED`. The separate `classify` command and capsule build execute its registered classifier, but that only proves deterministic mapping of the frozen synthetic file to a declared branch. It is not experimental or biological readiness. A contradiction invalidates the current partition, retains only the open residual, clears both frontiers, and requires a newly frozen case.

The fixed project parameter is:

`OPEN_MACHINE_VERIFIABLE_TRANSLATION_FROM_FRAGMENTED_BIOMEDICAL_EVIDENCE_TO_NEXT_FALSIFIABLE_ACTION`

Disease, modality, model, source type, and deployment setting remain deliberately changeable.

## Quick start

From this directory with Python 3.9 or later:

```bash
python -m pip install -e '.[dev]'
causalfrontier analyze examples/synthetic-aggregate
causalfrontier classify examples/synthetic-aggregate
causalfrontier compile examples/synthetic-aggregate /tmp/causalfrontier-capsule
causalfrontier verify /tmp/causalfrontier-capsule
```

Rehearse a branch frozen before compilation:

```bash
causalfrontier simulate \
  examples/synthetic-aggregate \
  experiment:held-out-invariance \
  outcome:held-invariant \
  4fca74e460ea51cd257ab80060da8e594448e9324b2f805ad0f992bcc3e6c0b6
```

Append the rehearsal to capsule memory using the ledger head copied from compilation into an independent checkpoint:

```bash
causalfrontier remember-rehearsal \
  /tmp/causalfrontier-capsule \
  --expected-ledger-head <independently-stored-ledger-head> \
  2026-08-28T21:01:00Z \
  experiment:held-out-invariance \
  outcome:held-invariant \
  4fca74e460ea51cd257ab80060da8e594448e9324b2f805ad0f992bcc3e6c0b6
```

Replace the external checkpoint with the newly returned head after every successful append. This compare-and-swap detects rollback only when the external copy is independently preserved. The operation never mutates the frozen case or analysis.

## Prior-free selection

CausalFrontier accepts no probability, likelihood, posterior, weight, utility, or scalar score fields. Across predeclared informative branches, the Pareto frontier jointly:

- maximizes conditional decision-class reduction and strict `SURVIVES`/`EXCLUDES` pair discrimination;
- minimizes conditional remaining decision classes and each declared resource dimension; and
- treats lexicographic IDs only as display tie-breakers, never scientific preferences.

Failure and no-call make the true all-outcome worst-case reduction zero. The reported minimax is therefore explicitly `INFORMATIVE_BRANCH_CONDITIONAL_MINIMAX`, not an empirical expected-value claim. The rule is conservative, but it is not a substitute for calibrated reasoning once defensible validation data exist.

## Dynamic workflow and persistent memory

```text
freeze evidence, worlds, gates, and every branch
                       |
                       v
             verify and compile
                       |
                       v
       rehearse a declared branch path
                       |
                       v
 append with an external head checkpoint
                       |
                       v
   continue the successor state, or on contradiction
   invalidate the partition and freeze a new case version
```

An empirical result recorder is intentionally absent. The fixture classifier executes only frozen synthetic input; a real result path additionally requires attested evidence receipts, authorization, calibration, and validation. The current ledger remembers compilation and sequential counterfactual rehearsals only. Its SHA chain detects corruption; without the independent head checkpoint it cannot authenticate a database owner or prove currentness.

## Two-week go/kill decision

Continue this representation only if all of these pass:

- three independently authored public-aggregate cases from at least two biomedical domains compile without relaxing the residual, total-branch, or authority rules;
- two encoders working from the same frozen source achieve at least 80% exact agreement on world/outcome cells before reconciliation, with disagreements machine-visible;
- at least two cases eliminate a dominated discriminator and return a nonempty structurally admissible, unexecuted frontier;
- a positive historical control, failed-translation control, and ambiguous control are prospectively hash-committed before held-out outcomes are revealed;
- hostile reviewers cannot add a post-hoc branch, remove the residual, bypass a gate, roll back checkpointed memory, or corrupt the capsule without detection; and
- normal and optimized Python produce the same run and verification digests.

Kill or redesign this schema if residuals make every discriminator non-informative, authored relations masquerade as machine inference, independent encoders cannot reconcile partitions, historical receipts cannot prevent time leakage, or users read the output as efficacy, diagnosis, safety, or treatment advice.

## Verification

```bash
python -m pytest -q
python tests/optimized_probe.py
python -O tests/optimized_probe.py
```

The hostile suite covers schema/type errors, prior and observed-outcome leakage, incomplete matrices, residual removal, contradiction behavior, failure/no-call updates, digest and inventory drift, source-semantics mismatches, omitted gates and authorities, post-hoc branches, partition-refinement bias, capsule tampering, semantic ledger forgery, local rollback with an external checkpoint, sequential branch lineage, and no-clobber publication.

## Nonclaims and safety boundary

- The included aggregate table is synthetic and is not biological evidence.
- Prediction relations, scientific totality/exclusivity, source dates, licenses, coverage, privacy class, and authority are author declarations. The built-in classifier makes the fixture's branch mapping executable; it does not externally attest those scientific declarations.
- Software replay validates structure, local file binding, and deterministic computation only.
- No patient-level data, clinical advice, wet-lab execution, material ordering, pathogen design, or human decision authority is supported.
- A frontier identifies discriminating checks under the declared model, not truth.
- Temporal metadata is labelled `DECLARED_TEMPORAL_METADATA_UNATTESTED`; historical scoring is disabled.
- This prototype has no prospective benchmark and no empirical health-impact result.

See [the architecture decision](docs/architecture.md), [benchmark contract](docs/benchmark.md), [problem-selection record](docs/problem-selection.md), [biomedical tool probe](docs/tooluniverse-probe.md), and [dynamic workflow](docs/dynamic-workflow.md).
