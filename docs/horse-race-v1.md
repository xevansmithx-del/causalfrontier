# Complete-matrix synthetic rehearsal v1

This local, unreleased successor tests whether an evaluation can be made
cherry-pick resistant before anyone treats it as a scientific benchmark. It
creates a preregistration-shaped hash-bound plan and then automatically executes
every case × encoder lane × locked policy coordinate. There is no API parameter
for selecting a favorable case, lane, or policy. The local artifact does not
prove that its checkpoint preceded the opening; temporal order remains `NO_CALL`.

The fixed parameter remains:

```text
OPEN_MACHINE_VERIFIABLE_TRANSLATION_FROM_FRAGMENTED_BIOMEDICAL_EVIDENCE_TO_NEXT_FALSIFIABLE_ACTION
```

## Contract

The plan requires all of the following:

- exactly six synthetic cases;
- exactly two positive, two failed-translation, and two ambiguous controls;
- exactly three declared synthetic domains with two cases each;
- no repeated domain/control cell, with each control spanning two domains and
  each domain spanning two controls;
- exactly two organization-distinct encoder lanes per case, reported separately;
- every policy trace locked from the checkpointed entrant view;
- all 36 coordinates for the current 6 × 2 × 3 reference-policy contract; and
- exact challenge, race, view, selection, envelope, oracle-preflight, and future
  opening checkpoints.

Planning never opens the oracle. Execution replays all cells in canonical order,
starts every episode with a fresh budget, preserves failures and abstentions, and
verifies the challenge before and after the matrix. Missing, duplicate, surplus,
or mutated coordinates fail closed. The plan separately binds the execution-order
rule: terminal policies execute no action, the candidate locks at most one action,
and uniform enumeration is treated as a set whose actual order is the opened
canonical frozen-action identifier order—not secret alias order.

## What the report contains

The steward-only report contains each complete validated episode receipt plus
its compact hash-linked summary, terminal state, adjudication-state counts, and
synthetic resource vector. Encoder lanes are never pooled into policy totals.
It explicitly emits:

```text
winner = null
ranking = []
acceleration_ratio = null
calibration_evaluated = false
scientific_scoring_ready = false
```

The command exits `3` after an integrity-valid structural rehearsal and `2` on
invalid structure, bytes, authority, or episode integrity.

## Why it still refuses to score

The run exposes decisive blockers rather than hiding them:

- the entrant view contains CausalFrontier-derived eligible and co-minimax
  action sets, so it is not a policy-neutral input tier;
- candidate compilation and preprocessing are not in the resource ledger;
- deterministic uniform enumeration is not a random baseline;
- the oracle is depth-one and cannot evaluate adaptive policies;
- classifier-derived branch effects are not independent terminal correctness;
- synthetic tariffs are not measured time, cost, labor, or compute;
- declared domains do not prove independent case generators;
- replicate independence, nonce custody, temporal order, privacy, and rollback
  remain unattested; and
- the required expert, retrieval, graph, current-workflow, agent, OFAT,
  Bayesian, cost-EIG, sequential-falsification, and oracle comparators have not
  executed.

Accordingly, this is a protocol stress-test tool—not a leaderboard. A simple
baseline matching the candidate, encoder instability, control leakage, or an
incomplete matrix is a redesign signal, never something to average away.

## CLI lifecycle

First preserve the returned plan and the SHA-256 of its exact bytes outside the
challenge root:

```bash
causalfrontier prepare-synthetic-horse-race \
  CHALLENGE_ROOT RACE_SPEC ENTRANT_VIEW SELECTION_LOCK \
  SELECTION_ENVELOPE COMMITMENT_PREFLIGHT \
  --expected-manifest-sha256 MANIFEST_SHA256 \
  --expected-sequence N \
  --expected-race-spec-sha256 RACE_SHA256 \
  --expected-view-sha256 VIEW_SHA256 \
  --expected-selection-sha256 SELECTION_SHA256 \
  --expected-selection-envelope-sha256 ENVELOPE_SHA256 \
  --expected-commitment-preflight-sha256 PREFLIGHT_SHA256 \
  --expected-opening-sha256 OPENING_SHA256 > HORSE_RACE_PLAN
```

After the plan is independently checkpointed and the committed synthetic oracle
is opened, run the complete matrix:

```bash
causalfrontier execute-synthetic-horse-race \
  CHALLENGE_ROOT RACE_SPEC ENTRANT_VIEW SELECTION_LOCK \
  SELECTION_ENVELOPE COMMITMENT_PREFLIGHT HORSE_RACE_PLAN ORACLE_ROOT \
  --expected-manifest-sha256 MANIFEST_SHA256 \
  --expected-sequence N \
  --expected-race-spec-sha256 RACE_SHA256 \
  --expected-view-sha256 VIEW_SHA256 \
  --expected-selection-sha256 SELECTION_SHA256 \
  --expected-selection-envelope-sha256 ENVELOPE_SHA256 \
  --expected-commitment-preflight-sha256 PREFLIGHT_SHA256 \
  --expected-plan-sha256 PLAN_SHA256 \
  --expected-opening-sha256 OPENING_SHA256 > HORSE_RACE_REPORT
```

Neither command writes inside the challenge root, performs network access,
executes wet-lab work, grants decision authority, or publishes a claim. Inputs
are contract-restricted to declared synthetic data; bounded pattern screening
does not independently certify the absence of patient-level data.

Preserve and checkpoint the exact report, then verify its portable no-score
contract without rerunning the oracle:

```bash
causalfrontier verify-synthetic-horse-race-report \
  HORSE_RACE_REPORT HORSE_RACE_PLAN \
  --expected-report-sha256 REPORT_SHA256 \
  --expected-plan-sha256 PLAN_SHA256
```

This detects edited winner, ranking, acceleration, calibration, integrity,
episode, or matrix fields. It verifies bytes and internal linkage only; it does
not prove execution custody, temporal order, or scientific truth.
