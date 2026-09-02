# Neutral baseline substrate v1

## Status and boundary

This is a **local, unreleased synthetic protocol exercise**. The word “baseline” names
three ordering protocols in the software; it does not mean that a scientific baseline
has been executed or validated. The exercise reads no outcome and emits
`scientific_baseline_families_executed = []`, `winner = null`, `ranking = []`,
`acceleration_ratio = null`, `real_resource_verified = false`, and
`scientific_scoring_ready = false`.

The substrate only checks that several orderings can start from the same exact embedded
organizer input, remain within the same synthetic counter budget, and replay from exact
checkpointed bytes:

```text
CHECKPOINTED_CATALOG_WITH_EMBEDDED_COMMON_INPUT
  -> PLAN_ALL_SEEDS_AND_BOTH_OFAT_CELLS_WITHOUT_OPENING_SEEDS
  -> OPEN_EVERY_SEED_AND_LOCK_EVERY_ORDER_WITHOUT_READING_OUTCOMES
  -> REPLAY_ORDERED_RESET/ACTION_COUNTER_EVENTS
  -> VERIFY_EXACT CHECKPOINTS, BINDINGS, ORDERS, AND SCORE CORES
```

It makes no biological, causal, clinical, patient, material, safety, efficacy, health-
impact, scientific-impact, 10x, scientific-baseline, semantic-neutrality, real-resource,
currentness, or rollback-protection claim.

## Command sequence

The local CLI exposes the artifact transitions directly:

```bash
causalfrontier validate-neutral-action-catalog CATALOG \
  --expected-catalog-checkpoint-sha256 CATALOG_CHECKPOINT_SHA256

causalfrontier neutral-commit-seed CATALOG SEED_FILE \
  --expected-catalog-checkpoint-sha256 CATALOG_CHECKPOINT_SHA256 \
  --expected-seed-checkpoint-sha256 SEED_FILE_CHECKPOINT_SHA256

causalfrontier prepare-neutral-baseline-plan CATALOG \
  --expected-catalog-checkpoint-sha256 CATALOG_CHECKPOINT_SHA256 \
  --seed-commitment-sha256 COMMITMENT_1 \
  --seed-commitment-sha256 COMMITMENT_2

causalfrontier lock-neutral-baseline-orders CATALOG PLAN \
  --expected-catalog-checkpoint-sha256 CATALOG_CHECKPOINT_SHA256 \
  --expected-plan-checkpoint-sha256 PLAN_CHECKPOINT_SHA256 \
  --seed-opening SEED_FILE_1 SEED_FILE_1_SHA256 \
  --seed-opening SEED_FILE_2 SEED_FILE_2_SHA256

causalfrontier exercise-neutral-baselines CATALOG PLAN LOCK \
  --expected-catalog-checkpoint-sha256 CATALOG_CHECKPOINT_SHA256 \
  --expected-plan-checkpoint-sha256 PLAN_CHECKPOINT_SHA256 \
  --expected-lock-checkpoint-sha256 LOCK_CHECKPOINT_SHA256

causalfrontier verify-neutral-baseline-exercise CATALOG PLAN LOCK REPORT \
  --expected-catalog-checkpoint-sha256 CATALOG_CHECKPOINT_SHA256 \
  --expected-plan-checkpoint-sha256 PLAN_CHECKPOINT_SHA256 \
  --expected-lock-checkpoint-sha256 LOCK_CHECKPOINT_SHA256 \
  --expected-report-checkpoint-sha256 REPORT_CHECKPOINT_SHA256
```

Repeat both the commitment option and the paired seed-opening option for the full
precommitted schedule. `exercise-neutral-baselines` also accepts
`--capture-observational-telemetry`; capture remains non-score-relevant. Each successful
neutral command emits a structural artifact and exits `3`, the project's structural-
abstention code. Preserve each emitted JSON file byte-for-byte and pass the SHA-256 of
those exact bytes to the next transition.

## Exact embedded common input

The catalog embeds the complete `causalfrontier.common-policy-input.v1` object by value;
it does not merely point to an organizer-controlled file. The catalog also repeats the
object's semantic digest as `common_input_sha256`, and validation requires that value to
equal the digest inside the embedded object.

The common input has an exact closed key set:

| Field | Bound value or meaning |
|---|---|
| `schema_version` | `causalfrontier.common-policy-input.v1` |
| `status` | `DECLARED_PRECOMPILATION_SYNTHETIC_COMMON_POLICY_INPUT_STRUCTURAL_NEUTRALITY_ONLY` |
| `scope` | `SYNTHETIC_PROTOCOL_TEST` |
| `case_id`, `knowledge_cutoff` | Must equal the enclosing catalog values |
| `fixed_parameter`, `boundary` | Must equal the compiler's fixed parameter and boundary |
| `dossier_sha256` | Declared synthetic dossier digest |
| `source_artifact_sha256s` | Nonempty, unique, sorted SHA-256 inventory |
| `granted_authorities` | Nonempty sorted subset of `SOFTWARE`, `SYNTHETIC_DATA` |
| `gates` | Canonically ordered `gate_id`/`status`/`authority` records; status is `PASS` or `OPEN` |
| `factor_space_sha256` | Domain-separated binding of factors and the common baseline assignment |
| `actions` | Canonically ordered action IDs, execution class, required gates and authorities, and payload digests |
| `candidate_derived_fields_absence_declared` | Exactly `true` |
| `semantic_blinding_verified` | Exactly `false` |
| `common_input_sha256` | SHA-256 of the canonical object without this field |

The enclosing catalog labels this tier
`EXACT_EMBEDDED_DECLARED_PRECOMPILATION_ACTION_AND_AUTHORITY_INPUT_STRUCTURAL_NEUTRALITY_ONLY`.
“Declared precompilation” is a required label, not proof that an independent witness
observed the catalog before compilation.

Every common-input action is restricted to `READ_ONLY_COMPUTATION`. Its required gate
IDs must exist, and its required authorities must be a subset of the two synthetic/
software authorities. The catalog derives each action's `PASS` or `BLOCKED` execution
gate only from those embedded grants and gate states; a separately authored catalog gate
result is rejected.

The recursive catalog scan rejects the named candidate-derived keys `analysis_sha256`,
`co_minimax_action_ids`, `current_status`, `decision_separating`,
`eligible_action_ids`, `frontier`, `minimax`, `pareto`, and
`selection_projection_sha256`, including when nested. This is a closed software check
for those field names, not proof of semantic blinding or neutral authorship.

## Factor space and action-payload binding

Factors use unique contiguous one-based neutral order indices. Each factor declares a
categorical or ordinal value kind, between two and 64 canonically ordered values, and
one baseline value. Value IDs are globally unique. The common baseline assignment must
cover every factor in factor order and exactly match every factor's baseline value.

The embedded factor-space digest is replayed as:

```text
SHA256(
  b"causalfrontier.neutral-factor-space.v1\0" ||
  canonical_json({"factors": factors, "baseline_assignment": baseline_assignment})
)
```

Each catalog action contains a complete factor assignment, one unique nonbaseline
assignment, an execution gate, and separate reset and action tariffs. The embedded
common-input action carries a digest of the exact executable payload:

```text
SHA256(
  b"causalfrontier.neutral-action-payload.v1\0" ||
  canonical_json({
    "action_id": action_id,
    "assignment": assignment,
    "action_tariff": action_tariff,
    "reset_tariff": reset_tariff
  })
)
```

The common-input and catalog action inventories must have the same IDs and neutral
indices. The catalog must contain exactly one authorized single-factor action for every
nonbaseline factor value; duplicate assignments and a duplicate of the common baseline
are rejected. Interactions may also be present. The authorized universe is bound
separately to the case ID, factor-space digest, and the sorted pairs of authorized action
ID and action-payload digest. Thus changing factor geometry, a tariff, an assignment, an
authority gate, or the authorized action set requires new consistent bindings.

These bindings establish byte-level structural agreement only. They do not establish
that the factors are scientifically meaningful, that an assignment is a valid
intervention, or that the action descriptions are semantically neutral.

## Precommitted multi-seed portable random ordering

The plan requires between two and 128 distinct seed commitments. A seed is exactly 32
bytes, and its commitment is context-bound to the authorized action universe:

```text
SHA256(
  b"causalfrontier.seed-commitment.v1\0" ||
  bytes.fromhex(authorized_action_universe_sha256) ||
  seed
)
```

The same seed therefore has a different commitment under a different authorized
universe. This binding still does not prove entropy quality, generation, custody, or
secrecy. The plan assigns contiguous one-based seed indices and freezes one random-policy matrix
cell per commitment, followed by one blind-OFAT cell and one informed-OFAT cell. Planning
opens no seed and reads no oracle. The lock must later receive every opening in schedule
order, reject duplicate seed bytes, and match every commitment. Every seed trace and
receipt is retained; best-seed selection and winner aggregation are disabled.

For each opened seed, the portable random protocol starts from all organizer-authorized
action IDs sorted lexicographically and performs Fisher–Yates without replacement. At
each swap it hashes:

```text
b"causalfrontier.seeded-uniform-shuffle.v1\0" ||
seed ||
bytes.fromhex(authorized_action_universe_sha256) ||
counter.to_bytes(8, "big")
```

The 256-bit block is accepted only below the largest multiple of the current bound less
than `2**256`; the accepted integer modulo the bound supplies the swap index. The
counter advances for every block. This construction makes the order replayable without
Python's RNG or hash-table iteration and leaves organizer neutral indices out of the
random starting universe. It does not attest seed entropy, generation, custody, secrecy,
timing, or absence of organizer influence.

## Blind and informed OFAT

Both OFAT protocols operate only on the proved single-factor geometry. Before every
action, the protocol records a reset to the exact common baseline. Neither OFAT order
includes an interaction action.

- `BLIND_OFAT_V1` orders factors by their neutral index and, within each factor, orders
  nonbaseline values by neutral value index. It does not read the informed prior.
- `INFORMED_OFAT_V1` orders the same complete set by precommitted factor rank, then the
  within-factor nonbaseline value rank, with neutral factor/value indices as deterministic
  tie-breakers. The catalog must bind a complete prior with a cutoff no later than the
  catalog cutoff, one rank for every factor, one rank for every nonbaseline value, a rubric
  digest, and a sorted source-receipt digest inventory.

The informed prior is visible in the common catalog checkpoint before planning and is
available to every protocol. Its declared independent authorship, source validity,
temporal admissibility, and independence are not verified. Neither OFAT protocol reads
an outcome, adapts its order, or establishes scientific design validity.

## Protocol counters and observational telemetry

The deterministic score core has seven counter dimensions, in this exact order:

```text
policy_invocations
selection_operations
reset_batches
action_batches
authorized_tool_units
oracle_bytes_delivered
classifier_invocations
```

The accounting mode is
`SYNTHETIC_STEWARD_DERIVED_PROTOCOL_COUNTERS_NOT_REAL_RESOURCES`. Every trace first
debits one `POLICY_SELECTION` event with one policy invocation and one selection
operation per catalog action. Each affordable action then debits a
`RESET_TO_COMMON_BASELINE` event and an `ACTION_PROTOCOL_BATCH` event as one atomic
budget decision; if their combined tariff does not fit, the action is recorded as
`BUDGET_NOT_AFFORDABLE` and neither debit is applied. Events bind sequence, predecessor,
kind, action, debit, before vector, and after vector in a deterministic hash chain.

These counters describe authored protocol operations. They are not measurements of
elapsed time, compute, labor, money, energy, network use, tool quality, or fully loaded
resources, and they cannot support a real-resource or 10x claim.

Optional observational telemetry is stored beside, never inside, the deterministic
score core. When enabled it records monotonic wall time, process CPU time, optional
`RUSAGE_SELF` user/system CPU, and a platform-labelled raw maximum-RSS high-water mark.
Its registered scope is `CURRENT_PROCESS_CUMULATIVE_NOT_ISOLATED`; process-tree
completeness is `false`, measurement trust is `UNVERIFIED`, and `score_relevant` must
remain `false`. The telemetry has its own digest, and the full receipt binds both the
score-core and telemetry digests. Environment-dependent telemetry may therefore change
the full receipt while the replayed score-core digest remains identical.

## Verifier output and mandatory false flags

The verifier reopens the exact catalog, plan, lock, and report checkpoints; replays all
bindings and orders; rebuilds each deterministic score core; validates telemetry shape
and score separation; and retains every committed seed receipt. It may emit these
positive software-integrity flags:

- `telemetry_score_separation_valid = true`
- `all_precommitted_seed_receipts_retained = true`
- `common_input_structural_neutrality_verified = true`
- `factor_space_and_action_payloads_replayed = true`
- `execution_gate_derivation_verified = true`

The phrase “structural neutrality” is limited to the closed field, digest, inventory,
and gate checks above. The verifier is required to emit all of these flags as `false`:

- `semantic_policy_neutrality_verified`
- `precompilation_timing_and_currentness_verified`
- `rollback_protection_verified`
- `authority_declarations_attested`
- `telemetry_authenticity_verified`
- `cohort_uniqueness_verified`
- `real_resource_verified`
- `scientific_scoring_ready`

Its fixed nonclaims state that verification proves exact checkpoint and deterministic
protocol replay, not scientific validity or impact; byte agreement does not establish
semantic policy neutrality; no independent witness establishes precompilation timing,
source custody, currentness, or rollback protection; authority, seed entropy, telemetry,
real resources, and cohort uniqueness remain unattested; and no outcome, winner,
scientific score, or acceleration ratio was verified.

## Local hostile and optimization record

The current focused neutral hostile/regression suite contains 17 tests. The combined
public API/CLI plus neutral slice contains 29 passing tests. The 17 hostile/regression
tests cover:

1. the complete case-level, seed-complete, replayable, no-score pipeline and verifier flags;
2. full-authorized-universe random ordering versus the proved OFAT subset;
3. universe-bound seed-commitment and portable-shuffle golden vectors;
4. recursive candidate-output rejection, complete OFAT geometry, and unique assignments;
5. factor-space and action-payload replay after coherent outer rehashing;
6. derived gate replay and rejection of catalog actions absent from the common input;
7. random-order invariance to organizer action reindexing;
8. complete, pre-cutoff, explicitly unverified informed-prior declarations;
9. rejection of phantom tariff operations, counter overflow, and underfunded OFAT;
10. multiple distinct seed commitments and exact openings;
11. checkpointable ordered-action-reference bounds;
12. event-derived counters and budget non-overrun;
13. rejection of a fully rehashed forged score core;
14. telemetry variation without score-core variation;
15. rejection of fully rehashed attempts to promote telemetry into the score;
16. registered telemetry provider/scope and RSS-coherence checks; and
17. exact external-checkpoint mismatch rejection.

The 29-test slice is this exact command:

```bash
pytest -q tests/test_neutral_api_cli.py tests/test_cli.py tests/test_neutral_baselines.py
```

`tests/neutral_optimized_probe.py` is assertion-independent. Its normal, `python -O`,
and alternate-`PYTHONHASHSEED` outputs are byte-identical. SHA-256 of each exact emitted
JSON byte stream, including its terminal newline, is:

```text
b4ea90ee210fbb046d32273845b84dc4611cb972aa0740c1664b34665c326bc0
```

This is a local working-tree reproducibility record, not a release, scientific result,
timestamp, independent checkpoint, currentness proof, or rollback witness.
