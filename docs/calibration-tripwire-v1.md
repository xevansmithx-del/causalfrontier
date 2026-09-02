# Known-hindsight calibration tripwire v1

**Status:** local, unreleased integrity tripwire; scientific scoring disabled
**Fixture:** [biomedical therapeutic-translation pilot](../examples/calibration-tripwire-v1/)
**Source rationale:** [calibration tripwire source map v1](calibration-tripwire-source-map-v1.md)

This gate asks a deliberately smaller question than the primary benchmark:
can exact evidence declarations, frozen policy actions, and complete declared
resource ledgers be bound before a separately committed historical oracle is
opened? It uses one positive, one failed-translation, and one ambiguous control.
It is a known-hindsight calibration exercise, not prospective evidence and not a
scientific performance comparison.

The fixed parameter remains:

```text
OPEN_MACHINE_VERIFIABLE_TRANSLATION_FROM_FRAGMENTED_BIOMEDICAL_EVIDENCE_TO_NEXT_FALSIFIABLE_ACTION
```

## Closed contract

The tripwire root has an exact inventory: one manifest, three declared input
files, six policy-output files, and six resource-ledger files. Extra, missing,
reused, case-fold-colliding, symlinked, or hard-linked paths fail closed. Every file
is checked against the digest in the manifest and snapshotted again after
inventory validation. The manifest, outputs, and ledgers use closed JSON
schemas. Input files must be strict JSON objects; both their raw UTF-8 and
canonical decoded form are screened for known private-path, credential, and
prohibited-field patterns. That structural screen is not privacy certification
or semantic interpretation. The opening and lock stay outside this root.

The fixed role order and required behavior are:

| Role | Required behavior |
|---|---|
| `POSITIVE` | `NEXT_FALSIFICATION` |
| `FAILED_TRANSLATION` | `REJECT_TRANSLATION` |
| `AMBIGUOUS` | `NO_CALL` |

The fixed policy order is `CAUSALFRONTIER`, then
`SIMPLE_RULE_PREDECLARED`. The latter is diagnostic only. It cannot create a
winner, ranking, comparison, or acceleration claim.

The registered schemas are:

| Artifact | Schema |
|---|---|
| steward manifest | `causalfrontier.calibration-tripwire.v1` |
| frozen policy output | `causalfrontier.calibration-policy-output.v1` |
| declared resource ledger | `causalfrontier.calibration-resource-ledger.v1` |
| phase-one lock | `causalfrontier.calibration-tripwire-lock.v1` |
| phase-two opening | `causalfrontier.calibration-tripwire-opening.v1` |
| committed opening payload | `causalfrontier.calibration-tripwire-opening-payload.v1` |
| evaluation report | `causalfrontier.calibration-tripwire-report.v1` |

Each policy output contains only its schema, opaque control identifier, policy
identifier, and one of `NEXT_FALSIFICATION`, `REJECT_TRANSLATION`, or
`NO_CALL`. Each ledger binds the same control and policy, all eight fixed stage
counters, `complete:true`, and `reveal_accessed:false`. A missing stage,
negative or unbounded counter, incomplete ledger, revealed output, or all-zero
placeholder ledger is rejected.

## Two-phase flow

Phase one reads only the closed root. It verifies the caller-supplied raw
manifest checkpoint and recomputes a domain-separated execution checkpoint from
exactly three canonical input-inventory digests, six raw output digests, and six
raw ledger digests in canonical role/policy order. It returns a lock with
`opening_read:false`.

From the repository root, the checked-in fixture replays as follows:

```bash
causalfrontier lock-calibration-tripwire \
  examples/calibration-tripwire-v1/root \
  --expected-manifest-sha256 \
  20d19bfda7c79f0aad4925c5d922a85cb0ffb3bb90f7a7b2f2820cdcaf67028b \
  --expected-execution-checkpoint-sha256 \
  9c6aa9ffbbe82465a2c35c35844ec40035b9774c7a76928b50373c3a264b3142 \
  > calibration-lock.replayed.json
```

The command deliberately exits `3` after emitting an integrity-valid
historical-abstention receipt. An invalid artifact or checkpoint exits `2`.
Preserve the emitted bytes and their raw SHA-256 outside the tripwire root before
making the opening available to the evaluator. For this fixture, exact canonical
replay produces raw lock SHA-256
`3d9abbdec3ca25c5a24d89e806b1e29197c1545a5233b0a091c82a080582648d`.

Phase two independently reloads the closed root, deterministically rebuilds the
lock, checks the caller-supplied raw lock checkpoint, and only then reads the
caller-checkpointed opening. The opening must authenticate against the
manifest's domain-separated commitment over the canonical payload and its exact
32-byte nonce. Its three entries must match the locked opaque identifiers and
canonical role order; each reveal must be declared later than its control's
knowledge cutoff.

```bash
causalfrontier evaluate-calibration-tripwire \
  examples/calibration-tripwire-v1/root \
  examples/calibration-tripwire-v1/lock.json \
  examples/calibration-tripwire-v1/opening.json \
  --expected-manifest-sha256 \
  20d19bfda7c79f0aad4925c5d922a85cb0ffb3bb90f7a7b2f2820cdcaf67028b \
  --expected-execution-checkpoint-sha256 \
  9c6aa9ffbbe82465a2c35c35844ec40035b9774c7a76928b50373c3a264b3142 \
  --expected-lock-sha256 \
  3d9abbdec3ca25c5a24d89e806b1e29197c1545a5233b0a091c82a080582648d \
  --expected-opening-sha256 \
  32ad1de50e3707fc3fde199280f2b6ab9177806506bd80e4c1fcfbeda1377e3c \
  > calibration-report.replayed.json
```

This command also exits `3` after a valid report and `2` on structural,
checkpoint, commitment, or replay failure. It rechecks the root, lock, and
opening before returning. Neither phase writes into the root, opens a network
connection, executes artifact content, or grants clinical, patient, human, or
material authority.

## Checkpoint layers

The fixture's [local checkpoint](../examples/calibration-tripwire-v1/checkpoints/local-checkpoint.json)
records the following values:

| Bound object | SHA-256 |
|---|---|
| raw manifest file | `20d19bfda7c79f0aad4925c5d922a85cb0ffb3bb90f7a7b2f2820cdcaf67028b` |
| execution components | `9c6aa9ffbbe82465a2c35c35844ec40035b9774c7a76928b50373c3a264b3142` |
| raw lock file | `3d9abbdec3ca25c5a24d89e806b1e29197c1545a5233b0a091c82a080582648d` |
| semantic lock core | `75d4cbe0976e51f6911b07c4354e6673ba03dc1b855da907ecbce19db8cd98fa` |
| raw opening file | `32ad1de50e3707fc3fde199280f2b6ab9177806506bd80e4c1fcfbeda1377e3c` |
| raw report file | `35be317a31fd3083117d44fdc6f37df23c503b2c2a242a737f527cdb4d69f3ec` |
| semantic report core | `9db3a4e621544441093d6dbdee185e83836cbe2d429dc51ee438f48d893ff680` |

The lock and report additionally expose canonical manifest digest
`64c65558f9abeeb8bf616c8fbd6c4062e9bb1ec1e55cd93c54f765c80a97fa47`
and canonical opening-payload digest
`0cc189607feeb79fec1b1f6cac139481dc05a0c61c7a2c246a7d038cd8a33d19`.
The manifest commits to the nonce-bound opening digest
`c497988f67c22a25f6bbce9392b995346bd0a4050a236278b482e3748293eaf2`.
Raw-file checkpoints bind exact serialized bytes, including the final newline;
semantic digests bind canonical objects with domain separation. The execution
checkpoint binds inventories and frozen policy artifacts, but not an external
clock. These values are stored together locally and are explicitly marked
`LOCAL_CHECKPOINT_NOT_INDEPENDENT_CUSTODY`. They do not prove who created an
artifact, when it existed, or that a later local owner could not roll the whole
set back.

## Actual fixture result

The checked-in [report](../examples/calibration-tripwire-v1/report.json) records
one pass out of three for each policy:

| Role | Required | CausalFrontier | Candidate status | Simple rule | Diagnostic status |
|---|---|---|---|---|---|
| `POSITIVE` | `NEXT_FALSIFICATION` | `NO_CALL` | `NO_CALL` | `NEXT_FALSIFICATION` | `PASS` |
| `FAILED_TRANSLATION` | `REJECT_TRANSLATION` | `NO_CALL` | `NO_CALL` | `NEXT_FALSIFICATION` | `FAIL` |
| `AMBIGUOUS` | `NO_CALL` | `NO_CALL` | `PASS` | `NEXT_FALSIFICATION` | `FAIL` |

Thus the candidate is `1/3`, the predeclared simple rule is diagnostically
`1/3`, and there is no winner. The terminal result is
`CALIBRATION_TRIPWIRE_NOT_PASSED_SCIENTIFIC_SCORING_DISABLED`. The failure is
informative only as an integrity tripwire: the candidate's always-`NO_CALL`
declaration happens to match the ambiguous role label. It did not exhibit
input-dependent ambiguity recognition, advance the positive control, or reject
the bounded failed translation.

This is not a comparison between independently run scientific systems. The
current candidate outputs are honest author-curated `NO_CALL` declarations
because the repository does not yet have a real historical-evidence-to-action
adapter for these inputs. The simple rule always emits `NEXT_FALSIFICATION`.
Neither output-generation process was blinded, independent, or externally
observed. The evaluator checks three-way label equality only; it cannot verify
the scientific semantics of a proposed falsification, rejection, or minimum-
information boundary.

## Why primary scoring remains blocked

Primary scoring is blocked for three recorded reasons:

1. `KNOWN_HINDSIGHT_CALIBRATION_ONLY`;
2. `MODEL_CONTAMINATION_UNRESOLVED`; and
3. `ONE_OR_MORE_REQUIRED_CAUSALFRONTIER_CONTROL_RESULTS_NOT_PASS`.

The third reason is contingent on this result; the first two are not. Even a
future `3/3` replay of these controls would remain known-hindsight calibration
and would not become prospective, primary-performance eligible, or scientific
claim evidence. The report therefore fixes `primary_scoring_blocked:true`,
`winner:null`, `ranking:[]`, `acceleration_ratio:null`, and every scientific
readiness flag to `false`.

Four fixture limitations are especially important:

- **Composite-input availability.** Each control currently binds one
  author-curated file that combines metadata for multiple publications. Its
  declared `available_at` value is no independent attestation that the exact
  composite bytes—or every constituent source object—were publicly available
  by the knowledge cutoff. The files are explicitly marked
  `CURRENT_METADATA_PREPARATION_NOT_HISTORICALLY_ADMISSIBLE`.
- **Revealed roles and absent blinding.** The steward manifest exposes each
  role and its required behavior. Opaque identifiers hide labels only
  syntactically, and the opening confirms roles already visible in the locked
  manifest. `blinding_verified`, `independent_output_generation_verified`, and
  `policy_generation_independence_verified` remain `false`.
- **Role-domain confounding.** Positive is cardiovascular, failed translation
  is neurodegeneration, and ambiguous is infectious disease. With one role per
  subdomain, role is perfectly confounded with subdomain. This pilot cannot show
  cross-domain generality; a minimum complete calibration matrix needs all
  three roles inside each of at least three independently reviewed domains.
- **No audited time or cost.** Ledger values are bounded declared exploratory
  counters, not measured seconds, labor, compute, money, or fully loaded cost.
  Their values cannot support a speed, cost, or `10x` acceleration estimate.
- **Label match, not calibrated abstention.** The report records one
  `action_role_matches_n` event and marks
  `candidate_always_abstain_equivalent:true`. It fixes
  `action_semantics_verified`, `control_semantic_validity_verified`, and
  `calibrated_abstention_verified` to `false`. A successor needs structured
  action and total-branch artifacts plus independent rubric adjudication.

The reveal-source files alongside the fixture are review aids only. Evaluation
binds the reveal-source digests and declared availability timestamps contained
in the opening; it does not fetch, parse, or independently authenticate those
source bytes.

## Exact report nonclaims

Every valid evaluation report emits these nonclaims verbatim:

- Calibration PASS means only that a frozen action matches a committed known-hindsight role oracle.
- Modern-model training exposure and content-level outcome leakage remain unresolved after every PASS.
- Declared availability timestamps are not independent temporal attestations of the exact source bytes.
- Committed reveal-source digests and availability declarations do not verify the source bytes or their actual public availability.
- Caller-preserved local checkpoints do not establish independent custody or rollback resistance.
- Roles, required behaviors, control identities, and scientific semantics are steward declarations.
- No machine-verifiable total branch contract is present in this calibration bundle.
- A label-role match is not calibrated abstention or validation of the action's scientific semantics.
- Policy outputs and resource ledgers are byte-bound declarations, not independently generated or audited facts.
- The simple-rule policy is retained as a diagnostic and cannot create a winner, ranking, or comparison claim.
- Known-hindsight calibration controls never enter primary effect estimation or scientific performance scoring.
- No patient, clinical, human-decision, biological-material, scoring, publication, or release authority is granted.

Accordingly, this fixture does not establish temporal admissibility, absence of
content-level outcome leakage, model-training cleanliness, independent custody,
rollback resistance, total branch coverage, blinded policy generation, privacy
certification, cross-domain validity, calibrated discovery performance, real
resource efficiency, acceleration, causal truth, clinical efficacy, patient
benefit, publication readiness, or release authority.
