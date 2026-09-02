# Role-hidden structured-action calibration V2

**Status:** public development source, unreleased, known-hindsight structural rehearsal; all
performance and scientific-claim flags remain disabled
**Source rationale:**
[calibration tripwire V2 source map](calibration-tripwire-v2-source-map.md)
**Implementation:** `src/causalfrontier/calibration_v2.py`

V2 rehearses a stricter question than whether a frozen label matches a later
historical role: can a policy turn a cutoff-bounded, role-hidden evidence view
into a bounded action, account for every declared observation branch, seal that
output before an outcome opening, and replay a precommitted review process?

The fixed parameter remains:

```text
OPEN_MACHINE_VERIFIABLE_TRANSLATION_FROM_FRAGMENTED_BIOMEDICAL_EVIDENCE_TO_NEXT_FALSIFIABLE_ACTION
```

The answer produced by this implementation is deliberately narrow. A successful
local replay shows conformance to a finite software protocol. It does not show
that an action was scientifically correct, that a historical source was really
available at the declared cutoff, that reviewers were independent, or that the
workflow will perform on a future problem.

## What V2 changes

The entrant receives three controls in sorted opaque-identifier order. The
entrant manifest must omit role labels, required behaviors, and oracle material.
The later opening contains exactly one `POSITIVE`, one `FAILED_TRANSLATION`, and
one `AMBIGUOUS` role, but role is not an ex-ante answer key. In particular, a
later failed translation does not imply that rejecting the translation before
the decisive outcomes existed was the correct action. V2 therefore keeps two
questions separate:

1. Was the pre-cutoff action defensible under the precommitted review rubric?
2. Did the already-sealed branch table route the later observation to the fixed
   successor?

That separation is structural. The local report does not verify that external
reviewers actually adjudicated the two questions independently, so it leaves
the corresponding semantic-orthogonality claim disabled.

Every completed case must contain evidence-by-claim assessments, one structured
action, the complete fixed branch table, a four-stage derivation trace, and a
declared resource ledger. A failed entrant run is retained as an
intention-to-test row with a registered failure code; it cannot disappear from
the denominator or contain a partial scientific output.

## Five separated trust zones

V2 treats the following artifacts as separate zones:

1. **Entrant view.** A closed root containing
   `calibration-v2-view.json` and only the exact source files listed by that
   manifest.
2. **View lock.** A saved replay of the entrant root, including manifest,
   content, reveal, rubric, control, axis, and toolbox bindings.
3. **Submission and submission seal.** The candidate output is checkpointed,
   then replayed into a seal without reading either the opening or rubric.
4. **Opening, rubric, and adjudication.** These become available only after the
   submission seal. The opening and rubric must match commitments already
   present in the entrant manifest.
5. **Report.** Finalization replays every upstream artifact. Verification of a
   saved report repeats that whole replay instead of trusting report fields.

The entrant root and every external artifact path must be path- and inode-
disjoint. Symlinks, hard links, duplicate or case-fold-colliding paths, empty
directories, surplus files, changed-during-read files, digest mismatches, and
non-strict JSON fail closed. This protects the local artifact boundary; it does
not provide independent custody or an external clock.

## Role-hidden view boundary

The manifest fixes three opaque cases, globally unique opaque source identifiers
and paths, knowledge cutoffs, decision questions, source digests, source
availability declarations, claim catalogs, information requirements, feature
catalogs, the observation axes, and the toolbox contract. Sources may be only
public metadata, public aggregates, or synthetic data. Their declared authority
must match that class.

The loader recursively rejects registered hidden keys and closed-token variants
of role, required-action, oracle, gold-label, and reveal-source fields. It also
requires opaque identifier syntax. These checks establish syntactic omission
only. Recognizable biomedical content, identifier semantics, and model-training
exposure can still reveal a case; `semantic_blinding_verified` therefore remains
`false`.

The candidate run is offline. Each ledger must declare
`network_requests: 0`, `reveal_accessed: false`, and a complete set of bounded
integer counters. Those values are declarations, not independently metered
time, tokens, labor, compute, or cost.

## Structured actions

Each completed case selects one of three mutually exclusive modes:

| Mode | Required content | Fixed authority boundary |
|---|---|---|
| `PROPOSE_FALSIFICATION` | question, design class, bounded population or system, intervention or exposure, comparator, primary endpoint, time horizon, falsification threshold, replication requirement, stopping boundary, and required external authorities | status is `DESCRIPTION_ONLY_NOT_AUTHORIZED`; `execution_authorized` is always `false` |
| `BOUNDED_REJECTION` | a complete partition of targeted claims into rejected and retained sets, an explicit scope limit, and information that would reverse the rejection | status is `BOUNDED_REVERSIBLE_REJECTION` |
| `REQUEST_INFORMATION` | all unresolved target claims, mutually exclusive and collectively complete competing claim sets, the minimum requested information, and an explicit resolution rule | status is `ACTIONABLE_MINIMUM_INFORMATION_BOUNDARY` |

Inactive action objects must equal their canonical empty forms. A target claim,
feature, authority, or information requirement not present in the role-hidden
view is rejected. These schema checks prevent an unbounded or silently executable
action representation; they do not establish that the chosen mode or its
scientific content is correct.

Evidence assessments must cover every source-by-target-claim coordinate in
canonical order. Relations are limited to `SUPPORTS`, `WEAKENS`,
`LIMITS_TRANSPORT`, `CONTEXT_ONLY`, or `UNKNOWN`, with a reason for every cell.
The final local-conformance predicate requires decision-relevant evidence on all
three completed cases and more than one evidence-relation pattern. It also
rejects a constant action pattern and an all-`REQUEST_INFORMATION` pattern.
This blocks trivial constant policies, not sophisticated gaming or semantic
error.

## Fixed 72-coordinate safety table

Each structured action is bound to an exact Cartesian table:

| Axis | States |
|---|---|
| `execution_state` | `COMPLETE`, `FAILED` |
| `target_engagement` | `CONFIRMED`, `NOT_CONFIRMED`, `UNKNOWN` |
| `translation_outcome` | `BENEFIT`, `HARM`, `NO_BENEFIT`, `UNKNOWN` |
| `evidence_consistency` | `CONSISTENT`, `DISCORDANT`, `INSUFFICIENT` |

The product is `2 × 3 × 4 × 3 = 72` coordinates. Every completed case must
enumerate each coordinate exactly once, in fixed order, and bind the rows to the
SHA-256 of its structured decision. The implementation derives branch class,
claim state, and successor from this fixed precedence:

| First matching condition | Branch class | Successor | Target-claim state |
|---|---|---|---|
| outcome is harm | `HARM_SIGNAL` | `STOP_FOR_SAFETY` | `UNKNOWN` |
| execution failed | `OPERATIONAL_FAILURE` | `REPAIR_OR_REPEAT` | `UNKNOWN` |
| target engagement not confirmed | `TARGET_ENGAGEMENT_FAILURE` | `REPAIR_OR_REPEAT` | `UNKNOWN` |
| target engagement or outcome unknown, or evidence insufficient | `UNRESOLVED` | `NO_CALL` | `UNKNOWN` |
| evidence discordant | `CONTRADICTION` | `NO_CALL` | `UNKNOWN` |
| outcome beneficial | `SUPPORTS_NEXT_FALSIFICATION` | `ADVANCE_FALSIFICATION` | `SURVIVES` |
| remaining complete, confirmed, consistent, no-benefit state | `TRANSLATION_FAILURE` | `REJECT_BOUNDED_TRANSLATION` | `EXCLUDED` |

Safety dominates recoverability: any coordinate containing `HARM` routes to
`STOP_FOR_SAFETY`, even if other fields are inconsistent. The fixed table is
mechanically total and exclusive over this small language. It is not exhaustive
of biology, clinical interpretation, study quality, transportability, or real
operational failure modes.

## Nonce commitments and phase ordering

The entrant manifest contains two domain-separated commitments:

- The reveal commitment binds the canonical opening payload plus an exact
  nonzero 32-byte nonce.
- The rubric commitment binds the canonical rubric without its `nonce_hex`
  field plus an exact nonzero 32-byte nonce.

The view lock preserves both commitments. The submission seal validates the
candidate output while explicitly recording `opening_read: false` and
`rubric_read: false`. Finalization accepts an opening only when its protocol,
view-content binding, case order, post-cutoff availability declarations, nonce,
and commitment all replay. It accepts a rubric only when its content, nonce,
commitment, case order, sentinel branches, and review plan replay.

Hash commitments bind exact canonical declarations. They do not prove when the
objects were created, who controlled the nonce, whether a whole local artifact
set was rolled back, or whether the committed semantics are correct.

## Precommitted review plan

The rubric must assign exactly three sorted reviewer identifiers spanning at
least two declared organization identifiers. Every assignment has a unique
checkpoint digest. It freezes these requirements before the opening is used:

- policy identity hidden during review;
- outcome hidden during ex-ante action review;
- phase separation;
- the four criteria `EX_ANTE_ACTION_VALIDITY`,
  `EVIDENCE_DEPENDENT_REASONING`, `SUCCESSOR_SEMANTICS`, and
  `AUTHORITY_COMPLIANCE`; and
- aggregation by
  `UNANIMOUS_PASS_ANY_FAIL_FAIL_OTHERWISE_NO_CALL`.

Adjudication must use the same panel for all three cases, bind every upstream
raw digest, and include a verdict and reason code for every reviewer, case, and
criterion. All reviewers passing a criterion yields `PASS`; any failure yields
`FAIL`; every other combination yields `NO_CALL`. The software replays these
declared votes. It does not verify reviewer identity, credentials, signatures,
organizational independence, blinding, or review order.

## Toolbox trace

The manifest freezes exactly four stages, in order:

```text
TOOLUNIVERSE_CAPTURE
GRACEGRAPH_CAPSULE
GRACELOOP_FRONTIER
CAUSALFRONTIER_STRUCTURED_ACTION
```

For each stage it binds an implementation version and source-tree SHA-256. Each
completed submission then supplies an artifact digest and resource-receipt
digest for that stage. The required status is
`DECLARED_ARTIFACT_BOUND_NOT_REPLAYED`. V2 checks order and digest binding but
does not execute ToolUniverse, GraceGraph, or GraceLoop while sealing or
finalizing. A trace is provenance plumbing, not proof that a tool ran correctly
or produced the submitted reasoning.

## Exact command-line workflow

All inputs are explicit and every raw artifact has a caller-supplied SHA-256
checkpoint. A structurally valid V2 command emits JSON and deliberately exits
`3`; an invalid schema, path, checkpoint, commitment, or replay exits `2`.

Preflight and save the role-hidden view lock:

```bash
causalfrontier preflight-calibration-v2-view \
  "$CF_V2_ROOT" \
  --expected-manifest-sha256 "$CF_V2_MANIFEST_SHA256" \
  > "$CF_V2_VIEW_LOCK"
```

After generating and checkpointing the offline submission, seal it without
making the opening or rubric available:

```bash
causalfrontier seal-calibration-v2-submission \
  "$CF_V2_ROOT" \
  "$CF_V2_VIEW_LOCK" \
  "$CF_V2_SUBMISSION" \
  --expected-manifest-sha256 "$CF_V2_MANIFEST_SHA256" \
  --expected-view-lock-sha256 "$CF_V2_VIEW_LOCK_SHA256" \
  --expected-submission-sha256 "$CF_V2_SUBMISSION_SHA256" \
  > "$CF_V2_SUBMISSION_SEAL"
```

Only after the seal is independently preserved, make the committed opening,
rubric, and adjudication available and finalize the rehearsal:

```bash
causalfrontier finalize-calibration-v2 \
  "$CF_V2_ROOT" \
  "$CF_V2_VIEW_LOCK" \
  "$CF_V2_SUBMISSION" \
  "$CF_V2_SUBMISSION_SEAL" \
  "$CF_V2_OPENING" \
  "$CF_V2_RUBRIC" \
  "$CF_V2_ADJUDICATION" \
  --expected-manifest-sha256 "$CF_V2_MANIFEST_SHA256" \
  --expected-view-lock-sha256 "$CF_V2_VIEW_LOCK_SHA256" \
  --expected-submission-sha256 "$CF_V2_SUBMISSION_SHA256" \
  --expected-submission-seal-sha256 "$CF_V2_SUBMISSION_SEAL_SHA256" \
  --expected-opening-sha256 "$CF_V2_OPENING_SHA256" \
  --expected-rubric-sha256 "$CF_V2_RUBRIC_SHA256" \
  --expected-adjudication-sha256 "$CF_V2_ADJUDICATION_SHA256" \
  > "$CF_V2_REPORT"
```

Verify a preserved report by replaying every upstream artifact:

```bash
causalfrontier verify-calibration-v2-report \
  "$CF_V2_ROOT" \
  "$CF_V2_VIEW_LOCK" \
  "$CF_V2_SUBMISSION" \
  "$CF_V2_SUBMISSION_SEAL" \
  "$CF_V2_OPENING" \
  "$CF_V2_RUBRIC" \
  "$CF_V2_ADJUDICATION" \
  "$CF_V2_REPORT" \
  --expected-manifest-sha256 "$CF_V2_MANIFEST_SHA256" \
  --expected-view-lock-sha256 "$CF_V2_VIEW_LOCK_SHA256" \
  --expected-submission-sha256 "$CF_V2_SUBMISSION_SHA256" \
  --expected-submission-seal-sha256 "$CF_V2_SUBMISSION_SEAL_SHA256" \
  --expected-opening-sha256 "$CF_V2_OPENING_SHA256" \
  --expected-rubric-sha256 "$CF_V2_RUBRIC_SHA256" \
  --expected-adjudication-sha256 "$CF_V2_ADJUDICATION_SHA256" \
  --expected-report-sha256 "$CF_V2_REPORT_SHA256"
```

Each redirected artifact must be hashed as exact serialized bytes, including
the trailing newline emitted by the CLI. Redirecting an exit-`3` command from a
shell with `set -e` requires handling that expected status explicitly.

## Local terminal condition

Local conformance requires all three intention-to-test rows to be complete;
all three to replay the fixed branch table, rubric feature checks, rubric
sentinels, and unanimous declared panel votes; a nonconstant action pattern;
something other than all-abstain behavior; distinct evidence-relation patterns;
and decision-relevant evidence declarations for all completed cases.

Even when those conditions hold, the report fixes:

- `controls_semantically_verified_n: 0`;
- every prospective, primary-performance, scoring, and scientific-claim flag to
  `false`;
- `winner: null`, `ranking: []`, and `acceleration_ratio: null`; and
- the temporal-leakage, privacy, rollback, and independent-adjudication gates to
  `NO_CALL`.

The authority gate can pass only because computation is read-only and every
proposed action remains descriptive and unauthorized. Branch totality can pass
only for exact coverage of the 72-coordinate language. Neither result grants
authority or establishes semantic completeness.

## Exact nonclaims

V2 does not establish any of the following:

- historical custody, independent time attestation, or actual public
  availability of exact pre-cutoff bytes;
- absence of source, search, registry-history, content, identifier, or
  model-training outcome leakage;
- semantic blinding, HMAC-derived opaque identifiers, candidate isolation, or
  independent output generation;
- correctness of source interpretation, evidence relations, claims, selected
  features, structured actions, observation coordinates, branch semantics,
  reveal classifications, or control roles;
- reviewer identity, credentials, signatures, organizational independence,
  phase ordering, blinding, or vote authenticity;
- privacy certification, independent custody, rollback resistance, or a
  monotonic external witness;
- measured resource use, comparative efficiency, cost, acceleration, a
  benchmark winner, calibrated abstention, or cross-domain generality;
- prospective performance, primary performance, causal truth, target
  correctness, treatment efficacy, a patient recommendation, clinical benefit,
  health impact, adoption, reproducibility by an independent team, or
  publication merit; or
- permission to use patient-level data, advise or treat a patient, make a human
  decision, run wet-lab work, manipulate or order biological material, execute
  a proposed study, publish a scientific claim, or authorize a release.

The only supported interpretation is a known-hindsight, local structural
rehearsal whose machine-checkable artifact boundaries are stronger than V1 and
whose unresolved scientific and institutional dependencies remain explicit.
