# Dynamic workflow and persistent-memory contract

## Purpose

The workflow keeps the fixed problem stable while allowing evidence adapters, causal worlds, experiment proposals, tests, and benchmarks to evolve. History is append-only: a new result or correction creates a successor artifact and ledger event; it never rewrites a prior case.

The current local development identity is `0.1.0a5`. The fixed parameter remains:

`OPEN_MACHINE_VERIFIABLE_TRANSLATION_FROM_FRAGMENTED_BIOMEDICAL_EVIDENCE_TO_NEXT_FALSIFIABLE_ACTION`

## State model

```text
DISCOVER
  -> FREEZE_RECEIPTS
  -> AUTHOR_INDEPENDENTLY
  -> RECONCILE_DISAGREEMENTS
  -> COMPILE
  -> ADVERSARIAL_VERIFY
  -> ASSESS_REGISTRY_CANDIDATE_FOR_STRUCTURAL_CLONES
  -> PREFLIGHT_IMMUTABLE_PROGRAM_GOAL_CLAIM_PLAN
  -> REGISTER_GOVERNANCE_AND_ANALYSIS_PLAN
  -> HASH_COMMIT_CHALLENGE
  -> EXECUTE_APPLICABLE_COMPARATORS
  -> VERIFY_REVEAL_OPENING_AND_OUTCOME_ADJUDICATION
  -> SCORE_HELD_OUT
  -> APPEND_CHECKPOINTED_EVENT
  -> BACKUP
  -> SELECT_NEXT_MILESTONE
```

Any temporal uncertainty, semantic incompleteness, open authority gate, classifier ambiguity, memory-head mismatch, privacy concern, or contradiction routes to `ABSTAIN_OR_NEW_CASE`, not an inferred scientific result.

## Five bound identities

Every evaluated run must bind five independent identities:

1. **Evidence identity:** immutable receipt inventory and the chain `receipt-set bytes -> replayed report -> raw-response digest plus acquisition semantics -> frozen dossier source digest plus compatible acquisition semantics -> shared encoder dossier digest`.
2. **Case identity:** evidence cutoff, decision, declared worlds, gates, experiments, total branch matrix, and nonclaims.
3. **Compiler identity:** source manifest, package version, runtime, and test result.
4. **Challenge identity:** sequence, predecessor and manifest digests, reveal scheme and commitment, cohort, provisional metric, and comparator specifications.
5. **Memory identity:** capsule manifest, ledger genesis, current external head, event count, and exact backup digest.

The program-level claim plan is an additional predecessor gate, not a sixth
mutable identity. Its immutable contract digest and exact plan checkpoint must be
included in the future challenge identity before any primary outcome is reachable.
The preserved challenge-v1 metric cannot satisfy this gate because it lacks the
full five-comparator tenfold conjunction.

If any identity changes, the run is a new version. “Latest” is never inferred from a locally valid chain.

## External checkpoint rule

The capsule ledger is append-only inside SQLite but locally unauthenticated. Every append therefore requires the prior head from persistent memory outside the capsule. After a successful append:

1. verify the capsule against the supplied prior head;
2. compare-and-swap append exactly one typed event;
3. replay every event semantically;
4. verify against the returned new head;
5. append that head and event count to the external project memory; and
6. make an exact, integrity-checked backup before the next transition.

A mismatch stops the workflow. Recovery restores the last exact backup, verifies it against the independently stored checkpoint, and then resumes. Neither the private project memory nor its backup belongs in a public repository.

Challenge v1 checks sequence and predecessor shape, but a caller can still supply an old bundle with its old checkpoint. It therefore emits `rollback=NO_CALL` until currentness is proven against an independently stored monotonic head.

## Local calibration V2 checkpoint order

The [calibration V2 structural rehearsal](calibration-tripwire-v2.md) is an
additive successor to the historical [V1 diagnostic](calibration-tripwire-v1.md).
It uses this bounded order:

```text
CHECKPOINT_CLOSED_ROLE-HIDDEN ENTRANT ROOT
  -> SAVE AND CHECKPOINT VIEW LOCK
  -> GENERATE OFFLINE STRUCTURED-ACTION SUBMISSION
  -> SAVE AND CHECKPOINT SUBMISSION
  -> SEAL SUBMISSION WITHOUT READING OPENING OR RUBRIC
  -> SAVE AND CHECKPOINT SUBMISSION SEAL
  -> OPEN NONCE-BOUND ROLE/OBSERVATION PAYLOAD + NONCE-BOUND RUBRIC
  -> REPLAY DECLARED THREE-REVIEWER/TWO-ORGANIZATION ADJUDICATION
  -> SAVE REPORT AND VERIFY IT FROM EVERY UPSTREAM CHECKPOINT
  -> STOP AT METHOD-RECOVERY AND SCIENTIFIC NO_CALL
```

The five path- and inode-disjoint zones are (1) entrant root, (2) view lock,
(3) submission plus submission seal, (4) opening plus rubric plus adjudication,
and (5) report. Every external artifact has an exact caller-supplied raw SHA-256
checkpoint. This is local file binding, not an independent clock, monotonic
register, authenticated identity, or rollback proof.

The entrant view uses opaque identifiers and rejects registered role, required-
action, oracle, gold-label, and reveal-source fields. This establishes syntactic
role hiding only. Biomedical content, source identifiers, and model-training
exposure may still reveal hindsight. Each completed intention-to-test row chooses
one structured mode—`PROPOSE_FALSIFICATION`, `BOUNDED_REJECTION`, or
`REQUEST_INFORMATION`—and binds its structured decision digest to every row of
the exact 72-coordinate product:

```text
2 execution states
x 3 target-engagement states
x 4 translation-outcome states
x 3 evidence-consistency states
= 72 coordinates
```

The fixed precedence is harm, execution failure, target-engagement failure,
unresolved information, contradiction, benefit, then no benefit. Harm is always
first: every coordinate containing `HARM` routes to `STOP_FOR_SAFETY`, including
coordinates whose execution state is `FAILED`. This proves totality and exclusivity
only for the fixed software language, not for biology, study quality, or clinical
interpretation.

Separate domain-bound commitments use nonzero 32-byte nonces for the reveal and
rubric. The rubric declares exactly three reviewer assignments spanning at least
two organization identifiers and binds phase separation, four criteria, unique
assignment checkpoints, and conservative aggregation. Replaying the declarations
does not verify reviewer credentials, signatures, independence, blinding, or review
order.

The manifest also freezes a four-stage toolbox trace—ToolUniverse capture,
GraceGraph capsule, GraceLoop frontier, and CausalFrontier structured action—and
each completed row binds artifact and resource-receipt digests. The V2 validator
does not replay or authenticate those tools; their status remains
`DECLARED_ARTIFACT_BOUND_NOT_REPLAYED`. Even a locally conforming report hard-codes
`METHOD_RECOVERY` to `NO_CALL`, leaves semantic controls verified at zero, and
keeps prospective, primary-scoring, scientific-scoring, and scientific-claim
outputs false or `NO_CALL`.

## Local sentinel dual-witness lock order

The phase-1 [sentinel dual-witness generation lock](sentinel-dual-witness-lock-v1.md)
adds this bounded pre-generation subworkflow:

```text
FREEZE_AND_CHECKPOINT_GENERATION_PLAN + ORGANIZATION_REGISTRY
  -> PREDECLARE_TWO_WITNESSES + POLICIES + TRUST_ROOTS + RUNTIMES + DEADLINE
  -> CHECKPOINT_ONE_CANONICAL_PRE_TOKEN_TARGET
  -> CREATE_TWO_RAW_RFC3161_BUNDLES_OVER_THE_EXACT_TARGET
  -> CLOSE_AND_CHECKPOINT_THE_DUAL_WITNESS_LOCK_MANIFEST
  -> REPLAY_BOTH_RAW_BUNDLES_FROM_PRIVATE_SNAPSHOTS
  -> DERIVE_GENERATION_EPOCH
  -> STOP_AT_NOT_ADMITTED
```

The target accepts no generated artifact, outcome, oracle opening, or score. It
binds both witness descriptors before either token exists. The lock preflight
replays both original RFC 3161 request/response/policy bundles against the same
target and derives an epoch from both token projections, the exact lock bytes,
and sequence. Each policy supplies exactly one canonical PEM trust-anchor
certificate. One case-insensitive collision namespace covers witness,
organization, controller, store, attestation, and policy IDs; replay also rejects
shared canonical mathematical key material for trust roots or timestamp signers.
These are implemented hygiene checks only and do not establish witness,
controller, store, legal, or operational independence.

Sentinel-v1 generated payloads do not require the epoch, so the phase-1 output
does not verify prospective order or actual artifact-creation time. Phase 2 must
require the exact epoch in every primary and calibration payload and provenance
packet, and bind the lock preflight as an admission predecessor. External witness
execution, two append-only store-continuity adapters, governance review, revocation,
rollback currentness, registration, admission, and scoring remain future gates.
The lack of a designated outcome argument does not prevent accepted identifiers,
certificates, nonces, tokens, or later manifests from covertly encoding or being
selected with outcome content; content/outcome isolation remains false.

## Local phase-bound sentinel successor order

The separate [phase-bound successor](sentinel-phase-binding-v1.md) now implements
the local schema seam without changing sentinel v1:

```text
CALLER_CHECKPOINT_OUTER_COMPOSITION_MANIFEST
  -> SNAPSHOT_THE_COMPLETE_OUTER_COMPOSITION
  -> REPLAY_PHASE_1_FROM_RAW_RFC3161_EVIDENCE
  -> DERIVE_EXACT_SEVEN_FIELD_GENERATION_CONTEXT
  -> VALIDATE_V2_MANIFEST + 39_PAYLOADS + 39_PROVENANCE_PACKETS
  -> VERIFY_GOAL_PLAN_BINDS_RAW_V2_SENTINEL_MANIFEST
  -> REPLAY_PHASE_1_AGAIN_AND_REQUIRE_IDENTICAL_REPORT
  -> REREAD_THE_ORIGINAL_OUTER_INVENTORY_AND_EVERY_BYTE
  -> STOP_AT_NOT_ADMITTED_WITH_EXIT_3
```

The seven fields are `schema_version`, `lock_id`, `sequence`,
`generation_plan_checkpoint_sha256`, `generation_plan_sha256`,
`generation_lock_preflight_sha256`, and `generation_epoch_sha256`. The exact same
context is required in the outer composition, successor sentinel manifest, all 30
primary and nine role-balanced control payloads, and all 39 provenance packets.
This establishes a byte dependency on the replayed phase-1 epoch. It does not date
content conception, prove prospective order or successor uniqueness, establish
independence/currentness/privacy/provenance truth, or admit or score a cohort.

## Local dual-declared-log continuity order

The local, unreleased, synthetic Phase 3
[dual-declared-log continuity successor](sentinel-dual-log-continuity-v1.md) adds
one bounded supplied-view transition after Phase 2:

```text
FREEZE_SEQUENCE + TWO_PRIOR_HEADS + TWO_STORE_KEYS IN ONE PRE_TOKEN_TARGET
  -> REPLAY_TWO_RAW RFC3161 CUSTODY_WITNESS_BUNDLES
  -> FRESHLY_REPLAY_THE_COMPLETE_PHASE_BOUND_COMPOSITION
  -> DERIVE_ONE_TRANSITION
  -> INCLUDE_THE_TRANSITION_AT_RESERVED_SLOT 2(n-1) IN BOTH DECLARED_VIEWS
  -> VERIFY_BOTH_SIGNED_INTERMEDIATE_HEADS
  -> DERIVE_ONE_SEAL_OVER_BOTH_EXACT_INTERMEDIATE_CHECKPOINTS
  -> INCLUDE_THE_SEAL_AT_RESERVED_SLOT 2(n-1)+1 IN BOTH DECLARED_VIEWS
  -> VERIFY_BOTH_CALLER_PINNED_FINAL_HEADS_AT_SIZE 2n
  -> EMIT_AND_EXTERNALLY_PRESERVE_CURRENT_STATE_FOR_SEQUENCE n+1
  -> STOP_AT_NOT_ADMITTED_WITH_EXIT_3
```

The only accepted checkpoint profile is
`c2sp.org/tlog-checkpoint@v1.0.0-ed25519-pinned-key`; the only accepted proof
profile is `RFC6962_SHA256_PREORDERED_TWO_SLOT_V1`. For sequence `n`, each view's
prior size is `2(n - 1)`, transition index and intermediate size are
`2(n - 1)` and `2(n - 1) + 1`, and seal index and final size are
`2(n - 1) + 1` and `2n`. Inclusion and consistency proofs plus the exact one-leaf
increments exclude an extra leaf only between the supplied heads; they do not
exclude another signed root, hidden view, unseen successor, or future fork.

Sequence 1 requires a null predecessor. Its `current_state` must be preserved as
canonical JSON plus LF outside the composition. Sequence 2 requires both that file
path and its embedded domain-separated `state_sha256`; the continuity ID,
immediate sequence, complete ordered store/operator/controller/store-group/
namespace/origin/verifier-key-digest/runtime/declared-independence tuple, and both
previous final signed heads must equal the next target's prior state. This is state
continuity relative to caller custody, not global latestness.

The terminal state is
`DUAL_DECLARED_LOG_EDGE_AND_CROSS_SEAL_REPLAYED_RELATIVE_TO_CALLER_CHECKPOINTS_NOT_ADMITTED`.
The local fixture uses two raw RFC 3161 custody-witness bundles over the pre-token
target and two declared log views, but no external witness or store performed the
ceremony. Structural identifier and key separation does not prove independence.
Global successor uniqueness, currentness, hidden/future-fork absence, external
operation, independence, admission, scoring, scientific impact, and a 10x result
remain false or `NO_CALL`.

## Local blind-successor checkpoint order

The local synthetic successor has a narrower, explicit subworkflow:

```text
BUILD_AND_CHECKPOINT_SANITIZED_VIEW
  -> PREFLIGHT_COMPLETE_ORACLE_WITHOUT_OPENING
  -> PERSIST_AND_EXTERNALLY_CHECKPOINT_COMMITMENT_PREFLIGHT
  -> INSERT_COMMITMENT_AND_SEAL_FINAL_CHALLENGE
  -> LOCK_SELECTION_FROM_VIEW_ONLY
  -> BIND_STEWARD_SELECTION/PREFLIGHT_ENVELOPE
  -> ADD_EXACT_CANONICAL_OPENING
  -> EXECUTE_WITH_FINAL_MANIFEST+VIEW+SELECTION+ENVELOPE+PREFLIGHT+OPENING_CHECKPOINTS
```

The challenge registration excludes only the commitment value, so the final seal
changes the manifest checkpoint without changing the registration digest used by
the already checkpointed view. Preparation happens while `opening.json` is absent:
it reads and digest-checks every committed observation, screens invalid UTF-8 and
prohibited patient-identifier field markers, rejects observations over 1 MiB, and
reserves the exact future canonical opening in both the 256-entry and 64 MiB oracle
limits. A second complete digest/privacy pass and final metadata inventory catch
same-length replacement during preflight. The commitment preflight is then persisted before its reveal commitment is
inserted into the final manifest.

The selector receives only the view. A separate steward-side envelope binds its
selection checkpoint to the commitment-preflight checkpoint and explicitly says
that the selector did not receive preflight input. Neither the intended artifact
order nor the envelope proves timestamp, custody, independent attestation, nonce
quality or secrecy, or monotonic currentness. At execution the selected complete
replicate batch is debited and processed atomically, classifier metrics and hidden
observation identifiers/digests are redacted, and unselected observation payloads
are not reread. The full receipt remains steward-only because its payload and
checkpoint hashes are linkable; no public unlinkable projection exists. Consequently
current full-oracle byte readiness remains unverified.

An integrity-valid terminal policy with no action report uses
`SYNTHETIC_BLIND_POLICY_TERMINATED_WITHOUT_OBSERVATION_CLASSIFICATION_SCIENTIFIC_SCORING_DISABLED`
and exits `3`, like every other successful structural receipt. An
integrity-invalid execution emits its invalid structured receipt and exits `2`;
it is never represented as a successful abstaining run.

## Local neutral-substrate checkpoint order

The separate [neutral baseline substrate](neutral-baselines-v1.md) is a local,
unreleased, case-level synthetic protocol exercise with this artifact order:

```text
CHECKPOINT_CATALOG_WITH_EXACT_EMBEDDED_COMMON_INPUT
  -> COMMIT_MULTIPLE_SEEDS_TO_THE_AUTHORIZED_ACTION_UNIVERSE
  -> CHECKPOINT_PLAN_WITH_ALL_SEEDS + BLIND_OFAT + INFORMED_OFAT
  -> OPEN_EVERY_SEED_AND_CHECKPOINT_ALL_PORTABLE_ORDERS
  -> CHECKPOINT_DETERMINISTIC_PROTOCOL_COUNTER_RECEIPTS
  -> VERIFY_CATALOG + PLAN + LOCK + REPORT AGAINST ALL EXTERNAL DIGESTS
```

The embedded common input is labelled declared-precompilation and binds the exact
dossier/source digests, synthetic/software authorities, gates, factor-space digest,
action inventory, and per-action payload digest before planning. The catalog replays
each payload from its complete factor assignment plus reset/action tariffs and derives
execution gates from the embedded authority structure. This is byte-level structural
parity only; precompilation timing and semantic policy neutrality remain unverified.

The plan requires multiple distinct 256-bit seed commitments, each context-bound to
the authorized action-universe digest, and opens none. The lock must open all of them
and deterministically replay a domain-separated, rejection-sampled Fisher–Yates order
over the complete authorized universe. Blind OFAT follows neutral factor/value order;
informed OFAT follows a complete precommitted factor/value ranking with neutral
tie-breakers. Both reset to the same baseline before each single-factor action and read
no outcome. Universe binding does not attest seed entropy, generation, custody, or
secrecy.

The report's synthetic protocol counters are deterministic hash-chained events, not
elapsed time, compute, labor, money, energy, or fully loaded resources. Optional
same-process timing/CPU/RSS telemetry is separately hashed, untrusted, incomplete, and
forbidden from the score core. Verification does not establish semantic neutrality,
precompilation timing/currentness, rollback protection, authority truth, telemetry
authenticity, cohort uniqueness, real-resource use, a scientific baseline, an impact
result, or 10x acceleration.

## Weekly dynamic cycle

The active weekly heartbeat performs one bounded, safe iteration:

- verify repository, release, capsule, external memory head, and backup health;
- scan primary sources and competing systems for changes relevant to the fixed parameter;
- run temporal-leakage, privacy, authority, branch-totality, and hostile-input gates;
- choose one highest-information milestone from the public roadmap;
- implement and test only read-only software or public/synthetic evidence work;
- append an evidence-backed result, failure, or abstention to persistent memory;
- update the external checkpoint and exact backup; and
- report what changed, what remains unvalidated, and the next kill gate.

It does not issue patient advice, execute an experiment, manipulate biological materials, use patient-level data, order anything, or publish a new scientific claim automatically. Public releases require a separate reviewed release gate.

## Current milestones

0. Bind the [goal-claim contract](goal-claim-contract-v1.md) before outcomes:
   every declared domain × independent expert/retrieval/graph/random/predeclared
   simple rule plus every pooled comparator must meet the tenfold lower-bound
   criterion. Use one global 95% claim family across acceleration, false exclusion,
   coverage, and selective risk; require at least ten primary cases and two
   case-linked laboratories per domain; and preselect one execution design with one
   common input, meter, and horizon. Every domain must also contain positive,
   failed-translation, and ambiguous calibration controls with role-specific
   criteria; any control failure yields `NO_CALL`, and controls never enter the
   primary effect. Provenance, comparator, control, reproduction, and usability
   hashes are declarations until their artifact bytes and execution are independently
   supplied and verified. No pooled, missing-ledger, or favorable-censoring
   substitute is allowed.
1. Freeze a complete `receipt.v1` contract with independently anchored temporal attestation.
2. Build the successor execution lifecycle: sanitized entrant view, pre-reveal policy lock, hidden-observation environment, append-only trace/resource ledger, reveal or outcome receipt, adjudication, and pure vector report.
3. Require a no-write registry-candidate assessment to reject v1 structural collisions for semantic review before any cohort can reach a future registration gate.
3a. Add a sentinel-admission manifest and independent generator-family audit that
    verifies domain semantics, case provenance, cutoff admissibility, and generator
    separation before any cohort can be scored; declared geometry alone remains
    `NO_CALL` for admission.
3b. Bind one canonical pre-token sentinel target to two raw RFC 3161 evidence
    replays, derive a post-token generation epoch, and require its exact seven-field
    context in a closed successor manifest plus every generated payload and
    provenance packet. The local schema seam is complete; identifier, root, key,
    token, and store differences remain structural checks, not proof of external
    independence or prospective order.
3c. Close one phase-bound transition and one cross-log seal in the next two
    reserved positions of each of two caller-pinned declared log views, then carry
    the exact final state forward as the mandatory predecessor of the next
    sequence. The local implementation is a supplied-view continuity preflight,
    not an external register, global uniqueness/currentness proof, or admission.
3d. Run one calibration-only tripwire before adding more custody machinery:
    freeze a positive, failed-translation, and ambiguous control as one inseparable
    set; commit the CausalFrontier and predeclared-simple-rule outputs plus complete
    exploratory resource ledgers before opening a separate reveal; and require
    `PASS`, `FAIL`, or `NO_CALL` for every role. Any non-pass blocks advancement.
    Known-hindsight controls remain training-contaminated and never become
    prospective or primary-performance cases because their hashes are new.
3e. Rehearse the [calibration V2 structured-action contract](calibration-tripwire-v2.md):
    syntactically hide roles; freeze exact structured decisions and the complete
    harm-first 72-coordinate table; separate view, submission, opening/rubric,
    adjudication, and report checkpoints; and predeclare the three-reviewer/two-
    organization panel. Local completion remains `NO_CALL` for method recovery and
    every scientific result until externally authenticated semantic review exists.
4. Execute a budget-matched synthetic/replay horse race across the 15 required baseline families, including POPPER-like sequential falsification, blind and informed OFAT, cost-aware design, abstain, human-plus-agent, and an oracle.
5. Add external successor checkpoints and independently anchored reveal/outcome receipts; caller-supplied local values remain `NO_CALL` for monotonicity.
6. Measure blinded, field-level encoder agreement and publish critical disagreements, not only reconciled cases.
7. Keep PCSK9 as known-hindsight calibration; lock failed-translation and ambiguous controls before any historical score.
8. Establish independent governance and at least two external outcome-provider commitments before a live pilot.
9. If those gates pass, preregister a small prospective, read-only challenge with independent domain reviewers.

Local 2026-09-02 progress: milestone **3d** now has a closed, read-only
[known-hindsight calibration tripwire](calibration-tripwire-v1.md) and one exact
biomedical pilot replay. CausalFrontier declared `NO_CALL` for all three roles,
so it matched only the ambiguous label and returned `NO_CALL`, `NO_CALL`,
`PASS`—one action-role match out of three and explicitly
`candidate_always_abstain_equivalent:true`. The simple rule matched only the
positive role. There is no winner or calibrated-abstention result. Advancement
remains blocked, and temporal admissibility, content/outcome isolation,
independent custody, rollback resistance, branch totality, privacy, action and
control semantics, real-resource measurement, scientific scoring, and every
authority expansion remain false. V1 remains a historical diagnostic; its local
label-match result is not carried forward as V2 evidence.

Local 2026-09-02 progress: milestone **3e** now has a local, read-only
[calibration V2 structural rehearsal](calibration-tripwire-v2.md). It adds the
syntactically role-hidden view, bounded structured actions, complete harm-first
72-coordinate table, separately nonce-bound opening and rubric, exact five-zone
checkpoint replay, and a declared three-reviewer/two-organization plan. It also
binds real ToolUniverse, GraceGraph, GraceLoop, and CausalFrontier trace artifacts,
but does not replay or authenticate those tool executions. No reviewer identity,
signature, independence, semantic correctness, historical custody, model blinding,
privacy certification, rollback protection, prospective performance, method
recovery, or scientific result is established. `METHOD_RECOVERY` stays `NO_CALL`,
and all scientific readiness, scoring, and claim fields remain disabled. The next
safe milestone is externally authenticated, phase-separated semantic adjudication
over prospectively committed controls, not another retrospective score.

Local 2026-08-31 progress: milestone **1a** now has a strict [receipt preflight](receipt-v1.md)
and a current-metadata PCSK9 preparation run. This does not complete milestone 1: no
independent temporal attestation was collected or integrated into receipt admission, so
both collected receipts abstain and historical scoring remains disabled. Earlier project notes already exposed
the FOURIER outcome, so preserve `KNOWN_HINDSIGHT`; a subsequent local hash freeze cannot
restore blinding. The failed-translation and ambiguous controls still precede any scoring.

Local 2026-09-01 progress: milestone **1b** now has a separate
[RFC 3161 temporal-witness verifier](rfc3161-attestation-v1.md). It runs independent
query/nonce/policy and target-byte verification passes against one signed timestamp
response under exact caller checkpoints for target, attestation, trust policy, and
OpenSSL binary. Twenty-five focused hostile tests pass. This closes a signed-target-imprint-
existence evidence gap only: no public TSA was contacted, no receipt is admitted,
and strict DER, unqualified timestamp validity or digest existence, source availability,
witness independence, revocation, runtime hermeticity,
rollback, cohort admissibility, and scientific scoring remain false or `NO_CALL`.

Local 2026-09-01 progress: a strict [scientific-decision challenge preflight](scientific-decision-challenge.md)
now replays embedded receipt sets, requires every frozen dossier source to match a replayed raw-response
digest, enforces post-lock and synthetic-scope boundaries, binds two organization-distinct encodings,
and validates 15 unexecuted baseline specifications. The milestone is structural only: temporal
attestation, external checkpoint monotonicity, control adjudication, encoder independence, baseline
execution, reveal opening, governance, and scientific scoring all remain `NO_CALL`.

Local 2026-09-01 progress: the [synthetic protocol-exercise kernel](protocol-exercise-v1.md)
now closes two prerequisites and exercises the first one-way transition. Receipt bytes must
retain compatible acquisition semantics when promoted into a dossier, and both encoders
must share an exact dossier/gate/action contract while their world models remain separate.
One command locks deterministic reference choices without accepting a reveal; a second
verifies a domain-separated synthetic commitment and complete case/action/replicate branch
inventory. This does not complete milestone 2: the steward bundle still exposes controls,
branches are not derived from hidden raw observations, all 15 scientific baselines remain
unexecuted, resource ledgers are unaudited, and scientific scoring remains `NO_CALL`.

Local 2026-09-01 progress: the [structurally blinded synthetic successor](blind-execution-v1.md)
now projects a keyed opaque entrant view, preflights and checkpoints the complete
raw-observation oracle before the final challenge seal, locks reference policies
from only the view, and creates a separate steward envelope binding the selection
to that preflight. The exact canonical opening is added only afterward. Execution
rechecks both external checkpoints, derives branches from selected authenticated
bytes rather than organizer labels, processes each complete replicate batch
atomically without majority voting, redacts group-keyed classifier metrics and
hidden observation identifiers, debits precommitted synthetic vector tariffs, and
emits a deterministic per-episode event chain. It does not complete milestone 2:
nonce entropy/uniqueness/secrecy, process isolation, temporal order, independent
attestation, current full-oracle byte readiness, and patient-data absence are not
verified; tariffs are not measured resources; the event chain is not yet durably
checkpointed; terminal decision truth is absent; all 15 scientific comparators
remain unexecuted; and scientific scoring remains `NO_CALL`.

Local 2026-09-01 progress: the [complete-matrix synthetic successor](horse-race-v1.md)
now hash-binds six cloned structural fixture instances across three declared
synthetic labels and all 36 current
case × encoder-lane × locked-policy coordinates without reading the opening, then executes
them without accepting a caller-selected episode. The candidate returned
`NO_CALL` on all 12 case-lane coordinates. This is a readiness/plumbing failure signal,
not a horse-race loss or win: the current input view is candidate-derived,
preprocessing is unmetered, uniform enumeration is not random, terminal truth is
not independent, 15 scientific comparator families remain unexecuted, and the
local checkpoint does not independently prove that binding preceded opening.
The cloned fixtures do not establish independent cases or cross-domain validity.

Local 2026-09-01 progress: the [neutral baseline substrate](neutral-baselines-v1.md)
now supplies one exact embedded, declared-precompilation synthetic action/authority
input for portable multi-seed random, blind-OFAT, and informed-OFAT order replay. The
17 focused hostile/regression tests pass; the 29-test public API/CLI plus neutral
slice passes; and normal, `python -O`, and alternate-hash-seed probe outputs match at
exact emitted-output SHA-256
`b4ea90ee210fbb046d32273845b84dc4611cb972aa0740c1664b34665c326bc0`. This closes a local
ordering/counter-plumbing gap only: all scientific baseline families remain
unexecuted, and semantic neutrality, outcome validity, real-resource measurement,
currentness, rollback protection, impact, and scientific scoring remain unverified
or disabled.

Local 2026-09-01 progress: the [registry-candidate assessment](registry-candidate-v1.md)
now replays the exact challenge, race, entrant view, and nonce, then compares each
case as an unordered pair of encoder-lane graphs without using IDs, labels, prose,
paths, timestamps, or nonce aliases. Refinement only prunes a bounded exact graph-
isomorphism search; exhaustion is `NO_CALL`. The current six differently labelled
fixtures collapse to one verified class in every layer, so all 15 cross-case pairs
are rejected as v1 structural collisions requiring semantic review. This is a successful falsification of the
candidate cohort, not a registration or scientific result. Semantic/domain/encoder/
store independence, time/currentness, governance, privacy certification, prospective
admissibility, comparator execution, impact, and scoring remain false or `NO_CALL`.
The next milestone is a structurally diverse sentinel cohort with independently
authored generators and a policy-neutral terminal-oracle interface, still without
scientific scoring.

Local 2026-09-01 progress: milestone **3a** now has a separate
[sentinel admission v1](sentinel-admission-v1.md) artifact-closure boundary. It
composes a caller-supplied pre-generation assignment declaration, a 326-artifact
synthetic sentinel packet, and the existing immutable goal plan; the raw sentinel-
manifest digest must be the preimage of the goal plan's cohort checkpoint. The
fixture binds three declared domains, three declared generator-family clusters
under the maximal-family rule, thirty primary cases, nine Latin-square calibration
controls, six laboratories, exhaustive generator and domain-pair packets, role-
specific controls, cutoff checks, and declared acyclic provenance structures.
Empty protocol bytes, JSON media-type mismatch, exact generator-component identity
or content reuse, casefolded and cross-dimension controller/store aliases, cross-
role aliases, source/date or branch-observation/role mislinkage, both-laboratory/
per-cell imbalance, normalized-domain and case-core collision, and post-cutoff
declarations now produce structural rejection. A clean synthetic packet still
returns `REVIEW_PACKET_COMPLETE_NOT_ADMITTED`: the predecessor locks are not
externally timestamped custody evidence, provenance truth and generator
independence are unverified, and external semantic/control review, exact public
availability, governance, privacy, content-level outcome isolation, a real sentinel
cohort, admission, and scoring remain unresolved. The next milestone is to obtain
independently authored public/synthetic generator and review packets for one
genuinely diverse sentinel rehearsal under two external pre-generation anchors;
scoring remains prohibited. The bounded software slice passes 88 focused tests and
92 sentinel-plus-CLI tests; four normal/optimized x hash-seed probe outputs are
byte-identical at SHA-256
`16c6c6c559bdbf989fbbd379ca23936425c7da180082ec09984cda779d6a1690`.

Local 2026-09-01 progress: milestone **3b phase 1** now has a separate
[sentinel dual-witness generation lock v1](sentinel-dual-witness-lock-v1.md).
It closes one canonical pre-token target, the exact generation plan and organization
registry, and two non-overlapping raw RFC 3161 attestation/trust-policy subtrees.
Both raw bundles are separately replayed against the same target under aligned
pinned OpenSSL byte checkpoints, both signed-time upper bounds must meet the one
predeclared deadline, and exact request/response/token projections derive a
generation epoch. The terminal state is
`DUAL_WITNESS_PLAN_LOCK_REPLAYED_GENERATION_EPOCH_DERIVED_NOT_ADMITTED`.
This is a local phase-1 composition result: no external witness or append-only store
performed the ceremony; identity and cryptographic distinctness do not prove
independence; revocation, currentness, privacy, provenance truth, and registration
remain unverified; and sentinel-v1 artifacts do not bind the epoch.

Local 2026-09-01 progress: milestone **3b phase 2** now has a separate
[phase-bound sentinel successor v1](sentinel-phase-binding-v1.md). A closed outer
snapshot rebuilds phase 1 twice from raw evidence and requires its exact seven-field
context in the v2 manifest, all 39 case payloads, and all 39 provenance packets.
The goal plan must bind the raw v2 sentinel-manifest checkpoint, and the original
outer inventory and bytes must remain unchanged. The terminal state is
`ALL_SENTINEL_PAYLOAD_AND_PROVENANCE_EPOCH_BINDINGS_REPLAYED_NOT_ADMITTED`.
This proves exact byte dependency, not content-conception time or prospective
order. Same-predecessor equivocation, external witness/store independence,
revocation and long-term validity, currentness, privacy, provenance truth, domain
and control semantics, admission, and scoring remain unresolved. The next safe
milestone is a separately reviewed external two-witness ceremony with append-only
store continuity and independently authored public/synthetic generator and reviewer
packets; admission and scoring remain prohibited.

The local Phase 2 boundary passes 53 focused hostile/API/CLI tests, 189 combined
sentinel/witness tests, and 215 tests when the RFC 3161 primitive is included. All
11 assertion-independent probes are byte-identical across normal/optimized Python
and `PYTHONHASHSEED` 1/77. The Phase 2 probe emits 7,599 bytes including the final
LF, SHA-256
`b1ad43c4f2a61c44ec4b1d893b3d843534718b05be105062d066804501d66efb`.

Local 2026-09-01 progress: milestone **3c / Phase 3** now has the separate
[dual-declared-log continuity successor](sentinel-dual-log-continuity-v1.md).
One pre-token custody target binds two witness/trust/runtime descriptors, two
declared store/key tuples, both caller-preserved prior signed heads, and the exact
two-slot rule; the closed outer manifest later supplies both raw RFC 3161 bundles.
The verifier replays those custody bundles and Phase 2 from raw evidence, derives
the transition, verifies it at the prescribed position in both C2SP-signed views
using RFC 6962 proofs, cross-seals both exact intermediate signed checkpoints, and
verifies that seal at the next position in both caller-pinned final heads. The
sequence-2 regression carries sequence 1's exact state forward and extends each
size-2 view to total size 4 by adding transition index 2 and seal index 3; its phase
and custody subreplays are mocked in that particular regression while the store
signatures and Merkle proofs are real synthetic evidence.

The local Phase 3 slice passes 90 focused continuity hostile/API/CLI tests plus 25
RFC 6962 transparency-primitive tests. Four normal/optimized x `PYTHONHASHSEED`
1/77 probe outputs are byte-identical at 9,334 bytes including the final LF,
SHA-256
`9ac4234694b31345034e966c3c4fdd1893d07c4b6596e2da430138a2d810a8a9`.
This milestone remains local, unreleased, and synthetic. No external witness or
store participated; global uniqueness, hidden/future-fork absence, currentness,
actual independence, admission, scoring, scientific impact, and a 10x result
remain false or `NO_CALL`. No commit, tag, release, publication, or scientific
claim is implied.

## Stop conditions

Pause the dynamic workflow and request review if:

- the fixed parameter would change;
- a step needs clinical, human, legal, biological, or material authority;
- only mutable or retrospectively contaminated evidence is available;
- an external checkpoint or exact backup cannot be verified;
- a requested action would expose private memory or sensitive data; or
- evidence supports a result claim beyond the software's measured scope.
