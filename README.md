# CausalFrontier

[![CI](https://github.com/xevansmithx-del/causalfrontier/actions/workflows/ci.yml/badge.svg)](https://github.com/xevansmithx-del/causalfrontier/actions/workflows/ci.yml)
[![CodeQL](https://github.com/xevansmithx-del/causalfrontier/actions/workflows/codeql.yml/badge.svg)](https://github.com/xevansmithx-del/causalfrontier/actions/workflows/codeql.yml)
[![Python 3.10–3.14](https://img.shields.io/badge/python-3.10%E2%80%933.14-blue)](https://www.python.org/)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)
[![Latest release](https://img.shields.io/github/v/release/xevansmithx-del/causalfrontier?include_prereleases&label=release)](https://github.com/xevansmithx-del/causalfrontier/releases)

> **Research status:** structural pre-alpha. The development tree is
> `0.1.0a5`; the latest packaged release is `v0.1.0a2`. Documented independent
> scientific uses, prospectively scored cases, and semantically verified
> controls are all zero. See the
> [publication-readiness assessment](docs/publication-readiness-2026-09-04.md).

CausalFrontier is a pre-alpha compiler for one narrow but potentially important scientific task: turn a frozen evidence package and explicit competing causal worlds into an auditable frontier of next falsification checks.

The long-range idea is a public causal challenge network in which biomedical claims become replayable, adversarially testable objects instead of prose conclusions. This repository is only the first software slice. It shows that a small authored case can be file-bound, open-world through a residual, branch-complete through failure and contradiction, compared without priors, and replayed with checkpointed local memory.

It does **not** discover a drug, infer a causal effect, validate a biological mechanism, recommend care, or save lives. Those goals require independent evidence and validation far beyond this prototype.

## Start here

- **New users:** [source-tree reproduction pilot](docs/independent-reproduction.md)
- **Reviewers:** [validation record](VALIDATION.md) and [exact source manifest](SOURCE_SHA256SUMS.txt)
- **Researchers:** [scientific problem and falsifiable success criteria](docs/problem-selection.md)
- **Maintainers:** [contribution guide](CONTRIBUTING.md), [governance](GOVERNANCE.md), and [support](SUPPORT.md)
- **Journal planning:** [publication-readiness assessment](docs/publication-readiness-2026-09-04.md)
- **All documentation:** [documentation index](docs/index.md)

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
10. rejects post-hoc branches, requires an independently stored ledger-head checkpoint for every append, and records linked counterfactual branch paths as rehearsals, never observations; and
11. conservatively rejects a synthetic registry candidate when differently named cases collide under an exact label-invariant v1 structural model, while requiring semantic review and leaving registration and scientific scoring disabled; and
12. binds a successor program-level claim plan that requires tenfold improvement against expert, retrieval, graph, random, and an explicitly predeclared simple-rule baseline in every declared domain, without accepting outcomes or scoring; and
13. closes a full three-domain sentinel packet over exact artifact bytes, a caller-supplied pre-generation Latin-square declaration, declared provenance-graph structures, cutoff declarations, external-review packets, and the immutable goal-plan cohort checkpoint while still refusing admission or scoring; and
14. replays two raw RFC 3161 evidence bundles against one canonical pre-token sentinel generation target and derives a post-token generation epoch, while keeping artifact phase binding, external independence, registration, admission, and scoring false; and
15. snapshots a closed successor composition, rebuilds phase 1 twice from raw evidence, and requires the resulting seven-field context in the v2 manifest and all 39 payload plus 39 provenance packets while preserving `NO_CALL` for timing, uniqueness, independence, admission, and scoring; and
16. replays two raw RFC 3161 custody-witness bundles over one pre-token target, freshly rebuilds the phase-bound transition, and requires that exact transition plus one cross-log seal in two caller-pinned C2SP-signed declared log views with RFC 6962 proofs, without admitting or scoring anything; and
17. locks one known-hindsight positive/failed-translation/ambiguous calibration trio, two declared policy outputs per role, and complete exploratory ledgers before a separate committed opening, then emits a blocked label-match report without enabling comparison or scientific scoring; and
18. adds a [calibration V2 structural rehearsal](docs/calibration-tripwire-v2.md) with a role-hidden-by-syntax entrant view, bounded structured actions, an exact harm-first 72-coordinate branch table, nonce-bound reveal and rubric commitments, a declared three-reviewer/two-organization plan, and five checkpointed artifact zones while hard-coding method recovery and every scientific result to `NO_CALL` or `false`.

Structural analysis labels an unblocked discriminator `STRUCTURALLY_ADMISSIBLE_UNEXECUTED`. The separate `classify` command and capsule build execute its registered classifier, but that only proves deterministic mapping of the frozen synthetic file to a declared branch. It is not experimental or biological readiness. A contradiction invalidates the current partition, retains only the open residual, clears both frontiers, and requires a newly frozen case.

The fixed project parameter is:

`OPEN_MACHINE_VERIFIABLE_TRANSLATION_FROM_FRAGMENTED_BIOMEDICAL_EVIDENCE_TO_NEXT_FALSIFIABLE_ACTION`

Disease, modality, model, source type, and deployment setting remain deliberately changeable.

## Quick start

From this directory with Python 3.10 or later:

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

The V2 calibration path is a separate, local rehearsal over five disjoint zones:
entrant root, view lock, submission plus submission seal, opening plus rubric plus
adjudication, and report. It binds real ToolUniverse, GraceGraph, GraceLoop, and
CausalFrontier artifact and resource-receipt digests, but the calibration verifier
does not replay or authenticate those tools. Role hiding is syntactic only, and a
valid local replay cannot promote method recovery or a scientific claim.

## Two-week go/kill decision

Continue this representation only if all of these pass:

- three independently authored public-aggregate cases from at least two biomedical domains compile without relaxing the residual, total-branch, or authority rules;
- two blinded encoders working from the same frozen source meet preregistered field-level, label-invariant graph/branch agreement and critical-disagreement thresholds before reconciliation, with every disagreement machine-visible;
- at least two cases eliminate a dominated discriminator and return a nonempty structurally admissible, unexecuted frontier;
- known-hindsight positive, failed-translation, and ambiguous historical replays are frozen as calibration-only controls; no local hash is described as restoring prospective blinding;
- hostile reviewers cannot add a post-hoc branch, remove the residual, bypass a gate, roll back checkpointed memory, or corrupt the capsule without detection; and
- normal and optimized Python produce the same run and verification digests.

Kill or redesign this schema if residuals make every discriminator non-informative, authored relations masquerade as machine inference, independent encoders cannot reconcile partitions, historical receipts cannot prevent time leakage, or users read the output as efficacy, diagnosis, safety, or treatment advice.

## Verification

```bash
python -m pytest -q
python tests/optimized_probe.py
python -O tests/optimized_probe.py
python tests/challenge_optimized_probe.py
python -O tests/challenge_optimized_probe.py
python tests/protocol_optimized_probe.py
python -O tests/protocol_optimized_probe.py
python tests/blind_optimized_probe.py
python -O tests/blind_optimized_probe.py
python tests/horse_race_optimized_probe.py
python -O tests/horse_race_optimized_probe.py
python tests/neutral_optimized_probe.py
python -O tests/neutral_optimized_probe.py
python tests/registry_optimized_probe.py
python -O tests/registry_optimized_probe.py
python tests/claim_optimized_probe.py
python -O tests/claim_optimized_probe.py
python tests/sentinel_optimized_probe.py
python -O tests/sentinel_optimized_probe.py
PYTHONHASHSEED=1 python tests/witness_optimized_probe.py
PYTHONHASHSEED=77 python tests/witness_optimized_probe.py
PYTHONHASHSEED=1 python -O tests/witness_optimized_probe.py
PYTHONHASHSEED=77 python -O tests/witness_optimized_probe.py
PYTHONHASHSEED=1 python tests/phase_optimized_probe.py
PYTHONHASHSEED=77 python tests/phase_optimized_probe.py
PYTHONHASHSEED=1 python -O tests/phase_optimized_probe.py
PYTHONHASHSEED=77 python -O tests/phase_optimized_probe.py
PYTHONHASHSEED=1 python tests/continuity_optimized_probe.py
PYTHONHASHSEED=77 python tests/continuity_optimized_probe.py
PYTHONHASHSEED=1 python -O tests/continuity_optimized_probe.py
PYTHONHASHSEED=77 python -O tests/continuity_optimized_probe.py
PYTHONHASHSEED=1 python tests/calibration_optimized_probe.py
PYTHONHASHSEED=77 python tests/calibration_optimized_probe.py
PYTHONHASHSEED=1 python -O tests/calibration_optimized_probe.py
PYTHONHASHSEED=77 python -O tests/calibration_optimized_probe.py
python -m pytest tests/test_calibration_v2.py tests/test_calibration_v2_api_cli.py -q
PYTHONHASHSEED=1 python tests/calibration_v2_optimized_probe.py
PYTHONHASHSEED=77 python tests/calibration_v2_optimized_probe.py
PYTHONHASHSEED=1 python -O tests/calibration_v2_optimized_probe.py
PYTHONHASHSEED=77 python -O tests/calibration_v2_optimized_probe.py
```

The hostile suite covers schema/type errors, prior and observed-outcome leakage, incomplete matrices, residual removal, contradiction behavior, failure/no-call updates, digest and inventory drift, source-semantics mismatches, omitted gates and authorities, post-hoc branches, partition-refinement bias, capsule tampering, semantic ledger forgery, local rollback with an external checkpoint, sequential branch lineage, no-clobber publication, neutral common-input and action-payload drift, incomplete OFAT geometry, multi-seed order replay, forged protocol counters, attempts to make observational telemetry score-relevant, label/ID/order-invariant structural-collision detection, nonce rotation, exact view replay, graph-search exhaustion, missing or aliased goal comparators, favorable censoring, reversed ratios, pooled-domain substitution, hindsight-as-primary substitution, forged claim-plan projections, v1-to-v2 downgrade, missing/wrong/mixed phase context across every case role, coherent epoch/preflight/plan/sequence substitution, raw outer-file preimage aliases, stale or CLI-forged reports, deterministic malformed-context errors, unsafe/empty/orphaned outer filesystem entries, closed-composition drift, escaped-JSON private-material encodings, and cross-role cloned calibration inputs.

## Nonclaims and safety boundary

- The included aggregate table is synthetic and is not biological evidence.
- Prediction relations, scientific totality/exclusivity, source dates, licenses, coverage, privacy class, and authority are author declarations. The built-in classifier makes the fixture's branch mapping executable; it does not externally attest those scientific declarations.
- Software replay validates structure, local file binding, and deterministic computation only.
- No patient-level data, clinical advice, wet-lab execution, material ordering, pathogen design, or human decision authority is supported.
- A frontier identifies discriminating checks under the declared model, not truth.
- Temporal metadata is labelled `DECLARED_TEMPORAL_METADATA_UNATTESTED`; historical scoring is disabled.
- A public-development-source, unreleased [RFC 3161 verifier](docs/rfc3161-attestation-v1.md) now verifies
  narrow offline signature, chain, target-imprint, nonce, policy, CMS-digest, and signed-
  accuracy evidence at signed `genTime` under caller-pinned trust. It requires exactly
  one canonical PEM trust-anchor certificate and exposes SPKI plus key-type-aware
  canonical mathematical key projections for the root and extracted signer. Recursive
  DER canonicality, runtime hermeticity, intended signer identity, full-accuracy-interval
  certificate validity, revocation, unqualified timestamp/digest existence, source
  availability, witness independence, rollback currentness, and historical admissibility
  remain false or `NO_CALL`.
- The [dual-witness generation lock](docs/sentinel-dual-witness-lock-v1.md) composes
  two such raw replays and derives an exact generation epoch. Its six-field universal
  identifier-collision namespace includes attestation and policy IDs, and it rejects
  shared root/signer mathematical key material. Those hygiene gates do not prove
  independence. Sentinel-v1 generated artifacts do not yet bind the epoch, and the
  absence of a designated outcome input does not exclude covert outcome encoding in
  accepted identifiers, certificates, nonces, tokens, or later manifests.
- The separate public-development-source, unreleased [phase-bound successor](docs/sentinel-phase-binding-v1.md)
  leaves sentinel v1 unchanged while requiring one freshly replayed seven-field
  phase context in its v2 manifest and all 39 payload and 39 provenance packets.
  This proves exact byte dependency only. It does not establish when content was
  conceived, genuine prospective order, successor uniqueness, independence,
  privacy, provenance truth, cohort admission, or scientific validity.
- The public-development-source, unreleased synthetic [dual-declared-log continuity successor](docs/sentinel-dual-log-continuity-v1.md)
  accepts only the C2SP checkpoint profile
  `c2sp.org/tlog-checkpoint@v1.0.0-ed25519-pinned-key` and the proof profile
  `RFC6962_SHA256_PREORDERED_TWO_SLOT_V1`. For sequence `n`, each supplied view
  must extend size `2(n - 1)` with the freshly derived transition at index
  `2(n - 1)` and the identical cross-log seal at index `2(n - 1) + 1`, ending at
  size `2n`. This verifies one edge only relative to caller-pinned signed heads.
  It does not prove external store or witness operation, hidden/future-fork
  absence, global successor uniqueness, global currentness, store/controller/
  signer independence, admission, scoring, a 10x result, or scientific impact.
- This prototype has no prospective benchmark and no empirical health-impact result.
- The public-development-source, unreleased [calibration tripwire](docs/calibration-tripwire-v1.md)
  returns one action-role label match out of three for CausalFrontier and one for
  the simple rule. CausalFrontier declared `NO_CALL` on every role, so its lone
  match is always-abstain-equivalent—not calibrated ambiguity recognition. No
  winner, action-semantic validation, total branch proof, real-resource result,
  independent custody, rollback resistance, 10x estimate, or scientific claim
  is present. V1 remains a historical diagnostic, not the current protocol.
- The public-development-source, unreleased [calibration V2 structural rehearsal](docs/calibration-tripwire-v2.md)
  strengthens artifact closure, structured-action representation, and mechanical
  branch coverage. Its view omits registered role/reveal fields only syntactically;
  recognizable content and model exposure can still leak roles. Its 72-coordinate
  table is total only over the fixed four-axis language, with `HARM` always routing
  first to `STOP_FOR_SAFETY`. The nonce-bound opening and rubric, declared
  three-reviewer/two-organization plan, and checkpointed zones do not prove time,
  custody, reviewer identity, independence, semantics, or currentness. Toolbox
  artifact digests are bound but not replayed or authenticated. Method recovery is
  hard-coded `NO_CALL`, and scientific readiness, scoring, and claim fields remain
  `false`.

See [the architecture decision](docs/architecture.md), [benchmark contract](docs/benchmark.md), [problem-selection record](docs/problem-selection.md), [competitive landscape](docs/competitive-landscape-2026-09-02.md), [public adoption audit](docs/adoption-audit-2026-09-02.md), [biomedical tool probe](docs/tooluniverse-probe.md), [historical calibration V1 diagnostic](docs/calibration-tripwire-v1.md), [calibration V2 structural rehearsal](docs/calibration-tripwire-v2.md), [V2 source map](docs/calibration-tripwire-v2-source-map.md), and [dynamic workflow](docs/dynamic-workflow.md).

The current zero-to-one direction is a model-neutral [scientific-decision challenge network](docs/scientific-decision-challenge.md): a cross-domain extension of CASP- and CACHE-like blind evaluation that would measure the audited resource needed for a correct, replicated decision-state transition. Public development source now replays receipt bundles, requires both byte and acquisition-semantic agreement with frozen dossier sources, binds a shared dossier/gate/action contract across two encoder strata, validates total branch contracts and 15 specification-only baseline schemas, and locks a provisional metric and reveal scheme. The earlier [synthetic protocol kernel](docs/protocol-exercise-v1.md) remains an explicitly nonblind commitment exercise. Its [structurally blinded successor](docs/blind-execution-v1.md) adds an allowlisted opaque entrant view, byte-derived replicate reports, synthetic vector tariffs, and a deterministic per-episode event chain. The [complete-matrix successor](docs/horse-race-v1.md) requires six cloned structural fixture instances arranged across three declared synthetic domain labels and automatically replays every case × encoder lane × locked policy coordinate, eliminating caller-selected favorable episodes. The new [registry-candidate assessment](docs/registry-candidate-v1.md) correctly rejects all six as one label-invariant v1 structural-collision class requiring semantic review instead of treating submitted labels as cross-domain evidence. These fixtures test plumbing, balance constraints, and collision rejection—not cross-domain validity. Scientific scoring remains disabled because the input tier is candidate-derived, preprocessing is unmetered, true random and required comparators are absent, terminal truth is not independent, and custody, privacy, resources, governance, and prospective validity remain unverified.

The separate [goal-claim contract](docs/goal-claim-contract-v1.md) fixes a P0
evaluation mismatch without modifying preserved challenge-v1 artifacts. A valid
plan must precommit the full domain × expert/retrieval/graph/random/simple-rule
conjunction plus pooled cells, a complete ITT matrix, one execution design, one
common input and resource meter, currency/date/horizon rules, conservative
missingness and censoring, simultaneous abstention and false-exclusion bounds,
at least ten primary cases and two case-linked laboratories per domain, and
positive/failed/ambiguous calibration controls in every domain. It also binds
exact provenance stages, prospective-blind primary
timing, a public/synthetic boundary, a complete independent holdout replay, and
a non-contributor multi-organization early-career usability study before any
outcome channel exists. Distinct digests do not verify baseline semantics or
controller independence. Passing preflight is still `NO_CALL`; none of those
external gates has been executed or verified.
Declared domain geometry is not cohort admission: domain semantics, generator
independence, and cutoff admissibility remain false pending an external
sentinel-admission manifest and audit.

The public-development-source, unreleased [sentinel admission v1](docs/sentinel-admission-v1.md) now
implements that artifact-closure seam. It fixes three domains and three declared
generator-family clusters under the maximal-family rule, thirty primary cases,
nine role-balanced historical controls, and six case-linked laboratories. A
caller-supplied predecessor plan declares every case and generator assignment
frozen before generation; it is not an externally timestamped or independently
held custody record. The resulting 326-artifact raw sentinel manifest must equal
the validated goal plan's cohort
checkpoint. Empty protocol bytes, JSON artifacts declared with a non-JSON media
type, exact shared generator-component bytes or identities, case-insensitive or
cross-dimension controller/store aliases, cross-role organization aliases, branch-
observation/role mislinkage, source/date inconsistencies, failure to place each
primary generator in both laboratories, per-cell imbalance, normalized collisions,
and post-cutoff declarations are rejected. A clean packet is only
`REVIEW_PACKET_COMPLETE_NOT_ADMITTED`: different hashes, reviewer IDs, declared
provenance graphs, and self-declared dates do not establish semantic, temporal,
privacy, provenance, independence, commitment-scheme, or governance truth, and no
outcome or score is accepted.

The public-development-source, unreleased [sentinel dual-witness generation lock v1](docs/sentinel-dual-witness-lock-v1.md)
adds a bounded phase-1 bridge. One canonical target binds the exact generation plan,
organization registry, witness pair, trust policies, runtime digests, completion
deadline, and absence of generated artifacts, outcomes, openings, and scoring before
either token is available. The preflight reconstructs two raw RFC 3161 verifications
against those same target bytes. It requires one canonical trust-anchor certificate per
policy; applies one case-insensitive collision namespace to each witness, organization,
controller, store, attestation, and policy ID; and rejects shared trust-root or TSA-signer
canonical mathematical key material in addition to byte/SPKI/token aliases. It then
derives `generation_epoch_sha256`. Its result remains
`DUAL_WITNESS_PLAN_LOCK_REPLAYED_GENERATION_EPOCH_DERIVED_NOT_ADMITTED`: no external
witness was used and witness or store independence is not established. The separate
[phase-bound successor](docs/sentinel-phase-binding-v1.md) now closes the local schema
seam: it rebuilds phase 1 twice from raw evidence, derives the exact seven-field
context, requires it in the v2 manifest and all 39 payload and 39 provenance packets,
and verifies that the goal plan binds the raw successor-manifest checkpoint. Its
terminal status is
`ALL_SENTINEL_PAYLOAD_AND_PROVENANCE_EPOCH_BINDINGS_REPLAYED_NOT_ADMITTED`. This is
still not evidence of content-conception time, prospective order, successor
uniqueness, external custody, independence, admission, or scientific validity. No
designated outcome parameter is accepted, but covert selection or encoding through
otherwise accepted fields remains possible, so content/outcome isolation is false.

A separate [neutral baseline substrate](docs/neutral-baselines-v1.md) now replays
portable multi-seed random, blind-OFAT, and informed-OFAT action orders from one
exact embedded, declared-precompilation synthetic action/authority input. Seed
commitments are context-bound to the authorized action universe. Deterministic
protocol counters remain separate from optional untrusted same-process telemetry.
This is ordering and counter plumbing only: no scientific baseline family, outcome,
winner, impact, 10x result, or real resource is measured, and semantic neutrality,
currentness, and rollback protection remain explicitly unverified.

## Public development source, unreleased

The [receipt v1 preflight](docs/receipt-v1.md) prepares hash-bound source metadata while
always abstaining from historical admission and scoring. Public repository source uses
the unreleased `0.1.0a5` development identity and is not part of the tagged `0.1.0a2`
release. Calibration V1 remains a historical diagnostic; V2 is a public-source structural
rehearsal, not a scientific or method-recovery result. An RFC 3161 offline signed-target-imprint evidence verifier is now implemented separately,
but no independent timestamp was collected, no source-availability verifier exists, and
receipt admission remains disabled. The PCSK9 control is explicitly known-hindsight
because its later outcomes were exposed in the initial project probe. Publishing source
does not create a package release, scientific publication, or scientific claim.

Freeze the program-level success definition before preparing a future scoring
cohort:

```bash
causalfrontier preflight-goal-claim-plan GOAL_CLAIM_PLAN.json \
  --expected-plan-checkpoint-sha256 EXACT_RAW_PLAN_SHA256
```

The command emits a deterministic structural preflight and exits `3`. It accepts
no outcome, result, reveal, winner, or score input. The original challenge-v1
metric remains preserved and is explicitly insufficient for the successor goal.

The timestamp verifier exposes one command and public API. It replays a nonce- and
policy-bearing request and the exact target bytes in separate OpenSSL verification passes,
requires exact caller checkpoints for the target, attestation, trust policy, and OpenSSL
binary plus the caller-preserved not-after limit. It exits `3` even after valid offline evidence
because broader temporal and scientific admissibility remain unresolved. The focused
hostile suite has 26 tests.

The phase-1 dual-witness command similarly exits `3` after replaying exactly two
aligned raw evidence bundles and deriving an unadmitted generation epoch:

```bash
causalfrontier preflight-sentinel-dual-witness-lock \
  LOCK_ROOT SENTINEL_GENERATION_PLAN.json \
  --expected-lock-manifest-sha256 RAW_LOCK_MANIFEST_SHA256 \
  --expected-generation-plan-sha256 RAW_GENERATION_PLAN_SHA256 \
  --expected-sequence 1 \
  --openssl /absolute/path/to/witness-a-openssl \
  --expected-openssl-sha256 WITNESS_A_OPENSSL_SHA256 \
  --openssl /absolute/path/to/witness-b-openssl \
  --expected-openssl-sha256 WITNESS_B_OPENSSL_SHA256
```

This is a local byte-composition preflight, not evidence that two external or
independent witnesses performed the ceremony.

The phase-bound successor also exits `3`. Pass each OpenSSL path and aligned digest
exactly twice, in the phase-1 witness order:

```bash
causalfrontier preflight-sentinel-phase-bound-admission \
  COMPOSITION_ROOT \
  --expected-composition-manifest-sha256 RAW_OUTER_MANIFEST_SHA256 \
  --expected-sequence 1 \
  --openssl /absolute/path/to/witness-a-openssl \
  --expected-openssl-sha256 WITNESS_A_OPENSSL_SHA256 \
  --openssl /absolute/path/to/witness-b-openssl \
  --expected-openssl-sha256 WITNESS_B_OPENSSL_SHA256
```

A valid result is an integrity receipt only. It does not admit or score the cohort.

The Phase 3 dual-declared-log continuity preflight is also public development source, unreleased, and
synthetic. Sequence 1 has a null predecessor; pass each aligned runtime and digest,
and each prior/final store checkpoint, exactly twice. Phase runtimes follow the
nested Phase 1 witness order; custody and store inputs follow the order frozen by
the pre-token custody target:

```bash
causalfrontier preflight-sentinel-dual-log-continuity \
  CONTINUITY_ROOT \
  --expected-composition-manifest-sha256 RAW_CONTINUITY_MANIFEST_SHA256 \
  --expected-sequence 1 \
  --expected-prior-store-checkpoint-sha256 STORE_A_PRIOR_CHECKPOINT_SHA256 \
  --expected-prior-store-checkpoint-sha256 STORE_B_PRIOR_CHECKPOINT_SHA256 \
  --expected-final-store-checkpoint-sha256 STORE_A_FINAL_CHECKPOINT_SHA256 \
  --expected-final-store-checkpoint-sha256 STORE_B_FINAL_CHECKPOINT_SHA256 \
  --phase-openssl /absolute/path/to/phase-witness-a-openssl \
  --expected-phase-openssl-sha256 PHASE_WITNESS_A_OPENSSL_SHA256 \
  --phase-openssl /absolute/path/to/phase-witness-b-openssl \
  --expected-phase-openssl-sha256 PHASE_WITNESS_B_OPENSSL_SHA256 \
  --custody-openssl /absolute/path/to/custody-witness-a-openssl \
  --expected-custody-openssl-sha256 CUSTODY_WITNESS_A_OPENSSL_SHA256 \
  --custody-openssl /absolute/path/to/custody-witness-b-openssl \
  --expected-custody-openssl-sha256 CUSTODY_WITNESS_B_OPENSSL_SHA256 \
  --store-openssl /absolute/path/to/store-a-openssl \
  --expected-store-openssl-sha256 STORE_A_OPENSSL_SHA256 \
  --store-openssl /absolute/path/to/store-b-openssl \
  --expected-store-openssl-sha256 STORE_B_OPENSSL_SHA256
```

Persist the returned `report["current_state"]` as one canonical JSON object plus LF
and preserve its `state_sha256` independently. For sequence 2, repeat the complete
command above with `--expected-sequence 2`, add
`--expected-predecessor-continuity-state-sha256 SEQUENCE_1_STATE_SHA256`, and add
`--predecessor-continuity-state /absolute/path/to/sequence-1-state.json`. Every
later sequence likewise requires the immediate predecessor while retaining all
two-element prior/final checkpoint and phase/custody/store runtime arguments.

The public API has the same contract:

```python
from pathlib import Path

from causalfrontier import preflight_sentinel_dual_log_continuity

report = preflight_sentinel_dual_log_continuity(
    root=Path("CONTINUITY_ROOT"),
    expected_composition_manifest_sha256=manifest_sha256,
    expected_sequence=2,
    expected_predecessor_continuity_state_sha256=previous_state["state_sha256"],
    predecessor_continuity_state_path=Path("/absolute/path/to/sequence-1-state.json"),
    expected_prior_store_checkpoint_sha256s=prior_store_checkpoints,
    expected_final_store_checkpoint_sha256s=final_store_checkpoints,
    phase_openssl_paths=phase_openssl_paths,
    expected_phase_openssl_sha256s=phase_openssl_sha256s,
    custody_openssl_paths=custody_openssl_paths,
    expected_custody_openssl_sha256s=custody_openssl_sha256s,
    store_openssl_paths=store_openssl_paths,
    expected_store_openssl_sha256s=store_openssl_sha256s,
)
```

The immediate predecessor state fixes the continuity ID, sequence, each complete
ordered store/operator/controller/store-group/namespace/origin/verifier-key-digest/
runtime/declared-independence tuple, and requires each prior checkpoint, root, and
size to equal the preceding final head. A successful CLI replay exits `3` with
status
`DUAL_DECLARED_LOG_EDGE_AND_CROSS_SEAL_REPLAYED_RELATIVE_TO_CALLER_CHECKPOINTS_NOT_ADMITTED`.
The focused local suites currently pass 90 continuity tests plus 25 transparency-
primitive tests. All four normal/optimized x hash-seed continuity probes emit 9,334
bytes including the terminal LF, SHA-256
`9ac4234694b31345034e966c3c4fdd1893d07c4b6596e2da430138a2d810a8a9`.
No external store or witness participated, and global uniqueness, currentness,
independence, admission, scoring, and a 10x result remain false or `NO_CALL`.

The neutral substrate exposes validate, universe-bound seed commitment, plan, order
lock, exercise, and verification commands. Successful commands emit structural
artifacts and exit `3`. The focused neutral hostile/regression suite has 17 tests,
and the focused public API/CLI plus neutral slice has 29. Normal, `python -O`, and
alternate-hash-seed probe outputs are byte-identical with exact emitted-output
SHA-256 `b4ea90ee210fbb046d32273845b84dc4611cb972aa0740c1664b34665c326bc0`.
See the dedicated contract for the exact common-input, factor/action, portable-random,
OFAT, counter/telemetry, verifier, and nonclaim rules.

The local protocol exercise is deliberately split:

```bash
causalfrontier lock-reference-selections CHALLENGE_ROOT \
  --expected-manifest-sha256 EXTERNAL_SHA256 --expected-sequence N

causalfrontier open-synthetic-reveal CHALLENGE_ROOT OPENING_JSON \
  --expected-manifest-sha256 EXTERNAL_SHA256 --expected-sequence N \
  --expected-opening-sha256 EXTERNAL_OPENING_SHA256
```

Both successful commands exit `3`. The first API has no reveal input; the second verifies commitment and inventory but cannot derive outcomes from hidden observation bytes. Neither executes the 15 required scientific comparators or measures a 10x result.

The successor path is also public development source and unreleased. Every redirected JSON receipt below
must be preserved byte-for-byte and supplied later with the SHA-256 of those exact
bytes:

```bash
causalfrontier build-sanitized-view CHALLENGE_ROOT RACE_SPEC NONCE_FILE \
  --expected-manifest-sha256 PROVISIONAL_CHALLENGE_SHA256 --expected-sequence N \
  --expected-race-spec-sha256 EXTERNAL_RACE_SHA256 \
  --expected-nonce-sha256 EXTERNAL_NONCE_SHA256 > ENTRANT_VIEW

causalfrontier assess-registry-candidate \
  CHALLENGE_ROOT RACE_SPEC ENTRANT_VIEW NONCE_FILE \
  --expected-manifest-sha256 PROVISIONAL_CHALLENGE_SHA256 --expected-sequence N \
  --expected-race-spec-sha256 EXTERNAL_RACE_SHA256 \
  --expected-view-sha256 EXTERNAL_VIEW_SHA256 \
  --expected-nonce-sha256 EXTERNAL_NONCE_SHA256 > REGISTRY_ASSESSMENT

causalfrontier prepare-observation-commitment \
  CHALLENGE_ROOT RACE_SPEC ENTRANT_VIEW ORACLE_ROOT ORACLE_PAYLOAD NONCE_FILE \
  --expected-manifest-sha256 PROVISIONAL_CHALLENGE_SHA256 --expected-sequence N \
  --expected-race-spec-sha256 EXTERNAL_RACE_SHA256 \
  --expected-view-sha256 EXTERNAL_VIEW_SHA256 \
  --expected-payload-sha256 EXTERNAL_PAYLOAD_SHA256 \
  --expected-nonce-sha256 EXTERNAL_NONCE_SHA256 > COMMITMENT_PREFLIGHT

# Persist and checkpoint COMMITMENT_PREFLIGHT, then insert its commitment
# and seal the final challenge manifest before invoking the selector.
causalfrontier lock-blind-selections ENTRANT_VIEW \
  --expected-view-sha256 EXTERNAL_VIEW_SHA256 > SELECTION_LOCK

causalfrontier bind-blind-selection-precommitment \
  ENTRANT_VIEW SELECTION_LOCK \
  --expected-view-sha256 EXTERNAL_VIEW_SHA256 \
  --expected-selection-sha256 EXTERNAL_SELECTION_SHA256 \
  --expected-commitment-preflight-sha256 EXTERNAL_PREFLIGHT_SHA256 \
  > SELECTION_ENVELOPE

# Checkpoint SELECTION_ENVELOPE, then add the exact preflighted opening.json.
causalfrontier execute-blind-synthetic \
  CHALLENGE_ROOT RACE_SPEC ENTRANT_VIEW SELECTION_LOCK \
  SELECTION_ENVELOPE COMMITMENT_PREFLIGHT ORACLE_ROOT \
  ENTRANT_CASE_ID ENTRANT_LANE_ID POLICY_ID \
  --expected-manifest-sha256 FINAL_CHALLENGE_SHA256 --expected-sequence N \
  --expected-race-spec-sha256 EXTERNAL_RACE_SHA256 \
  --expected-view-sha256 EXTERNAL_VIEW_SHA256 \
  --expected-selection-sha256 EXTERNAL_SELECTION_SHA256 \
  --expected-selection-envelope-sha256 EXTERNAL_ENVELOPE_SHA256 \
  --expected-commitment-preflight-sha256 EXTERNAL_PREFLIGHT_SHA256 \
  --expected-opening-sha256 EXTERNAL_OPENING_SHA256
```

`ORACLE_ROOT` contains only the committed observation files during preparation. Persist
and checkpoint `COMMITMENT_PREFLIGHT`, copy its `reveal_commitment_sha256` into the
otherwise final challenge manifest, and preserve that newly sealed manifest digest.
The challenge registration excludes only the commitment value, so this final seal does
not change the opaque registration binding. After the view-only lock and steward-side
envelope are checkpointed, add `ORACLE_ROOT/opening.json` as the exact canonical JSON
object formed from the checkpointed payload and nonce, plus one newline; its raw digest
must equal both the preflight's `oracle_opening_sha256` and the execution argument.

The complete execution receipt is steward-only. Direct hidden observation fields and
group-keyed metrics are omitted, but payload and checkpoint hashes remain linkable and
can confirm guesses about otherwise known hidden artifacts; no public unlinkable
projection is implemented.

Successful structural receipts—including terminal policies that classify no
observation—exit `3`. A no-observation execution reports
`SYNTHETIC_BLIND_POLICY_TERMINATED_WITHOUT_OBSERVATION_CLASSIFICATION_SCIENTIFIC_SCORING_DISABLED`.
An execution that returns `integrity_valid:false` still emits its structured JSON receipt
but exits `2`; rejected inputs also exit `2` with an error. The successor derives
synthetic branches from exact selected bytes and records their lifecycle, but it remains
a protocol test rather than a budget-matched scientific comparison.
