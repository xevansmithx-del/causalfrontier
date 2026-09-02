# Sentinel generation phase binding v1

## Purpose

This local, unreleased successor closes the byte-level seam left open by the
[sentinel dual-witness generation lock](sentinel-dual-witness-lock-v1.md). Phase 1
derives a `generation_epoch_sha256` after replaying two raw RFC 3161 bundles, but
the legacy sentinel-v1 payload and provenance schemas do not contain that epoch.
This successor reconstructs phase 1 from the raw evidence and requires one exact
generation-phase context directly in every generated case payload and every case
provenance packet.

The terminal status is:

```text
ALL_SENTINEL_PAYLOAD_AND_PROVENANCE_EPOCH_BINDINGS_REPLAYED_NOT_ADMITTED
```

That status means only that the exact accepted bytes depend on the freshly
replayed phase-1 result. It does not establish when the scientific content was
conceived or prepared, that the witnesses or stores were independent, that this
is the unique successor to the phase-1 lock, or that the cohort is admissible or
scientifically useful.

The fixed project parameter remains:

```text
OPEN_MACHINE_VERIFIABLE_TRANSLATION_FROM_FRAGMENTED_BIOMEDICAL_EVIDENCE_TO_NEXT_FALSIFIABLE_ACTION
```

Admission and scientific scoring remain disabled.

## Closed composition

One caller-checkpointed outer root contains the complete phase-1 evidence, the
phase-bound sentinel bundle, and both predecessor plans:

```text
COMPOSITION_ROOT/
  sentinel-phase-bound.json
  <generation-plan path>
  <goal-claim-plan path>
  <dual-witness-lock root>/
    dual-witness-lock.json
    <canonical target and organization registry>
    <two raw attestation and trust-policy subtree pairs>
  <sentinel root>/
    sentinel-admission.json
    <complete phase-bound sentinel artifact graph>
```

The generation-plan and goal-plan paths are distinct relative file paths. The
dual-witness and sentinel roots are distinct single directory components. None
of the three direct files may equal or lie under either inner root. The outer
file inventory must be exactly the three direct files plus every file below the
two declared roots; no extra or orphan file is accepted.

The outer reader is bounded to 640 visited filesystem entries, 1 MiB per file,
and 96 MiB in total. It rejects traversal, symlinks, hard-linked files, other
unsafe filesystem objects, checkpoint mismatches, overlapping paths, and file or
inventory drift. All supplied files are copied into a process-owned private
temporary snapshot before either inner verifier runs. After both inner replays,
the original outer inventory and every original byte are read again and compared
with the first snapshot.

The outer operation does not modify the supplied composition. Temporary snapshot
files are an internal verification mechanism, not a persistent output or external
checkpoint.

## Exact composition-manifest schema

`sentinel-phase-bound.json` must be the single canonical JSON encoding plus one
terminal LF. It uses schema
`causalfrontier.sentinel-phase-bound-composition.v1`, status
`PHASE_BOUND_SENTINEL_COMPOSITION_CLOSED_ADMISSION_AND_SCORING_DISABLED`, and
exactly these keys:

| Key | Required meaning |
|---|---|
| `schema_version` | Exact composition schema literal |
| `status` | Exact composition status literal |
| `composition_id` | Stable composition identifier |
| `sequence` | Positive sequence equal to the phase context, generation plan, inner sentinel manifest, phase-1 lock, goal plan, and caller value |
| `fixed_parameter` | Exact fixed project parameter |
| `boundary` | Exact no-patient/no-clinical/no-material authority boundary |
| `generation_phase_context` | Exact seven-field context described below |
| `generation_plan` | Exact `{path, sha256, media_type}` descriptor for the generation-plan file |
| `goal_claim_plan` | Exact `{path, sha256, media_type}` descriptor for the goal-claim-plan file |
| `dual_witness_lock_root` | Single relative directory component containing the complete phase-1 lock |
| `dual_witness_lock_manifest_checkpoint_sha256` | Raw SHA-256 of the nested `dual-witness-lock.json` file |
| `sentinel_root` | Distinct single relative directory component containing the complete sentinel bundle |
| `sentinel_manifest_checkpoint_sha256` | Raw SHA-256 of the nested `sentinel-admission.json` file |
| `designated_outcome_input_absent` | Exactly `true` |
| `oracle_opening_input_absent` | Exactly `true` |
| `admission_disabled` | Exactly `true` |
| `scoring_disabled` | Exactly `true` |
| `composition_sha256` | Domain-separated semantic digest of every preceding composition field |

Both direct file descriptors have exactly `path`, `sha256`, and `media_type`;
the media type must be `application/json`. The generation-plan descriptor digest
must also equal `generation_plan_checkpoint_sha256` in the phase context.

The semantic composition digest is distinct from the raw manifest-file
checkpoint:

```text
composition_sha256 = SHA256(
  "causalfrontier.sentinel-phase-bound-composition.v1\0"
  || canonical_json(composition_without_composition_sha256)
)
```

The caller supplies the raw SHA-256 of the complete canonical manifest file,
including its terminal LF, as `expected_composition_manifest_sha256`.

## Exact generation-phase context

The context schema is
`causalfrontier.sentinel-generation-phase-context.v1`. It has exactly:

| Key | Source and requirement |
|---|---|
| `schema_version` | Exact context schema literal |
| `lock_id` | Phase-1 report's lock identifier |
| `sequence` | Positive phase-1 report sequence |
| `generation_plan_checkpoint_sha256` | Phase-1 report's raw generation-plan checkpoint |
| `generation_plan_sha256` | Phase-1 report's validated semantic plan digest |
| `generation_lock_preflight_sha256` | Non-null `preflight_sha256` of the current freshly rebuilt phase-1 report |
| `generation_epoch_sha256` | Epoch freshly derived by that same phase-1 report |

Every digest must be a nonzero SHA-256 value. The accepted context is constructed
from one phase-1 report; callers cannot independently choose the epoch or
preflight digest.

`generation_lock_preflight_sha256` is deliberately not the phase-1 target's
`predecessor_lock_preflight_sha256`. The target field is `null` at sequence 1
and, at later sequences, refers to the previous lock. The successor context
instead names the current phase-1 report that derived the accepted epoch.

The complete context is compared by canonical bytes. Field-by-field subsets,
mixed contexts, or an otherwise valid epoch paired with a different preflight,
plan, lock, or sequence are rejected.

## Successor sentinel schemas

The phase-bound path retains the complete geometry and structural checks from
[sentinel admission v1](sentinel-admission-v1.md), while selecting distinct
schemas for the three artifacts that must carry the successor context.

### Phase-bound sentinel admission manifest

The inner `sentinel-admission.json` uses schema
`causalfrontier.sentinel-phase-bound-admission-manifest.v1`. It contains every
exact key required by `causalfrontier.sentinel-admission-manifest.v1` plus one
required `generation_phase_context` object.

The embedded context must equal the freshly derived outer context. The inner
manifest still binds the exact generation-plan raw and semantic digests, the
fixed goal-claim contract, all organizations, generators, domains, cases, review
packets, protocol artifacts, and the complete bounded artifact inventory. Its
`designated_outcome_input_absent`, `oracle_opening_input_absent`, and
`scoring_disabled` values remain exactly `true`.

The exact raw inner manifest checkpoint must equal both:

- `sentinel_manifest_checkpoint_sha256` in the outer composition manifest; and
- `cohort_checkpoint_sha256` in the goal-claim plan.

This makes the goal plan close over the phase-bound successor manifest rather
than over the legacy sentinel-v1 manifest.

### Phase-bound case payload

Every `CASE_PAYLOAD` artifact uses schema
`causalfrontier.sentinel-phase-bound-case-payload.v1` and exactly:

```text
schema_version
case_id
domain_id
decision_core
presentation
generation_phase_context
```

The `case_id`, `domain_id`, decision core, branch contract, terminal-oracle
commitment, and presentation retain their sentinel-v1 meanings and validation.
The `generation_phase_context` is a direct embedded object, not a sidecar path,
artifact identifier, or caller-supplied digest pointer. It must equal the one
fresh context derived from phase 1.

### Phase-bound case provenance

Every `CASE_PROVENANCE` artifact uses schema
`causalfrontier.sentinel-phase-bound-case-provenance.v1` and exactly:

```text
schema_version
case_id
generator_family_id
source_inventory_sha256
generator_source_content_sha256
transformations
final_artifact_ids
provenance_truth_externally_verified
generation_phase_context
```

The existing provenance verifier still requires a bounded, sorted, acyclic
source-to-payload graph; generator implementations from the exact validated
source tree; consumption of every declared source; one final case-payload
artifact; and no disconnected branch. `provenance_truth_externally_verified`
remains exactly `false`. The phase context establishes a byte dependency in the
provenance packet, not the truth of the narrated transformations.

### Artifacts intentionally unchanged

The generation plan remains `causalfrontier.sentinel-generation-plan.v1`.
Case-role packets and source inventories retain their existing schemas because
their exact hashes were precommitted before phase 1. Adding the later epoch to
those precommitted packets would invalidate the target that the witnesses signed.

Phase binding therefore applies directly to the generated payload and provenance
packet for each case, while the pre-lock role/source commitments remain unchanged.

## Exact binding geometry

The successor accepts the fixed sentinel geometry only:

| Role | Payload contexts | Provenance contexts |
|---|---:|---:|
| `PRIMARY` | 30 | 30 |
| `POSITIVE` | 3 | 3 |
| `FAILED_TRANSLATION` | 3 | 3 |
| `AMBIGUOUS` | 3 | 3 |
| **Total** | **39** | **39** |

For every case, the validator parses the payload and provenance packet from the
closed artifact inventory and requires the complete exact context in both. The
role counts are derived from the already validated generation assignment and
checked independently for payloads and provenance packets. A missing context,
legacy-v1 schema, extra field, substituted digest, single-case mismatch, mixed
epoch, cross-plan replay, or incomplete role geometry fails closed.

The raw SHA-256 digest of every file in the outer snapshot, plus the context and
each of its digest fields, enters the existing enumerated preimage set used to
keep generator-seed and case-oracle commitments disjoint from supplied bundle and
predecessor digests. This exact-equality check is a sanity boundary, not proof of
commitment hiding, entropy, or secret custody.

## Replay order

The public preflight performs this composition:

```text
CHECKPOINT_AND_SNAPSHOT_ONE_CLOSED_OUTER_ROOT
  -> STAGE_EVERY_FILE_IN_A_PRIVATE_TEMPORARY_ROOT
  -> REBUILD_PHASE_1_FROM_RAW_TARGET_REQUEST_RESPONSE_POLICY_BYTES
  -> DERIVE_ONE_FRESH_GENERATION_PHASE_CONTEXT
  -> REQUIRE_OUTER_MANIFEST_CONTEXT_EQUALITY
  -> REQUIRE_PHASE_1_HISTORICAL_ARTIFACT_BOUND_FIELD_REMAIN_FALSE
  -> RUN_FULL_PHASE_BOUND_SENTINEL_STRUCTURAL_PREFLIGHT
  -> REQUIRE_CONTEXT_IN_39_PAYLOADS_AND_39_PROVENANCE_PACKETS
  -> REBUILD_PHASE_1_AGAIN_FROM_THE_SAME_RAW_SNAPSHOT
  -> REQUIRE_THE_TWO_PHASE_1_REPORTS_BYTE_IDENTICAL
  -> REREAD_THE_ORIGINAL_OUTER_INVENTORY_AND_EVERY_BYTE
  -> EMIT_NOT_ADMITTED_REPORT
```

The phase-1 replay receives the original generation plan, nested lock root,
caller-pinned lock-manifest checkpoint, sequence, and exactly two aligned OpenSSL
path/digest pairs. It reconstructs both RFC 3161 verifications from the raw target,
queries, responses, policies, trust material, and pinned runtime checkpoints. A
saved phase-1 report is not accepted as evidence.

After deriving the context, the successor calls the full sentinel structural
preflight under the phase-bound schema policy. The generation plan, goal plan,
inner sentinel artifact graph, role/source precommitments, branch totality,
generator/domain collision checks, cutoff declarations, control geometry, and
fixed authority boundary all continue to replay. The goal plan must bind the raw
phase-bound sentinel manifest as its cohort preimage.

The second phase-1 replay detects instability inside the closed snapshot. The
final outer reread detects mutation of the supplied composition during the
combined replay. Neither check is an external monotonic-currentness witness.

## CLI and API

The CLI accepts the outer composition root, its independently preserved raw
manifest checkpoint, the sequence, and exactly two OpenSSL path/digest pairs in
canonical witness order:

```bash
causalfrontier preflight-sentinel-phase-bound-admission \
  COMPOSITION_ROOT \
  --expected-composition-manifest-sha256 COMPOSITION_MANIFEST_RAW_SHA256 \
  --expected-sequence 1 \
  --openssl /absolute/path/to/witness-a-openssl \
  --expected-openssl-sha256 WITNESS_A_OPENSSL_SHA256 \
  --openssl /absolute/path/to/witness-b-openssl \
  --expected-openssl-sha256 WITNESS_B_OPENSSL_SHA256
```

An integrity-valid structural report emits canonical JSON and exits `3`, the
project's abstention code. Invalid schemas, paths, inventories, checkpoints,
runtimes, phase-1 evidence, contexts, packet bindings, or predecessor composition
emit no JSON result and exit `2`.

The public Python API is:

```python
from causalfrontier import (
    preflight_sentinel_phase_bound_admission,
    verify_sentinel_phase_bound_admission_preflight,
)
```

The preflight signature is:

```python
preflight_sentinel_phase_bound_admission(
    root,
    expected_composition_manifest_sha256,
    expected_sequence,
    openssl_paths,
    expected_openssl_sha256s,
)
```

`verify_sentinel_phase_bound_admission_preflight(...)` accepts a saved successor
report plus those same replay inputs. It reconstructs the entire expected report
from the raw closed composition and rejects any canonical difference. The saved
report is never promoted to phase-1 or sentinel evidence.

Neither API accepts an outcome, oracle opening, comparator result, winner,
resource effect, scientific score, or admission decision.

## Report and gates

The report schema is `causalfrontier.sentinel-phase-bound-preflight.v1`. It binds:

- the exact fixed parameter, boundary, compiler, composition identifier, and
  sequence;
- raw and semantic composition checkpoints;
- the complete generation-phase context;
- raw phase-1 lock, generation-plan, goal-plan, and phase-bound sentinel-manifest
  checkpoints;
- the freshly rebuilt phase-1 preflight digest and underlying sentinel structural
  preflight digest;
- the goal and generation plans' semantic digests;
- the underlying sentinel admission state and any computable structural rejection
  reasons;
- exact 30/3/3/3 payload counts and 39 provenance bindings;
- the enumerated outer-snapshot digest count and the narrow seed/oracle
  exact-preimage non-alias result;
- replay booleans, fixed-false authority fields, ordered gates, nonclaims; and
- a domain-separated `preflight_sha256` over the complete report core.

The report's passing structural gates are:

| Gate | Narrow meaning |
|---|---|
| `closed_composition` | One caller-checkpointed outer file snapshot replayed |
| `raw_phase1_replay` | The dual RFC 3161 lock rebuilt twice from raw evidence |
| `generation_phase_context` | Manifest context equals the fresh phase-1 projection |
| `payload_epoch_binding` | Exactly 30 primary and three payloads per control role bind the context |
| `provenance_epoch_binding` | Exactly 39 provenance packets bind the context |
| `goal_plan_successor_closure` | Goal plan binds the raw phase-bound sentinel manifest |
| `seed_oracle_outer_preimage_alias` | Seed/oracle commitments do not equal any enumerated raw outer-file digest |
| `authority` | The operation is read-only validation with no clinical, biological, or material authority |

These gates remain `NO_CALL`:

| Gate | Reason |
|---|---|
| `artifact_creation_time` | Byte dependency cannot date content conception or preparation |
| `prospective_order` | Generator execution was not independently observed |
| `successor_uniqueness` | No external append-only successor register was queried |
| `witness_independence` | Distinct replayed declarations and keys are not proof of independence |
| `recursive_der_canonicality` | Phase 1 retains its qualified DER boundary |
| `runtime_hermeticity` | Pinned executable bytes do not prove hermetic execution |
| `signed_accuracy_interval_certificate_validity` | Phase 1 does not verify certificate validity over the complete signed interval |
| `rollback_currentness` | A caller checkpoint is not a monotonic currentness witness |
| `privacy` | Pattern screening is not privacy certification |
| `provenance_truth` | Graph closure is not external provenance truth |
| `cohort_admission` | Phase binding does not admit a cohort |
| `scientific_scoring` | No outcome, comparator, resource, or score channel exists |

The successor report always keeps these fields false:

```text
actual_artifact_creation_time_verified
content_conception_after_epoch_verified
prospective_order_verified
successor_uniqueness_verified
witness_signer_identity_verified
witness_independence_verified
controller_independence_verified
store_independence_verified
certificate_revocation_checked
canonical_der_verified
openssl_runtime_hermeticity_verified
certificate_validity_over_signed_accuracy_interval_verified
long_term_validity_verified
rollback_currentness_verified
public_registration_verified
provenance_truth_verified
privacy_certified
content_outcome_isolation_verified
cohort_admitted
prospective_primary_eligible
scientific_scoring_ready
scientific_claim_ready
publication_claim_authorized
```

The report can preserve an underlying sentinel structural rejection while still
truthfully reporting that the rejected bytes were phase-bound. Phase binding does
not convert a structurally rejected packet into an admissible one.

## Threat model

Within its bounded byte-level model, the successor is designed to reject:

- a missing, extra, malformed, null, all-zero, or substituted phase-context field;
- a legacy payload, provenance, or admission-manifest schema on the successor
  path;
- one case carrying a different context from the other 38;
- a valid epoch paired with a different phase-1 report, plan, lock, or sequence;
- reuse of the phase-1 target's nullable predecessor in place of the current
  phase-1 preflight digest;
- a caller-authored saved phase-1 or successor report used as evidence;
- a changed generation plan, goal plan, inner lock manifest, sentinel manifest,
  artifact byte, or outer composition manifest;
- a seed or oracle commitment equal to any enumerated raw outer-snapshot file
  digest;
- an incomplete payload/provenance role matrix;
- an overlapping, traversing, symlinked, hard-linked, oversized, orphaned, or
  drifting file input, including an unrepresented empty directory; and
- any explicit attempt to enable outcome input, oracle opening, admission, or
  scoring in the composition manifest.

The accepted context is a structural dependency, not a trusted wall-clock event.
A generator can prepare scientific content before phase 1 and append the context
afterward. Arbitrary accepted identifiers, certificates, tokens, payloads, and
provenance text can encode or be selected using outcome knowledge. The module
therefore does not verify content conception time, prospective order, or
content/outcome isolation.

### Same-predecessor equivocation and currentness

The caller supplies one expected outer-manifest checkpoint. That selects one
exact local composition, but it does not prove that the selected checkpoint is
the latest or only successor. Two different phase-bound sentinel bundles can
embed the same valid phase-1 context and each pass when invoked with its own
checkpoint.

Consequently:

- `successor_uniqueness_verified` remains false;
- `rollback_currentness_verified` remains false;
- the `successor_uniqueness` and `rollback_currentness` gates remain `NO_CALL`;
  and
- same-predecessor equivocation, fork choice, monotonic sequence, and external
  currentness remain external governance and storage problems.

Local full replay cannot resolve those properties without an independently
controlled append-only register or equivalent external state.

## Nonclaims

Passing this preflight does not establish:

- when case content, review text, source selections, or provenance narratives were
  conceived, prepared, or generated;
- actual plan-before-content order or independently observed generator conduct;
- that this is the unique or current successor to the phase-1 preflight;
- public, immutable, append-only, honest, continuous, or externally controlled
  storage;
- legal, beneficial-owner, infrastructure, controller, witness, signer, generator,
  reviewer, laboratory, outcome-provider, adjudicator, or store independence;
- certificate revocation status, signer identity, runtime hermeticity, or long-term
  timestamp validity;
- provenance truth, source authorship, exact public availability before the
  cutoff, absence of post-cutoff access, or semantic correctness;
- privacy certification or patient-data absence;
- domain diversity, control validity, cohort admission, public registration, or
  prospective-primary eligibility;
- comparator execution, measured real resources, calibration, a ranking, a
  winner, tenfold acceleration, or a scientific result;
- biological, clinical, health, patient, wet-lab, material, deployment, release,
  publication, scoring, or human-decision authority; or
- adoption, novelty, breakthrough status, health impact, lives saved, or journal
  publication.

Positive, failed-translation, and ambiguous controls remain known-hindsight
calibration cases. Their presence and phase binding do not turn them into
prospective primary evidence or authorize opening or scoring them.

## External ceremony next step

The next step is not to enable admission or scoring. It is to run a separately
reviewed real ceremony whose external evidence can address properties that local
composition cannot:

1. Freeze the exact generation plan, organization registry, witness descriptors,
   trust policies, runtimes, and deadline before either external witness response.
2. Have two reviewed, organizationally and operationally independent witnesses
   produce and retain the raw RFC 3161 evidence over the one canonical target.
3. Record the phase-1 preflight and its generation epoch in two independently
   controlled append-only stores.
4. Generate the sentinel payload and provenance bytes under the resulting context,
   close the phase-bound sentinel and outer composition manifests, and preserve
   their raw checkpoints before any outcome or oracle opening is available.
5. Require the external stores to enforce one accepted successor per phase-1
   predecessor, monotonic sequence, and explicit fork/equivocation detection.
6. Obtain authenticated governance/conflict review, revocation and long-term
   validity evidence, source-availability review, privacy review, provenance
   witness evidence, and independent domain/control adjudication.
7. Replay the complete public/synthetic composition independently and publish the
   structural receipt without calling the cohort admitted or scoring-ready.

Only a later, separately authorized admission process may evaluate whether all
external custody, independence, privacy, provenance, semantic, control, and
currentness gates are sufficient. Comparator execution, real-resource metering,
outcome opening, scientific scoring, health-impact claims, and publication remain
separate downstream decisions.
