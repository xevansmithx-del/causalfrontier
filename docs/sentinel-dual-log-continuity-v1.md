# Sentinel dual-declared-log continuity v1

## Purpose

This local, unreleased successor closes one narrow continuity seam left open by
the [sentinel generation phase binding](sentinel-phase-binding-v1.md). It
requires two raw RFC 3161 custody witnesses over one pre-transition target,
rebuilds the complete phase-bound sentinel result, derives one exact transition,
and verifies that the transition and a cross-log seal occupy two consecutive,
reserved positions in each of two caller-supplied signed log views.

Its terminal status is:

```text
DUAL_DECLARED_LOG_EDGE_AND_CROSS_SEAL_REPLAYED_RELATIVE_TO_CALLER_CHECKPOINTS_NOT_ADMITTED
```

That status is intentionally about **declared log views**, not proven independent
public logs. A passing replay establishes that one supplied signed head in each
view extends one caller-pinned prior head by exactly the same transition and then
the same seal. It does not establish that either head is globally current, that
the two views are the only views, that no signer equivocated, that the stores
actually operated externally, or that their operators are independent.

The fixed project parameter remains:

```text
OPEN_MACHINE_VERIFIABLE_TRANSLATION_FROM_FRAGMENTED_BIOMEDICAL_EVIDENCE_TO_NEXT_FALSIFIABLE_ACTION
```

The fixed boundary remains:

| Boundary field | Exact value |
|---|---:|
| `clinical_authority` | `false` |
| `human_decision_authority` | `false` |
| `material_execution_authority` | `false` |
| `patient_level_data` | `false` |
| `prospective_benchmark_cases_scored_n` | `0` |
| `prospective_experiments_executed_n` | `0` |
| `prospective_results_recorded` | `false` |

Admission, scientific scoring, scientific claims, release claims, and
publication claims remain disabled.

## Narrow guarantee

For sequence `n`, the verifier accepts only this supplied-view history:

```text
caller-pinned prior checkpoint, size 2(n - 1)
  -> identical derived transition at leaf index 2(n - 1)
  -> signed intermediate checkpoint, size 2(n - 1) + 1
  -> identical derived cross-log seal at leaf index 2(n - 1) + 1
  -> caller-pinned signed final checkpoint, size 2n
```

It verifies, for each declared store:

1. the prior, intermediate, and final C2SP checkpoints have valid Ed25519
   signatures under the key frozen in the custody target;
2. the prior checkpoint equals both the target pin and the aligned caller pin,
   and after sequence 1 the full immutable store tuple equals the caller-pinned
   predecessor state;
3. an RFC 6962/9162 consistency proof extends the prior head to the intermediate
   head;
4. an RFC 6962/9162 inclusion proof places the exact derived transition at the
   reserved transition index;
5. the cross-log seal commits the exact signed intermediate checkpoints from
   both stores;
6. a second consistency proof extends the intermediate head to the final head;
7. a second inclusion proof places the exact common seal at the reserved seal
   index; and
8. the final signed checkpoint equals the aligned caller pin.

Because each size increment is exactly one, there is no additional leaf between
the supplied prior and final heads in either accepted view. This is not a claim
about an unseen view, a different signed root at the same size, an unseen later
head, or a future fork.

## Ceremony and replay order

The intended evidence order is:

```text
freeze generation-plan digests, declared store identities and keys,
caller-preserved prior heads, sequence, slot rule, and authority boundary
                              |
                              v
canonical sentinel-continuity-custody-target.v1
  (generated artifact, outcome, oracle opening, admission, and scoring absent)
                              |
                +-------------+-------------+
                |                           |
                v                           v
       raw RFC 3161 witness A       raw RFC 3161 witness B
       request/response/policy      request/response/policy
                |                           |
                +-------------+-------------+
                              |
                              v
fresh full replay of phase-bound sentinel composition
                              |
                              v
derive one canonical transition from target + both custody reports + Phase 2
                              |
                +-------------+-------------+
                |                           |
                v                           v
       declared log view A          declared log view B
       transition at slot 2n-2      transition at slot 2n-2
                |                           |
                +-------------+-------------+
                              |
                              v
derive one seal over both exact intermediate signed checkpoints
                              |
                +-------------+-------------+
                |                           |
                v                           v
       seal at slot 2n-1            seal at slot 2n-1
                |                           |
                +-------------+-------------+
                              |
                              v
emit deterministic not-admitted continuity report and next-state digest
```

The verifier does not accept saved custody or phase reports as evidence. It
replays both RFC 3161 bundles from their raw target, request, response,
trust-policy, trust-material, and pinned OpenSSL bytes. It then invokes the full
phase-bound sentinel replay from the nested raw composition. Only after those
replays does it derive the transition. A saved continuity report is accepted only
by reconstructing the complete report again and requiring canonical equality.

This program order and byte dependency do not prove that scientific content was
conceived after the custody timestamps or that a generator followed the intended
prospective procedure.

## Closed composition and filesystem contract

The root contains one `sentinel-continuity.json` manifest and exactly the files
or subtrees it owns:

```text
CONTINUITY_ROOT/
  sentinel-continuity.json
  <canonical custody-target file>
  <canonical transition file>
  <canonical seal file>
  <complete phase-bound composition root>/
  <custody witness A attestation root>/
  <custody witness A trust-policy root>/
  <custody witness B attestation root>/
  <custody witness B trust-policy root>/
  <store A prior checkpoint>
  <store A prior-to-intermediate consistency proof>
  <store A intermediate checkpoint>
  <store A transition inclusion proof>
  <store A intermediate-to-final consistency proof>
  <store A final checkpoint>
  <store A seal inclusion proof>
  <the same seven artifacts for store B>
```

The target, transition, seal, and fourteen store artifacts are individually
declared relative files. The phase-bound root and each
attestation/trust-policy root are single, non-overlapping directory components.
All declared file paths and subtree roots must be distinct under case folding and
must not equal, contain, or lie below one another.

The inventory is limited to 896 visited entries, 1 MiB per file, and 128 MiB in
total. A signed checkpoint is additionally limited to 128 KiB. The reader rejects
path traversal, empty directories, symlinks, hard-linked files, non-regular
objects, overlapping ownership, orphan files, undeclared files, missing subtree
files, and inventory or byte drift. It snapshots every input byte into a private
temporary directory, runs all nested verification there, then rereads the
original inventory and every original byte before returning.

The operation is read-only with respect to the supplied composition. The private
snapshot is temporary verification state, not a persisted log, backup, or
external checkpoint.

## Canonical JSON and digest rules

Every JSON artifact in this profile is exactly one canonical JSON value followed
by one LF. Unknown keys, missing keys, noncanonical encodings, null placeholders
where a digest is required, and all-zero SHA-256 placeholders fail closed.

Artifact file descriptors always have exactly:

```text
path
sha256
media_type
```

JSON descriptors use `application/json`. Signed checkpoint descriptors use
`text/vnd.c2sp.tlog-checkpoint`.

Semantic digests are distinct from raw file checkpoints. The raw checkpoint is
`SHA256(exact_file_bytes)`, including the terminal LF. A semantic digest uses the
schema-specific domain tag followed by canonical JSON of the object without its
own digest field.

## Exact custody-target schema

The target uses schema `causalfrontier.sentinel-continuity-custody-target.v1`,
status `PRE_TOKEN_DUAL_LOG_CUSTODY_TARGET_SCORING_DISABLED`, and exactly:

| Key | Required meaning |
|---|---|
| `schema_version` | Exact target schema literal |
| `status` | Exact target status literal |
| `continuity_id` | Stable continuity-chain identifier |
| `sequence` | Positive integer from 1 through 100,000,000, equal to the caller sequence |
| `predecessor_continuity_state_sha256` | `null` at sequence 1; otherwise a nonzero caller-preserved prior-state digest |
| `fixed_parameter` | Exact fixed project parameter |
| `boundary` | Exact fixed authority boundary |
| `generation_plan_checkpoint_sha256` | Raw checkpoint of the precommitted generation plan |
| `generation_plan_sha256` | Semantic digest of that generation plan |
| `witness_completion_not_after` | Whole-second RFC 3339 UTC deadline used for both RFC 3161 replays |
| `statement_profile` | Exactly `CAUSALFRONTIER_PHASE_BOUND_TRANSITION_CANONICAL_JSON_V1` |
| `checkpoint_profile` | Exactly `c2sp.org/tlog-checkpoint@v1.0.0-ed25519-pinned-key` |
| `proof_profile` | Exactly `RFC6962_SHA256_PREORDERED_TWO_SLOT_V1` |
| `slot_rule` | Exact five-field rule derived from `sequence` |
| `cross_log_rule` | Exactly `IDENTICAL_TRANSITION_THEN_IDENTICAL_INTERMEDIATE_CHECKPOINT_CROSS_SEAL` |
| `custody_witnesses` | Exactly two canonically sorted witness descriptors |
| `stores` | Exactly two canonically sorted declared-store descriptors |
| `generated_artifact_input_absent` | Exactly `true` |
| `outcome_input_absent` | Exactly `true` |
| `oracle_opening_input_absent` | Exactly `true` |
| `admission_disabled` | Exactly `true` |
| `scoring_disabled` | Exactly `true` |
| `target_sha256` | Domain-separated semantic digest of every preceding target field |

The target semantic digest is:

```text
SHA256(
  "causalfrontier.sentinel-continuity-custody-target.v1\0"
  || canonical_json(target_without_target_sha256)
)
```

### Exact custody-witness descriptor

Each target witness object has exactly:

```text
witness_id
witness_organization_id
controller_group_id
store_group_id
attestation_id
trust_policy_id
trust_policy_checkpoint_sha256
trust_anchor_sha256
trust_anchor_spki_sha256
tsa_signer_spki_sha256
openssl_binary_sha256
independence_state
```

`independence_state` must be
`DECLARED_DISJOINT_NOT_INDEPENDENTLY_AUDITED`. Witness IDs are sorted and
case-insensitively distinct. Within and across the pair, all six identifier
fields form one case-insensitive collision namespace. The two descriptors must
also use different trust-anchor byte digests, trust-anchor SPKI digests, and TSA
signer SPKI digests. These checks do not prove organizational, controller,
infrastructure, signer, trust-root, or operational independence.

For each witness, the composition later supplies a raw RFC 3161 attestation root
and trust-policy root. Fresh replay must reproduce the predeclared attestation
ID, policy ID, trust-anchor digests, TSA signer SPKI digest, OpenSSL checkpoint,
and exact target-file checkpoint. The two accepted reports must contain different
timestamp-token byte digests. Certificate revocation, verified signer identity,
runtime hermeticity, and long-term timestamp validity remain unproved.

### Exact declared-store descriptor

Each target store object has exactly:

| Key | Requirement |
|---|---|
| `store_id` | Stable declared-store identifier |
| `operator_organization_id` | Declared operator identifier |
| `controller_group_id` | Declared controller group |
| `store_group_id` | Declared store group |
| `namespace_id` | Declared dedicated log namespace |
| `checkpoint_origin` | Canonical C2SP checkpoint origin without whitespace, `+`, NUL, or control characters |
| `checkpoint_verifier_key` | Canonical C2SP Ed25519 verifier key whose name equals the origin |
| `checkpoint_verifier_key_sha256` | SHA-256 of the exact UTF-8 verifier-key string |
| `openssl_binary_sha256` | Pinned OpenSSL 3 executable-byte checkpoint |
| `prior_checkpoint_sha256` | Raw SHA-256 of the signed prior checkpoint |
| `prior_tree_size` | Exactly `2(sequence - 1)` |
| `prior_root_sha256` | Hex SHA-256 root from the signed prior checkpoint |
| `independence_state` | Exactly `DECLARED_DISJOINT_NOT_INDEPENDENTLY_AUDITED` |

Store IDs are sorted and case-insensitively distinct. The five identity fields in
each descriptor must be distinct, all ten store identity values must be distinct
across the pair, and none may alias any of the twelve custody-witness identity
values. The two stores must use different case-folded checkpoint origins and
different raw Ed25519 public keys. Identifier and key distinctness remain
structural hygiene, not proof of store independence or actual operation.

## Exact composition-manifest schema

`sentinel-continuity.json` uses schema
`causalfrontier.sentinel-dual-declared-log-continuity-composition.v1`, status
`DUAL_DECLARED_LOG_CONTINUITY_COMPOSITION_CLOSED_ADMISSION_AND_SCORING_DISABLED`,
and exactly:

| Key | Required meaning |
|---|---|
| `schema_version` | Exact composition schema literal |
| `status` | Exact composition status literal |
| `continuity_id` | Must equal the custody-target continuity ID |
| `sequence` | Must equal the target and caller sequence |
| `fixed_parameter` | Exact fixed project parameter |
| `boundary` | Exact fixed authority boundary |
| `custody_target` | JSON file descriptor for the canonical target |
| `custody_target_sha256` | Target semantic digest |
| `custody_witnesses` | Exactly two sorted witness evidence descriptors |
| `phase_bound_root` | Single directory component containing the complete Phase 2 composition |
| `phase_bound_manifest_checkpoint_sha256` | Raw checkpoint of nested `sentinel-phase-bound.json` |
| `transition` | JSON file descriptor for the canonical derived transition |
| `seal` | JSON file descriptor for the canonical derived cross-log seal |
| `stores` | Exactly two sorted manifest-store descriptors |
| `designated_outcome_input_absent` | Exactly `true` |
| `oracle_opening_input_absent` | Exactly `true` |
| `admission_disabled` | Exactly `true` |
| `scoring_disabled` | Exactly `true` |
| `composition_sha256` | Domain-separated semantic digest of every preceding field |

The composition semantic digest is:

```text
SHA256(
  "causalfrontier.sentinel-dual-declared-log-continuity-composition.v1\0"
  || canonical_json(composition_without_composition_sha256)
)
```

The independently preserved caller checkpoint is instead the raw SHA-256 of the
complete canonical `sentinel-continuity.json` file including its LF.

### Exact manifest witness descriptor

Each of the two sorted manifest witness objects has exactly:

```text
witness_id
attestation_root
attestation_checkpoint_sha256
trust_policy_root
trust_policy_checkpoint_sha256
```

Witness IDs must match the target order. The manifest trust-policy checkpoint
must equal the value frozen in the target. Each attestation and policy root must
be a distinct, non-overlapping single directory component containing the exact
closed evidence accepted by the
[RFC 3161 verifier](rfc3161-attestation-v1.md).

### Exact manifest store descriptor

Each of the two sorted manifest store objects has exactly:

```text
store_id
prior_checkpoint
prior_to_intermediate_consistency
intermediate_checkpoint
transition_inclusion
intermediate_to_final_consistency
final_checkpoint
seal_inclusion
```

The store ID must match the target order. Every artifact member is an exact
`{path, sha256, media_type}` descriptor. Checkpoints declare
`text/vnd.c2sp.tlog-checkpoint`; all four proofs declare `application/json`.

## Exact transition statement

The transition file is freshly derived. A caller-authored projection is accepted
only if its exact canonical bytes equal the reconstruction. It uses schema
`causalfrontier.sentinel-phase-bound-transition.v1`, status
`PHASE_BOUND_TRANSITION_DERIVED_ADMISSION_AND_SCORING_DISABLED`, and exactly:

```text
schema_version
status
record_type
continuity_id
sequence
fixed_parameter
boundary
predecessor_continuity_state_sha256
custody_target_checkpoint_sha256
custody_target_sha256
custody_witness_report_sha256s
generation_phase_context
phase1_dual_witness_preflight_sha256
phase_bound_composition_manifest_checkpoint_sha256
phase_bound_composition_sha256
phase_bound_preflight_sha256
sentinel_manifest_checkpoint_sha256
sentinel_structural_preflight_sha256
designated_outcome_input_absent
oracle_opening_input_absent
admission_disabled
scoring_disabled
transition_sha256
```

`record_type` is exactly
`CAUSALFRONTIER_SENTINEL_PHASE_BOUND_TRANSITION`. The two custody report digests
are in canonical witness order. All Phase 1, Phase 2, generation-context, and
sentinel fields come from the fresh nested replay. The four final boundary flags
are `true`.

The semantic digest is:

```text
SHA256(
  "causalfrontier.sentinel-phase-bound-transition.v1\0"
  || canonical_json(transition_without_transition_sha256)
)
```

The transition raw-file checkpoint is separately bound by the manifest and the
cross-log seal. Its exact file bytes, including LF, are Merkle-hashed into each
intermediate log root.

## Exact cross-log seal

After both intermediate signed checkpoints and transition inclusion proofs
verify, the verifier derives a seal with schema
`causalfrontier.sentinel-dual-log-seal.v1`, status
`DUAL_DECLARED_LOG_INTERMEDIATE_CHECKPOINTS_CROSS_SEALED_NOT_ADMITTED`, and
exactly:

```text
schema_version
status
record_type
continuity_id
sequence
transition_statement_checkpoint_sha256
transition_statement_sha256
stores
partial_commit_accepted
admission_disabled
scoring_disabled
seal_sha256
```

`record_type` is exactly
`CAUSALFRONTIER_SENTINEL_DUAL_DECLARED_LOG_SEAL`.
`partial_commit_accepted` is `false`; `admission_disabled` and
`scoring_disabled` are `true`.

The `stores` array is in canonical target-store order. Each entry has exactly:

```text
store_id
intermediate_checkpoint_sha256
intermediate_root_sha256
intermediate_tree_size
```

Both the raw SHA-256 and authenticated tree root of each exact intermediate
signed checkpoint enter the seal. Consequently, a seal from only one store, a
seal over swapped intermediate heads, a seal for another transition, or a seal
with a substituted intermediate checkpoint fails exact reconstruction.

The semantic digest is:

```text
SHA256(
  "causalfrontier.sentinel-dual-log-seal.v1\0"
  || canonical_json(seal_without_seal_sha256)
)
```

The same canonical seal-file bytes, including LF, must be included at the next
reserved position in both final log heads.

## C2SP signed-checkpoint profile

Every prior, intermediate, and final checkpoint is a bounded, LF-only C2SP
signed note. The checkpoint body is extension-free and has exactly three lines:

```text
<checkpoint_origin> LF
<canonical_decimal_tree_size> LF
<canonical_base64_32_byte_root> LF
```

The complete signed note then has one blank line and between one and sixteen
signature lines:

```text
<three-line body>
LF
U+2014 SPACE <signer_name> SPACE <base64(signature_blob)> LF
<zero to fifteen additional signature lines in the same framing>
```

The verifier rejects CR bytes, non-UTF-8 text, forbidden controls, extensions,
leading-zero or signed tree sizes, no signatures, more than sixteen signatures,
malformed signature names, noncanonical base64, a signature blob outside 5 to
8,192 bytes, or any tree size above 200,000,000.

The verifier-key string is:

```text
<name>+<8-lowercase-hex-key-id>+<base64(0x01 || raw_ed25519_public_key_32_bytes)>
```

The name must equal the checkpoint origin. The four-byte key ID is:

```text
SHA256(UTF8(name) || "\n" || 0x01 || raw_public_key)[0:4]
```

At least one signature line must use that exact pinned key name and key ID. Every
matching pinned-key blob must be exactly 68 bytes -- the four-byte key ID followed
by a 64-byte Ed25519 signature -- and every such signature is verified. Other
bounded, correctly framed signature lines are permitted as C2SP co-signatures,
but they are ignored for authenticity: this verifier does not verify or make a
claim about them.

Ed25519 verification uses a private snapshot of the caller-provided OpenSSL
executable whose bytes match the target checkpoint. The executable must identify
as OpenSSL 3. The signature covers the exact three-line checkpoint body ending in
LF. This pins executable bytes and a public key; it does not make the runtime
hermetic, prove host integrity, identify a human or organization, check key
revocation, or establish long-term validity.

This profile is intentionally narrower than arbitrary C2SP signed notes: one
checkpoint origin, one required pinned Ed25519 key, at most sixteen total
signature lines, and no checkpoint extensions.

## RFC 6962/9162 Merkle and proof profile

The log uses the SHA-256 Merkle construction defined by RFC 6962 and retained by
RFC 9162-style transparency logs:

```text
empty_root       = SHA256("")
leaf_hash(bytes) = SHA256(0x00 || bytes)
node_hash(L, R)  = SHA256(0x01 || L || R)
```

The exact canonical transition and seal files, including their terminal LF, are
the leaf bytes. No JSON reserialization occurs inside the leaf hash.

Every proof file uses schema `causalfrontier.rfc6962-sha256-proof.v1` and exactly:

```text
schema_version
proof_profile
proof_type
left_size
right_size
hashes
```

`proof_profile` is `RFC6962_SHA256_PREORDERED_TWO_SLOT_V1`.
`proof_type` is either `INCLUSION` or `CONSISTENCY`. The meaning of the size
fields is:

| Proof | `left_size` | `right_size` |
|---|---:|---:|
| prior-to-intermediate consistency | prior tree size | intermediate tree size |
| transition inclusion | zero-based transition leaf index | intermediate tree size |
| intermediate-to-final consistency | intermediate tree size | final tree size |
| seal inclusion | zero-based seal leaf index | final tree size |

`hashes` is a JSON array of at most 63 canonical base64-encoded 32-byte hashes.
The proof verifier rejects truncated paths, trailing paths, malformed hashes,
impossible indices or sizes, incorrect ordering, inconsistent roots, and an
incorrect empty-tree root. At sequence 1, the size-zero prior checkpoint must
therefore carry `SHA256("")` and the zero-to-one consistency proof must be empty.

An RFC inclusion proof establishes membership in one authenticated tree. An RFC
consistency proof establishes extension between two supplied authenticated
roots. Neither proof establishes that a root is the only signed root at its size
or that a supplied final root is globally latest.

The standards boundary is deliberate:

- [RFC 3161](https://www.rfc-editor.org/rfc/rfc3161.html) supplies the timestamp
  token format used by the two custody witnesses.
- [RFC 6962](https://www.rfc-editor.org/rfc/rfc6962.html) supplies the SHA-256
  leaf, node, inclusion, and consistency construction implemented here.
- [RFC 9162](https://www.rfc-editor.org/rfc/rfc9162.html) describes the modern
  Certificate Transparency log model and its split-view limitations; this module
  does not implement a Certificate Transparency service.
- The [C2SP signed-note](https://c2sp.org/signed-note) and
  [tlog-checkpoint](https://c2sp.org/tlog-checkpoint) formats supply the
  checkpoint envelope parsed by this bounded profile.

The two-slot namespace and cross-log seal are CausalFrontier application rules,
not properties granted automatically by any of those standards.

## Two-slot sequence rule

The target carries the exact result of this function:

```text
prior_tree_size       = 2 * (sequence - 1)
transition_leaf_index = 2 * (sequence - 1)
intermediate_tree_size = prior_tree_size + 1
seal_leaf_index        = prior_tree_size + 1
final_tree_size        = prior_tree_size + 2
```

Examples:

| Sequence | Prior size | Transition index | Intermediate size | Seal index | Final size |
|---:|---:|---:|---:|---:|---:|
| 1 | 0 | 0 | 1 | 1 | 2 |
| 2 | 2 | 2 | 3 | 3 | 4 |
| 3 | 4 | 4 | 5 | 5 | 6 |

The dedicated preordered namespace is an application-level restriction. Generic
Certificate Transparency or Rekor membership proofs do not by themselves
establish these reserved-position semantics. An adapter must provide the exact
signed heads and proofs in this profile; otherwise this verifier must abstain or
reject, not upgrade a weaker receipt into successor uniqueness.

At sequence 1, `predecessor_continuity_state_sha256` must be `null` and no
predecessor-state file is accepted. At later sequences, the caller supplies both
one nonzero predecessor-state digest and the canonical predecessor-state file.
The target must contain the same digest. The state must belong to the same
continuity ID, fixed parameter, and immediately preceding sequence; its semantic
digest must reconstruct exactly. For each sorted store, its store, operator,
controller, store-group, and namespace IDs; checkpoint origin; verifier-key and
OpenSSL executable digests; declared independence state; final checkpoint; final
tree size; and final root must equal this step's declared prior state. The
predecessor file is read again after the outer replay to detect mutation.

The verifier does not query a global state registry. The two independently
preserved prior signed-checkpoint digests remain separate, required caller inputs
at every sequence.

## CLI and Python API

The CLI command is:

```bash
causalfrontier preflight-sentinel-dual-log-continuity \
  CONTINUITY_ROOT \
  --expected-composition-manifest-sha256 OUTER_MANIFEST_RAW_SHA256 \
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

For sequences greater than 1, also pass:

```text
--expected-predecessor-continuity-state-sha256 PREVIOUS_STATE_SHA256
--predecessor-continuity-state /absolute/path/to/previous-state.json
```

Every repeated pair is aligned to the canonical witness or store order. Exactly
two values are required for each repeated option. The phase runtimes replay the
nested Phase 1 evidence used by Phase 2; the custody runtimes replay the two new
target timestamps; the store runtimes verify the two C2SP checkpoint chains.

A valid structural receipt emits canonical JSON and exits `3`, the project's
historical-abstention code. Malformed inputs, changed checkpoints, invalid
signatures or proofs, replay mismatches, and unsafe filesystem state emit no JSON
receipt and exit `2`.

The public Python API is:

```python
from causalfrontier import (
    preflight_sentinel_dual_log_continuity,
    verify_sentinel_dual_log_continuity_preflight,
)
```

The preflight signature is:

```python
preflight_sentinel_dual_log_continuity(
    root,
    expected_composition_manifest_sha256,
    expected_sequence,
    expected_predecessor_continuity_state_sha256,
    predecessor_continuity_state_path,
    expected_prior_store_checkpoint_sha256s,
    expected_final_store_checkpoint_sha256s,
    phase_openssl_paths,
    expected_phase_openssl_sha256s,
    custody_openssl_paths,
    expected_custody_openssl_sha256s,
    store_openssl_paths,
    expected_store_openssl_sha256s,
)
```

`verify_sentinel_dual_log_continuity_preflight(value, ...)` takes a saved report
followed by the same replay inputs. It rebuilds the complete expected report and
rejects any canonical difference. Neither API accepts outcomes, oracle openings,
comparator results, resource effects, winners, rankings, scientific scores,
admission decisions, or release/publication decisions.

## Exact preflight-report schema

The returned report uses schema
`causalfrontier.sentinel-dual-declared-log-continuity-preflight.v1`, status
`DUAL_DECLARED_LOG_EDGE_AND_CROSS_SEAL_REPLAYED_RELATIVE_TO_CALLER_CHECKPOINTS_NOT_ADMITTED`,
and implementation status
`LOCAL_UNRELEASED_DUAL_DECLARED_LOG_CONTINUITY_PREFLIGHT`.

It has exactly these identity and digest fields:

```text
schema_version
status
implementation_status
base_compiler_version
fixed_parameter
boundary
continuity_id
sequence
composition_manifest_checkpoint_sha256
composition_sha256
predecessor_continuity_state_sha256
custody_target_checkpoint_sha256
custody_target_sha256
custody_witness_report_sha256s
phase_bound_composition_manifest_checkpoint_sha256
phase_bound_preflight_sha256
generation_phase_context
transition_statement_checkpoint_sha256
transition_statement_sha256
seal_checkpoint_sha256
seal_sha256
slot_rule
checkpoint_profile
proof_profile
```

These narrow structural fields are exactly `true`:

```text
pre_token_custody_target_dual_witness_replayed
continuity_relative_to_supplied_checkpoints_verified
one_reserved_transition_slot_per_supplied_view_verified
checkpoint_signatures_under_precommitted_keys_verified
same_transition_bytes_in_both_supplied_views_verified
dual_store_intermediate_views_cross_logged_verified
complete_two_store_seal_relative_to_supplied_final_heads_verified
no_extra_leaf_between_supplied_prior_and_final_heads_verified
closed_outer_snapshot_replayed
designated_outcome_input_absent
oracle_opening_input_absent
admission_disabled
scoring_disabled
```

The report also contains `current_state`, sorted `gates`, ordered `nonclaims`, and
`preflight_sha256`. The report digest is:

```text
SHA256(
  "causalfrontier.sentinel-dual-declared-log-continuity-preflight.v1\0"
  || canonical_json(report_without_preflight_sha256)
)
```

Every gate entry has exactly `id`, `status`, and `reason`; the array is sorted by
`id`. `nonclaims` is the fixed ordered list emitted by the implementation, not a
caller-authored annotation field.

### Exact current-state object

`current_state` uses schema
`causalfrontier.sentinel-dual-declared-log-continuity-state.v1` and exactly:

```text
schema_version
continuity_id
sequence
fixed_parameter
transition_sha256
seal_sha256
stores
state_sha256
```

Each sorted store entry has exactly:

```text
store_id
operator_organization_id
controller_group_id
store_group_id
namespace_id
checkpoint_origin
checkpoint_verifier_key_sha256
openssl_binary_sha256
independence_state
final_checkpoint_sha256
final_tree_size
final_root_sha256
```

The state digest is:

```text
SHA256(
  "causalfrontier.sentinel-dual-declared-log-continuity-state.v1\0"
  || canonical_json(current_state_without_state_sha256)
)
```

Preserving both this canonical state object and its semantic digest outside the
composition gives the next sequence a caller-controlled predecessor pin. At the
next sequence, the verifier requires the state object to reconstruct that digest
and requires the complete immutable store identity, namespace, checkpoint
origin, verifier-key digest, OpenSSL executable digest, independence declaration,
and prior-head tuple to equal the new target's prior store state. Version 1 has no
silent store-ID, operator-organization, controller-group, store-group, namespace,
checkpoint-origin, verifier-key, OpenSSL-runtime, or independence-state rotation.
Any future reviewed rotation requires a different explicit protocol; it cannot be
represented by changing a v1 successor target. The state object is still not an
automatically published, globally witnessed, monotonic, or authoritative state
record.

## Claim and nonclaim matrix

The report's gates make the boundary explicit:

| Gate | Status | Exact narrow interpretation |
|---|---|---|
| `closed_composition` | `PASS` | One caller-checkpointed outer snapshot was replayed and reread |
| `pre_token_custody` | `PASS` | Two raw RFC 3161 bundles over the artifact-absent target replayed |
| `phase_bound_transition` | `PASS` | The transition was derived from fresh Phase 1 and Phase 2 replay |
| `prior_head_binding` | `PASS` | Both prior signed heads equal the target/caller pins; after sequence 1 the immutable store tuples also equal the predecessor state |
| `reserved_transition_slots` | `PASS` | The identical transition is included at both prescribed positions |
| `cross_log_seal` | `PASS` | One identical seal commits both exact intermediate signed checkpoints |
| `reserved_seal_slots` | `PASS` | The identical seal is included at both next prescribed positions |
| `supplied_view_continuity` | `PASS` | Both two-step consistency chains replay against the supplied roots |
| `authority` | `PASS` | The verifier is read-only and grants no clinical, biological, or material authority |
| `global_uniqueness` | `NO_CALL` | Supplied views cannot exclude hidden or future forks |
| `rollback_currentness` | `NO_CALL` | Caller final heads are not proof of global latestness |
| `store_independence` | `NO_CALL` | Distinct declarations and keys do not prove independence |
| `prospective_order` | `NO_CALL` | Generator execution was not independently observed |
| `privacy` | `NO_CALL` | Structural replay is not privacy certification |
| `scientific_scoring` | `NO_CALL` | No outcome, comparator, resource, or score channel exists |

The `authority` pass is a confinement result: it means no authority was granted,
not that any medical, scientific, operational, release, or publication action was
authorized.

The report always keeps these fields `false`:

```text
actual_external_store_operation_verified
store_operator_identity_verified
store_independence_verified
controller_independence_verified
global_successor_uniqueness_verified
unseen_equivocation_absent_verified
future_fork_absence_verified
rollback_currentness_verified
public_registration_verified
content_conception_after_epoch_verified
prospective_order_verified
witness_signer_identity_verified
witness_independence_verified
certificate_revocation_checked
openssl_runtime_hermeticity_verified
long_term_validity_verified
provenance_truth_verified
privacy_certified
content_outcome_isolation_verified
cohort_admitted
prospective_primary_eligible
scientific_scoring_ready
scientific_claim_ready
publication_claim_authorized
```

## Split-view and equivocation caveat

A valid consistency proof says that the supplied intermediate root extends the
supplied prior root. A valid inclusion proof says that one exact leaf is present
at one index under the supplied root. A valid Ed25519 signature says that the
precommitted key signed that checkpoint body. None of those facts prevents the
same key from signing a different root at the same size for another client.

Accordingly, the verifier cannot detect a hidden split view unless the conflicting
checkpoint is supplied. It does not perform checkpoint gossip, witness
cosigning, public-log monitoring, network lookup, global fork choice, or a query
for a newer head. Two valid compositions can therefore each pass relative to
different caller-supplied signed views.

The cross-log seal raises the cost of silent divergence within the supplied pair:
each final view commits the exact transition and both exact intermediate heads.
It does not transform the stores into independent witnesses, prevent both keys
from equivocating, or prove that the sealed pair was public.

The accurate statement is:

> One fresh Phase 1-to-Phase 2 transition and one seal over both intermediate
> checkpoints occupy the two prescribed append-only positions in each of two
> declared, caller-supplied signed views.

It is inaccurate to shorten this to “globally unique successor,” “two independent
public logs,” “no rollback,” or “no equivocation.”

## Security limits and threat model

Within its bounded byte-level model, the verifier is designed to reject:

- a missing, malformed, noncanonical, or substituted custody target;
- fewer or more than two witnesses or stores;
- case-folded role aliases, shared store public keys, shared origins, and the
  explicit identity collisions checked by the target;
- reused custody timestamp-token bytes;
- a changed generation plan or Phase 2 composition;
- a saved Phase 1, Phase 2, custody, or continuity projection used in place of
  raw replay;
- a wrong continuity ID, sequence, predecessor-state pin, fixed parameter,
  boundary, protocol profile, slot rule, or cross-log rule;
- a silent store/operator/controller/group/namespace change, checkpoint-origin
  change, verifier-key change, OpenSSL-runtime change, or independence-state
  change across a predecessor-state edge;
- an absent or invalid pinned-key checkpoint signature, wrong pinned key ID,
  wrong origin, extension-bearing checkpoint, malformed or excessive signature
  list, wrong size, wrong root, or changed checkpoint bytes;
- a truncated, trailing, reordered, oversized, or otherwise invalid inclusion or
  consistency proof;
- a transition at another index, a seal at another index, an extra size step, or
  a sequence gap or repeat relative to the supplied pins;
- different transition bytes between views;
- a partial seal, a seal for another transition, swapped intermediate heads, or
  a seal that omits or substitutes one store;
- a caller final checkpoint different from the closed composition;
- a forged saved report that changes even one canonical output field;
- a duplicate, case-fold-aliased, overlapping, traversing, symlinked,
  hard-linked, oversized, orphaned, incomplete, or concurrently changing
  filesystem input; and
- any manifest or target flag that opens generated-artifact, outcome, oracle,
  admission, or scoring input at the prohibited stage.

The OpenSSL paths are executable, application-controlled trusted inputs. Digest
pinning does not sandbox their host effects. The verifier therefore does not
defend against a malicious or compromised OpenSSL binary whose bytes were
intentionally pinned, a compromised host, two colluding log keys, dishonest
declarations, semantic deception inside identifier strings or scientific
artifacts, or an unseen alternate signed view. It also does not
authenticate beneficial ownership, operator identity, controller independence,
source truth, biological validity, or clinical utility.

## Hostile validation expectations

Before any reviewed release or external ceremony, the synthetic validation
matrix should contain at least 60 distinct hostile cases and at least 70 total
executions. It should cover all of these families:

| Family | Required examples |
|---|---|
| Determinism | Clean sequence 1 and sequence 2; saved-report full replay; normal and optimized Python; multiple hash seeds |
| Custody | Missing raw witness evidence; saved report substitution; wrong target, deadline, token, policy, trust root, witness identity, or runtime checkpoint |
| Phase transition | Wrong Phase 2 checkpoint, sequence, generation epoch, composition digest, Phase 1 digest, or transition projection |
| Store declarations | Missing/extra/swapped stores; case-fold aliases; shared key material; shared origin; wrong proof/checkpoint profile; uncommitted key rotation |
| Signatures/checkpoints | Missing/invalid pinned Ed25519 signature; wrong key ID, origin, size, root, or encoding; valid bounded unknown co-signature; malformed or excessive co-signatures; or wrong caller prior/final pin |
| Merkle proofs | Wrong leaf, index, tree size, root, node order, truncated/trailing path, malformed hash, corrupted inclusion proof, or corrupted consistency proof |
| Rollback/forks | Missing or changed predecessor-state file; stale prior head; predecessor store/operator/controller/group/namespace, origin, key, runtime, independence-state, size, root, or checkpoint mismatch; incomparable head; same-size conflicting root; sequence gap/repeat; duplicate reserved position; or conflicting supplied successor |
| Cross-log composition | One transition only, one seal only, different transition bytes, swapped intermediate checkpoints, partial seal, seal for another edge, or stale predecessor state |
| Projection attacks | Forged report field, removed false field, upgraded gate, altered current state, or saved-report-only evidence |
| Filesystem/runtime | Duplicate or case-fold-aliased path, traversal, symlink, hard link, empty directory, orphan file, extra file, file/inventory drift, oversize file/count/total, proof bomb, or runtime substitution |
| Authority/channel isolation | Outcome, oracle, comparator, ranking, winner, resource, score, admission, release, or publication channel introduced through API, CLI, manifest, target, transition, seal, or report |

Positive tests should prove only the narrow supplied-view statement. Negative
tests should assert deterministic rejection and must never auto-select one fork,
repair a sequence, discard one store, weaken the proof profile, or convert a
`NO_CALL` into `PASS`.

## Current status: local and synthetic only

The implementation identifies itself as
`LOCAL_UNRELEASED_DUAL_DECLARED_LOG_CONTINUITY_PREFLIGHT`. Its current evidence
and validation fixtures are synthetic. It has not demonstrated operation against
two externally controlled stores, a public registration service, production key
governance, checkpoint gossip, an independent witness network, or a real
prospective scientific cohort.

This module therefore makes no release claim, no public-adoption claim, no
scientific claim, and no claim that a benchmark or journal standard has been met.
Connecting it to Rekor, Trillian, SCITT, another transparency service, or a public
witness network requires a separately reviewed adapter and ceremony. The adapter
must preserve the exact two-slot and cross-seal semantics; generic inclusion
alone is insufficient.

## Nonclaims

Passing this preflight does not establish:

- actual external storage, public visibility, public registration, global
  latestness, unique succession, or absence of hidden or future forks;
- legal, organizational, beneficial-owner, infrastructure, controller, witness,
  signer, operator, store, laboratory, outcome-provider, reviewer, or adjudicator
  independence;
- when scientific content was conceived, selected, prepared, or generated;
- plan-before-content order or independently observed generator conduct;
- certificate revocation status, signer identity, host integrity, runtime
  hermeticity, long-term timestamp validity, or durable key custody;
- provenance truth, source authorship, semantic correctness, cutoff compliance,
  privacy certification, or patient-data absence;
- domain diversity, control validity, cohort admission, prospective-primary
  eligibility, biological validity, clinical utility, or patient benefit;
- comparator execution, calibrated prediction, measured resources, a ranking, a
  winner, tenfold acceleration, a breakthrough, lives saved, or social impact;
- biological, clinical, health, patient, wet-lab, material, deployment,
  human-decision, release, publication, or scientific-scoring authority; or
- acceptance by a journal, regulator, standards body, registry, transparency-log
  operator, scientific community, or any other external party.

The continuity receipt is one auditable prerequisite for a future ceremony. It
is not the ceremony's scientific result and does not authorize the next phase.
