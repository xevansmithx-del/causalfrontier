# Sentinel dual-witness generation lock v1

## Purpose

This local, unreleased phase-1 module closes one narrow seam between the
[sentinel generation plan](sentinel-admission-v1.md) and a later externally run
generation ceremony. It replays two raw RFC 3161 evidence bundles against one
canonical target whose digest is bound by both later timestamp responses, then
derives a generation-epoch digest from the exact lock and token bytes.

Its terminal state is:

```text
DUAL_WITNESS_PLAN_LOCK_REPLAYED_GENERATION_EPOCH_DERIVED_NOT_ADMITTED
```

This is byte-level composition under caller-pinned offline trust policies. It is
not external registration, proof of prospective order, witness or store
independence, cohort admission, or scientific scoring. The current sentinel-v1
payload and provenance schemas do not require the derived epoch, so this phase
does not yet prove that generated artifacts followed the lock.

The fixed project parameter remains:

```text
OPEN_MACHINE_VERIFIABLE_TRANSLATION_FROM_FRAGMENTED_BIOMEDICAL_EVIDENCE_TO_NEXT_FALSIFIABLE_ACTION
```

## Boundary and data flow

```text
exact sentinel-generation-plan.v1 + exact organization registry
                              |
                              v
canonical sentinel-generation-lock-target.v1
  (generated artifacts, outcomes, oracle openings, and scoring absent)
                              |
             +----------------+----------------+
             |                                 |
             v                                 v
 raw RFC 3161 witness A                raw RFC 3161 witness B
 request + response + policy           request + response + policy
             |                                 |
             +----------------+----------------+
                              |
                              v
closed sentinel-dual-witness-lock-manifest.v1
                              |
                  replay both raw bundles
                              |
                              v
generation_epoch_sha256 + fixed-false scientific fields
```

The implementation never accepts a saved RFC 3161 report as evidence. It copies
the closed input bundle into a private temporary snapshot and invokes the
[RFC 3161 verifier](rfc3161-attestation-v1.md) twice from the original target,
request, response, trust-policy, trust-material, and pinned OpenSSL bytes. It
then rereads the generation plan and every input artifact before returning.

## Exact target schema

The target file must be the single canonical JSON encoding plus one terminal LF.
It has schema `causalfrontier.sentinel-generation-lock-target.v1`, status
`SENTINEL_PREGENERATION_WITNESS_TARGET_SCORING_DISABLED`, and exactly these keys:

| Key | Required meaning |
|---|---|
| `schema_version` | Exact target schema literal |
| `status` | Exact target status literal |
| `lock_id` | Stable lock identifier |
| `sequence` | Positive sequence equal to the generation-plan and caller checkpoints |
| `predecessor_lock_preflight_sha256` | `null` at sequence 1; otherwise the declared predecessor preflight digest |
| `fixed_parameter` | Exact project parameter |
| `boundary` | Exact fixed no-patient/no-clinical/no-material authority boundary |
| `goal_claim_contract_sha256` | Immutable goal-contract digest |
| `generation_plan_id` | Exact predecessor plan identifier |
| `generation_plan_checkpoint_sha256` | Raw generation-plan checkpoint |
| `generation_plan_sha256` | Replayed semantic generation-plan digest |
| `organization_registry_checkpoint_sha256` | Raw canonical registry-file checkpoint |
| `organization_registry_sha256` | Semantic registry digest already bound by the generation plan |
| `witness_completion_not_after` | Whole-second RFC 3339 UTC deadline supplied to both timestamp verifications |
| `witnesses` | Exactly two canonically sorted pre-token witness descriptors |
| `generated_artifact_input_absent` | Exactly `true` |
| `outcome_input_absent` | Exactly `true` |
| `oracle_opening_input_absent` | Exactly `true` |
| `scoring_disabled` | Exactly `true` |
| `target_sha256` | Domain-separated semantic digest of all preceding target fields |

The target's `target_sha256` is distinct from the raw target-file checkpoint.
The semantic value is:

```text
SHA256(
  "causalfrontier.sentinel-generation-lock-target.v1\0"
  || canonical_json(target_without_target_sha256)
)
```

### Exact target witness descriptor

Each target witness object has exactly:

| Key | Requirement |
|---|---|
| `witness_id` | Stable witness identifier |
| `witness_organization_id` | Declared TSA organization identifier |
| `controller_group_id` | Declared controller group |
| `store_group_id` | Declared store group |
| `attestation_id` | Predeclared RFC 3161 attestation identifier |
| `trust_policy_id` | Predeclared trust-policy identifier |
| `trust_policy_checkpoint_sha256` | Raw trust-policy manifest checkpoint |
| `trust_anchor_sha256` | Exact trust-anchor certificate-byte digest |
| `trust_anchor_spki_sha256` | Exact trust-anchor subject-public-key-info digest |
| `tsa_signer_spki_sha256` | Predeclared timestamp-signer subject-public-key-info digest |
| `openssl_binary_sha256` | Pinned OpenSSL 3 executable-byte digest |
| `independence_state` | Exactly `DECLARED_DISJOINT_NOT_INDEPENDENTLY_AUDITED` |

Witness IDs must be sorted. The validator treats all six identifier fields --
`witness_id`, `witness_organization_id`, `controller_group_id`, `store_group_id`,
`attestation_id`, and `trust_policy_id` -- as one case-insensitive collision
namespace. All six must be distinct within each descriptor, and no value may
recur anywhere in the other descriptor. It also rejects equal trust-policy
checkpoint, trust-anchor-byte, trust-anchor-SPKI, or TSA-signer-SPKI digests in
the pre-token pair. These are identifier-hygiene and collision checks, not proof
of independence.

## Organization-registry input

The registry file is the single canonical JSON encoding plus LF of the exact
sentinel organization array accepted by sentinel v1. It contains 8–128 sorted,
case-insensitively unique objects with exactly:

```text
organization_id
roles
controller_group_id
store_group_id
```

At least one declaration must include the `STEWARD` role. The raw file must match
`organization_registry_checkpoint_sha256`; the canonical validated array must
match `organization_registry_sha256` in both the target and generation plan.
Every value in each witness descriptor's six-field identifier namespace,
including its attestation and trust-policy IDs, must be disjoint from every
organization/controller/store identity in this precommitted registry. That check
prevents an obvious role alias; it cannot detect common beneficial ownership,
hidden controllers, affiliates, or shared infrastructure.

## Exact lock-manifest schema

The lock root contains `dual-witness-lock.json`, the target and registry files,
and exactly two non-overlapping attestation/trust-policy subtree pairs. The root
manifest uses schema `causalfrontier.sentinel-dual-witness-lock-manifest.v1`,
status `DUAL_WITNESS_EVIDENCE_BUNDLE_CLOSED_SCORING_DISABLED`, and exactly:

| Key | Required meaning |
|---|---|
| `schema_version` | Exact lock-manifest schema literal |
| `status` | Exact lock-manifest status literal |
| `lock_id` | Must equal the target lock ID |
| `sequence` | Must equal the target, plan, and caller sequence |
| `fixed_parameter` | Exact project parameter |
| `boundary` | Exact fixed authority boundary |
| `target` | `{path, sha256, media_type}` for the canonical target file |
| `target_sha256` | Must equal the target's semantic digest |
| `organization_registry` | `{path, sha256, media_type}` for the canonical registry file |
| `organization_registry_sha256` | Must equal the plan/target semantic registry digest |
| `generation_plan_checkpoint_sha256` | Exact raw predecessor checkpoint |
| `generation_plan_sha256` | Exact replayed predecessor semantic digest |
| `witnesses` | Exactly two sorted lock-witness objects |
| `generated_artifact_input_absent` | Exactly `true` |
| `outcome_input_absent` | Exactly `true` |
| `oracle_opening_input_absent` | Exactly `true` |
| `scoring_disabled` | Exactly `true` |
| `lock_sha256` | Domain-separated semantic digest of the other manifest fields |

Both root artifact descriptors must declare `application/json`; their paths must
be distinct from each other and from `dual-witness-lock.json`. `lock_sha256` is:

```text
SHA256(
  "causalfrontier.sentinel-dual-witness-lock-manifest.v1\0"
  || canonical_json(manifest_without_lock_sha256)
)
```

The exact raw manifest checkpoint supplied on the command line is the SHA-256 of
the canonical manifest file including its terminal LF.

### Exact lock witness object

Each lock-manifest witness object has exactly:

```text
witness_id
attestation_root
attestation_checkpoint_sha256
trust_policy_root
trust_policy_checkpoint_sha256
```

The two witness IDs must match the canonical target order. Attestation and
trust-policy roots are relative, non-overlapping subtrees. Each subtree conforms
to the exact closed schemas in [RFC 3161 temporal evidence v1](rfc3161-attestation-v1.md):
an attestation manifest plus one query and response, and a trust-policy manifest
plus exactly one canonical PEM trust-anchor certificate and an optional untrusted
intermediate chain. A concatenated or additional trusted certificate is rejected.
The lock root permits no extra, orphan, ambiguously owned, symlinked, hard-linked,
or empty evidence subtree. This exact-one rule constrains the caller-pinned trust
input; it does not certify the root as current or independently governed.

## Ceremony

Phase 1 is intended to be performed in this order:

1. Freeze and externally preserve the exact sentinel generation-plan bytes, raw
   SHA-256, semantic digest, and sequence. Do not provide generated case artifacts,
   outcomes, or oracle openings to this phase.
2. Freeze the exact organization-registry bytes. Its semantic digest must already
   be bound by the generation plan.
3. Before requesting either timestamp, choose both witness descriptors, both
   trust policies, roots, timestamp-signer keys, both pinned OpenSSL binaries,
   and one common completion deadline. Build and checkpoint the canonical target.
4. Give the same exact target bytes to both witness workflows. Each creates its
   own nonce-bearing RFC 3161 request and response under its predeclared policy.
5. Assemble the target, registry, two attestation subtrees, two trust-policy
   subtrees, and canonical lock manifest into the closed lock root. Preserve the
   raw lock-manifest checkpoint outside that root.
6. Run the preflight with exactly two OpenSSL path/digest pairs aligned to canonical
   witness order. The preflight snapshots the entire bundle and reconstructs each
   RFC 3161 verification against the one target.
7. Preserve the emitted report and `generation_epoch_sha256`. Do not call the
   cohort admitted, prospective, registered, independent, or scoring-ready.

The declared ceremony requires the target to precede both token requests because
it commits the two attestation IDs, policies, trust anchors, runtime digests, and
deadline before either response enters the closed lock. Local replay verifies the
resulting digest relationships and signed-time bounds; it does not independently
observe the ceremony, prove when a person conceived content, rule out an earlier
secret generator run, or prove that the declared witnesses are independent.

## Replay checks and generation epoch

A valid preflight verifies these narrow software properties:

- exact generation-plan and organization-registry raw/semantic binding;
- one canonical pre-token target and a closed bundle inventory;
- two raw RFC 3161 request/response/policy replays against identical target bytes;
- both policy-derived signed-time upper bounds no later than the predeclared
  deadline;
- distinct trust-anchor bytes, trust-anchor SPKIs, and canonical mathematical
  trust-anchor key material, plus distinct timestamp-signer SPKIs and canonical
  mathematical timestamp-signer key material;
- distinct attestation, trust-policy, request, response, and token bytes;
- absence of the implemented witness/registry identity aliases; and
- deterministic derivation of one generation epoch.

The underlying RFC 3161 replay derives the key-material digests with a
key-type-aware canonical projection. RSA and RSA-PSS certificates are compared
through the same RSA modulus/exponent representation; EC keys use an uncompressed
point and named-curve encoding; Ed25519 and Ed448 keys use their normalized public-
key projection. The projection is domain- and key-family-separated before hashing.
This closes common certificate/SPKI-encoding aliases for supported key families;
different projected key material still does not prove different controllers or
independent witnesses.

The generation epoch is:

```text
epoch_core = {
  target_checkpoint_sha256,
  lock_manifest_checkpoint_sha256,
  sequence,
  witnesses: sorted [
    {
      witness_id,
      attestation_checkpoint_sha256,
      request_sha256,
      response_sha256,
      timestamp_token_sha256
    },
    ... exactly two
  ]
}

generation_epoch_sha256 = SHA256(
  "causalfrontier.sentinel-generation-epoch.v1\0"
  || canonical_json(epoch_core)
)
```

The epoch intentionally cannot be placed in the pre-token target or lock manifest
because it depends on both later token projections and the raw lock-manifest
checkpoint. The separate phase-bound successor binds this output as its exact
predecessor without changing this phase-1 schema.

## Report schema and fixed-false boundary

The preflight report uses schema
`causalfrontier.sentinel-dual-witness-lock-preflight.v1`. It binds the compiler,
fixed parameter and boundary; lock, target, plan, registry, sequence, predecessor,
deadline, and witness projections; the generation epoch; deterministic replay
booleans; sorted gates; nonclaims; and its own domain-separated
`preflight_sha256`.

Each witness projection binds its declared identities plus exact attestation,
policy, anchor, request, response, token, time-bound, runtime, and underlying
RFC 3161 report digests. The anchor and signer projections include the extracted
key algorithm, SPKI digest, and canonical mathematical key-material digest. Each
witness projection is required to retain these values as false:

```text
witness_signer_identity_verified
witness_independence_verified
certificate_revocation_checked
canonical_der_verified
openssl_runtime_hermeticity_verified
certificate_validity_over_signed_accuracy_interval_verified
```

The complete report is required to keep all of these false:

```text
generated_artifact_phase_bound
actual_artifact_creation_time_verified
prospective_order_verified
witness_signer_identity_verified
witness_independence_verified
controller_independence_verified
store_independence_verified
certificate_revocation_checked
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

The authority gate passes only for the narrow fact that this is read-only input
validation with no clinical, biological, material, or human-decision authority.
The generated-artifact phase, actual creation time, witness/store independence,
store continuity, revocation, rollback, privacy, admission, and scoring gates
remain `NO_CALL`.

## CLI and API

Pass each `--openssl` and aligned `--expected-openssl-sha256` option exactly twice,
in the sorted witness order:

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

An integrity-valid structural preflight emits canonical JSON and exits `3`, the
project's abstention code. Invalid schemas, bindings, checkpoints, times,
identities, evidence, runtimes, or files emit no result and exit `2`. The command
does not perform network access or mutate the supplied inputs; it does execute
the two pinned OpenSSL binaries from private temporary byte snapshots.

The public API is:

```python
from causalfrontier import (
    preflight_sentinel_dual_witness_lock,
    verify_sentinel_dual_witness_lock_preflight,
)
```

`verify_sentinel_dual_witness_lock_preflight(...)` accepts a saved report plus the
same raw replay inputs, deterministically rebuilds the report, and rejects any
coherent projection forgery. It does not treat the saved report itself as witness
evidence.

## Nonclaims

Passing phase 1 does not establish:

- legal, beneficial-owner, infrastructure, controller, witness, signer, or store
  independence;
- certificate revocation or long-term timestamp validity;
- public, immutable, append-only, honest, or externally controlled storage;
- predecessor existence, chain currentness, or rollback resistance;
- actual content conception or artifact-creation time;
- a phase-bound generated sentinel payload or plan-before-generation result;
- source public availability, content-level outcome isolation, provenance truth,
  privacy certification, domain/control validity, or patient-data absence;
- external registration, prospective-primary eligibility, or cohort admission;
- comparator execution, measured resources, a winner, acceleration, or a
  scientific result; or
- publication, release, clinical, biological, wet-lab, material, scoring, or
  human-decision authority.

Different organization labels, roots, public keys, tokens, and directory paths
cannot expose a hidden common controller or colluding witness. Two signed target
imprints also cannot prove that a generator did not prepare artifacts secretly
before the ceremony. Although the API has no designated artifact, outcome,
opening, result, or score argument, accepted identifiers, certificates, nonces,
tokens, and post-target manifests can still encode or be selected using such
content. The module therefore keeps `content_outcome_isolation_verified` false.

## Phase-bound successor and next external phase

The separate [phase-bound sentinel successor](sentinel-phase-binding-v1.md) now
closes that local schema seam without changing sentinel v1. Every primary,
positive, failed-translation, and ambiguous generated payload and provenance
packet binds the exact seven-field context containing this
`generation_epoch_sha256` and this phase-1 preflight digest. Its closed outer
composition and hostile tests reject missing, substituted, mixed, or replayed
contexts across plans or sequences.

That local schema closure does not establish genuine prospective custody, which still requires
the real ceremony to be run by independently reviewed organizations, append-only
store-continuity evidence from two externally controlled stores, authenticated
governance and conflict review, and independent generator conduct. Only after
those external gates, domain/control review, privacy review, and source-
availability checks pass can a later authority consider cohort admission. None
of these phases by itself enables scientific scoring.
