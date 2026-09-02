# Synthetic protocol-exercise kernel v1

This local, unreleased kernel tests the one-way boundary between choosing an action and opening an outcome. It is not a scientific benchmark or a score.

## Why it is separate from challenge-lock v1

`challenge-lock.v1` permanently binds specification-only baseline artifacts and disables scoring. Execution artifacts must be successors that reference the immutable challenge rather than silently upgrading it. The full steward manifest also exposes control classes, so it is not an entrant view.

Before a protocol exercise can run, the two encoder strata must share exact dossier, gate, measurement, action, classifier, resource, and branch-plan contracts. Their worlds and prediction relations remain separate. Exact action alignment does not establish encoder independence or semantic agreement.

Receipt binding now checks both byte identity and compatible data class, authority, retrieval state, retrieval time, semantic state, and coverage. The same bytes cannot be unusable in a receipt and silently become complete usable evidence in a case.

## Phase 1: pre-reveal selection lock

```bash
causalfrontier lock-reference-selections CHALLENGE_ROOT \
  --expected-manifest-sha256 EXTERNAL_CHALLENGE_SHA256 \
  --expected-sequence EXTERNAL_SEQUENCE
```

The command has no reveal, outcome, observation, environment, network, subprocess, dynamic-import, or material-execution input. It emits three deterministic policies for each encoder stratum:

1. `CAUSALFRONTIER_UNIQUE_MINIMAX_V1` selects only one unique structurally admissible co-minimax action. A tie is `NO_CALL`; the display-only lexicographic ID is never converted into a scientific preference.
2. `DO_NOTHING_OR_ABSTAIN_REFERENCE_V1` always abstains.
3. `UNIFORM_ACTION_ENUMERATION_REFERENCE_V1` enumerates each eligible action once without replacement. It is a machine-exact reference distribution, not an empirical random-policy run.

The resulting `selection_lock_sha256` must be stored outside the challenge before reveal. Until independently timestamped, timing and rollback remain unverified. These reference policies do not count as execution of the required scientific baselines.

## Phase 2: synthetic reveal opening

The opening envelope has exactly:

```text
schema_version = causalfrontier.synthetic-reveal-opening.v1
nonce_hex       = 64 lowercase hexadecimal characters
payload         = committed synthetic payload
```

The payload binds challenge ID, sequence, predecessor digest, a non-circular `challenge_registration_sha256`, synthetic scope, required replicate count, and a total action-to-replicate-branch table for every case. The registration digest covers the entire challenge manifest except the `reveal_commitment_sha256` value. This prevents cross-challenge opening replay without creating a hash cycle through the manifest that stores the commitment.

The normative commitment is:

```text
SHA256(
  b"causalfrontier.reveal.v1\0"
  || canonical_json(payload)
  || b"\0"
  || nonce_32_bytes
)
```

Open it with:

```bash
causalfrontier open-synthetic-reveal CHALLENGE_ROOT OPENING_JSON \
  --expected-manifest-sha256 EXTERNAL_CHALLENGE_SHA256 \
  --expected-sequence EXTERNAL_SEQUENCE \
  --expected-opening-sha256 EXTERNAL_OPENING_SHA256
```

The verifier uses constant-time commitment comparison and rejects wrong framing, nonce length, challenge lineage, case/action inventory, replicate count, or post-hoc outcome ID. A valid report still says:

`SYNTHETIC_REVEAL_OPENED_OUTCOME_DERIVATION_AND_SCIENTIFIC_SCORING_DISABLED`

V1 accepts organizer-authored branch IDs only to exercise commitment plumbing. It cannot derive those branches from hidden raw observations with the frozen classifier, so it never evaluates a policy.

## Exact normal/optimized test vector

For the generated synthetic fixture:

```text
challenge_manifest_sha256 0d3035ec67b695df9505d599491b2b1de50956e0cdf16c38f943c636c92334ba
opening_sha256            9f7cdd99456c4ffbf71a481ef595a1b6bd6a163bf2fb3f08ad019a40d9c7423a
selection_lock_sha256     16451e5f7ae43e0c0ebf3aa5836f8f0c2cdc86064af01d3ddf257f82c0f9f79c
reveal_report_sha256      19c0428951554552d1e92ba1d8425c7caa9cb08d65add37b19c923f21674a7e1
```

Normal Python and `python -O` must reproduce all four values exactly.

## Successor status and remaining artifacts

The local [structurally blinded successor](blind-execution-v1.md) now implements
the first three items below for a synthetic fixture only: it creates an opaque
allowlisted view, derives branches from committed raw observation bytes, and
emits deterministic policy/tariff events. Those events and tariffs are not yet
independently checkpointed or audited resources.

Before any scientific comparison, complete:

- remotely or operating-system isolated entrant execution with semantic-leakage review;
- independently timestamped selection and observation checkpoints;
- a durable append-only policy ledger and measured vector resource receipts;
- a frozen analysis plan and applicability matrix for every required comparator;
- separate agent and steward-environment interfaces;
- independent timestamp, governance, adjudication, and checkpoint roles; and
- a pure vector scorer that preserves censoring, abstention, failure, and authority violations.

A prospective live experiment cannot precommit its unknown future outcome. It must instead precommit its acquisition and adjudication contract, then append a separately signed and timestamped outcome receipt after measurement.

## Permanent nonclaims

This kernel does not establish entrant blinding, temporal admissibility, control validity, encoder agreement, baseline adequacy, resource truth, outcome truth, causal or biological validity, real-world acceleration, a 10x gain, clinical utility, patient benefit, or health impact.
