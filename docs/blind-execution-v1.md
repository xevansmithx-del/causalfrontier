# Structurally blinded synthetic execution v1

This local, unreleased successor closes one narrow protocol gap: a reference
policy can lock a choice from an allowlisted entrant view before an authenticated
raw observation is opened, and the resulting branch is derived by the frozen
classifier rather than supplied as an organizer label.

It is a synthetic software exercise. It is not a scientific benchmark, a
prospective result, a verified sandbox, or evidence of acceleration or health
impact.

## Checkpoint order and trust zones

The supported order is part of the protocol:

```text
steward challenge without its final commitment seal
  -> build and checkpoint the sanitized entrant view
  -> preflight every oracle coordinate and observation byte
  -> persist and externally checkpoint the commitment-preflight receipt
  -> seal its reveal commitment into the final challenge manifest
  -> lock reference policies using only the checkpointed view
  -> steward binds the view, selection, and preflight checkpoints in an envelope
  -> add the exact preflighted canonical opening
  -> execute with final-manifest, view, selection, envelope, preflight, and opening checkpoints
```

The challenge registration digest excludes only `reveal_commitment_sha256` to
avoid a hash cycle. The otherwise complete provisional challenge can therefore
produce the race, view, and commitment preflight; inserting the returned
commitment and resealing the manifest changes the manifest checkpoint but not the
registration digest or opaque entrant bindings. Both the provisional and final
manifest bytes must be treated as explicit artifacts; the executor receives the
final checkpoint.

“Checkpointed” has two layers here. Each JSON receipt has its own canonical
semantic digest, and the caller separately preserves the SHA-256 of the exact
receipt file, including its final newline. The execution API requires the latter
for the view, selection, envelope, commitment preflight, and opening. A local
digest does not establish authorship, custody, wall-clock order, or currentness.

## Sanitized entrant view

The entrant view is built by inclusion, not by deleting a denylist. It contains
only nonce-keyed opaque challenge and race bindings, the fixed boundary, opaque
case/lane/action aliases, complete synthetic tariff vectors, and the two sets
needed by the registered selector: eligible actions and co-minimax actions. It
omits explicit original case, encoder, organization, action, control, and domain
IDs; artifact paths and digests; receipt and baseline inventories; reveal
material; and observation paths, digests, identifiers, values, and counts beyond
the precommitted replicate count. Case-specific action counts, eligibility sets,
and tariffs can still form structural fingerprints, so semantic blinding remains
independently unverified.

Aliases and steward-contract bindings are domain-separated HMAC-SHA-256 values
keyed by a 32-byte secret. This prevents direct matching or permutation
enumeration of low-entropy steward identifiers while the key remains secret. The
nonce file is exactly 64 lowercase hexadecimal characters plus one newline and
is passed by checkpointed file rather than a command argument. Syntax and length
do not prove entropy, uniqueness, generation quality, or secrecy through the
selection lock. `blinding_nonce_entropy_verified`,
`blinding_nonce_uniqueness_verified`, and
`blinding_nonce_secrecy_until_selection_verified` therefore remain `false`.

The selector API accepts only the entrant-view path and its raw file checkpoint:

```bash
causalfrontier build-sanitized-view CHALLENGE_ROOT RACE_SPEC NONCE_FILE \
  --expected-manifest-sha256 PROVISIONAL_CHALLENGE_SHA256 \
  --expected-sequence EXTERNAL_SEQUENCE \
  --expected-race-spec-sha256 EXTERNAL_RACE_SHA256 \
  --expected-nonce-sha256 EXTERNAL_NONCE_FILE_SHA256 > ENTRANT_VIEW

causalfrontier lock-blind-selections ENTRANT_VIEW \
  --expected-view-sha256 EXTERNAL_VIEW_FILE_SHA256 > SELECTION_LOCK
```

`lock_blind_reference_selections` has no challenge, steward, oracle, preflight,
reveal, outcome, environment, or nonce argument. It deterministically reproduces
the three reference policies from opaque fields. A co-minimax tie remains
`NO_CALL`; opaque lexical order is never a scientific tie-breaker. The persisted
selection receipt also records `reveal_input_accepted:false`.

## Commitment preflight before the final seal

The steward first prepares `causalfrontier.synthetic-observation-oracle.v1` as
canonical JSON plus one newline and checkpoints those exact payload bytes. Its
closed schema binds a total case × action × replicate coordinate table with
original and opaque bindings, observation paths, exact byte digests, and the
registered TSV media type. It accepts no branch token, outcome ID, replicate
outcome list, or other organizer-authored classification.

At this stage `ORACLE_ROOT` must contain exactly the observation files and their
necessary directories; `opening.json` must not yet exist:

```bash
causalfrontier prepare-observation-commitment \
  CHALLENGE_ROOT RACE_SPEC ENTRANT_VIEW ORACLE_ROOT ORACLE_PAYLOAD NONCE_FILE \
  --expected-manifest-sha256 PROVISIONAL_CHALLENGE_SHA256 \
  --expected-sequence EXTERNAL_SEQUENCE \
  --expected-race-spec-sha256 EXTERNAL_RACE_SHA256 \
  --expected-view-sha256 EXTERNAL_VIEW_FILE_SHA256 \
  --expected-payload-sha256 EXTERNAL_PAYLOAD_FILE_SHA256 \
  --expected-nonce-sha256 EXTERNAL_NONCE_FILE_SHA256 \
  > COMMITMENT_PREFLIGHT
```

Preparation replays the view from the same nonce, validates the closed coordinate
and filesystem inventories, snapshots every committed observation twice around
metadata inventory checks, verifies every digest on both passes, applies the
bounded synthetic privacy-marker screen, and performs a final inventory check.
Invalid UTF-8 and prohibited patient-identifier field markers are rejected without
echoing the source material. This is defense in
depth, not de-identification; the later execution receipt keeps
`patient_level_data_absence_independently_verified:false`.

The limit contract is itself digest-bound. It currently reserves and enforces:

- at most 256 oracle filesystem entries, including directories and the future
  `opening.json` entry;
- at most 64 MiB across oracle regular-file bytes, including the future opening;
- at most 4 MiB for any regular file and any parsed JSON document;
- at most 1 MiB for each classifier observation; and
- at most 8,192 UTF-8 bytes per classifier cell when classification occurs.

The preflight constructs the prospective opening in memory, verifies that its
canonical bytes are executable under the 4 MiB JSON/file limit, and reserves
both its entry and byte length in `oracle_entries_n` and
`oracle_total_bytes_n`. It returns `reveal_commitment_sha256`, the exact raw
`oracle_opening_sha256`, a digest of the complete limit/parser contract, and
counts for cases, actions, observations, entries, bytes, and replicates. Persist
this receipt as canonical JSON plus one newline, preserve its raw file digest,
then copy its reveal commitment into the otherwise final challenge manifest and
seal that manifest.

The preparation receipt says that all committed bytes matched at that checkpoint.
It does not claim independent attestation, verified temporal order, later
unselected-byte stability, or present full-oracle readiness. In particular,
`independent_attestation_verified` and `preflight_temporal_order_verified` remain
`false`.

## View-only selection and steward envelope

After the final challenge seal, run the selector from only `ENTRANT_VIEW`, persist
`SELECTION_LOCK`, and preserve its raw file digest. The steward—not the
selector—then binds the exact view, selection, and commitment-preflight
checkpoints:

```bash
causalfrontier bind-blind-selection-precommitment \
  ENTRANT_VIEW SELECTION_LOCK \
  --expected-view-sha256 EXTERNAL_VIEW_FILE_SHA256 \
  --expected-selection-sha256 EXTERNAL_SELECTION_FILE_SHA256 \
  --expected-commitment-preflight-sha256 EXTERNAL_PREFLIGHT_FILE_SHA256 \
  > SELECTION_ENVELOPE
```

The builder replays the selection from the view before creating
`causalfrontier.blind-selection-precommitment-envelope.v1`. The envelope is not
an entrant input: it records `selector_preflight_input_accepted:false` and
`temporal_order_independently_verified:false`. It binds artifacts produced in
the intended sequence but cannot prove their wall-clock order, authorship, or
custody. The builder receives the externally preserved preflight file digest,
not the preflight path or content; execution later requires actual preflight
bytes matching that digest.

## Exact canonical opening

Only after the selection and envelope checkpoints exist does the steward add
`ORACLE_ROOT/opening.json`. It must be exactly the object

```text
{
  "schema_version": "causalfrontier.synthetic-observation-opening.v1",
  "nonce_hex": <the checkpointed 64-character lowercase nonce>,
  "payload": <the exact checkpointed oracle payload object>
}
```

serialized by the repository’s canonical JSON rules: UTF-8, sorted keys,
compact separators, no duplicate keys or floating-point numbers, followed by
exactly one newline. Reformatting or editing it is not allowed. Its raw SHA-256
must equal the preflight’s `oracle_opening_sha256` and the execution-time
external opening checkpoint.

Execution authenticates the opening against the final challenge commitment
before performing secret-dependent payload semantics. It then requires exact
agreement with the preflight’s opening, payload, nonce, coordinate and entry
counts, limit contract, and registration bindings. The opened nonce must
regenerate the checkpointed entrant view byte-for-byte, and the selection must
replay independently from that view. Surplus files or empty directories,
symlinks, hard links, FIFOs, path reuse, missing coordinates, unsafe objects,
oversized files, and filesystem inventory drift during execution fail closed.
This does not imply that every unselected observation digest is reread at
execution time.

## Execution, isolation, and atomic batches

```bash
causalfrontier execute-blind-synthetic \
  CHALLENGE_ROOT RACE_SPEC ENTRANT_VIEW SELECTION_LOCK \
  SELECTION_ENVELOPE COMMITMENT_PREFLIGHT ORACLE_ROOT \
  ENTRANT_CASE_ID ENTRANT_LANE_ID POLICY_ID \
  --expected-manifest-sha256 FINAL_CHALLENGE_SHA256 \
  --expected-sequence EXTERNAL_SEQUENCE \
  --expected-race-spec-sha256 EXTERNAL_RACE_SHA256 \
  --expected-view-sha256 EXTERNAL_VIEW_FILE_SHA256 \
  --expected-selection-sha256 EXTERNAL_SELECTION_FILE_SHA256 \
  --expected-selection-envelope-sha256 EXTERNAL_ENVELOPE_FILE_SHA256 \
  --expected-commitment-preflight-sha256 EXTERNAL_PREFLIGHT_FILE_SHA256 \
  --expected-opening-sha256 EXTERNAL_OPENING_FILE_SHA256
```

The executor verifies the commitment-preflight and envelope checkpoints before
opening any oracle file. Only actions authorized by the exact locked trace have
their observation payloads read. `ABSTAIN` and `NO_CALL` policies read zero
observation payloads. Inventory checks examine metadata for the closed oracle,
but execution deliberately does not reread every unselected payload; therefore
`current_full_oracle_byte_readiness_verified:false` is accurate even after a
successful run. An aggregate entry or byte-total mismatch against the preflight
invalidates the episode before any action debit or observation read.

The same receipt also keeps
`commitment_preflight_independent_attestation_verified:false` and
`precommitment_temporal_order_independently_verified:false`. These fields do not
become true merely because a caller supplies mutually consistent local files and
hashes.

Every accepted action is charged exactly one complete `action_batches` unit
before any observation is read. The executor snapshots, authenticates, and
privacy-screens the entire selected replicate batch before classifying any
replicate. A digest, encoding, privacy, authority, or structural classifier
failure aborts the whole batch: it emits no partial action report or
`OBSERVATION_CLASSIFIED` events, retains the debit, marks the episode integrity
invalid, and stops. Authenticated UTF-8 TSV content that reaches a registered
parser/value failure instead derives the declared `FAILURE` branch. Accepted
actions are never refunded for informative, contradiction, failure, or no-call
results.

The complete execution report is a steward-only artifact, not a public unlinkable
projection. Its payload/opening/preflight checkpoint digests can confirm guesses
about otherwise known hidden artifacts. No public projection that removes those
confirmation channels is implemented. Within that steward receipt, direct classifier
group-keyed metrics and direct hidden observation identifier/digest fields are omitted. Each replicate receipt retains the registered
branch and outcome plus classifier/adapter digests, a digest computed only from the
redacted receipt, and an optional bounded diagnostic code, while setting
`group_keyed_metrics_omitted`, `direct_observation_identifier_field_omitted`, and
`direct_observation_digest_field_omitted` to `true`.
The raw classifier-result digest is omitted from both receipts and events because
it commits to the hidden observation digest, identifier, and unredacted metrics.
The report interprets each derived branch separately through the chosen encoder
lane’s frozen branch plan; lanes are never pooled into a winner.

Replication never majority-votes:

- one identical informative outcome across every required observation is
  `CONSISTENT_INFORMATIVE_SYNTHETIC_BATCH_INDEPENDENCE_UNVERIFIED`;
- consistent failure, no-call, or contradiction remains non-informative;
- any disagreement has no aggregate outcome;
- any contradiction also invalidates the declared partition; and
- repeated byte digests are reported only as a distinctness boolean, while
  replicate independence remains unverified.

`UNIFORM_ACTION_ENUMERATION_REFERENCE_V1` executes all selected actions in the
challenge’s frozen original action-ID order, never secret alias order. It is a
set-valued complete replay from one baseline state, so nonce changes cannot
choose an early action or suppress a later action.

## Status and CLI exit contract

An integrity-valid run with at least one action report uses
`SYNTHETIC_BLIND_OBSERVATIONS_CLASSIFIED_SCIENTIFIC_SCORING_DISABLED`. Here
“classified” means that the registered synthetic byte classifier ran; it is not
a scientific classification or score. A terminal policy that produces no
action report uses
`SYNTHETIC_BLIND_POLICY_TERMINATED_WITHOUT_OBSERVATION_CLASSIFICATION_SCIENTIFIC_SCORING_DISABLED`.
Its `action_reports` array is empty and no observation payload was opened.

All successful blind-protocol structural commands exit `3`, including either
integrity-valid execution status, to preserve explicit abstention from scientific
scoring. If execution returns `integrity_valid:false`, it emits a structured
receipt with status
`SYNTHETIC_POLICY_EXECUTION_ABORTED_INTEGRITY_INVALID_SCIENTIFIC_SCORING_DISABLED`
to standard output and exits `2`. Inputs rejected before a receipt can be formed
also exit `2` and report an error on standard error.

## Deterministic event chain

Each episode emits a separate canonical, domain-separated event chain:

```text
EPISODE_REGISTERED
POLICY_OUTPUT
(ACTION_DEBITED -> OBSERVATION_CLASSIFIED* -> ACTION_ADJUDICATED)*
EPISODE_TERMINATED
```

Budget rejection uses `ACTION_REJECTED` before termination; integrity failure
uses `EPISODE_ABORTED_INTEGRITY_OR_AUTHORITY`. Every event binds the episode ID,
sequence, previous digest, type, and payload. The episode ID binds the challenge,
race, view, selection, envelope, preflight, opening, opaque case/lane, policy,
and trace.

This deterministic trace is not a durable independently checkpointed policy
ledger. Its returned head must be stored externally before it can participate in
rollback detection, and even then a local chain alone does not prove authorship,
time, currentness, or rollback resistance.

## What remains `NO_CALL`

- nonce entropy, uniqueness, custody, and secrecy until selection;
- operating-system or remotely attested entrant isolation;
- independent timestamping, wall-clock ordering, and monotonic
  selection-before-opening proof;
- independent attestation of the preflight, outcome provider, controls, or
  current full-oracle byte readiness;
- semantic blinding, latent model-contamination assessment, patient-data absence,
  and privacy certification;
- replicate independence, measured resource truth, and a durable compare-and-swap
  episode ledger;
- terminal decision correctness and the registered primary endpoint;
- execution of the 15 scientific comparator families;
- temporal admission, encoder agreement, governance, and prospective validation;
  and
- every scientific, causal, biological, clinical, 10x, and health-impact claim.

Every view, selection, envelope, preflight, and execution receipt records
`scientific_scoring_ready:false`. The implementation status is local and
unreleased throughout.
