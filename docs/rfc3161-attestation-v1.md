# RFC 3161 temporal evidence v1 — local, unreleased

This is roadmap milestone **1b**: a real verifier for offline signed-target-imprint evidence, not
completion of historical evidence admission or prospective custody. It uses the IETF
Time-Stamp Protocol rather than a CausalFrontier-specific timestamp scheme. No public
TSA was contacted and no project artifact was externally registered in this iteration.

## Exact claim boundary

A report whose time-limit gate is `PASS` establishes this narrow, offline statement:

> The exact checkpointed target bytes match the SHA-256 message imprint in a nonce- and
> policy-bearing RFC 3161 request and response whose TSA signature and certificate path
> validate without revocation under the exact caller-checkpointed trust policy, whose
> single CMS signer uses SHA-256, and whose signed token accuracy produces an upper bound
> no later than the caller-checkpointed limit.

It does not establish that the bytes were public, accessible, complete, authored by a
particular party, semantically current, independently witnessed, or the newest state. It
does not establish recursive DER canonicality, certificate good standing, an unqualified
cryptographic timestamp, or unqualified digest existence before the limit. It does not
admit a historical receipt or enable scientific scoring.

## Why two cryptographic replays are mandatory

OpenSSL accepts only one of `-queryfile`, `-data`, or `-digest` per `ts -verify` call.
CausalFrontier therefore runs both:

1. response against the exact query DER, binding the requested policy, nonce, and
   message imprint; and
2. response against a private snapshot of the exact target bytes, preventing a valid
   request for artifact A from being presented with artifact B.

Both run with the same pinned binary, deterministic minimal OpenSSL configuration,
private working directory, explicit trust anchor, optional exact intermediate chain,
token `genTime` certificate-validation basis, `timestampsign` purpose, and strict X.509
mode with authentication level 2. A separately extracted CMS token must contain exactly
one SignerInfo, one SHA-256 digest-set algorithm, a SHA-256 signer digest, exactly one
default-SHA-256 ESSCertIDv2 certificate binding, and no SHA-1 algorithm text. No shell or
caller-supplied OpenSSL flags are used.

## Closed artifacts

The attestation directory contains exactly:

- `attestation.json`;
- one nominal DER `TimeStampReq`; and
- one nominal DER `TimeStampResp`.

The trust-policy directory contains exactly:

- `trust-policy.json`;
- one canonical PEM trust-anchor certificate; and
- optionally one PEM untrusted intermediate chain.

The trust-anchor file must contain exactly one certificate in the accepted
canonical PEM form. Extra or concatenated trusted certificates, invalid base64,
and trailing or concatenated bytes outside the single top-level certificate
sequence fail closed. This exact-one input rule does not establish recursive DER
canonicality, current trust-root status, or independent governance.

Every file is single-link, regular, bounded, no-follow read, and raw-SHA-256 bound. Query
and response must each be one definite-length top-level ASN.1 sequence with no trailing,
concatenated, truncated, or indefinite-length bytes. OpenSSL accepts some noncanonical
BER encodings inside that frame, so recursive canonical DER remains an explicit
`NO_CALL`; the verifier does not silently promote parser acceptance into a DER claim. The
target, both manifests, the OpenSSL executable, request, response, trust anchor, and
optional chain all have distinct raw-byte checkpoints.

The trust policy fixes:

- RFC 3161/RFC 5816 SHA-256 response semantics;
- the exact verification profile;
- one declared TSA organization;
- a canonical allowlist of numeric TSA policy OIDs;
- a maximum accepted value for the accuracy explicitly signed in the token;
- exact trust material;
- offline revocation status; and
- caller-declared, unaudited independence.

The request must explicitly contain an accepted numeric policy OID, a nonce, SHA-256
imprint, and a certificate request. The token must explicitly sign a positive accuracy
within the checkpointed policy maximum. A SHA-1 message imprint or CMS signer digest,
nonce-free request, default-policy request, token-only object, self-selected replacement
root, unspecified accuracy, or one-pass verification fails closed.

## Runtime boundary

The OpenSSL 3 executable is resolved, checked as a bounded executable regular file,
hashed, copied byte-for-byte into the private directory, executed only from that snapshot,
and rehashed there afterward. Ambient
`OPENSSL_CONF`, provider, certificate-file, certificate-directory, path, locale, and time
zone variables do not enter the subprocess. The verifier supplies a deterministic minimal
configuration and empty default certificate directory.

Bundle retention is capped by the shared total-byte limit. Parent-side selector draining
enforces a 64-KiB limit on each OpenSSL output pipe and terminates the isolated process
group on completion, overflow, or timeout; forked descendants cannot retain the pipes or
outlive a rejected verifier while they remain in that process group. This is process-group
cleanup, not a sandbox against a hostile child that creates a new session. No pre-exec hook
or disk spool is used. Runtime and output limits fail closed.

This is not a hermetic runtime: dynamically linked libraries and compiled provider search
paths are not byte-bound. The report therefore sets `openssl_runtime_hermeticity_verified`,
`certificate_revocation_checked`, and `long_term_validity_verified` to false. Independent
reproduction with separately reviewed runtimes remains required.

## Result vector

Successful offline verification can set these fields true:

- `request_response_binding_verified`;
- `target_response_binding_verified`;
- `expected_policy_oid_verified`;
- `nonce_binding_verified`;
- `imprint_algorithm_allowed`;
- `tsa_signature_and_chain_at_signed_gentime_verified_without_revocation`;
- `cryptographic_timestamp_signature_verified_without_revocation`; and
- `signed_target_imprint_time_bound_under_caller_policy_verified_without_revocation_or_signer_identity`,
  only when the signed-accuracy upper bound passes.

These fields remain false:

- source public availability, authorship, and semantic currentness;
- recursive canonical DER conformance;
- unqualified cryptographic timestamp verification and unqualified target-digest
  existence before the limit;
- unqualified TSA signature/chain verification and certificate validity across the
  complete signed-accuracy interval;
- authenticated witness-signer identity;
- witness independence;
- revocation and long-term validity;
- rollback currentness;
- prospective cohort admissibility;
- historical and scientific scoring readiness.

A valid but late timestamp returns a structured `NO_CALL` for the time-limit gate. Invalid
bytes, trust, schemas, policy, nonce, algorithms, signatures, paths, or runtime checkpoints
raise a controlled error. The CLI exits `3` for both valid result states and `2` for an
invalid verification.

## Usage

```bash
causalfrontier verify-rfc3161-attestation \
  TARGET_FILE ATTESTATION_ROOT TRUST_POLICY_ROOT /absolute/path/to/openssl \
  --expected-target-sha256 TARGET_RAW_SHA256 \
  --expected-attestation-checkpoint-sha256 ATTESTATION_JSON_RAW_SHA256 \
  --expected-trust-policy-checkpoint-sha256 TRUST_POLICY_JSON_RAW_SHA256 \
  --expected-openssl-sha256 OPENSSL_EXECUTABLE_RAW_SHA256 \
  --expected-not-after CALLER_CHECKPOINTED_RFC3339_UTC_LIMIT
```

The expected values, including the not-after limit, must be preserved out of band.
Recomputing them from possibly substituted local inputs immediately before verification
defeats rollback detection. This module verifies equality to the caller checkpoint; only a
later prospective registry can establish that the limit itself was frozen before outcome
access.

## Current validation and next gate

Twenty-five focused tests cover the valid path, late-token abstention, coherent target
substitution, trust-policy rewrite, missing nonce, missing requested policy, SHA-1 message
imprint, SHA-1 CMS signer, SHA-1 ESS certificate binding, unspecified signed accuracy,
token-only input, trailing ASN.1,
noncanonical BER non-overclaim, wrong trust root, binary checkpoint drift, unsafe links,
ambient OpenSSL variables, private executable-snapshot TOCTOU resistance,
caller-cutoff mismatch, total-bundle retention, bounded child output, same-process-group
forked-descendant termination, and CLI exit/nonclaim behavior.

The next layer is a prospective registry that consumes replayed reports from at least two
organization- and store-distinct witnesses. It must reject cloned decision points by a
label-invariant structural fingerprint, bind entrant and steward projections separately,
and keep unknown future outcomes out of the preregistration. No report from this module by
itself may flip cohort, independence, source-availability, rollback, or scoring gates.

The local verifier report also exposes the exact trust-anchor certificate digest
and, for both the trust anchor and extracted timestamp signer, the public-key
algorithm, SPKI digest, and domain- and key-family-separated canonical mathematical
key-material digest. RSA/RSA-PSS projections normalize to RSA modulus/exponent;
EC projections force an uncompressed point and named curve; Ed25519 and Ed448 use
their normalized public-key projection. These are byte/key projections for
collision checks by the dual-witness composition layer; they do not establish
signer identity, witness independence, or current trust. The report explicitly
keeps `canonical_der_verified`, `openssl_runtime_hermeticity_verified`, and
`certificate_validity_over_signed_accuracy_interval_verified` false.
