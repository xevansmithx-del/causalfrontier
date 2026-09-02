# Receipt v1 preflight — local, unreleased milestone

This is roadmap milestone **1a**, not completion of the immutable-temporal-attestation
milestone. It prepares and checks source receipts without admitting historical evidence,
changing a causal world, or scoring a benchmark. The public `0.1.0a2` release does not
contain this command; its source manifest remains the record of that released version.

## What is implemented

`preflight-receipts` checks an exact file inventory against a caller-supplied, independently
preserved SHA-256 of `receipt-set.json`. That document binds every raw response and any
unverified attestation artifact. One file may support several receipts only when all of
them declare the same digest. Source bytes are read through no-follow directory/file
descriptors, bounded, screened, and hashed from the same in-memory snapshot.

The contract preserves these distinct concepts:

| Field | Meaning, not an inferred substitute |
|---|---|
| `request.submitted_arguments` | Canonical submitted arguments; the report also hashes them |
| `request.executed_query`, `query_rewrites` | Actual reported execution, or `null` when not exposed; a query echo is not proof of execution |
| `retrieved_at` | Current acquisition timestamp, not historical availability |
| `publication_unspecified`, `publication_online`, `publication_print` | Separate source-reported publication fields |
| `registry_first_posted`, `index_entry`, `source_updated` | Separate registration, indexing, and update dates |
| `snapshot_created` | A claimed snapshot date; not automatically trusted |
| `temporal_attestation` | Absent or an explicitly unverified artifact, never self-certified evidence |
| `retrieval_state` | Acquisition completion, partial response, failure, timeout, or not run |
| `semantic_state` | Metadata, context, declared decision evidence, unusable response, or synthetic fixture |
| `coverage` | Scope, returned/total counts, pages, remaining cursor, and truncation |

Every date is `{value, precision, source_field}`. Precision is `YEAR`, `MONTH`, `DAY`,
or `UNKNOWN`. Unknown means both value and source field are null. A year must not be
silently expanded to January 1; a month must not be expanded to its first day. These
declarations are type-checked, not authenticated against a historical archive.

Every receipt names stable source records and HTTPS locators, entity mappings, population,
comparator, endpoint, model, exposure, duration, funding/conflicts, and license metadata.
Unknown context remains null and unextracted metadata is `NOT_EXTRACTED`. Public metadata
does not become efficacy evidence by being labelled complete. `response_layer` distinguishes
a tool's serialized response from a raw HTTP body and from synthetic text.

## Deterministic outcomes

Malformed schemas, impossible dates, digest drift, unsafe files, prohibited material, or
authority/type changes raise an error. The CLI prints no receipt result and exits **2**.
Validly bound receipts produce `STRUCTURALLY_BOUND_NOT_HISTORICALLY_ADMISSIBLE` and exit
**3**, an explicit abstention rather than a success code that could enable scoring.

- A recorded acquisition `FAILED` or `TIMEOUT` yields receipt class `FAILURE`, not evidence absence.
- Other structurally valid receipts yield `NO_CALL`.
- Missing historical attestation stays visible even when acquisition failed.
- An unverified, backdated, hash-bound attestation remains `NO_CALL`: receipt v1 does not
  consume the separate RFC 3161 verifier, and no independent timestamp was collected.
- `historically_eligible_receipts_n` stays zero and `historical_scoring` stays `DISABLED`.

The receipt classes are acquisition/preparation diagnostics, **not** scientific classifier
outcomes and not evidence of contradiction or world exclusion. There is no adapter into
`classify`, no empirical result recorder, no scoring command, and no authorization switch.
The original fixed parameter and seven-field no-patient/no-authority/N=0 boundary are
unchanged. Boundary equality now also rejects integer/boolean aliases.

## Use

Run from an unreleased source checkout with Python 3.10 or later:

```bash
python -m causalfrontier preflight-receipts RECEIPT_DIRECTORY \
  --expected-set-sha256 INDEPENDENTLY_PRESERVED_RECEIPT_SET_DIGEST
```

The expected digest must come from an independent checkpoint, not be recalculated from
the potentially substituted input immediately before verification. Matching a caller's
digest does not establish who created it, its date, or its independence. The source and
validation identities for a working run must be checkpointed separately; the base package
version alone is not the identity of this unreleased implementation.

The set contains exactly `schema_version`, `id`, `fixed_parameter`, `boundary`, `frozen_at`,
`evidence_cutoff`, `selection_origin`, and `receipts`. Each receipt uses
`causalfrontier.receipt.v1`; `receipts.py` is the executable exact-key schema. Unknown fields
are rejected. The set and its declared payload files are the complete file inventory.
The preflight itself performs no writes, networking, or execution of source content.

## PCSK9 preparation result, 2026-08-31

A local preparation run retrieved the six previously selected PMIDs through ToolUniverse
1.4.1 PubMed and Europe PMC queries. Both returned six named records. This establishes
coverage of the requested identifiers only, not complete literature or author coverage.
The current tool responses are locally frozen; neither is an immutable 2012 archive.

Both receipts returned `NO_CALL`, with missing independent temporal attestation,
unreported executed-query/rewrite provenance, and metadata-only semantics. PubMed's date
strings were preserved at day precision and Europe PMC's returned publication years at
year precision. No historical score, control-trio commitment, biological result, or new
public release was produced. The raw responses and private checkpoint are deliberately
outside the public repository.

**This case is known-hindsight.** The initial project probe already exposed FOURIER outcome
values in the public tool-probe document. Avoiding further outcome retrieval does not erase
that exposure. A future hash commitment can bind a subsequent workflow, but cannot turn
this author or case selection into a blinded prospective evaluation. Independent encoders
with controlled exposure and fresh controls are required for any defensible blind test.

## Gates still open

1. Review the separate RFC 3161 verifier and trust policy, collect an independent
   timestamp, and integrate replayed reports without confusing digest existence with
   historical source availability.
2. Source-specific semantic extraction, complete execution/coverage receipts, and full context.
3. Independently authored positive, failed-translation, and ambiguous controls, with exposure tracked.
4. Precommitted classifiers, scoring rules, baseline comparisons, and independent review.

No declaration or collection of hashes closes these gates. Privacy screening is limited
pattern screening, **not** de-identification, patient-data detection, or a privacy certificate.
Hashes protect selected byte identities, not a fully compromised host, source authenticity,
or a globally atomic filesystem snapshot. The preflight requires POSIX no-follow descriptor
support and refuses unsupported platforms. No clinical, human, legal, biological, material,
publication, or scientific-claim authority is added.

## Test strategy

Unit/contract tests cover exact schemas and types, date precision, missing provenance,
coverage contradictions, and deterministic failure/no-call precedence. Hostile filesystem
tests cover traversal, links, FIFOs, size limits, substitution, and extra files. CLI tests
check abstention/error exit codes and redacted diagnostics. The full original case,
branch-totality, rollback, classifier, and capsule suites must remain green. A normal and
optimized-runtime probe must preserve both the original synthetic identity and the new
receipt result. None of these software tests substitutes for biomedical validation.
