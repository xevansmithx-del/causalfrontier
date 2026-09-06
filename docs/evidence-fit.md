# Source-bound aggregate evidence-fit audit

This development-source feature asks a narrow question: do a source-bound
extraction's **declared labels** fit an explicitly authored target? It does not
extract evidence automatically, establish that the extraction is correct, or
decide whether a treatment works. The existing integer/TSV classifier is
unchanged; clinical estimates are not coerced into artificial integer observations.

## What is compared

The audit accepts a [receipt-v1](receipt-v1.md) root and separately checkpointed
extraction bytes. A target declares endpoint, population, intervention,
comparator, timepoint, estimand, evidence kind, analysis population, counting
unit, measurement unit, estimate kind, and required source identities/versions/roles.
Each record binds one receipt, source locator and exact raw-response digest.

Comparisons are literal: `DECLARED_MATCH`, `DECLARED_MISMATCH`, or `UNKNOWN`.
Different strings can describe scientifically equivalent concepts; equal strings
can conceal different concepts. Neither condition is resolved here. A source
field or version label is an author declaration, not automatically checked
against the source text. Hashes establish byte identity, not faithful extraction.

The report retains each record verbatim, all source-date fields, confidence
intervals, contrasts, optional aggregate counts, acquisition coverage and
semantic state. Source requirements with no records remain explicitly missing.
Missing counts or intervals are not filled in. Failed acquisition is not
evidence that the scientific effect is absent.

## Typed quantities and time

Supported labels are `HAZARD_RATIO`, `RISK_RATIO`, `RATE_RATIO`, and
`MEAN_DIFFERENCE`. `UNSUPPORTED` preserves reported text with null value and
interval. Quantities use bounded decimal **strings**, not binary floating-point
numbers. Intervals retain `lower`, `upper`, and `level` (for example `"0.9751"`,
not an assumed 95%). Direction is retained in the explicit numerator/denominator
contrast; mean differences retain a declared measurement unit, with missing
units remaining unknown. The audit does
not pool estimates, invert contrasts, compute significance, or judge efficacy.
Numerical inconsistencies such as a reversed interval are reported, not repaired.

Aggregate counts distinguish participants, observations, person-time and unknown
denominators. Person-time retains a decimal string and its unit. Recurrent events
may exceed the participant denominator. Randomized and safety-analysis counts
must not be substituted for one another; the engine cannot discover a false
authored population label. Missing counts may be null.

Each record optionally selects one of its receipt's existing date fields.
Year/month precision produces an interval, not an invented exact publication
day. A date wholly after the frozen cutoff is a declared input mismatch; a date
interval spanning it remains unknown. `REVEAL_ONLY` and `CONTEXT_ONLY` records
are retained with their temporal relation, but the input-date constraint applies
only to a required `INPUT` role. No selected date establishes independently
attested availability. All records remain historically ineligible, including
apparently timely records. Current retrieval does not erase known hindsight.

## Run and replay

Use a development checkout containing this feature, not packaged release
`v0.1.0a2`. Keep extraction and reports outside the exact-inventory receipt root.
Use physical paths without symlink ancestors or `..`.

The shipped [synthetic example](../examples/synthetic-evidence-fit/extraction.json)
contains three artificial records. This exact invocation needs no external data:

```bash
causalfrontier audit-evidence-fit examples/synthetic-evidence-fit/receipt-root \
  examples/synthetic-evidence-fit/extraction.json \
  --expected-set-sha256 144c406e7474b6e90365a3c13fc7da3cd19026a27023ab68cd5175343e4cc27b \
  --expected-extraction-sha256 dd6a8c0b71efee41d1d3ee7d4d4ea42280c372f0cb2ca547fb70890e231b1635
```

The checkpointed fixture exercises by-cutoff, after-cutoff and unknown source
dates, and HR/rate-ratio/mean-difference distinctions. Its published digests are
reproduction pointers, not independent temporal custody. For other inputs:

```bash
causalfrontier audit-evidence-fit RECEIPT_ROOT EXTRACTION_JSON \
  --expected-set-sha256 EXACT_RECEIPT_SET_FILE_SHA256 \
  --expected-extraction-sha256 EXACT_EXTRACTION_FILE_SHA256
causalfrontier verify-evidence-fit RECEIPT_ROOT EXTRACTION_JSON REPORT_JSON \
  --expected-set-sha256 EXACT_RECEIPT_SET_FILE_SHA256 \
  --expected-extraction-sha256 EXACT_EXTRACTION_FILE_SHA256 \
  --expected-report-sha256 EXACT_SERIALIZED_REPORT_FILE_SHA256
```

Both commands return **3 for structural-only completion**, 2 for rejection.
Preserve stdout exactly, including its newline, before computing a report-file
checkpoint. The report's internal domain-separated `report_sha256` is not that
serialized-file digest. Replay rebuilds the entire audit and compares all fields;
a modified report with a coherently recomputed hash is still rejected.

The public APIs accept the same checkpointed raw extraction/report bytes:
`audit_evidence_fit(receipt_root, expected_set_sha256, extraction,
expected_extraction_sha256)` and `verify_evidence_fit` with additional `report`
and `expected_report_sha256` arguments. Both read the receipt root; neither
writes files, executes classifiers, requests a network service, or updates worlds.
The CLI acquires bounded, no-follow, single-link extraction/report snapshots.

## Resource and authority boundary

The complete request is rejected above its limits, without silent sampling:
128 records, 128 source requirements, 16 arms per count record, bounded text,
decimal strings and JSON complexity, and 4 MiB per serialized input/report.
Receipt-v1's exact file inventory and acquisition limits also apply. Before/after
receipt checks detect observed drift, not every possible mutation on the host.
Pattern-based privacy screening is not privacy certification.

There is no admission switch, scoring route, patient advice, biological/material
execution, or independent-review claim. Diagnostic counts depend on encoding;
they are not numbers of independent studies, statistical confidence or measured
research acceleration. Independent semantic extraction review, a prospectively
committed control trio, and an appropriately controlled evaluation remain
separate work. This feature does not establish scientific novelty or lives saved.
