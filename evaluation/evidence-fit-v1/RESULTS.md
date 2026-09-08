# Results: authored declared-policy and preservation evaluation

The full 132-scenario run has no retained failed case. CausalFrontier and the
table-rule baseline each matched the authored expected projection in every
scenario, and their projected outputs agree. Production source, fixture bytes,
protocol, generator, baseline and runner were unchanged between the prerequisite
commit and the completed run.

| Family | Scenarios | Engine matches expectation | Baseline matches expectation | Paired agreement |
| --- | ---: | ---: | ---: | ---: |
| Four-factor label census | 81 | 81 | 81 | 81 |
| Date precision × required role | 33 | 33 | 33 | 33 |
| Missing target/record/both | 3 | 3 | 3 | 3 |
| Source version, role and absent extraction | 6 | 6 | 6 | 6 |
| Semantic counterexamples | 6 | 6 | 6 | 6 |
| Quantity preservation | 3 | 3 | 3 | 3 |
| Total | 132 | 132 | 132 | 132 |

The factorial contributes 324 selected label cells per implementation: 108
matches, 108 mismatches and 108 unknowns, with no off-diagonal entry against the
authored oracle. These dependent cells are the complete specified design, not
an empirical sample. The one zero-record source scenario is included as a
source-requirement outcome and contributes no record-level cells.

## Semantic controls

| Artificial scenario | Selected literal result in both programs | What it shows |
| --- | --- | --- |
| Endpoint synonym | Endpoint mismatch | Equivalent stipulated meaning does not normalize unequal strings |
| Population synonym | Population mismatch | A second unequal-string example has the same limitation |
| Different endpoint meanings under equal labels | Selected fields match | Matching labels do not establish matching concepts |
| Different population meanings under equal labels | Selected fields match | Hidden analysis-population differences require source interpretation |
| Nonexistent source-field coordinate | Selected fields match | A source-field string is not resolved against the raw response |
| Source HR 0.80 changed to 0.81 in extraction | Selected fields match | Valid byte binding and plausible arithmetic do not authenticate an extracted value |

The semantic meanings are explicitly authored stipulations. No semantic accuracy
rate is calculated. “Selected fields match” does not mean a complete engine
report approves the record: synthetic source status and unreported counts remain
visible, and all records remain unverified and historically ineligible.

## Preservation and reproducibility

Every record-bearing case retained the exact extraction record, selected date and
cutoff, the corresponding source's complete date object, coverage, retrieval and
semantic states, and temporal-attestation state. The quantity controls retain
nulls, unsupported text, decimal precision, the interval level `0.9751`, and
person-time units. These are preservation checks, not authentication against
real publications or a comprehensive numerical-validation benchmark.

The runner's `all_source_dates_retained` field concerns the source corresponding
to each audited record. Unrepresented source entries remain in the saved receipt
input; the report does not create extraction rows for them. The empty-record
case has no record-preservation observations, although the complete report and
its missing-source outcome still replay.

Every full report verified by reconstruction. A second run under optimized
Python reproduced the full 927-file artifact exactly. These results check local
reproducibility; they do not authenticate a coordinated replacement of source,
manifest and outputs or create independent temporal custody.

| Artifact | SHA-256 |
| --- | --- |
| `results/summary.json` | `3043f2716d381c475d90ae5ee0d575f46c7a75e87a08138b42ac1c03d7ca47c8` |
| `results/run_manifest.json` | `9d6b59a0de407d100b609e66f788f4fd211ed56b8db04ee3149b013996030dd7` |
| `results/artifact_hashes.json` | `444bc0e07e0d8b343715941b791c198359465cf49fa697f86b003f3af6b1dcee` |

## What the comparison supports

On the declared finite domain, a short literal rule implementation is sufficient
to reproduce the selected compatibility diagnostics. **No decision-rule
advantage over this baseline was observed.** This does not assess whether the
tool's byte binding, report generation, validation or replay saves work, because
the comparator does not implement those tasks and their practical utility was
not measured.

The evaluation does not cover arbitrary calendar boundaries, all nullable fields,
all acquisition failures, all numeric consistency diagnostics, adversarial
parsers, full-compiler selection, scientific extraction fidelity or independent
human use. No biological validation, prospective scientific scoring, novelty,
clinical authority or tenfold improvement follows. A component manuscript may
report these results with those limits; journal submission readiness remains open.
