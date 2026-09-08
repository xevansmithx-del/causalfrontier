# Evidence-fit v1: finite synthetic evaluation protocol

This evaluation asks whether CausalFrontier and a transparent table-rule program
produce the explicitly declared answers for a small, known synthetic design. It
also demonstrates semantic failures that literal comparisons cannot resolve.
All cases and expected answers are authored with knowledge of the implementation.
This is an executable methods artifact, not a blinded benchmark, independent
validation, human spreadsheet study, estimate-fidelity test or biological result.

The protocol, generator, baseline and runner must be committed and pushed before
the complete run. Development may execute at most eight named or prefix cases in
a run labelled `SMOKE_ONLY`. The initial full run binds a prerequisite Git commit
and checks every bound file against that commit. The operator separately records
that the commit was on the remote before execution; the script does not attest
remote custody. Later replay uses the recorded file digests. A correction after a
full run requires a separately disclosed successor, not replacement of results.

## Inputs and finite design

The only source is the repository's existing invented
`examples/synthetic-evidence-fit` fixture. Its exact extraction, receipt-set and
raw response digests are constants in `generator.py`. It contains no study,
participant, biological or private publication data. Each case copies the hr
record and its source requirement; all three original receipt source entries and
raw bytes remain retained. New labels, dates and quantities are explicitly
synthetic author declarations. Their meaning is not established by their binding
to unchanged raw bytes. `SYNTHETIC`, `SYNTHETIC_FIXTURE_ONLY`, absent temporal
attestation and all authority restrictions remain intact.

The complete design has exactly **132 cases**:

| Stratum | Cases | Authored variation |
| --- | ---: | --- |
| Declared-label factorial | 81 | 3^4 states: matched, mismatched, missing across endpoint, population, analysis population and estimate kind |
| Temporal precision and required role | 33 | 11 date variants crossed with INPUT, REVEAL_ONLY and CONTEXT_ONLY |
| Missing declaration side | 3 | Endpoint null in target, record, or both |
| Source conditions | 6 | Missing target/record version, different version, missing/different observed role, and absent required source with zero records |
| Semantic counterexamples | 6 | Two synonymous unequal labels, two concealed different meanings with equal labels, false source coordinate, false extracted quantity |
| Quantity preservation | 3 | Missing value/interval, unsupported reported text, unusual interval precision and person-time counts |

For the factorial, missing endpoint/population/analysis population means an
explicit null record declaration. Missing estimate kind means a null target:
the input schema requires a record kind. This is a schema asymmetry, not a claim
to exhaust every missingness pattern. The three additional endpoint cases make
the two missing sides and both-null behavior explicit. The factorial includes
mixed mismatch and unknown states; unknowns remain in the output even when a
record also has a mismatch. Null counts in the base fixture remain null.

The authored cutoff is `2012-06-15T12:00:00Z`. For each of DAY, MONTH and YEAR,
dates are wholly before, wholly after, or span that cutoff; UNKNOWN and an
unselected existing date field are the two other variants. A day spans the cutoff
when only day precision is known and the cutoff is midday. A required INPUT role
enables the input-date constraint. A missing or mismatched observed role does
not change the required role. All rows remain historically ineligible regardless
of apparent date fit. No selected metadata date independently attests availability.

## Paired comparison and expected answers

Both programs receive the same valid declared extraction and receipt metadata.
The baseline imports only the Python standard library. It reads no expected
answers, generator functions or CausalFrontier implementation. Its policy is a
literal nullable equality rule, a calendar interval rule and an explicit missing
source requirement check. Its date implementation uses next-period boundaries;
the tool uses calendar month ends. The expected date bounds and relations are an
explicit authored table in the generator, not outputs from either implementation.

The shared projection is limited to six label comparisons (endpoint, population,
analysis population, estimate kind, study version and role); selected-date
interval, relation, required INPUT applicability and input-date fit; historical
ineligibility; and missing source requirements. Missingness maps to UNKNOWN if
either declaration is null, including both-null. Different non-null labels map
to DECLARED_MISMATCH. Interval overlap maps to UNKNOWN input-date fit. Non-INPUT
roles also retain UNKNOWN input-date fit without changing the temporal relation.

The baseline does **not** implement receipt validation, byte checkpoints,
structural rejection, privacy screening, numerical consistency checks, complete
report generation or replay. Those features are outside the paired claim. Overall
record diagnostic status is also outside that claim: synthetic authority and
missing counts keep the base rows incomplete independently of the selected
labels. This baseline is deliberately competent for the shared diagnostic task;
its outcomes do not estimate human spreadsheet performance, analyst effort or
time saved. Neither program is given semantic stipulations as evidence input.

## Outcomes and analysis

The runner saves the entire generated input and authored expectation for every
case, actual receipt/extraction bytes, full tool reports, comparator outputs,
case outcomes, per-stratum totals, a factorial-only three-state confusion table
for each program, and a digest inventory. The factorial denominator is 81 cases
and 324 selected label cells per program. These cells are dependent by design,
not independent studies, replications or confidence estimates. The zero-record
case is counted separately as a source-requirement outcome; it contributes no
per-record cells. There is no pooled semantic accuracy score.

Additional engine-only checks verify exact preservation of input records and all
receipt source dates, coverage, retrieval state, semantic state and attestation;
preservation of unknown counts/intervals/decimal strings follows from full-record
equality. They also verify historical ineligibility, disabled scoring, false
scientific/semantic authority and exact whole-report replay. These are engineering
checks. The three quantity cases do not authenticate extracted values against
source meaning or test every numeric consistency rule. The full report retains
the original diagnostic status, reasons and all unselected dimensions for inspection.

Semantic cases carry separate, explicitly fictional stipulations. A synonym is
expected to produce a literal mismatch; concealed meaning and false source
coordinates/quantities are expected to pass the selected literal comparisons.
These are exhibited limits of the method, not mislabeled empirical successes.

All cases, failures and abstentions are retained. No random seed, tuning, sampled
exclusion, performance timing, significance test or superiority threshold is
used. Full generation and replay must agree byte-for-byte across output paths.
Only a completely successful declared-policy and preservation run exits zero.
The stored case outcomes and summary, rather than exit status alone, are the
result. The artifact is expected to stay below 10 MB and complete within a minute
on ordinary hardware; those are convenience targets, not evaluated speed claims.

## Execution

From a development checkout with its locked environment installed:

```bash
uv run --frozen --no-sync python evaluation/evidence-fit-v1/run.py \
  --output /absolute/new/output --freeze-commit FULL_PREREQUISITE_COMMIT
uv run --frozen --no-sync python evaluation/evidence-fit-v1/run.py \
  --verify-existing /absolute/existing/output
```

The first output directory must not exist. The artifact records repository-relative
input identities and no timestamp or machine path. Replay regenerates in a fresh
temporary directory and checks the full file inventory and exact bytes, using
the bound prerequisite source digests. A limited development run instead uses
`--smoke-limit 3` or up to eight `--smoke-case CASE_ID` arguments and never counts
as a full result. The retained full result is separate from its prerequisite
protocol commit, preserving the distinction between design and observation.
