# Evidence-fit v1: post-run scope clarifications

These clarifications apply to the evaluation frozen at prerequisite
`2f34b5d7279241e842e263e4dfbad5c023336d2e` and reviewed result commit
`46a90676bd7279bf513ce62037a96b130abf726d`. The original protocol, programs,
inputs and retained results remain unchanged. The clarifications do not alter
the 132-scenario comparison or its interpretation.

## F-2: source-date preservation applies to audited records

The frozen `PROTOCOL.md` phrase "all receipt source dates" and the outcome field
`all_source_dates_retained` are broader than the implemented check. Read them as:
**all date fields belonging to each source represented by an audited record are
retained exactly in that record's report row**.

In the standard record-bearing case, the input receipt contains three sources,
each with seven date fields. The report contains one audited source's seven
date fields. The other two sources' fourteen fields remain in the saved receipt
input, without invented extraction/report rows. Equal null-valued dates across
sources do not count as preservation of those distinct source-field identities.
The empty-record case has no per-record preservation observations; its
missing-source requirement remains explicit.

The field name and frozen protocol are preserved for exact replay. This note
supplies their narrower interpretation; any later rename requires a separately
identified successor. The manuscript and result note already distinguish audited
sources from unrepresented input sources.

## F-5: lexical date ordering assumes one UTC format

The comparator orders formatted interval bounds and the cutoff as strings. In
this fixed design they all use zero-padded, whole-second UTC timestamps in
`YYYY-MM-DDTHH:MM:SSZ` format, for which lexical and chronological order agree.
The fixed-format precondition does not extend to mixed offsets, mixed precision
or arbitrary ISO-8601 strings. Those inputs were not evaluated. The review found
no date-order disagreement in the declared cases; this is a scope clarification,
not a corrected experimental result.

## F-1: subsequent operational diagnostics correction

The original evaluated source can collapse a filesystem failure into a generic
evidence-fit input rejection. The current development source preserves structured,
path-free operational diagnostics. The [review disposition](../../docs/reviews/evidence-fit-2026-09-08.md)
records the correction and its checks.

This source change is deliberately distinguishable from the frozen evaluation.
Use the [original-source replay wrapper](README.md#reproduce) to regenerate the
retained v1 artifact, and the separate current-API compatibility check to compare
the corrected API's reports. The wrapper does not remove or relax the original
runner's source-identity check. No existing result is relabeled as an evaluation
of the corrected source.
