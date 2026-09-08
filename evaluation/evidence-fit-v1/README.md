# Finite synthetic evidence-fit evaluation

The evidence-fit component and a transparent table-rule comparator agreed on the
selected projection in **132/132 authored scenarios**. Each separately matched
the authored expectations. This is finite contract agreement, not evidence that
CausalFrontier makes better scientific decisions or improves human performance.

Read the frozen [protocol](PROTOCOL.md), its [post-run clarification](ERRATA.md), [results and limits](RESULTS.md), and
[component manuscript draft](../../docs/manuscript/evidence-fit-component.md).
The baseline implements the six selected label comparisons, date interval rules
and missing-source condition. It is not a whole-tool replacement or a measured
spreadsheet workflow.

## Reproduce

From the repository root with Python 3.10 or later:

```bash
uv sync --frozen --extra dev
uv run --frozen --no-sync python evaluation/evidence-fit-v1/replay_frozen.py \
  --verify-existing evaluation/evidence-fit-v1/results
uv run --frozen --no-sync python -O evaluation/evidence-fit-v1/replay_frozen.py \
  --verify-existing evaluation/evidence-fit-v1/results
uv run --frozen --no-sync python evaluation/evidence-fit-v1/check_current_compatibility.py \
  --results evaluation/evidence-fit-v1/results
```

The first two commands replay the original evaluation with its original source.
The wrapper verifies a sealed archive of all 41 prerequisite files, extracts only
the verified bytes into a temporary directory, and invokes the unchanged original
runner. It compares the complete 927-file output with the retained artifact.
The original protocol, generator, baseline, runner and result files are preserved.
The third command separately compares the current API's complete reports with
the retained reports. That is a post-review compatibility check, not a replacement
of the original evaluation or a new scientific benchmark.

The distinction is needed because a subsequent correction preserves operational
filesystem diagnostics in the current API. The original runner intentionally
rejects current source whose digests differ from its recorded prerequisite. The
wrapper does not bypass that check: it supplies the original source instead.
Neither command modifies retained results. Both work without Git metadata,
including from the source distribution. This component was added after packaged
release v0.1.0a2; use a development-source checkout containing this directory.

The initial full run used prerequisite commit
[`2f34b5d7279241e842e263e4dfbad5c023336d2e`](https://github.com/xevansmithx-del/causalfrontier/commit/2f34b5d7279241e842e263e4dfbad5c023336d2e).
The operator observed the commit and read back the four protocol/code files from
GitHub before the run. That sequencing is an operator record, not independent
historical custody or blinding. The runner checks local bytes against that commit
for an initial run; subsequent replay checks the stored source digests.

The original initial-run command below is a historical record. It requires an
isolated checkout with the exact prerequisite bytes; it is not a command for the
subsequently corrected development source. Use the wrapper above to reproduce
the retained evaluation from the current package.

```bash
uv run --frozen --no-sync python evaluation/evidence-fit-v1/run.py \
  --output /absolute/new/evaluation-output \
  --freeze-commit 2f34b5d7279241e842e263e4dfbad5c023336d2e
```

## Artifacts

- [Run manifest](results/run_manifest.json): all case IDs and prerequisite source hashes.
- [Summary](results/summary.json): per-family census and factorial confusion counts.
- [Artifact inventory](results/artifact_hashes.json): exact hashes for all other result files.
- `results/cases/`: all 132 input/expectation definitions, receipt payloads,
  extraction files, complete engine reports, replay receipts and case outcomes.

The saved artifact has 927 files and 3,151,054 bytes. One scenario has zero
extraction rows and an explicitly missing required source; the other 131 each
contain one artificial extraction row. These are variations of the same
synthetic fixture, not independent source studies.

The [additional AI review and checked disposition](../../docs/reviews/evidence-fit-2026-09-08.md)
record the diagnostic correction, the frozen field-name clarification and the
review's own limitations.
