# Author a case and freeze its inputs

`freeze-draft` turns your explicit case declarations and source files into a
new case that `analyze`, `classify`, and `compile` can read. It fills the source,
classifier, and branch-plan digest fields, then applies the ordinary case
validator. You supply the scientific content; the command does not generate
worlds, choose thresholds, infer relations, change dates, or validate biology.

This command is in development source `0.1.0a5`, not packaged release
`v0.1.0a2`. From a current source checkout, install the locked environment with
`uv sync --frozen --extra dev`. See [diagnostics](diagnostics.md) for environment
issues. The authoring workflow itself does not need OpenSSL or network access
after installation.

## A complete synthetic practice workflow

Run these commands from the repository root. The unique practice directory
keeps the bundled example and every frozen predecessor intact:

```bash
practice_root=$(mktemp -d)
practice_root=$(cd "$practice_root" && pwd -P)
export practice_root
uv run --frozen --no-sync python - <<'PY'
import json
import os
import pathlib
import shutil

root = pathlib.Path(os.environ["practice_root"])
draft_root = root / "draft"
shutil.copytree("examples/synthetic-aggregate", draft_root)
case_path = draft_root / "case.json"
draft = json.loads(case_path.read_text(encoding="utf-8"))
draft["schema_version"] = "causalfrontier.case-draft.v1"
draft["case_id"] = "synthetic-authoring-practice"
draft["title"] = "Synthetic authoring practice using the existing aggregate fixture"
for source in draft["provenance"]:
    source["sha256"] = None
for experiment in draft["experiments"]:
    experiment["classifier_sha256"] = None
    experiment["branch_plan_sha256"] = None
(draft_root / "draft.json").write_text(
    json.dumps(draft, indent=2) + "\n", encoding="utf-8"
)
case_path.unlink()
print(draft_root / "draft.json")
PY

uv run --frozen --no-sync causalfrontier freeze-draft \
  "$practice_root/draft" "$practice_root/frozen"
uv run --frozen --no-sync causalfrontier analyze "$practice_root/frozen"
uv run --frozen --no-sync causalfrontier classify "$practice_root/frozen"
uv run --frozen --no-sync causalfrontier compile \
  "$practice_root/frozen" "$practice_root/capsule"
uv run --frozen --no-sync causalfrontier verify "$practice_root/capsule"
```

All five commands should exit `0`. The freeze receipt reports
`AUTHORED_DRAFT_FROZEN_STRUCTURAL_VALIDATION_ONLY`, the exact draft digest,
frozen case and analysis digests, and each copied source digest. Verification
reports `SELF_CONSISTENT_UNAUTHENTICATED_PROTOTYPE`. Keep these identifiers with
your work. This practice copy is the existing synthetic case with a new label;
it is not a new independent case, prospective freeze, or research finding.

In the analysis, `experiment:global-recompute` is dominated. The held-out and
negative-control checks remain tied co-winners: their resource trade-offs are
not collapsed into a score. An identifier appearing first is only display
order. The classifier results are deterministic mappings of invented integers
through authored rules. They are not observations of the declared worlds.

To revise the practice case, edit `draft/draft.json`, review your declarations,
and freeze to a different destination such as `frozen-v2`. Never edit a frozen
case to preserve an earlier identifier. The original draft bytes and sources
are left unchanged by `freeze-draft`.

## What the author must supply

The draft contains the same fields as `causalfrontier.case.v1`, with just these
explicit authoring differences:

| Field | Draft value |
|---|---|
| File name | `draft.json` |
| `schema_version` | `causalfrontier.case-draft.v1` |
| Every `provenance[].sha256` | `null` |
| Every `experiments[].classifier_sha256` | `null` |
| Every `experiments[].branch_plan_sha256` | `null` |

All other declarations are required. Start from the practice fixture to learn
their structure, then author and review each declaration for a new research
case. A copied label or edited number does not supply scientific justification.

- **Question and decision:** state the narrow question, substantive options,
  and defer option. Define operationally exclusive worlds and exactly one
  open residual, with the source IDs supporting each declaration.
- **Sources and dates:** retain permitted public-aggregate or synthetic UTF-8
  source bytes, locators, license, queries, retrieval status, scope, and dates.
  The command checks declared date ordering; it never establishes that these
  dates are true or that freezing preceded knowledge of an outcome.
- **Discriminators:** author protocols, required gates and authorities, all
  five integer resource dimensions, and a complete world-by-outcome relation
  matrix. Failure and no-call preserve worlds; contradiction preserves only
  the residual and invalidates the named partition.
- **Classifiers:** bind one existing registered classifier to each experiment.
  The current engine accepts strict TSV inputs and bounded canonical integers,
  using only `GROUPED_CONTRAST_RANGE_V1`, `GROUPED_SHARED_VALUE_RANGE_V1`, or
  `HELDOUT_CONTRAST_ENVELOPE_V1`. Arbitrary statistics, floating-point files,
  external code, and new classifier kinds are not supported by this command.
  Do not squeeze an incompatible study into these rules to obtain a pass.
- **Interpretation:** retain the fixed alpha boundary and explicit nonclaims.
  Source truth, model semantics, thresholds, privacy, licensing, and resources
  still require accountable review. Freeze output does not enable scoring.

The complete field contract remains enforced by the validator; the
[architecture](architecture.md) explains the reasoning behind these rules.

## Files, failures, and recovery

The draft root must contain exactly `draft.json` plus the declared source
files. Paths use the receipt reader's canonical relative path contract: at
most eight components, each beginning with a letter or digit and containing
only letters, digits, underscores, hyphens and periods (128 characters maximum);
no absolute paths, traversal, symlinks, hard links, special files, or empty
directories. Authoring is bounded to 128 filesystem entries, 4 MiB for the
draft JSON, 1 MiB per source, and 16 MiB total. Keep notes and editor backups
outside the draft root. The destination's parent must already exist and must
not traverse symlinks; the new directory must be outside the draft.

On invalid declarations, missing input, or an existing destination, the CLI
exits `2`, prints an error to stderr, and emits no success receipt. For
machine-readable errors, put `--error-format json` before `freeze-draft`.
Incorrect supplied digests are not silently replaced: all three digest kinds
must be explicit `null` placeholders in an explicit draft.

Validation occurs before output creation. A caught write or final-replay
failure removes only the output directory created by this attempt, guarded by
its inode identity. An existing destination is never overwritten or removed.
A process kill can leave a partial output directory; keep it for diagnosis
and retry with a fresh destination. No crash-atomic publication, immutable
filesystem permission, external custody, or hostile-host protection is claimed.

The Python API is `causalfrontier.freeze_draft(Path("draft"), Path("frozen"))`
and returns the same receipt as the CLI. It raises `CausalFrontierError` on
rejected input. It does not create a capsule or record an empirical result;
those roles remain separate in the existing workflow.
