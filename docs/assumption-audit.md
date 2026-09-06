# Single prediction-cell withdrawal audit

For explicitly declared multi-cell premises, see the separate
[grouped withdrawal audit](group-assumption-audit.md). That successor does not
change this audit's single-cell contract or turn cell counts into premise counts.

This development-source feature asks a narrow authoring question: **which
individual declared relations change the compiler's outputs when replaced with
`UNKNOWN`, and which withdrawals invalidate the case contract?** It makes
dependencies inspectable; it does not establish biological truth or recommend
an experiment. Packaged release `v0.1.0a2` does not contain this feature.

## Run and independently replay

From a checkout containing this feature and its locked development environment:

```bash
uv sync --frozen --extra dev
uv run --frozen --no-sync causalfrontier audit-assumptions examples/synthetic-aggregate
```

The command emits a JSON report to stdout and returns **3 for successful
structural-only completion**, or 2 for validation/runtime failure. No output
directory, capsule, classifier, ledger event or experiment is created. Save stdout
to a file **outside the frozen case root** if desired, preserve its exact-byte
SHA-256 separately, and verify it with:

```bash
causalfrontier verify-assumption-audit examples/synthetic-aggregate audit.json \
  --expected-report-sha256 <preserved-exact-report-file-sha256>
```

Verification also returns 3 on successful structural-only replay. It uses one
bounded, no-follow, single-link regular-file snapshot, checks the caller's byte
checkpoint, and rederives the complete report. Updating an edited report's own
hash does not make it pass. The report's internal domain-separated `audit_sha256`
is **not** the exact serialized file hash. Neither hash proves independent
custody, historical timing or currentness without an independently preserved
external record. The audit contains no historical scoring path.

Supply report paths without `..` components or symlinked ancestors (use an
absolute, physically resolved path when the report lives outside the checkout).
Parent traversal, symlinks, hard links, nonregular files and oversized reports
are rejected, not transparently followed.

Both commands call the ordinary case-root loader to verify current source bytes.
The pure Python APIs `audit_assumptions(case)` and
`verify_assumption_audit(case, report)` accept case dictionaries and check declared
provenance only; use `load_case(Path(...))` beforehand when source-byte checking
is required. Embedded `source_files_opened: false` describes the pure audit or
replay, not the CLI's preceding case load. Source citations remain author claims,
not independently authenticated support for a relation.

## Exact scope

The audit visits every `SURVIVES` or `EXCLUDES` cell in a nonresidual world and
an `INFORMATIVE` outcome. Each row changes **one prediction cell** to `UNKNOWN`
in a separate deep copy and recomputes that hypothetical branch-plan digest.
Sources, world/option partitions, other cells, outcome classes, classifier
declarations, gates and resources stay fixed. The original case is not edited;
the copied freeze/cutoff declarations do not turn a present-day hypothetical
variant into a historical commitment. The ordinary validator and compiler are
used for every accepted variant; no private validation bypass exists.

An informative branch must exclude at least one named world while retaining
at least one. Withdrawing its last exclusion therefore produces
`REQUIRES_REAUTHORING` / `REJECTED_BY_CASE_CONTRACT`, with null analysis,
selection and differences. It is neither a valid empty frontier nor evidence
that a biological alternative is impossible. These rows remain in the full
denominator and are not counted as unchanged selections.

For valid variants, the report separately compares both frontier memberships
and **all** co-minimax IDs, not just the lexicographic display representative.
Structurally admissible/unexecuted and conditional scientific structure remain
separate. Per-experiment projections distinguish strict pair separation from
retained worlds, retained decision classes and conditional reduction.
`SURVIVES → UNKNOWN` retains a world but can erase strict separation;
`EXCLUDES → UNKNOWN` can additionally retain a world or decision class.

Work is bounded at 128 eligible cells, 32 experiments, 256 total outcomes and
4,096 predictions, with explicit JSON depth, node, container and byte limits in
the report. Excess is rejected, never silently truncated. Input/report JSON is
limited to 4 MiB; stricter audit work limits can reject otherwise valid cases.
There is no guarantee that every case inside the cell cap fits the report limit.

## Known-input synthetic demonstration

At base `ec6bba85967a4e0ea5a7e30666e6b26eea96e38e`, the existing examples contain
one standalone case-v1 root: `examples/synthetic-aggregate`. This was selected
before the new audit demonstration, after inspection of its known contents.
It is a regression exercise, not a prospective study or independent scientific
cohort. All 12 eligible cells are retained:

| Result | Count |
| --- | ---: |
| Eligible and reported cells | 12 |
| Valid hypothetical withdrawals | 6 |
| Withdrawals requiring reauthoring | 6 |
| Valid withdrawals changing strict pair separation | 6 |
| Valid withdrawals changing co-minimax membership, in each scope | 4 |
| Valid withdrawals changing frontier membership, in each scope | 0 |
| Valid withdrawals changing retained worlds or decision classes | 0 |

The six valid rows withdraw `SURVIVES`; the six rejected rows withdraw each
branch's sole `EXCLUDES`. Four valid rows remove the perturbed experiment from
the tied co-minimax set. Two change strict separation without changing the
selection projection. Thus unchanged frontier membership alone misses a
decision-rule dependency. This is a synthetic illustration, not a measured
improvement in scientific decisions. `tests/assumptions_optimized_probe.py`
replays these counts and rejects a coherently rehashed omitted row with explicit
checks that remain active under `python -O`.

## Limits and established methods

One cell is not one independent scientific assumption. Shared premises can
support multiple cells; duplicating decision-equivalent worlds can change
withdrawal counts without changing baseline selection. Frequencies must not be
interpreted as confidence or compared as robustness scores across encodings.
Joint withdrawals, correlated premises, missing worlds, alternative classifiers,
source uncertainty, resource uncertainty and independent author agreement are
untested. Changes in a relative frontier are not scientific improvement.

Sensitivity to analysis choices is established methodology. Multiverse analysis
systematically exposes dependence on reasonable analytic choices
([Steegen et al., 2016](https://doi.org/10.1177/1745691616658637)); robust
model-discrimination design has optimized biochemical-model discrimination under
adverse parameter configurations
([Stegmaier, Skanda & Lebiedz, 2013](https://journals.plos.org/plosone/article?id=10.1371/journal.pone.0055723)).
This small, discrete, one-cell neighborhood is neither a new sensitivity theory
nor a global robust-design optimization or worst-case performance certificate.

The next utility gate is an independently authored case where a reviewer uses
the audit to locate a consequential disputed premise, with time and baseline
comparisons specified before assessment. Internal AI review and unit tests do
not supply that evidence. Documented independent scientific uses, prospective
scores and semantically verified controls remain zero; all clinical, human and
material authority remains false.
