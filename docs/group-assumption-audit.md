# Declared grouped prediction-cell withdrawal

The [single-cell audit](assumption-audit.md) tests one authored relation at a
time. It can miss a consequential change when an author represents one premise
in several cells. This successor audits explicit groups and their unique member
singletons. It does not infer premises, dependencies or refutations from citations.

## Question and contract

Given a valid case and a separately checkpointed manifest, what changes when all
members of each declared group become `UNKNOWN` together? All sources, worlds,
branches, classifiers, resources and gates remain fixed. Only selected relations
and the affected hypothetical branch-plan digests change. The original case is
not modified. Classifiers and experiments are not executed.

Every hypothetical case undergoes ordinary validation; only accepted variants
are compiled. An
invalid variant is retained as `REQUIRES_REAUTHORING`, with null analysis and
selection. For example, removing the last exclusion from an informative branch
does not produce a valid empty frontier. The author must decide whether and how
to reauthor it; this audit does not do so automatically.

`singleton_masked_joint_selection_change` means all member singletons and the
joint variant are valid, each singleton's exact selection projection is unchanged,
and the joint frontier or tied co-minimax membership changes in at least one
scope. Applicability is reported separately: an invalid variant is not evidence
that no joint effect exists. Both the structurally admissible unexecuted and
conditional scientific-structure scopes are retained. Lexicographic display
representatives are not treated as the whole co-minimax set.

## Manifest and use

Use a development checkout containing this feature; this change does not publish
a new package release. For a runnable source-tree example (a transport demonstration, not the
duplicated-world witness below):

```bash
causalfrontier audit-assumption-groups examples/synthetic-aggregate \
  examples/synthetic-assumption-groups.json \
  --expected-manifest-sha256 d62edf0f190e808b9d0a3a301e8abae7958a7ad50f008b27041122bea36d0692
```

The checkpoint identifies the exact shipped example bytes; it does not assert
independent custody or that the declared groups are scientifically warranted.

The manifest schema is `causalfrontier.assumption-groups.v1`:

```json
{
  "schema_version": "causalfrontier.assumption-groups.v1",
  "case_sha256": "<normalized case digest reported by analyze>",
  "groups": [
    {
      "id": "group:declared-premise",
      "rationale": "Author-declared reason these exact cells are audited together.",
      "members": [
        {"experiment_id": "experiment:a", "outcome_id": "outcome:x", "world_id": "world:a"},
        {"experiment_id": "experiment:a", "outcome_id": "outcome:x", "world_id": "world:a-copy"}
      ]
    }
  ]
}
```

This is a schema illustration, not a runnable biological case. Use real IDs from
your case. Each member must identify a non-residual `SURVIVES` or `EXCLUDES` cell
in an informative outcome. Groups may overlap or span experiments. Duplicate
members within a group and duplicate group IDs are rejected. Group and member
ordering is canonicalized. Distinct IDs with identical member sets remain
distinct author declarations, not independent evidence.

```bash
causalfrontier audit-assumption-groups CASE_ROOT GROUPS_JSON \
  --expected-manifest-sha256 EXACT_MANIFEST_FILE_SHA256
causalfrontier verify-group-assumption-audit CASE_ROOT GROUPS_JSON REPORT_JSON \
  --expected-manifest-sha256 EXACT_MANIFEST_FILE_SHA256 \
  --expected-report-sha256 EXACT_REPORT_FILE_SHA256
```

Use physical paths without `..` or symlink ancestors. Keep manifests/reports
outside the frozen case root, whose exact file inventory remains authoritative.
Both commands return **3 for structural-only success**, 2 for rejection; capture
stdout without treating 3 as scientific validation. Checkpoints cover the exact
serialized bytes including whitespace and the report's trailing newline. The
report also binds canonical manifest and case identities; canonical equality is
not an independently witnessed timestamp, authorship or custody claim.

The CLI verifies source bytes with `load_case` and reads the manifest/report from
bounded, no-follow, single-link snapshots. The pure APIs
`audit_assumption_groups(case, manifest)` and
`verify_group_assumption_audit(case, manifest, report)` perform no filesystem
access. Their `source_files_opened: false` applies to that pure stage, not the
CLI's preceding source verification. Full-report replay rejects changed rows,
counts, labels and authority flags even when a forged report has a new coherent
digest. Hash matching by itself is insufficient.

The whole request is rejected above any bound: 32 groups, 2–16 members per group,
128 distinct members, 256 memberships, 160 singleton-plus-group variants,
32 experiments, 256 outcomes, 4096 predictions, 4 MiB canonical JSON (including
one report newline), and bounded JSON nodes/depth/containers. No silent sampling
or truncation. All declared groups and unique member singletons are audited;
combinations of different groups are **not** automatically enumerated.

## Finite synthetic control, not an empirical benchmark

`tests/group_oracle_fixture.py` constructs an explicitly synthetic witness with
two equal-resource/equal-gate candidates, two informative branches each, two
decision-equivalent copies of one substantive world, one excluded world and the
residual. Both copies initially survive each informative branch. Each individual
withdrawal leaves the class surviving; withdrawing both changes it to unknown.
The surviving classes remain fixed, but strict separation can disappear and
change selection. Merging the duplicate worlds preserves baseline selection but
changes the family of individual-cell interventions. This is an encoding
dependence of that audit, not a demonstrated baseline selector defect.

`tests/test_group_oracle.py` independently enumerates all 256 binary withdrawal
masks of the eight surviving cells, plus 16 coarse masks paired with equivalent
refined groups. Its small truth-table oracle does not use production aggregation
or selection helpers. The known two-cell witness was observed during exploratory
problem selection, before this implementation. It is not a blinded prospective
discovery. Agreement validates only this finite synthetic contract.

The checked frontier/co-minimax counts are 117 ties, 69 alpha-only, 69 beta-only
and one empty selection for the refined panel; the coarse panel has 5, 5, 5 and
1 respectively. All 16 mapped coarse/refined selections agree. The six-group
control manifest selects ten unique singleton cells: eight valid and unchanged,
two requiring reauthoring. Five groups are valid (four masked joint changes and
one unchanged); the remaining group requires reauthoring. These are counts of
constructed encodings, not independent cases, effects or success rates.

## Established methods and remaining nonclaims

Joint sensitivity analysis and the limitations of one-at-a-time changes are
established; this is not new sensitivity theory ([Saltelli and Annoni, 2010](https://doi.org/10.1016/j.envsoft.2010.04.012)).
Testing expected relations under input transformations is established
metamorphic testing ([Chen, Cheung and Yiu, 1998](https://www.cse.ust.hk/~scc/publ/CS98-01-metamorphictesting.pdf)).
The contribution here is a bounded, explicitly authored, replay-verifiable
withdrawal contract in this compiler.

A group rationale is an author claim, not an independently established premise.
Joint cells need not be independent scientific assumptions; this is not a test
of interactions between independently warranted biological premises. Counts are
encoding- and manifest-dependent, not confidence percentages. Neither changed
nor unchanged selection establishes semantic robustness, source validity,
causality, clinical usefulness, novelty or superiority. There are no independent
human pilots or biological experiments in this evaluation. Temporal admission,
positive/failed/ambiguous controls, independent custody, scoring and human
scientific utility remain separate unresolved gates.
