# Evidence-fit evaluation: additional AI review and disposition

On 8 September 2026, Anthropic Claude Science reviewed a sealed public-source
packet targeting commit
[`46a90676bd7279bf513ce62037a96b130abf726d`](https://github.com/xevansmithx-del/causalfrontier/commit/46a90676bd7279bf513ce62037a96b130abf726d),
tree `9c074a9b126c59c824d49a4e569ac054c2c10ca1`. The interface displayed
**Opus 5** and saved **Reasoning effort Max**. The reviewer identified itself as
`claude-opus-5`; the exact backend build was not independently preserved.

## Exact review scope

The supplied ZIP contained all 1,163 tracked repository files, a separate request
and a seal manifest. The reviewer verified the file hashes and Git blob/tree
identities, replayed the finite evaluation in normal and optimized Python, and
implemented its own selected projection from the protocol. It reported no
substantive projection disagreement across the 132 cases. It also checked the
three inventories, six semantic controls and the manuscript's checkable factual
claims. Its saved verdict was a bounded pass with two low-severity findings and
no blocker for that stated scope: 35 passing and two failing checklist items.
These are review checklist counts, not independent scientific replications.

Science used system CPython 3.11.15 with a usable temporary directory and the
normal script import path. It did not execute the locked `uv` environment, run
the full repository suite or inspect every source line. Sealing every file is
not equivalent to reviewing every file's behavior. The review does not cover
later changes merely because they belong to the same pull request.

| Preserved review object | Bytes | SHA-256 |
|---|---:|---|
| Submitted public ZIP | 2,359,954 | `c19d2319cb5a7938b9c1f564fad89ed9573afc48cdbc574bb617c544e51bfbe0` |
| Original review Markdown | 23,784 | `50379a064ebb4622338859b79a5cc254f7a15b5dbcacd17badc2d47247fc39fb` |
| Original findings JSON | 18,998 | `8efe381d8a7aaf19a90e245ccc3fbb59605be4e7e46b85aa5fe84988168ef7a3` |
| Reconciliation addendum | 9,273 | `6e019dc3c395f48a64b61786b25d50509de50712f823e5bed6bb3acbb90e0b97` |

The original downloaded artifacts are retained unchanged in the owner's review
records. This public note reports their checked disposition without publishing
private session history or unrelated project material.

## Findings and disposition

| Finding | Checked disposition |
|---|---|
| F-1: filesystem failures collapse into evidence-fit input rejection | Accepted. Fault injection reproduced loss of the operational reason and `errno` in both audit and verification, including a wrapped receipt error. The correction preserves structured, path-free operational diagnostics while retaining generic rejection for invalid evidence. |
| F-2: frozen preservation-field and protocol wording are too broad | Accepted. The [additive erratum](../../evaluation/evidence-fit-v1/ERRATA.md) scopes preservation to sources represented by audited records. The original protocol, field name and results remain frozen; no output is renamed retrospectively. |
| F-3: this review requires an AI-use entry | Added a dated row to [AI_USAGE.md](../../AI_USAGE.md). |
| F-4: citation metadata lacks the recorded affiliation | Added the already recorded affiliation to [CITATION.cff](../../CITATION.cff). No ORCID was supplied or invented; applicable final metadata remains open. |
| F-5: lexical dates rely on one fixed format | The erratum states the fixed UTC whole-second precondition. There was no observed error in this design, so the frozen comparator remains unchanged. |

## Qualifications to the original review

The local source-based check agrees with the substantive findings, with four
qualifications. The standard case has 21 source-bound date fields in its input
and seven in its single report row; fourteen remain input-only. The review's
“20 of 21” value-equality count is not a source-identity preservation count.
The complete Git diff between the stated base and reviewed head contains 943
changed paths; the review's 300-path summary is incomplete.

Identical prerequisite blobs and Git ancestry establish content continuity and
ancestry at review time, not when a commit was pushed or when an evaluation was
executed. The original operator sequencing record remains an operator record.
Finally, incomplete whole-record status exposes missing declarations; it does
not detect concealed semantic falsity or guarantee correct consumer behavior.
The reviewer confirmed all four qualifications in a separately saved addendum,
while preserving the original artifacts. It corrected its date count and the
GitHub comparison API cap, withdrew the stronger chronology wording, and
confirmed that concealed-meaning records share the same incomplete status and
reason as the ordinary matching control. Its bounded verdict did not change.
The addendum did not review the subsequent correction or repeat the original
execution checks.

## Distinguishable follow-up and reproducibility

The diagnostic correction changes current source. The retained v1 evaluation
continues to target its original source and is not relabeled as an evaluation
of that correction. Its four frozen protocol/program files and all 927 result
files are preserved. A sealed UTF-8 JSON snapshot supplies the original 41 prerequisite
files to a separate replay wrapper, which checks identities before invoking the
original runner. A separate current-API compatibility check compares complete
reports with the retained reports. See the [commands and interpretation](../../evaluation/evidence-fit-v1/README.md).

This additional review and its follow-up are AI-assisted software checks. They
do not establish independent human review, semantic or biological validity,
novelty, practical superiority, journal readiness or final author approval.


## Separate correction audit at `5891227`

The same existing Science session, with Opus 5 and Max reasoning reverified,
subsequently audited correction commit
[`5891227c96cffb7f575c1582bef7dc42d8a2a5f4`](https://github.com/xevansmithx-del/causalfrontier/commit/5891227c96cffb7f575c1582bef7dc42d8a2a5f4),
tree `8ce9b184da3056274603dc8f3aefbd0893de3393`. Its separately saved verdict
was **bounded pass: 62 passing checklist items, three informational observations,
zero confirmed defects and no blocker within the audited scope**. These counts
measure its audit checklist, not scientific replication or an exhaustive audit.

| Preserved correction-review object | Bytes | SHA-256 |
|---|---:|---|
| Submitted public ZIP | 2,712,404 | `06b854d59657b114172c2efdb9f92d6b08c1483cdb38a37b656f64e9cd6242c4` |
| Correction review Markdown | 26,463 | `db8904c5ceb332593c5e18ccae687b8dde90f029cabc6b772061a9f080b0b891` |
| Correction findings JSON | 30,244 | `0eca211894f4bf85495dfeef8d2711fbe85ba683873a8c4d0e3f66e6a38c9933` |

Science independently checked all 1,171 payload hashes and Git blob identities,
reconstructed the tree, compared the full 18-path correction diff, and verified
preservation of the original four program/protocol files and 927 results. It
executed original-source replay and current-API compatibility normally and under
`-O`, directly reproduced and verified all 132 current reports with its own
harness, exercised operational faults and tampering, and ran the 59 new focused
tests. Its direct probes confirmed the sanitized diagnostic categories and
continued generic rejection for the tested malformed inputs, unsafe paths and
unknown wrapped categories. Those probes are bounded evidence, not a guarantee
about all possible errors, hosts or consumer behavior.

The review used system CPython 3.11.15 with a usable temporary directory and
normal script import path. It did not run the full repository suite or the
locked `uv` environment, rederive the original selected projection in this round,
or inspect every line of the changed modules. It corrected its own early probe
setup errors before reporting results. It found the prior disposition faithful.

| Informational observation | Disposition |
|---|---|
| C-1: the seal sidecar is descriptive, not a runtime input | Clarified in the evaluation README. Runtime enforcement uses fixed script digests and the original run-manifest bindings; tests cross-check the sidecar. No executable change was requested or made. |
| C-2: verification's own outer operation label was not reached by its probes | No correction required. Nested audit/receipt failures retain the operation where classification occurred. An unreached defensive branch was not proven dead. |
| C-3: the old frozen runner refuses current source with an exit-1 traceback | Named explicitly in the erratum. This is preserved original behavior; use the documented replay wrapper. The frozen runner was not rewritten. |

Separate local validation at `5891227` passed 1,290 offline tests in normal
Python and 1,290 under `-O`, with 88.23% normal statement coverage. All ten hosted
checks passed on that exact commit. A fresh remote readback matched all 1,171
payloads. The no-Git source archive verified all 1,170 source-manifest entries,
then passed original replay and current-API compatibility in both modes. A fresh
installed wheel, with isolated imports verified, matched and verified all 132
reports and passed 27 bounded operational fault probes in both modes. These are
separate operator/software checks, not results executed by Science.

A separate consolidation check found an outdated branch-plan digest in the
main README's simulation and rehearsal-append examples. The old simulation
command reproduced exit 2; both examples now use a variable read from the
supplied case artifact. The documented simulation, append and subsequent
verification succeeded against a disposable capsule, preserving a separate
checkpoint captured from compilation before the append. This check did not
change source or examples and was not part of the Science audit above.

This closing section, the new AI-use row, the C-1/C-3 explanatory sentences
and a separately checked README rehearsal-command correction were added after
Science reviewed `5891227`. Its audit does not cover those later prose edits. The executable source, tests, transport and all original
results remain unchanged; later CI and source hashes belong to their own commit.
No result here establishes independent human review, semantic or biological
validity, practical superiority, journal readiness or final author approval.
