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
