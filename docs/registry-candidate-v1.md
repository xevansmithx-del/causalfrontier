# Registry-candidate assessment v1

## Purpose

This local, unreleased boundary answers one narrow question before a challenge can
enter any future registry: are differently named synthetic cases exact structural
duplicates under a bounded, label-invariant comparison?

The current six-case fixture uses three submitted domain labels and all three
control labels, but every case was built by copying the same frozen decision
problem. Label balance is therefore not scientific diversity. The assessment turns
that discovered failure into a machine-enforced rejection while preserving all
larger admissibility questions as `NO_CALL`.

This is a **registry-candidate assessment**, not a registry. It performs no write,
accepts no separately designated outcome, reveal, opening, oracle, or score channel,
and can never emit `REGISTERED`, `PROSPECTIVE`, `ADMITTED`, a winner, or a
scientific score. It does read arbitrary frozen case text and source bytes, which
could themselves encode outcome information; content-level outcome isolation is
therefore explicitly `NO_CALL`.

## Bound inputs

The command consumes four read-only artifact roles plus caller-preserved exact
checkpoints:

```bash
causalfrontier assess-registry-candidate \
  CHALLENGE_ROOT RACE_SPEC ENTRANT_VIEW NONCE_FILE \
  --expected-manifest-sha256 CHALLENGE_MANIFEST_SHA256 \
  --expected-sequence CHALLENGE_SEQUENCE \
  --expected-race-spec-sha256 RACE_SPEC_SHA256 \
  --expected-view-sha256 ENTRANT_VIEW_CHECKPOINT_SHA256 \
  --expected-nonce-sha256 NONCE_CHECKPOINT_SHA256
```

A structurally valid assessment exits `3`, including a v1 collision rejection.
Malformed, substituted, non-replayed, or unsafe input exits `2`.

The implementation:

1. replays the complete challenge and both encoder lanes;
2. checks the race-specification checkpoint through the sanitized-view builder;
3. safely reads and validates the exact entrant-view checkpoint;
4. safely reads the exact 32-byte nonce checkpoint;
5. regenerates the entrant view and requires canonical equality;
6. compares cases without using case, domain, control, organization, encoder,
   action, source, world, option, gate, outcome, or lane IDs;
7. repeats the complete input replay before returning; and
8. validates an exact aggregate report schema and its hash before emission; and
9. emits only a steward report with aggregate class sizes and pair counts, never a
   case-to-fingerprint or steward-to-entrant mapping.

The caller checkpoints establish exact bytes only. They do not prove that the
values were independently stored, existed before an outcome, or are current.
Patient-level data and material action are prohibited and outside this tool's
declared scope, but a synthetic label and bounded pattern screen do not certify the
content-level absence of patient data; privacy certification remains `NO_CALL`.

## Layered comparison

A single composite hash is unsafe: a clone could change it with an irrelevant
source, cosmetic timestamp, tariff nudge, or renamed field. V1 therefore evaluates
six separate layers.

| Layer | Preserved | Deliberately ignored |
|---|---|---|
| `STEWARD_FULL` | decision-critical source bytes and states; decision/world/option/gate/action/outcome/prediction incidence; exact operational classifier schema/selectors/scalars; authorities; resources | opaque entity IDs, ordering, labels, prose, paths, queries, timestamps, ID-sensitive digests |
| `CAUSAL_TOPOLOGY` | the same causal structure plus the three operational classifier roles, intervention roles, rule kind, and numeric thresholds | literal headers/group/arm tokens, inert non-role column names and counts, source-byte hashes, experiment resources, and presentation fields |
| `EXECUTION_CONTRACT` | causal structure, classifier scalar contract, and experiment resources | source-byte hashes and presentation fields |
| `DECISION_CRITICAL_EVIDENCE` | exact byte hashes and semantic/acquisition states for sources actually referenced by worlds, predictions, or classifiers | unused sources and presentation fields |
| `ALL_EVIDENCE` | the same exact identity fields for every source | source IDs, paths, prose, timestamps, and ordering |
| `ENTRANT_GEOMETRY` | case budget, action tariffs, lane/action eligibility, co-minimax incidence, required replicates, and policy contract | every nonce-derived alias, opaque binding, and alias-sensitive projection digest |

An exact `STEWARD_FULL` match is a v1 structural collision and rejects the
candidate pending semantic review. It is not called a definite semantic clone:
decision questions and protocol prose are intentionally excluded because v1 cannot
canonicalize their meaning. An irrelevant unused source or race-tariff-only
perturbation cannot evade this collision because the full steward graph uses the
decision-critical evidence and authored experiment contract. A match in only one
non-entrant layer remains unresolved and blocks any independence inference. This
includes coherent relabeling of operational TSV headers, group names, and arm names:
the exact execution contract changes, but normalized causal topology still matches.
Entrant geometry alone never rejects a case because genuinely distinct scientific
questions may intentionally share a standardized interface.

Different fingerprints or graphs mean only that v1 did not verify an exact match.
They do not establish semantic or domain independence.

## Exact graph rule

Each encoder lane becomes a colored, directed, edge-labeled multigraph. Node colors
retain typed intrinsic state; edges retain direction, label, and multiplicity. The
two lane graphs are compared as an unordered multiset so swapping encoder labels
does not change case identity.

Color refinement is used only to prune candidates. A match is reported only after
a bounded backtracking search finds a complete attribute- and edge-preserving
bijection. Input IDs never change graph colors or the equality predicate, but the
bounded implementation uses internal IDs to break otherwise symmetric search ties.
A bijective relabeling can therefore degrade an available `true` result to
`NO_CALL` under the fixed work budget; it cannot turn an isomorphism into `false`
or a no-collision pass. If graph construction or exact search exceeds a fixed size,
state, or work limit, the assessment returns `NO_CALL_CANONICALIZATION_LIMIT`;
refinement equality alone is never called identity.

This is exact representation-level isomorphism under the declared normalization,
not scientific ontology matching. Synonyms, equivalent equations, equivalent code,
or semantically identical data with different bytes remain outside v1.

## Result states

The possible state transition is deliberately one-way and no-write:

```text
CHALLENGE_PREFLIGHTED
  -> REGISTRY_CANDIDATE_ASSESSED
       -> REJECTED_V1_STRUCTURAL_COLLISIONS_REVIEW_REQUIRED
       -> NO_CALL_STRUCTURAL_SIMILARITY
       -> NO_CALL_CANONICALIZATION_LIMIT
       -> NO_V1_STRUCTURAL_COLLISION_FOUND_NOT_REGISTERED
```

All four results retain:

- `candidate_registered=false`;
- `registration_write_performed=false`;
- `designated_outcome_input_accepted=false`;
- `content_outcome_isolation_verified=false`;
- `semantic_cohort_uniqueness_verified=false`;
- `domain_independence_verified=false`;
- `encoder_independence_verified=false`;
- `store_independence_verified=false`;
- `temporal_admissibility_verified=false`;
- `prospective_registration_verified=false`;
- `privacy_certified=false`; and
- `scientific_scoring_ready=false`.

Artifact integrity, branch totality, synthetic/software authority, absence of a
separately designated outcome channel, and exact race/view/nonce replay can pass.
Content-level outcome isolation, domain and control validity, encoder/store
independence, governance, privacy certification, currentness, prospective timing,
and scientific scoring remain `NO_CALL`.

## Current falsification result

The bounded six-case fixture produces one verified equivalence class of size six in
every layer. All 15 cross-case pairs are exact matches, so the candidate state is
`REJECTED_V1_STRUCTURAL_COLLISIONS_REVIEW_REQUIRED`. This falsifies the fixture as a six-case,
three-domain scientific cohort. It does not falsify the integrity plumbing the
fixture was originally designed to exercise.

The deterministic normal, optimized, and alternate-hash-seed probe emits identical
bytes. Its current exact output SHA-256 is
`81ce04968c1cc1813f988f9b4ff89a9b0a70a0b62f4c15b54dd6424d36110956`.

## What is still required

The next scientific-design milestone is not a looser duplicate rule. It is a small
sentinel cohort with independently authored generators, at least one genuinely
different decision structure per declared domain, a policy-neutral common input,
and an independent terminal-oracle interface. Positive, failed-translation, and
ambiguous roles must not be confounded with domain. That cohort must pass this
screen without weakening branch totality, privacy, provenance, or authority gates.

Only a later reviewed system with append-only registry persistence, independently
anchored time/currentness, external custody, conflict-of-interest rules, domain
review, outcome-provider commitments, and a frozen analysis plan could perform a
prospective registration. This implementation supplies none of those authorities.
