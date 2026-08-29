# Dynamic workflow and persistent-memory contract

## Purpose

The workflow keeps the fixed problem stable while allowing evidence adapters, causal worlds, experiment proposals, tests, and benchmarks to evolve. History is append-only: a new result or correction creates a successor artifact and ledger event; it never rewrites a prior case.

## State model

```text
DISCOVER
  -> FREEZE_RECEIPTS
  -> AUTHOR_INDEPENDENTLY
  -> RECONCILE_DISAGREEMENTS
  -> COMPILE
  -> ADVERSARIAL_VERIFY
  -> HASH_COMMIT_CHALLENGE
  -> SCORE_HELD_OUT
  -> APPEND_CHECKPOINTED_EVENT
  -> BACKUP
  -> SELECT_NEXT_MILESTONE
```

Any temporal uncertainty, semantic incompleteness, open authority gate, classifier ambiguity, memory-head mismatch, privacy concern, or contradiction routes to `ABSTAIN_OR_NEW_CASE`, not an inferred scientific result.

## Four bound identities

Every evaluated run must bind four independent identities:

1. **Evidence identity:** immutable receipt inventory and raw-response digests.
2. **Case identity:** evidence cutoff, decision, declared worlds, gates, experiments, total branch matrix, and nonclaims.
3. **Compiler identity:** source manifest, package version, runtime, and test result.
4. **Memory identity:** capsule manifest, ledger genesis, current external head, event count, and exact backup digest.

If any identity changes, the run is a new version. “Latest” is never inferred from a locally valid chain.

## External checkpoint rule

The capsule ledger is append-only inside SQLite but locally unauthenticated. Every append therefore requires the prior head from persistent memory outside the capsule. After a successful append:

1. verify the capsule against the supplied prior head;
2. compare-and-swap append exactly one typed event;
3. replay every event semantically;
4. verify against the returned new head;
5. append that head and event count to the external project memory; and
6. make an exact, integrity-checked backup before the next transition.

A mismatch stops the workflow. Recovery restores the last exact backup, verifies it against the independently stored checkpoint, and then resumes. Neither the private project memory nor its backup belongs in a public repository.

## Weekly dynamic cycle

The active weekly heartbeat performs one bounded, safe iteration:

- verify repository, release, capsule, external memory head, and backup health;
- scan primary sources and competing systems for changes relevant to the fixed parameter;
- run temporal-leakage, privacy, authority, branch-totality, and hostile-input gates;
- choose one highest-information milestone from the public roadmap;
- implement and test only read-only software or public/synthetic evidence work;
- append an evidence-backed result, failure, or abstention to persistent memory;
- update the external checkpoint and exact backup; and
- report what changed, what remains unvalidated, and the next kill gate.

It does not issue patient advice, execute an experiment, manipulate biological materials, use patient-level data, order anything, or publish a new scientific claim automatically. Public releases require a separate reviewed release gate.

## Current milestones

1. Freeze a complete `receipt.v1` contract with immutable temporal attestation.
2. Extend the completed synthetic digest-bound classifier to independently attested public receipts and retain exactly-one-branch boundary tests.
3. Prospectively commit the PCSK9 positive control, a failed-translation control, and an ambiguous control before opening outcomes.
4. Measure independent-encoder agreement and publish disagreements, not only reconciled cases.
5. Compare selection with expert, retrieval, graph-ranking, random, and simple-rule baselines.
6. If historical gates pass, preregister a small prospective, read-only challenge with independent domain reviewers.

## Stop conditions

Pause the dynamic workflow and request review if:

- the fixed parameter would change;
- a step needs clinical, human, legal, biological, or material authority;
- only mutable or retrospectively contaminated evidence is available;
- an external checkpoint or exact backup cannot be verified;
- a requested action would expose private memory or sensitive data; or
- evidence supports a result claim beyond the software's measured scope.
