# ADR-001: Frozen causal challenge compiler with append-only rehearsal memory

**Status:** Accepted for pre-alpha evaluation  
**Date:** 2026-08-28  
**Decision authority:** Software prototype only

## Context

Biomedical evidence often arrives as incompatible measurements, narrative claims, partial negative results, and proposed next experiments. A tool that simply aggregates these artifacts can make uncertainty look smaller without identifying what evidence would actually separate causal explanations.

The first CausalFrontier slice needs to test a narrower proposition: can a machine verify that an author froze the evidence, competing worlds, outcome branches, authority boundary, and resource trade-offs *before* seeing a result, then identify nondominated discriminators without invented probabilities?

The alpha must remain useful when every named world is wrong, when a computation fails, when a result contradicts the entire model set, or when no call can be made.

## Decision

Use a separate, standard-library Python package with four explicit layers:

| Layer | Responsibility | Authority ceiling |
|---|---|---|
| Case validator | Exact schema, source inventory/digests, world and outcome totality, frozen branch digest | Documentary/software |
| Frontier compiler | Counterfactual survivor sets, Pareto dominance, epistemic minimax tie set | Software |
| Capsule verifier | No-clobber build, immutable manifest, exact replay | Software |
| Event ledger | Append-only compilation and counterfactual-rehearsal history | Software |

The case partition is labelled `DECLARED_MUTUALLY_EXCLUSIVE_COLLECTIVELY_EXHAUSTIVE_WITH_RESIDUAL`. Exactly one residual world is mandatory and may map only to defer. This does not prove nature is partitioned correctly or that the authored worlds are truly exclusive; it guarantees the compiler never silently treats named worlds as exhaustive.

Every experiment declares a total outcome partition containing at least one branch in each class:

| Class | Required compiler behavior |
|---|---|
| `INFORMATIVE` | Apply only the predeclared survivor relation; residual remains `UNKNOWN` |
| `CONTRADICTION` | Exclude the named partition, retain only the residual, clear selection, and require a new case |
| `FAILURE` | Preserve every active world and report execution failure |
| `NO_CALL` | Preserve every active world and report no call |

Classifier syntax and data-contract violations—including malformed integers, duplicate cells, undeclared interventions, and undeclared extra groups—map to `FAILURE`. `CONTRADICTION` is reserved for a schema-valid measurement that violates the frozen prediction contract; malformed input cannot invalidate the named causal partition.

Each world/outcome cell is present exactly once. A registered classifier contract maps every runtime token to exactly one outcome, and separate SHA-256 digests bind the classifier and complete branch plan. Capsule build executes the classifier on its exact frozen source and verification re-executes it. Rehearsal accepts only an experiment, outcome, and branch-plan digest already present in the frozen case.

## Alternatives considered

### Extend GraceGraph only

This would reuse provenance and authority concepts, but graph closure is not a causal discriminator policy. Adding world partitions, total branches, and minimax semantics there would blur the distinction between claim-state compilation and experiment discrimination.

### Extend GraceLoop only

This would reuse most frontier concepts, but CausalFrontier is testing a broader evidence-to-falsification contract with self-contained case capsules and integrated persistent memory. A separate package prevents the experimental schema from changing GraceLoop's sealed alpha contract.

### Learned end-to-end causal model

A learned model could eventually propose worlds and predictions, but the first slice would be impossible to audit and easy to overclaim. This option remains a future component behind the same frozen case boundary; generated relations must never be presented as verified causal evidence.

## Selection algorithm

For each informative outcome, the compiler calculates the effective survivor set. Failure and no-call preserve the active set; contradiction invalidates the named partition. Selection uses decision-equivalence classes so duplicating a world with the same decision disposition cannot improve a discriminator. Each experiment exposes:

- conditional worst informative-branch remaining decision-class count;
- conditional minimax decision-class reduction;
- guaranteed and possible strictly separated decision-class pairs; and
- a five-dimensional integer resource declaration.

Dominance requires no-worse performance on every epistemic and resource dimension and strict improvement on at least one. The minimax display choice is selected only within that Pareto set. If several experiments share the same epistemic minimax tuple, all are returned as co-winners and resource differences remain unscalarized. Because failure and no-call yield zero reduction, this is explicitly `INFORMATIVE_BRANCH_CONDITIONAL_MINIMAX`, not true all-outcome minimax.

No probabilities, priors, likelihoods, posteriors, weights, utilities, expected values, or scalar scores are accepted.

## Persistent-memory contract

Each capsule contains a SQLite ledger with:

- immutable metadata;
- contiguous event sequence numbers;
- canonical JSON payloads;
- a SHA-256 chain over the previous digest, timestamp, event type, subject, and payload;
- database triggers rejecting updates and deletes; and
- replay verification of typed event payloads.

The first event binds the case digest, analysis digest, and run identifier. Every append requires the current ledger head supplied from an independent checkpoint. Rehearsal events bind predecessor and successor run IDs, active-world sets, and case states, so a later rehearsal continues the previous branch path rather than restarting from baseline. There is deliberately no event type for an empirical observation.

The ledger is locally self-consistent, not authenticated. Its digest chain detects corruption, but a database owner can rewrite or roll back the whole chain. Only comparison with an independently preserved head detects rollback; the returned head must replace that checkpoint after a successful append.

## Threat model

The validator is designed to fail closed against:

- hidden or post-hoc outcome branches;
- missing world/outcome prediction cells;
- removal of the residual world;
- information updates on failure or no-call branches;
- satisfied clinical, human, legal, biological, or material authority gates;
- source digest drift and unmanifested files;
- duplicate JSON keys, floating-point values, and prior-like fields;
- overwritten capsule destinations;
- immutable analysis or source tampering; and
- event mutation, removed append-only triggers, and rollback relative to an externally supplied head.

It does not defend against a dishonest author who declares misleading worlds, relations, dates, privacy classes, licenses, coverage, thresholds, or resource integers. The synthetic branch mapping is executable, but scientific totality and exclusivity remain authored. Independent receipts, calibrated adapters, prospective commitments, and external review are required before this can support scientific conclusions.

## Consequences

What becomes easier:

- reproducing exactly why a discriminator appeared on a frontier;
- exposing model-set contradiction without retroactive branch creation;
- preserving negative/no-call history; and
- comparing heterogeneous next checks without a hidden scalar utility.

What becomes harder:

- authors must enumerate a complete outcome partition in advance;
- open-world residuals often prevent a single decisive conclusion;
- resource comparisons remain tied when dimensions conflict; and
- updating any frozen input requires a new case version.

These costs are intentional for the alpha. If real cases cannot satisfy them, the representation should be killed or redesigned rather than weakened silently.
