# First-slice benchmark contract

## Purpose

The bundled `synthetic-aggregate` fixture tests software behavior, not biology. It represents a tiny aggregate perturbation-response table with three contexts, two interventions, one response index, and one negative-control index. All values are invented integers. There are no people, samples, sequences, compounds, pathogens, or material instructions.

The evidence file is frozen at:

```text
evidence/aggregate_response.tsv
SHA-256 e0035faad7a9ade27d6d6e259e338208d68cec0ce4211361ad9b92e9b3dea627
```

## Declared worlds

The fixture contains three operationally exclusive worlds:

1. the aggregate response is invariant enough to keep a mechanism-oriented read-only check eligible;
2. the response is primarily explained by context-linked confounding; and
3. a residual explanation outside the named model set.

The residual maps only to defer. The other worlds map to one substantive read-only lane plus defer.

These relations are authored declarations. The compiler binds and analyzes them but does not derive them from the table.

## Discriminators

| Identifier | Read-only protocol | Resource distinction | Expected status |
|---|---|---|---|
| `experiment:held-out-invariance` | Apply an authored frozen contrast rule to the held-out row | Shorter, one external dependency | Structural Pareto/conditional-minimax co-winner |
| `experiment:negative-control` | Apply an authored control/context rule | Longer, zero external dependencies | Structural Pareto/conditional-minimax co-winner |
| `experiment:global-recompute` | Recompute all context contrasts | More expensive on every dimension than held-out check | Dominated |

Every discriminator has two informative branches plus contradiction, execution failure, and no-call. Its prediction matrix has exactly 15 cells: three worlds by five outcomes.

## Frozen expected result

With CausalFrontier `0.1.0a1`, the exact baseline run identifier is:

```text
80fd18eade206f90efe8f30bfcd6e3cecb18d0474591b119b26cbba4b5153d9d
```

The structurally-admissible-unexecuted and conditional-scientific-structure Pareto frontiers both contain:

```text
experiment:held-out-invariance
experiment:negative-control
```

Both are informative-branch-conditional minimax co-winners. The held-out experiment is displayed first only because its identifier sorts first. No scientific preference is inferred from that ordering. Each classifier is executable and digest-bound for this synthetic TSV, but its thresholds and mapping remain authored and have no biological calibration.

## Hostile benchmark cases

The automated suite must continue to reject or detect:

- duplicate JSON keys and floating-point fields;
- prior, posterior, and observed-outcome leakage;
- an edited branch plan under an old digest;
- a missing outcome class or prediction cell;
- an informative branch that removes the residual;
- a failure branch that changes world state;
- a contradiction that removes the open residual or regenerates the invalidated frontier;
- multiple residual worlds;
- clinical authority inside the alpha boundary;
- source digest drift and unmanifested files;
- source semantic/data-class mismatches and omitted gate or source authorities;
- post-hoc outcome identifiers;
- capsule analysis tampering;
- removed ledger append-only triggers; and
- a locally rolled-back ledger checked against an independently preserved head;
- a forged or discontinuous counterfactual branch path; and
- decision-selection changes caused only by duplicating an equivalent world;
- an attempt to overwrite an existing capsule.

The normal and `python -O` probes must produce the same run identifier and frontier. The probe contains no `assert` statements, so optimization cannot erase its checks.

## Benchmark ladder after the first slice

The next evaluation should add, in order:

1. three independently encoded public-aggregate biomedical cases;
2. duplicate blinded encodings to measure author-dependence;
3. extend the digest-bound executable classifier contract from the completed synthetic slice to independently attested public evidence;
4. adversarial case authors attempting post-hoc leakage;
5. versioned corrections that supersede rather than mutate old cases; and
6. a prospectively hash-committed historical challenge with a positive, failed-translation, and ambiguous control; and
7. only after those pass, a prospective benchmark designed and reviewed by domain experts.

No step in this ladder grants clinical authority. Any real biological or health-impact claim requires separate empirical validation and governance.
