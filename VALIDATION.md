# Validation record

Validated locally on 2026-08-28. This record covers software behavior and the synthetic fixture only.

## Results

| Check | Result |
|---|---|
| Minimum runtime | Python 3.9.6: 77 passed and `compileall` pass |
| Main runtime | Python 3.13.13: 77 passed |
| Pytest | 77 passed on each validated runtime |
| Statement coverage | 85% (85.19% exact) on each validated runtime |
| Ruff 0.16.5 | Check and format pass |
| Normal assertion-independent probe | Pass |
| `python -O` assertion-independent probe | Pass |
| Normal/optimized run and verification parity | Exact |
| Digest-bound classifier replay | Three of three exact synthetic results |
| Capsule build and semantic replay | Pass |
| External memory-head rollback test | Pass |

Frozen synthetic fixture result:

```text
run_id 80fd18eade206f90efe8f30bfcd6e3cecb18d0474591b119b26cbba4b5153d9d
verification_sha256 42ce7ec9d516f83d68b625e6966d646c49303b41230eaf5d0f87ac01418807a6
structurally_admissible_unexecuted experiment:held-out-invariance, experiment:negative-control
classifier_results_sha256 dd052e01cdd4d9f3102f61dbdf11bedf822f0bdacf927c2983734e30cb68c15a
```

The executable synthetic classifier returns:

| Experiment | Branch token | Outcome |
|---|---|---|
| `experiment:global-recompute` | `LOW` | `outcome:global-invariant` |
| `experiment:held-out-invariance` | `LOW` | `outcome:held-invariant` |
| `experiment:negative-control` | `HIGH` | `outcome:control-tracks-context` |

These are deterministic classifications of invented integers under authored thresholds, not biological results.

## Commands

```bash
uv sync --frozen --extra dev
uv run --frozen --no-sync pytest --disable-socket --allow-unix-socket \
  --cov=causalfrontier --cov-report=term-missing --cov-fail-under=80
uv run --frozen --no-sync python -m compileall -q src tests
uv run --frozen --no-sync ruff check .
uv run --frozen --no-sync ruff format --check .
uv run --frozen --no-sync python tests/optimized_probe.py
uv run --frozen --no-sync python -O tests/optimized_probe.py
```

Publication CI additionally builds the wheel and source distribution, runs `twine check`, installs artifacts in clean environments, validates the repository-scoped source manifest, scans allowlisted text for private material, and executes the installed CLI. Release artifacts receive a separate SHA-256 manifest.

## Hostile coverage

The suite covers:

- duplicate keys, floats, malformed types, timestamps, enum values, and prior/result leakage;
- incomplete outcome partitions and prediction matrices;
- residual removal, contradiction invalidation, and failure/no-call state preservation;
- source digest, inventory, symlink, hardlink, semantic-state, temporal, gate, and authority failures;
- classifier digest drift, post-validation source-byte drift, non-bijective outcome mapping, non-distinct role columns, header drift, duplicate cells, undeclared interventions, missing or extra groups, deterministic malformed-input and incomplete-evidence precedence, valid-measurement contradictions, and adjacent numeric boundaries;
- decision-world refinement bias and strict `SURVIVES`/`EXCLUDES` separation;
- post-hoc branches and wrong branch-plan digests;
- capsule tampering, nested control-name collisions, destination-inside-source attempts, coherently rehashed classifier-result forgery, manifest/case/genesis mismatch, trigger removal, forged semantic events, and overwrite attempts;
- sequential branch lineage, contradiction stop, and rollback detected by an independent head checkpoint; and
- normal versus optimized execution parity.

## Scope

This validates deterministic compilation, the built-in synthetic classifier, exact local file binding, prior-free structural comparison, capsule replay, and checkpointed counterfactual memory.

It does not validate causal correctness, author-declared totality/exclusivity, biological predictions, source dates or licenses, historical tool receipts, clinical usefulness, or health impact. Prospective benchmark cases scored remain zero; experiments executed remain zero; clinical, human, and material authority remain false.
