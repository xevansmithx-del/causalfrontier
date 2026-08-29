# Validation record

Validated locally on 2026-08-28. This record covers software behavior and the synthetic fixture only.

## Results

| Check | Result |
|---|---|
| Minimum runtime | Python 3.10.20: 77 passed and `compileall` pass |
| Main runtime | Python 3.13.13: 77 passed |
| Pytest | 77 passed on each validated runtime |
| Statement coverage | 85% (85.19% exact) on each validated runtime |
| Package, API, and compiler version | `0.1.0a2` exact |
| Ruff 0.16.5 | Check and format pass |
| Normal assertion-independent probe | Pass |
| `python -O` assertion-independent probe | Pass |
| Normal/optimized run and verification parity | Exact |
| Digest-bound classifier replay | Three of three exact synthetic results |
| Capsule build and semantic replay | Pass |
| External memory-head rollback test | Pass |

Frozen synthetic fixture result:

```text
run_id 0a28022c6e31be13d09a57a3d5bdddfc644962740e032183f441827572faf7c0
verification_sha256 4f3935331642c4699aa18378df4834a1d45ecdb54a0d59ec6cf318ca0374a3f5
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
uv lock --check
uv run --frozen --no-sync pytest --disable-socket --allow-unix-socket \
  --cov=causalfrontier --cov-report=term-missing --cov-fail-under=80
uv run --frozen --no-sync python -m compileall -q src tests
uv run --frozen --no-sync ruff check .
uv run --frozen --no-sync ruff format --check .
uv run --frozen --no-sync python tests/optimized_probe.py
uv run --frozen --no-sync python -O tests/optimized_probe.py
```

Publication CI additionally builds the wheel and source distribution, runs `twine check`, installs artifacts in clean environments, validates the repository-scoped source manifest, scans allowlisted text for private material, and executes the installed CLI. Release artifacts receive a separate SHA-256 manifest.

## Supported-marker lock audit

`uv.lock` requires Python 3.10 or later and has no Python 3.9-only resolution branch.
The supported lock graph contains one unmarked entry for each audited package:

| Package | Locked version | Required floor | Result |
|---|---:|---:|---|
| cryptography | 50.0.1 | 50 | Pass |
| setuptools | 84.0.0 | 83 | Pass |
| urllib3 | 2.7.0 | 2.7 | Pass |
| pytest | 9.1.1 | 9.0.3 | Pass |
| requests | 2.34.2 | 2.33 | Pass |
| filelock | 3.32.4 | 3.20.3 | Pass |

No entry below these GitHub-reported advisory thresholds remains in a supported
marker. These packages belong to the locked development and publication environment;
the installable CausalFrontier package continues to have zero runtime dependencies.

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
