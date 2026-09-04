# External source-tree reproduction pilot

## Purpose

This walkthrough lets an unfamiliar user test one pinned development-source
revision on synthetic data and report failures. It tests source-tree
environment setup, documentation, deterministic compilation, and capsule
replay. It does not install or validate a packaged or archived release, and it
does not test biological validity, causal truth, prospective timing, clinical
utility, or scientific impact.

Use no patient-level, private, restricted, or wet-lab data. Do not upload
credentials or sensitive logs to a public issue.

## Prerequisites

- Git
- [uv](https://docs.astral.sh/uv/)
- a supported CPython runtime (3.10 through 3.14)
- a POSIX-like shell for the commands below

## Reproduce the reviewed engine baseline from source

The current V2 engine baseline is the following exact development commit. It is
not a stable or archived release:

```bash
git clone https://github.com/xevansmithx-del/causalfrontier.git
cd causalfrontier
git checkout 1995cf7379523c952dc19f56fdc01b15a9212583
uv sync --frozen --extra dev
```

Capture the environment before running the tool:

```bash
git rev-parse HEAD
uv --version
uv run --frozen --no-sync python --version
uv run --frozen --no-sync causalfrontier --version
```

Run the smallest complete synthetic workflow:

```bash
reproduction_root=$(mktemp -d)
uv run --frozen --no-sync causalfrontier analyze examples/synthetic-aggregate
uv run --frozen --no-sync causalfrontier classify examples/synthetic-aggregate
uv run --frozen --no-sync causalfrontier compile \
  examples/synthetic-aggregate "$reproduction_root/capsule"
uv run --frozen --no-sync causalfrontier verify "$reproduction_root/capsule"
```

For this pinned revision, `analyze` must report `run_id`
`84346c5eecebbfdeb5909e26535ed5661b655a840fe2cd0c0a64a0d78d379c4d`,
and `classify` must report `results_sha256`
`2c9ddf255dca69aa14c756f3bdd253e2769af03d772fbbfee0419f6e70feb188`.
These are synthetic software-output checks only.

Then run the offline test suite:

```bash
uv run --frozen --no-sync pytest \
  --disable-socket --allow-unix-socket \
  --cov=causalfrontier --cov-report=term-missing --cov-fail-under=80
```

The checked-in source freeze should also verify:

```bash
sha256sum --check SOURCE_SHA256SUMS.txt
```

On macOS, use `shasum -a 256 -c SOURCE_SHA256SUMS.txt` if GNU
`sha256sum` is unavailable.

## What to record

Record the exact commit, environment, exit statuses, expected output
identifiers, first failure, elapsed time, and documentation ambiguities. State
any prior project contribution, collaboration, or author assistance. The public
issue is an account-attributed self-report; it does not authenticate identity or
independence.

Submit the result through the repository's **External source-tree
reproduction** issue template. A failed environment sync or confusing
instruction is valuable evidence; do not silently work around it.

## Success criteria

A structural reproduction succeeds only when all of the following are true:

- the source tree syncs into its locked development environment without an
  undocumented step;
- the four synthetic workflow commands complete with their documented status;
- capsule verification replays successfully;
- the offline tests pass at or above the declared coverage floor; and
- the reviewer can explain, in their own words, what the output does and does
  not claim.

Success here is a self-declared source-tree usability result. It does not
validate a release and cannot promote any scientific or clinical gate.
