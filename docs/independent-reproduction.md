# Independent reproduction walkthrough

## Purpose

This walkthrough lets an unfamiliar user verify the public software interface
on synthetic data and report every failure. It tests installation,
documentation, deterministic compilation, and capsule replay. It does not test
biological validity, causal truth, prospective timing, clinical utility, or
scientific impact.

Use no patient-level, private, restricted, or wet-lab data. Do not upload
credentials or sensitive logs to a public issue.

## Prerequisites

- Git
- [uv](https://docs.astral.sh/uv/)
- a supported CPython runtime (3.10 through 3.14)
- a POSIX-like shell for the commands below

## Reproduce the development tree

Clone the repository and pin the exact revision being reviewed:

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

Record the exact commit, operating system, architecture, Python and uv versions,
each command's exit status, the first unexpected output, elapsed setup time, and
any place where the documentation required interpretation. Do not report a run
as independent if an author or prior contributor performed the commands for
you.

Submit the result through the repository's **Independent reproduction** issue
template. A failed installation or confusing instruction is valuable evidence;
do not silently work around it.

## Success criteria

A structural reproduction succeeds only when all of the following are true:

- the locked environment installs without an undocumented step;
- the four synthetic workflow commands complete with their documented status;
- capsule verification replays successfully;
- the offline tests pass at or above the declared coverage floor; and
- the reviewer can explain, in their own words, what the output does and does
  not claim.

Success here is a software-usability result. It cannot promote any scientific or
clinical gate.
