# External source-tree reproduction pilot

## Purpose

This walkthrough lets an unfamiliar user test one pinned development-source
revision on synthetic data and report failures. It binds the instructions and
the tested engine as separate immutable objects. It tests source-tree
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

## Bind the instructions being evaluated

Clone the repository revision that contains this guide. If a reviewer or issue
supplies a specific full commit, set `CAUSALFRONTIER_GUIDE_REF` to that commit
before running the block; otherwise the fetched default-branch head is used.
Record both the resolved commit and this file's digest. A moving branch name is
not a sufficient identifier.

```bash
cf_sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    return 127
  fi
}
cf_sha256_check() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum --check "$1"
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 -c "$1"
  else
    return 127
  fi
}
cf_select_guide_ref() {
  if [ -n "${CAUSALFRONTIER_GUIDE_REF:-}" ]; then
    git checkout --detach "$CAUSALFRONTIER_GUIDE_REF"
  else
    :
  fi
}
if guide_parent=$(mktemp -d) &&
   guide_parent=$(cd "$guide_parent" && pwd -P) &&
   [ -n "$guide_parent" ] &&
   [ "${guide_parent#/}" != "$guide_parent" ] &&
   [ "$guide_parent" != "/" ] &&
   touch "$guide_parent/.causalfrontier-guide-root" &&
   guide_root="$guide_parent/repository" &&
   git clone https://github.com/xevansmithx-del/causalfrontier.git \
     "$guide_root" &&
   cd "$guide_root" &&
   cf_select_guide_ref &&
   guide_status=$(git status --porcelain) &&
   [ -z "$guide_status" ] &&
   guide_revision=$(git rev-parse HEAD) &&
   guide_sha256=$(cf_sha256 docs/independent-reproduction.md) &&
   [ "${#guide_sha256}" -eq 64 ] &&
   manifest_guide_sha256=$(
     awk '$2 == "docs/independent-reproduction.md" {print $1}' \
       SOURCE_SHA256SUMS.txt
   ) &&
   [ "$guide_sha256" = "$manifest_guide_sha256" ] &&
   cf_sha256_check SOURCE_SHA256SUMS.txt; then
  printf 'Guide ready\nrevision=%s\nsha256=%s\n' \
    "$guide_revision" "$guide_sha256"
else
  printf 'Guide binding failed; stop here. Temporary root: %s\n' \
    "${guide_parent:-not-created}" >&2
  false
fi
```

The unique destination prevents a failed clone from falling through to a stale
checkout. Do not continue unless the block prints `Guide ready`. Record the two
printed identifiers. The ready marker means the checkout was clean, the
independently computed guide digest matched its source-freeze row, and the
complete source freeze passed.

Keep this checkout as the instruction checkout. The engine is tested in a
separate detached worktree so that the guide revision is not confused with the
engine revision.

## Reproduce the pinned/tested development baseline from source

The current V2 engine baseline is the following exact development commit. It is
not a stable or archived release:

```bash
if guide_root=$(pwd -P) &&
   [ -n "$guide_root" ] &&
   [ "${guide_root#/}" != "$guide_root" ] &&
   [ "$guide_root" != "/" ] &&
   reproduction_root=$(mktemp -d) &&
   reproduction_root=$(cd "$reproduction_root" && pwd -P) &&
   [ -n "$reproduction_root" ] &&
   [ "${reproduction_root#/}" != "$reproduction_root" ] &&
   [ "$reproduction_root" != "/" ] &&
   [ "$reproduction_root" != "$guide_root" ] &&
   touch "$reproduction_root/.causalfrontier-reproduction-root" &&
   git worktree add --detach "$reproduction_root/engine" \
     1995cf7379523c952dc19f56fdc01b15a9212583 &&
   cd "$reproduction_root/engine" &&
   uv sync --frozen --extra dev; then
  printf 'Setup ready in %s\n' "$reproduction_root"
else
  if [ -n "${reproduction_root:-}" ] &&
     [ "${reproduction_root#/}" != "$reproduction_root" ] &&
     [ "$reproduction_root" != "/" ] &&
     [ -f "$reproduction_root/.causalfrontier-reproduction-root" ] &&
     [ ! -e "$reproduction_root/engine" ]; then
    rm "$reproduction_root/.causalfrontier-reproduction-root" &&
      rmdir "$reproduction_root"
  fi
  printf '%s\n' 'Setup failed before the synthetic workflow; stop here.' >&2
  false
fi
```

Do not continue unless the block prints `Setup ready`. The final `false`
returns a failing status without terminating an interactive parent shell.

Capture the environment before running the tool:

```bash
git rev-parse HEAD
uv --version
uv run --frozen --no-sync python --version
uv run --frozen --no-sync causalfrontier --version
```

Run the smallest complete synthetic workflow:

```bash
uv run --frozen --no-sync causalfrontier analyze examples/synthetic-aggregate
uv run --frozen --no-sync causalfrontier classify examples/synthetic-aggregate
uv run --frozen --no-sync causalfrontier compile \
  examples/synthetic-aggregate "$reproduction_root/engine/capsule"
uv run --frozen --no-sync causalfrontier verify \
  "$reproduction_root/engine/capsule"
```

Then run the offline test suite:

```bash
uv run --frozen --no-sync pytest \
  --disable-socket --allow-unix-socket \
  --cov=causalfrontier --cov-report=term-missing --cov-fail-under=80
```

The engine checkout's source freeze should also verify:

```bash
sha256sum --check SOURCE_SHA256SUMS.txt
```

On macOS, use `shasum -a 256 -c SOURCE_SHA256SUMS.txt` if GNU
`sha256sum` is unavailable.

## Golden software-output contract

For the pinned engine revision, compare the exit status and named fields below.
Do not substitute a visually similar value. The guide digest is specific to the
revision and must match the guide checkout's own source-freeze row rather than a
value copied from another revision.

| Step | Expected exit | Expected output |
|---|---:|---|
| Guide `git status --porcelain` | 0 | No output |
| Guide source-freeze check | 0 | Every file reports `OK`; guide digest matches its manifest row |
| Engine `git rev-parse HEAD` | 0 | `1995cf7379523c952dc19f56fdc01b15a9212583` |
| `uv sync --frozen --extra dev` | 0 | Locked environment sync completes |
| `causalfrontier --version` | 0 | CLI version `0.1.0a5` |
| `analyze` | 0 | Embedded compiler version `0.1.0a4`; `run_id`/`analysis_sha256` `84346c5eecebbfdeb5909e26535ed5661b655a840fe2cd0c0a64a0d78d379c4d` |
| `classify` | 0 | `results_sha256` `2c9ddf255dca69aa14c756f3bdd253e2769af03d772fbbfee0419f6e70feb188` |
| `compile` | 0 | `manifest_sha256` `03ba39c0193d0e9b9447a72996e8c56aadfffd3c7506e2d4583d59e6eedfc2ee` |
| `verify` | 0 | The same `manifest_sha256`; status `SELF_CONSISTENT_UNAUTHENTICATED_PROTOTYPE` |
| Offline test suite | 0 | 873 tests pass; total coverage is at least 80% |
| Engine source-freeze check | 0 | Every file reports `OK` |

The CLI/dependency identity and the embedded compiler identity are deliberately
reported separately. None of these synthetic software markers is a scientific
result.

## Optional cleanup

After recording the requested outputs, return to the guide checkout and remove
only the marked temporary worktree created above. `--force` is required because
the locked environment, capsule, and test artifacts are intentionally untracked.

```bash
if [ -n "${guide_root:-}" ] &&
   [ "${guide_root#/}" != "$guide_root" ] &&
   [ "$guide_root" != "/" ] &&
   [ -n "${reproduction_root:-}" ] &&
   [ "${reproduction_root#/}" != "$reproduction_root" ] &&
   [ "$reproduction_root" != "/" ] &&
   [ "$reproduction_root" != "$guide_root" ] &&
   [ -f "$reproduction_root/.causalfrontier-reproduction-root" ] &&
   [ -d "$reproduction_root/engine" ]; then
  if cd "$guide_root" &&
     git worktree remove --force "$reproduction_root/engine" &&
     rm "$reproduction_root/.causalfrontier-reproduction-root" &&
     rmdir "$reproduction_root"; then
    printf '%s\n' 'Cleanup complete; current directory is the guide checkout.'
  else
    printf '%s\n' 'Cleanup stopped after a command failed.' >&2
    false
  fi
else
  printf '%s\n' \
    'Cleanup aborted: temporary paths or marker did not validate.' >&2
  false
fi
```

The unique guide checkout is intentionally retained so its recorded revision
and digest remain available while the public report is prepared. This cleanup
block does not remove that evidence-bearing checkout.

## What to record

Record the exact guide commit and digest, engine commit, environment, exit
statuses, expected output identifiers, first failure, elapsed time, and
documentation ambiguities. State any prior project contribution, collaboration,
or author assistance. The public issue is an account-attributed self-report; it
does not authenticate identity or independence.

Submit the result through the repository's **External source-tree
reproduction** issue template. A failed environment sync or confusing
instruction is valuable evidence; do not silently work around it.

## Success criteria

A structural reproduction succeeds only when all of the following are true:

- the source tree syncs into its locked development environment without an
  undocumented step;
- the recorded guide revision and digest match the instructions actually used;
- the four synthetic workflow commands complete with their documented status;
- capsule verification replays successfully;
- the offline tests pass at or above the declared coverage floor; and
- the reviewer can explain, in their own words, what the output does and does
  not claim.

Success here is a self-declared source-tree usability result. It does not
validate a release and cannot promote any scientific or clinical gate.
