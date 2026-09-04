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
- an OpenSSL 3.x executable on `PATH` whose resolved executable is a regular
  file with exactly one hard link (`st_nlink == 1`)

The complete automated matrix is currently CI-verified on Ubuntu only. The
macOS instructions below are a source-tree usability pilot, not a claim of
verified platform support. Stock macOS `/usr/bin/openssl` reports LibreSSL and
does not satisfy the OpenSSL 3.x contract. Conda, mamba, and pixi commonly
hard-link package files into environments, so their otherwise valid OpenSSL 3
binary can have `st_nlink > 1` and will be rejected intentionally: another
hard-link name could mutate a binary after its digest was checkpointed.

Prefer an inode-distinct system installation, such as Homebrew OpenSSL 3 on
macOS, and put its actual `bin` directory first on `PATH`:

```bash
PATH="$(brew --prefix openssl@3)/bin:$PATH"
export PATH
```

When conda, mamba, or pixi is active, keep the Python environment active but
put a non-conda OpenSSL 3 installation first on `PATH`. On macOS, use the
Homebrew command above. On Linux, use an operating-system OpenSSL 3 package and
its real executable path. Do not copy or relink the conda-family binary as a
workaround: CausalFrontier itself snapshots only the executable bytes into a
private directory and strips loader-related environment variables before
replay, so binaries that require environment-relative libraries are
incompatible. If the preflight below fails and no external OpenSSL 3 is
available, stop and report the environment as unsupported rather than
weakening the verifier.

The pinned engine step below performs a bounded preflight inside the same locked
`uv run` context as the tests. Do not execute an unverified candidate merely to
inspect its version.

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

The only eligible engine for this pilot is the following exact development
commit. It is not a stable or archived release. Packaged release `v0.1.0a2` is
explicitly excluded: it is internally self-consistent but is not aligned with
the current source-tree example or this guide. Do not substitute a tag, branch,
or newer commit for the pinned engine revision:

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

Do not continue unless the setup block prints `Setup ready`. Now validate and
snapshot the exact OpenSSL resolved inside the locked environment, then replay
only its private byte copy through CausalFrontier's bounded subprocess runner:

```bash
uv run --frozen --no-sync python - <<'PY'
import hashlib
import os
import pathlib
import shutil
import stat
import tempfile

from causalfrontier import attestation

found = shutil.which("openssl")
if found is None:
    raise SystemExit("OpenSSL 3.x is not on PATH inside the locked environment")
path = pathlib.Path(found).resolve(strict=True)
try:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size > attestation.MAX_OPENSSL_BYTES
            or before.st_mode & 0o111 == 0
        ):
            raise SystemExit("OpenSSL must be a bounded, executable, single-link regular file")
        digest = hashlib.sha256()
        total = 0
        remaining = attestation.MAX_OPENSSL_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(remaining, 65536))
            if not chunk:
                break
            digest.update(chunk)
            total += len(chunk)
            remaining -= len(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
except OSError:
    raise SystemExit("OpenSSL candidate cannot be read safely") from None
if (
    total > attestation.MAX_OPENSSL_BYTES
    or total != before.st_size
    or (before.st_size, before.st_mtime_ns, before.st_ctime_ns, before.st_nlink)
    != (after.st_size, after.st_mtime_ns, after.st_ctime_ns, after.st_nlink)
):
    raise SystemExit("OpenSSL candidate changed during the bounded digest read")
expected = digest.hexdigest()
try:
    snapshot, snapshot_digest = attestation._read_openssl_binary(path, expected)
    with tempfile.TemporaryDirectory(prefix="causalfrontier-openssl-preflight-") as temporary:
        root = pathlib.Path(temporary)
        replay = root / "openssl-verifier"
        config = root / "openssl.cnf"
        (root / "empty-cert-directory").mkdir(mode=0o700)
        attestation._write_private(replay, snapshot)
        replay.chmod(0o500)
        attestation._write_private(config, attestation.OPENSSL_CONFIG)
        version = attestation._run_openssl(
            replay,
            ["version"],
            "preflight version inspection",
            root,
            config,
        ).strip()
except (OSError, attestation.CausalFrontierError):
    raise SystemExit(
        "OpenSSL binary cannot be replayed in isolation; use an external "
        "non-conda OpenSSL 3 installation"
    ) from None
if attestation.OPENSSL_VERSION.fullmatch(version) is None:
    raise SystemExit(f"unsupported isolated OpenSSL version: {version}")
print(f"openssl_path={path}")
print(f"openssl_sha256={snapshot_digest}")
print(f"openssl_version={version}")
print("openssl_nlink=1")
print("openssl_isolated_replay=pass")
PY
```

Do not continue unless the preflight prints `openssl_isolated_replay=pass`.
The setup block's final `false` returns a failing status without terminating an
interactive parent shell.

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
| OpenSSL preflight | 0 | OpenSSL 3.x; resolved executable is recorded; `openssl_nlink=1`; `openssl_isolated_replay=pass` |
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
