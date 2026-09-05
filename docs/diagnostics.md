# Local prerequisite and runtime diagnostics

These commands belong to the development source containing `doctor` and the
global `--error-format` option. They are not available in packaged release
`v0.1.0a2` or the older engine pinned by the
[source-tree reproduction pilot](independent-reproduction.md). Keep that pilot's
instructions and engine identity intact; record any run of these new commands
as a separate development-source diagnostic.

## Check local prerequisites

From an already prepared, locked development environment:

```bash
uv run --frozen --no-sync causalfrontier doctor
```

The default command executes no OpenSSL candidate. It checks CPython 3.10–3.14,
required POSIX capabilities, a temporary synthetic file through the production
descriptor readers, and a simple in-memory SQLite query. It checks whether
`PATH` contains an OpenSSL candidate but reports only a boolean. When the other
checks pass, the result is `INCOMPLETE`, exit `3`, with
`OPENSSL_CHECKPOINT_REQUIRED`. A prerequisite failure instead returns `BLOCKED`,
exit `2`.

To include the OpenSSL check, select an executable you already trust and supply
its separately preserved lowercase SHA-256 checkpoint. Replace both quoted
placeholders below; do not use the example values literally:

```bash
uv run --frozen --no-sync causalfrontier doctor \
  --openssl-binary '/absolute/path/to/trusted/openssl' \
  --expected-openssl-sha256 '<64-lowercase-hex-checkpoint>'
```

Both options are required together. The verifier safely reads a bounded,
executable regular file with one hard link, checks its bytes against the caller's
digest, and executes a private copy with the production subprocess limits and
environment. It checks the copied executable's OpenSSL 3.x version response and
rereads the copy afterward. Loader-relative conda-family binaries can fail this
replay even when they run in their original environment. Preserve the failure;
use an independently trusted compatible installation for a new attempt.

The digest binds bytes. It does not establish executable provenance, provide a
sandbox, or independently authenticate an OpenSSL implementation. Doctor-owned
code requests no network access or package installation, but the selected
executable's side effects are **not monitored**. The report states
`subprocess_side_effects: "NOT_MONITORED"`; it does not certify an offline or
side-effect-free subprocess.

## Interpret the environment report

Doctor emits `causalfrontier.environment-report.v1` JSON on standard output:

| Status | Exit | Meaning |
|---|---:|---|
| `READY_FOR_LOCAL_VERIFICATION` | 0 | Every implemented prerequisite probe passed, including the caller-checkpointed executable replay |
| `BLOCKED` | 2 | At least one prerequisite probe failed; inspect that check's `reason_code` |
| `INCOMPLETE` | 3 | No probe failed, but at least one required check was not run |

Each row in `checks` names the check, its `PASS`, `FAIL`, or `NOT_RUN` status,
and a `reason_code`. Failure rows may also include `operation` and numeric
`errno`. A successful OpenSSL row includes its byte digest, numeric version,
`caller_checkpoint_matched: true`, and `independent_trust_verified: false`.

The report also records distribution version and the runtime's Python,
implementation, system, architecture, and SQLite version. Its scope is
`LOCAL_PREREQUISITES_ONLY`. The fields `scientific_validation`,
`release_validation`, and `independent_reproduction` remain `false`.

Passing this probe does not run the synthetic scientific workflow, the test
suite, capsule replay, a memory backup check, or biomedical analysis. Follow the
appropriate source-specific verification instructions afterward.

## Request machine-readable runtime errors

Place the global option **before the subcommand**:

```bash
uv run --frozen --no-sync causalfrontier --error-format json \
  analyze examples/synthetic-aggregate
```

For caught runtime `CausalFrontierError`, `OSError`, and `ValueError` exceptions,
the command exits `2` and writes `causalfrontier.error.v1` JSON to standard error.
The fields are `schema_version`, `reason_code`, `operation`, and `errno`.
`operation` and `errno` may be `null`. Messages, filenames, paths, exception text,
and subprocess output are omitted from this error envelope.

The default is `--error-format text`, which retains human-readable error text.
The option does not change successful output schemas. It also does not convert
argument-parser errors, missing arguments, or an invalid subcommand to JSON.
Existing command results such as a returned `INVALID` verification report keep
their own schemas and output streams; they are not caught runtime exceptions.
Callers must inspect the exit status and the relevant report schema.

Common diagnostic meanings include:

| Reason code | Interpretation |
|---|---|
| `ENVIRONMENT_DENIED` | The operating system reported an access or permission denial |
| `INPUT_MISSING` | A required filesystem object was not found |
| `SAFE_PATH_REJECTED`, `SAFE_FILE_REJECTED` | A path or file failed the implemented access contract |
| `INPUT_CHANGED`, `INVENTORY_MISMATCH` | A read changed or an inventory failed its expected binding |
| `IO_FAILURE` | Another operating-system I/O failure occurred |
| `OPENSSL_CHECKPOINT_REQUIRED` | The explicit executable/checkpoint pair is missing or incomplete |
| `OPENSSL_VERSION_UNSUPPORTED` | The isolated response did not satisfy the accepted version contract |
| `SUBPROCESS_TIMEOUT`, `SUBPROCESS_NONZERO_EXIT` | The bounded executable replay timed out or exited unsuccessfully |
| `VALIDATION_REJECTED` | A validation rejection without a more specific code; this includes some checkpoint failures |

These codes describe software observations. Missing input is not absence of
biomedical evidence; a path rejection does not establish malicious intent; an
execution failure does not classify a biological hypothesis.

## Record and share a diagnostic

Record the exact source commit and source-manifest digest independently of the
report, which does not bind them. From the checkout being evaluated:

```bash
git rev-parse HEAD
git status --porcelain
shasum -a 256 SOURCE_SHA256SUMS.txt
shasum -a 256 -c SOURCE_SHA256SUMS.txt
```

Use `sha256sum` instead of `shasum -a 256` where appropriate. Preserve any dirty
status or manifest failure in the record. Also retain the invocation, exit
status, report, and any prior workaround. A branch name alone is insufficient
to identify the source tested.

Sharing a report is optional and manual. The built-in environment report omits
local paths and arbitrary executable output, but its runtime details and binary
digest form a potentially identifying fingerprint. It is not anonymous. Review
any attachment before posting; parser errors and ordinary text logs may expose
paths or supplied arguments. If a shared copy is redacted, label it as a
derivative and preserve the original separately. No report upload is performed.

For historical biomedical retrieval context, see the
[ToolUniverse probe](tooluniverse-probe.md). That record documents a previous
capability check and receipt requirements, not a diagnostic of the current
ToolUniverse installation.
