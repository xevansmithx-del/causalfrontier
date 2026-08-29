# Security policy

## Supported versions

CausalFrontier is pre-alpha research software. Only the newest GitHub release receives
security fixes.

## Reporting

Use GitHub private vulnerability reporting for security-sensitive issues. Do not open
a public issue containing credentials, restricted datasets, private research records,
patient information, or an unpatched exploit. Ordinary correctness and documentation
issues may use the public issue tracker.

## Security boundary

CausalFrontier parses untrusted JSON and local evidence files, builds capsule
directories, and maintains a local SQLite ledger. It is designed to reject duplicate
JSON keys, non-finite numbers, unknown schema fields, unsafe paths, symlinked or
hard-linked evidence, inventory drift, branch-plan drift, malformed timestamps,
post-hoc branches, and fixed-boundary escalation.

Hashes establish byte identity, not truth, permission, independence, authorship, or
currentness. The ledger is hash-chained but not externally authenticated; rollback
detection requires an independently preserved expected head. CausalFrontier is not a
sandbox, signature system, causal-inference engine, medical device, experiment
executor, or source of clinical, laboratory, material, or human-decision authority.
