# Contributing

Contributions are welcome when they preserve the fail-closed structural and claim
boundaries.

1. Fork the repository and create a focused branch.
2. Do not add credentials, private paths, restricted data, raw sequences, patient
   records, or evidence without complete rights and provenance.
3. Add positive and adversarial tests for every state transition, parser boundary,
   gate, and ledger mutation.
4. Run `uv sync --frozen --extra dev`, offline tests under normal and optimized Python,
   Ruff, pre-commit, the privacy scanner, source-manifest verification, and package
   checks.
5. Submit a pull request describing the failure mode addressed and exact acceptance
   evidence.

No contribution may invent a prior, treat `UNKNOWN` as evidence, record an authored
relation as an observation, raise the prospective benchmark count, or imply causal,
clinical, laboratory, material, or human-decision authority merely because software
checks pass.
