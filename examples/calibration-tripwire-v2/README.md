# Calibration Tripwire V2: public-metadata rehearsal

This checked-in example exercises CausalFrontier V2 end to end on three known-hindsight therapeutic-translation
histories. It is a **structural rehearsal**, not a recovered scientific method, prospective benchmark, clinical tool, or
scientific result.

The entrant sees only cutoff-bounded public-metadata cards and opaque identifiers. The sorted blinded order is
remdesivir, PCSK9, then verubecestat; the hidden roles therefore do not use the canonical positive/failed/ambiguous
position. After the submission is sealed, a nonce-bound opening supplies these fixed protocol observations:

| History | Cutoff | Structured action | Opened coordinate | Fixed successor |
|---|---:|---|---|---|
| PCSK9 before FOURIER | 2012-12-31 | `PROPOSE_FALSIFICATION` | `COMPLETE / CONFIRMED / BENEFIT / CONSISTENT` | `ADVANCE_FALSIFICATION` |
| Verubecestat before EPOCH readout | 2016-11-03 | `REQUEST_INFORMATION` | `COMPLETE / CONFIRMED / HARM / CONSISTENT` | `STOP_FOR_SAFETY` |
| Remdesivir before ACTT | 2020-02-20 | `REQUEST_INFORMATION` | `COMPLETE / UNKNOWN / UNKNOWN / INSUFFICIENT` | `NO_CALL` |

The role-hidden view excludes FOURIER, post-cutoff verubecestat registry versions, ACTT, abstracts, full text, patient
rows, and treatment recommendations. Each source card says exactly what it is: a steward-authored current metadata
reconstruction. Its date is a declared ordering field, not independent custody of historical bytes.

## Layout

- `entrant-root/` — exact role-hidden manifest and twelve public-metadata cards.
- `external-zones/` — view lock, submission, seal, opening, rubric, declared adjudication, and final report.
- `opening-sources/` — digest-bound, post-cutoff metadata cards; the validator does not independently classify them.
- `toolbox/` — bound diagnostic traces for ToolUniverse, GraceGraph, GraceLoop, and CausalFrontier. V2 deliberately
  records them as `DECLARED_ARTIFACT_BOUND_NOT_REPLAYED`.
- `checkpoints.json` — exact local raw-byte hashes. It is not an independent timestamp or rollback witness.
- `generate_example.py` — deterministic, offline generator and verifier.

Regenerate from the repository root:

```bash
.venv/bin/python examples/calibration-tripwire-v2/generate_example.py
```

Replay the focused test:

```bash
.venv/bin/python -m pytest tests/test_calibration_v2_example.py -q
```

## Source boundary

The entrant metadata maps to public records including
[PMID 16554528](https://pubmed.ncbi.nlm.nih.gov/16554528/),
[PMID 23113833](https://pubmed.ncbi.nlm.nih.gov/23113833/),
[PMID 23141813](https://pubmed.ncbi.nlm.nih.gov/23141813/),
[DOI 10.1126/scitranslmed.aad9704](https://doi.org/10.1126/scitranslmed.aad9704),
[NCT01739348](https://clinicaltrials.gov/study/NCT01739348),
[NCT01953601](https://clinicaltrials.gov/study/NCT01953601),
[PMID 28659436](https://pubmed.ncbi.nlm.nih.gov/28659436/),
[PMID 32020029](https://pubmed.ncbi.nlm.nih.gov/32020029/),
[PMID 32054787](https://pubmed.ncbi.nlm.nih.gov/32054787/),
[NCT04252664](https://clinicaltrials.gov/study/NCT04252664), and
[NCT04257656](https://clinicaltrials.gov/study/NCT04257656).

The opening cards cite later public metadata, but their coordinates remain steward declarations. The local report must
and does retain `method_recovery_pass=false`, `controls_semantically_verified_n=0`,
`independent_semantic_adjudication_verified=false`, and `scientific_claim_ready=false`.

Nothing here provides patient advice, clinical or human-decision authority, privacy certification, wet-lab or material
authority, permission to execute a study, publication authority, or evidence that any approach saves lives.
