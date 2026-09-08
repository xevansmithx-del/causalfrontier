# The CausalFrontier evidence-fit component: replayable audits of declared aggregate-evidence compatibility

Working software-paper draft, 8 September 2026. This draft evaluates one component of the existing CausalFrontier development source. Final human review, journal fit and submission approval remain pending. Recorded author: Evan Smith, Independent Researcher, Pueblo, Colorado, USA. It has not been submitted or independently reviewed by human researchers.

## Abstract

An evidence record can be precisely cited and still be unsuitable for an intended comparison. Differences in population, endpoint, analysis set, source version, contrast direction or availability date can change what the record supports. The CausalFrontier evidence-fit component provides a source-bound audit of explicitly declared compatibility. The audit retains reported quantities and source identities, compares authored fields using three-valued literal rules, and exposes missing declarations without pooling estimates or inferring causal effects. A deterministic synthetic evaluation compares a selected projection of its output with a transparent table-rule implementation given the same information. Across 132 authored scenarios, both implementations matched all expected projected outputs. Six constructed controls distinguished literal agreement from semantic fidelity. The evaluation supports reproducible behavior on its declared finite domain; it does not establish accurate evidence extraction, independent usability or superiority to another research workflow. The implementation and evaluation are supplied as inspectable source, synthetic inputs and replayable outputs.

## Motivation and scope

Moving from a publication to a research decision involves several distinct operations. The researcher must identify a source, record the reported quantity, decide what population and outcome it describes, and determine whether those meanings fit the question being asked. Recording a source hash addresses only the first operation's byte identity. An internally consistent extraction may still misdescribe its source. Conversely, different strings may refer to an equivalent scientific concept.

This work addresses a narrow software problem: preserve that distinction while making declared incompatibilities and missing information mechanically inspectable. The evidence-fit component accepts a target and a source-bound extraction authored outside the program. It returns field-level comparisons and a replayable report. It does not retrieve publications, extract clinical findings automatically, perform semantic normalization, calculate a pooled estimate or decide whether an intervention works.

CausalFrontier's wider development tree also contains authored causal-world and branch-planning machinery. Those components are outside the present comparison. This evaluation does not execute their classifiers, admit historical controls, update causal worlds or evaluate the choice of a next experiment. The contribution examined here is the inspectable implementation and packaging of a declared compatibility contract. Literal comparison, content hashing and calendar-interval arithmetic are not presented as new methods.

## Implementation

### Inputs and binding

An evaluation request supplies a receipt directory, an extraction document and expected SHA-256 digests for the serialized receipt-set.json manifest and extraction JSON bytes. Receipt metadata identifies source records and the acquired raw responses. Each extraction record declares its receipt and source identifiers, raw-response digest, source locator, source field, study version and role. The receipt verifier checks the closed file inventory and referenced payloads; the evidence-fit layer checks the corresponding bindings and request schema. A separately supplied digest is a reproducibility checkpoint. Its existence does not authenticate the person who authored it or establish independent historical custody.

The target declares endpoint, population, intervention, comparator, timepoint, estimand, evidence kind, analysis population, counting unit and measurement unit. It also declares estimate kind and required source identities, versions and roles. A required source declared in the manifest but lacking an extraction row remains visible at the report level. Requirements referring to a receipt or source identifier absent from the manifest reject the request. Neither condition is converted into a zero effect, a missing biological phenomenon or an extra observation.

### Literal comparisons and quantities

For a compared pair of labels, either missing declaration produces `UNKNOWN`; otherwise equality produces `DECLARED_MATCH` and inequality produces `DECLARED_MISMATCH`. A missing target is not a wildcard. Comparisons also expose discrepancies in contrast labels, estimate units and declared counting populations. The complete implementation reports record consistency and numerical diagnostics in addition to the selected projection evaluated here.

Estimates retain decimal strings, reported text and confidence interval levels. Supported kind labels include hazard, risk and rate ratios and mean differences; unsupported kinds preserve reported text without inventing a numerical estimate. The audit can flag internal inconsistencies such as reversed interval bounds. It neither repairs the estimate nor determines its statistical or clinical significance. Missing counts and intervals remain missing; this is not a finding that a study is unusable.

### Dates and authority

A selected source-date field is represented by its declared precision. A year or month denotes an interval rather than an invented exact day. An interval whose upper bound is at or before the cutoff matches the declared input-date condition; an interval whose lower bound is after the cutoff mismatches; intervals crossing the cutoff and unknown dates remain unknown. The input-date condition is applied according to the target-required source role. Reveal-only and context-only sources retain temporal information without becoming historical inputs.

Every record remains historically ineligible. The report keeps scientific scoring disabled and does not grant scientific, clinical or material authority. A plausible source date or reproducible hash cannot erase known hindsight or demonstrate that the evidence was publicly available at a claimed earlier time.

### Replay and execution boundary

Report verification reconstructs the audit from the bound inputs and compares the complete report. This checks more than a report's self-hash: a modified report cannot pass merely by replacing its checksum. The implementation bounds serialized inputs, record counts and text lengths and performs no evidence retrieval or research action in the audit command. These controls establish a specified software boundary; pattern-based privacy screening is not a guarantee that arbitrary material is appropriate to publish.

## Evaluation design

The evaluation uses synthetic records derived from the already public synthetic example. Case definitions, comparison code and the protocol are committed before the complete run. This ordering makes the run reproducible under a fixed specification, but the cases were deliberately authored with knowledge of the implementation. There is no held-out sampling, independent temporal custody or blinded adjudication.

The primary comparator is a small table-rule implementation of the selected literal and date contract. It receives the same declarations and date precision as CausalFrontier. It is not a measured spreadsheet workflow or a representation of expert performance. Because both implement the same rules, exact agreement is an expected and informative possible result. The comparison does not test the baseline's ability to reproduce the engine's complete receipt validation, report-verification, numerical or security behavior.

Separate controls stipulate a semantic relationship in addition to the literal expected result. These include equivalent intended meanings with different strings and consistent strings that misdescribe an authored source. The semantic relationship is part of each artificial scenario, not a newly adjudicated biomedical truth. These controls test the interpretation of the software's output: agreement on labels must not be reported as authenticated meaning.

All generated scenarios and per-scenario outputs are retained. Results are tabulated by family; pooled counts are a census of this authored domain, not an estimate of the frequency of errors in publications. No significance test, confidence interval, human-time saving or speedup estimate is appropriate for this design.

## Results

The complete run contained 132 scenarios and 131 artificial extraction rows. One scenario deliberately omitted its required extraction row. Both implementations matched the authored expected projection in every scenario, with no paired disagreement or retained failed case.

| Scenario family | Cases | Engine / baseline agreement with authored projection |
| --- | ---: | ---: |
| Four-factor literal-label design | 81 | 81 / 81 |
| Date precision and required role | 33 | 33 / 33 |
| Missing target, record or both | 3 | 3 / 3 |
| Source versions, roles and absent extraction | 6 | 6 / 6 |
| Semantic counterexamples | 6 | 6 / 6 |
| Quantity preservation | 3 | 3 / 3 |

The four-factor design contained 324 selected label cells per implementation: 108 matched, 108 mismatched and 108 unknown, all on the expected diagonal. The one zero-record scenario was retained as a missing-source outcome and contributed no per-record cells. These counts describe the authored domain and have no sampling interpretation.

Both synonym controls produced literal mismatches despite equivalent stipulated meaning. The two concealed-meaning controls, the nonexistent source-field coordinate and the false extracted quantity retained matching selected labels. In the quantity example, the raw synthetic source reported 0.80 while the extraction supplied 0.81 within otherwise plausible interval bounds. Those matching projected fields did not make the records scientifically approved: synthetic status, missing counts and unverified meaning remained explicit in the full engine reports.

All 131 extracted records were retained exactly, including the quantity-preservation controls. All corresponding audited-source date objects and declared source-quality states were retained. Unrepresented source entries remained in the saved receipt inputs; no report rows were invented for them. Every report verified by reconstruction. Optimized-Python replay reproduced all 927 retained artifact files, totaling 3,151,054 bytes, exactly.

The four [protocol/code files](../../evaluation/evidence-fit-v1/PROTOCOL.md) were published at prerequisite [2f34b5d7279241e842e263e4dfbad5c023336d2e](https://github.com/xevansmithx-del/causalfrontier/commit/2f34b5d7279241e842e263e4dfbad5c023336d2e). The operator read the remote commit and those payloads before the full run. This is an operator sequencing record, not independent historical attestation. [Result tables, hashes and limits](../../evaluation/evidence-fit-v1/RESULTS.md) and [replay instructions](../../evaluation/evidence-fit-v1/README.md) accompany this draft. Production source was unchanged from base commit 0af3c52134434e5364f56b2b41df2f151458f9a7.

## Discussion

The fair literal comparator reproduced all selected CausalFrontier outputs. The evaluation therefore supplies no evidence of a better compatibility decision rule. The possible practical contribution would instead lie in binding inputs, retaining uncertainty and source roles, producing inspectable reports and replaying them consistently. The present experiment does not measure the practical value of those operations to researchers.

The semantic controls also show why a successful software run cannot be described as scientific validation. A syntactically valid extraction may identify a nonexistent source field or assign a misleading label. A receipt digest remains correct in both situations. Conversely, an abbreviation or equivalent phrasing may create a literal mismatch without creating a substantive incompatibility. A future system could add terminology reconciliation or source-aware extraction, but those operations would require their own error analysis and accountable review.

The synthetic domain is small and selected; its date examples do not exhaust calendar boundaries and its field examples do not exhaust all nullable declarations. It cannot establish coverage of arbitrary evidence documents, parser attacks, all numerical diagnostics or real research questions. The evaluation must therefore be read alongside the source contract and the wider test suite, with each retaining its own scope. Existing private known-source rehearsals are not silently counted as independent studies or public benchmark cases in this report.

Independent evidence extraction, workflow usability and comparative research utility remain separate questions. A later evaluation could ask researchers to encode a fixed public-source packet, record pre-reconciliation disagreements and compare complete task burden with a competent baseline. Such a study would need its own participants, protocol and evidence. It is not a prerequisite for writing this narrow software draft, and it has not been performed here.

## Availability and declarations

Software is available from the existing public [xevansmithx-del/causalfrontier repository](https://github.com/xevansmithx-del/causalfrontier) under Apache-2.0. This package uses development-source version `0.1.0a5`; it does not publish a new release or imply that the earlier packaged version includes the evaluated feature. The evaluation directory contains synthetic inputs, definitions, comparison code, outputs and replay instructions. No private source responses, patient data, sequencing archives or private project-memory records are included.

Generative AI assisted evaluation design, implementation, source checking, drafting and internal review. The repository's AI-use record identifies this assistance and its limitations. AI agents are not authors or independent human reviewers. The recorded sole human author is Evan Smith, with the affiliation stated above and a prior declaration of no external funding. His standing contribution record lists conceptualization, project administration, and writing review/editing; additional roles must reflect work he personally verifies and accepts. The final article still requires his review of the current work, applicable competing-interest wording, any required ORCID metadata, and explicit approval. This draft does not attest that those final steps have happened.

## References and related-work context

Provenance modeling and interchange are established in the W3C PROV family [1]; this implementation does not claim a tested PROV mapping. Trialstreamer identifies trial reports and extracts structured trial information [2]. It is an adjacent upstream system, whereas this component consumes already authored extractions. Open Targets integrates evidence for target identification and prioritization [3]. Work on temporal evidence within Open Targets distinguishes evidence dates and examines target novelty [4]. Neither timestamps nor source-linked evidence are new in this component. None of these platforms was run as a comparator here. This bounded positioning check does not establish priority, uniqueness or a gap that no existing system addresses.

1. Groth P, Moreau L, editors. *PROV-Overview*. W3C Working Group Note, 30 April 2013. [W3C source](https://www.w3.org/TR/2013/NOTE-prov-overview-20130430/)
2. Marshall IJ et al. Trialstreamer: A living, automatically updated database of clinical trial reports. *Journal of the American Medical Informatics Association*. 2020;27(12):1903–1912. [doi:10.1093/jamia/ocaa163](https://doi.org/10.1093/jamia/ocaa163)
3. Buniello A et al. Open Targets Platform: facilitating therapeutic hypotheses building in drug discovery. *Nucleic Acids Research*. 2025;53(D1):D1467–D1475. [doi:10.1093/nar/gkae1128](https://doi.org/10.1093/nar/gkae1128)
4. Falaguera MJ et al. Temporal trends in evidence supporting novel drug target discovery. *Nature Communications*. 2026;17:492; first published online 7 December 2025. [doi:10.1038/s41467-025-67180-y](https://doi.org/10.1038/s41467-025-67180-y)
