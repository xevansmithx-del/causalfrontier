# Biomedical toolbelt probe and first historical benchmark

**Probe date:** 2026-08-28  
**ToolUniverse CLI:** `tu 1.4.1`  
**Mode:** read-only discovery and retrieval; no patient-level data, intervention, material action, or external write

## Capability inventory

Catalog discovery found callable families for PubMed, ClinicalTrials.gov, Open Targets, LINCS/L1000, EpiGraphDB Mendelian randomization, and GWAS Catalog. Match counts were search-relevance counts, not evidence-coverage claims.

Representative interfaces:

- `PubMed_search_articles` and `PubMed_get_article`
- `ClinicalTrials_search_studies` and `ClinicalTrials_get_study`
- `OpenTargets_get_associated_targets_by_disease_efoId` and `OpenTargets_get_evidence_by_datasource`
- `LINCS_search_signatures`
- `EpiGraphDB_get_mendelian_randomization`
- `GWAS_search_associations_by_gene`

Tool availability proves infrastructure feasibility only. It does not validate source semantics, historical completeness, causal interpretation, or CausalFrontier.

## Selected positive control

**Question:** Using only evidence knowable by `2012-12-31T23:59:59Z`, should the next discriminating action be a sufficiently powered cardiovascular outcomes trial of pharmacologic PCSK9 inhibition added to standard lipid-lowering care?

**Why this case:** Pre-cutoff human genetics and early intervention trials supported LDL lowering, while the later FOURIER trial supplies a clear held-out cardiovascular outcome. It tests temporal leakage, surrogate-versus-clinical branching, safety branching, and the difference between lifelong genetic variation and finite pharmacologic intervention.

This is a hindsight-defined positive control, not proof of prospective performance.

## Pre-cutoff evidence candidates

- Human genetics: PMID [`16554528`](https://pubmed.ncbi.nlm.nih.gov/16554528/), DOI `10.1056/NEJMoa054013`. The abstract reports lower LDL-C and lower coronary-heart-disease risk for PCSK9 variants. This is association evidence and does not prove that a drug reproduces lifelong loss of function.
- Phase 1/2 evolocumab/AMG 145 evidence: PMIDs [`23083772`](https://pubmed.ncbi.nlm.nih.gov/23083772/), [`23129602`](https://pubmed.ncbi.nlm.nih.gov/23129602/), [`23141813`](https://pubmed.ncbi.nlm.nih.gov/23141813/), [`23141812`](https://pubmed.ncbi.nlm.nih.gov/23141812/), and [`23128163`](https://pubmed.ncbi.nlm.nih.gov/23128163/).
- Registered early trials include `NCT01375751`, `NCT01380730`, `NCT01375777`, and `NCT01375764`.

Allowed inputs must be independently shown to have been public by the cutoff. Current aggregate target scores, current MR rows, current GWAS rows, and current LINCS metadata are capability/context probes only unless an immutable dated snapshot is available. A current aggregate cannot be filtered backward into a historical fact.

## Held-out evidence

- FOURIER registration: [`NCT01764633`](https://clinicaltrials.gov/study/NCT01764633), started in February 2013.
- Primary publication: PMID [`28304224`](https://pubmed.ncbi.nlm.nih.gov/28304224/), DOI `10.1056/NEJMoa1615664`.

The retrieved publication reported approximately 59% LDL-C reduction versus placebo, a primary composite endpoint hazard ratio of 0.85, and a key secondary endpoint hazard ratio of 0.80. The trial was industry funded; funding belongs in the receipt. These outcomes are withheld from the 2012 input package.

## Required predeclared branches

1. No LDL-C reduction: target engagement, exposure, dose, or modality failure.
2. LDL-C reduction without cardiovascular-event reduction: surrogate or translation hypothesis weakened; do not call the target clinically validated.
3. Event reduction with offsetting serious harm: net benefit unresolved.
4. LDL-C and event reduction with acceptable safety: advance the bounded hypothesis while requiring replication and guarding against population overgeneralization.
5. Contradiction, retrieval failure, semantic no-call, and open residual remain distinct branches.

## Failure semantics observed during the probe

- An OpenGWAS resolver returned HTTP 500 while a direct MR call succeeded. Resolver failure is not evidence absence.
- A clinical-trial outcome extractor returned a success envelope but no usable numeric result. Transport success is not semantic completeness.
- An evolocumab LINCS request timed out. Timeout means indeterminate, not “no signatures exist.”
- Open Targets and GWAS responses were truncated or paginated.
- PubMed exposed query rewriting and an ignored phrase; submitted and executed queries must both be sealed.
- ClinicalTrials.gov returned a large protocol record without structured numeric outcomes; downstream projections must retain the raw-response digest.
- Simvastatin LINCS signatures are adjacent lipid-lowering context, not PCSK9 evidence or a clinical predictor.

## Receipt contract required before historical scoring

Every source receipt must bind:

- tool name and version;
- canonical submitted arguments and executed query, including rewrites;
- retrieval timestamp and raw-response SHA-256;
- stable source identifiers and locators;
- publication, registration, update, and immutable snapshot dates as separate fields;
- pagination totals, truncation, and coverage state;
- entity mappings and experimental context such as population, comparator, endpoint, model, cell line, dose, and duration;
- funding/conflict metadata where applicable; and
- retrieval state and semantic usability as separate enums.

Historical scoring must fail closed without an independently checkable knowledge date. The current case schema records these concepts but labels them `DECLARED_TEMPORAL_METADATA_UNATTESTED`; it is therefore ineligible for historical scoring.

## Next controls

The PCSK9 case must be paired with at least one failed-translation case and one genuinely ambiguous case. Otherwise a system can win by recommending the experiment that history makes obvious. Case selection, allowed receipts, outcome classifiers, and scoring must be hash-committed before held-out outcomes are opened.
