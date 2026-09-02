# Calibration tripwire source map v1

**Status:** candidate source map; semantic validity, temporal admissibility, and control behavior are not verified
**Scope:** known-hindsight biomedical calibration only; never primary or prospective performance
**Fixed parameter:** `OPEN_MACHINE_VERIFIABLE_TRANSLATION_FROM_FRAGMENTED_BIOMEDICAL_EVIDENCE_TO_NEXT_FALSIFIABLE_ACTION`

This document proposes one bounded positive, failed-translation, and ambiguous
control for testing evidence-to-falsification workflow behavior. It separates
pre-cutoff inputs from reveal-only outcomes and records the exact behavior each
role should exercise. It does not admit, score, or scientifically adjudicate any
control.

## Candidate control map

| Role | Case | Candidate knowledge cutoff | Required decision state |
|---|---|---:|---|
| `POSITIVE` | PCSK9 inhibition before FOURIER | `2012-12-31T23:59:59Z` | `NEXT_FALSIFICATION` |
| `FAILED_TRANSLATION` | BACE1 inhibition with verubecestat before EPOCH and APECS outcomes | `2016-11-03T23:59:59Z` | `REJECT_TRANSLATION` |
| `AMBIGUOUS` | Remdesivir before ACTT-1 and WHO Solidarity | `2020-02-20T23:59:59Z` | `NO_CALL` |

The cutoffs are candidate boundaries, not verified knowledge checkpoints. In
particular, the BACE1 boundary is one day after the publication date reported
for the compound-specific human target-engagement paper. It is inadmissible
until an immutable publisher, Crossref, PubMed, PMC, or archive receipt proves
the paper was publicly available by that timestamp. If the receipt gives a later
time, the cutoff must move to the first independently attested public timestamp
and the complete input inventory must be refrozen.

## Positive tripwire: PCSK9 to FOURIER

### Pre-cutoff input allowlist

- Human genetic evidence relating PCSK9 sequence variation, LDL cholesterol,
  and coronary events: [PMID 16554528](https://pubmed.ncbi.nlm.nih.gov/16554528/),
  DOI `10.1056/NEJMoa054013`.
- AMG 145 phase 1 and phase 2 evidence:
  [PMID 23083772](https://pubmed.ncbi.nlm.nih.gov/23083772/),
  [PMID 23129602](https://pubmed.ncbi.nlm.nih.gov/23129602/),
  [PMID 23141813](https://pubmed.ncbi.nlm.nih.gov/23141813/),
  [PMID 23141812](https://pubmed.ncbi.nlm.nih.gov/23141812/), and
  [PMID 23128163](https://pubmed.ncbi.nlm.nih.gov/23128163/).
- Historical versions of early trial records `NCT01375751`, `NCT01380730`,
  `NCT01375777`, and `NCT01375764` may be admitted only when their exact
  pre-cutoff bytes and public-availability dates are independently preserved.

Current database summaries, current citation graphs, and later annotations to
these records are not pre-cutoff evidence.

### Reveal-only oracle

- FOURIER registration:
  [NCT01764633](https://clinicaltrials.gov/study/NCT01764633).
- Primary report:
  [PMID 28304224](https://pubmed.ncbi.nlm.nih.gov/28304224/), DOI
  `10.1056/NEJMoa1615664`.

The current ClinicalTrials.gov record reports first submission on 2013-01-08,
first posting on 2013-01-09, and study start on 2013-02-08. These dates are after
the candidate cutoff, but a current record is not itself proof of the bytes in
an earlier registry version.

### Decision-relevant falsification target

In people with established atherosclerotic cardiovascular disease receiving
background statin therapy, does pharmacologic PCSK9 inhibition reduce time to
first cardiovascular death, myocardial infarction, stroke, hospitalization for
unstable angina, or coronary revascularization, rather than only lowering LDL
cholesterol?

The branch contract must distinguish:

1. absent LDL lowering, which implicates target engagement, exposure, dose, or
   modality;
2. LDL lowering without cardiovascular-event reduction, which weakens the
   surrogate-to-outcome translation;
3. event reduction with offsetting serious harm, which leaves net benefit
   unresolved; and
4. event reduction without a predeclared offsetting safety signal, which permits
   only a bounded transition subject to replication and population limits.

### Positive-role criterion

The tripwire recovers `NEXT_FALSIFICATION` only if the workflow selects a
sufficiently powered randomized cardiovascular-outcomes test, preserves the
genetic-versus-pharmacologic transport gap, and does not treat LDL lowering as
clinical validation. Recovering the historical outcome from model memory,
current metadata, or a reveal artifact is leakage, not method recovery.

## Failed-translation tripwire: BACE1 and verubecestat

### Pre-cutoff input allowlist

- APP A673T human genetic evidence:
  [PMID 22801501](https://pubmed.ncbi.nlm.nih.gov/22801501/), DOI
  `10.1038/nature11283`.
- Compound-specific animal and human CNS amyloid target engagement:
  [PMID 27807285](https://pubmed.ncbi.nlm.nih.gov/27807285/), DOI
  `10.1126/scitranslmed.aad9704`.
- Only cutoff-valid historical versions of the EPOCH and APECS protocols may be
  inputs. Their later status, result modules, linked publications, and derived
  references are reveal data.

EPOCH was submitted on 2012-11-29, first posted on 2012-12-03, and began on
2012-11-30. APECS was submitted on 2013-09-25, first posted on 2013-10-01, and
began on 2013-11-05. The proposed 2016 cutoff therefore defines a pre-outcome
translation and rejection challenge, not a pre-initiation trial-selection
challenge.

### Reveal-only oracle

- EPOCH:
  [NCT01739348](https://clinicaltrials.gov/study/NCT01739348),
  [PMID 29719179](https://pubmed.ncbi.nlm.nih.gov/29719179/), and
  [PMC6776074](https://pmc.ncbi.nlm.nih.gov/articles/PMC6776074/).
- APECS:
  [NCT01953601](https://clinicaltrials.gov/study/NCT01953601),
  [PMID 30970186](https://pubmed.ncbi.nlm.nih.gov/30970186/), and
  [PMC6776078](https://pmc.ncbi.nlm.nih.gov/articles/PMC6776078/).

### Decision-relevant falsification target

Does sustained BACE1 inhibition with demonstrated CNS amyloid lowering slow
clinical cognitive or functional decline versus placebo in both of these
bounded settings?

- mild-to-moderate Alzheimer disease over 78 weeks; and
- amyloid-positive prodromal Alzheimer disease over 104 weeks.

### Failed-translation role criterion

The precutoff translated expectation is that meaningful CNS amyloid target
engagement will slow the declared clinical decline. Terminal failure requires
failure of superiority on the declared clinical endpoints despite adequate
exposure and target engagement, without an operational explanation sufficient
to account for both trials.

The operational-failure exclusion must separately inspect adherence, exposure,
CNS target engagement, amyloid confirmation, missingness, endpoint completion,
stopping, and population stage. Only after those checks may the required state
be `REJECT_TRANSLATION`, bounded to:

> verubecestat-mediated amyloid lowering did not establish the declared clinical
> benefit in these populations, doses, disease stages, and time horizons.

The control must reject overtranslation without asserting that BACE1, all amyloid
biology, prevention at a different stage, or every intervention against the
pathway has been falsified.

## Ambiguity tripwire: remdesivir

### Pre-cutoff input allowlist

- SARS-CoV-2 cell-culture evidence:
  [PMID 32020029](https://pubmed.ncbi.nlm.nih.gov/32020029/) and
  [PMC7054408](https://pmc.ncbi.nlm.nih.gov/articles/PMC7054408/), DOI
  `10.1038/s41422-020-0282-0`.
- MERS-CoV rhesus-macaque evidence:
  [PMID 32054787](https://pubmed.ncbi.nlm.nih.gov/32054787/) and
  [PMC7104368](https://pmc.ncbi.nlm.nih.gov/articles/PMC7104368/), DOI
  `10.1073/pnas.1922083117`.

ACTT-1 was submitted on 2020-02-20 but was first posted and began on
2020-02-21. Its submission was not a public input at the proposed end-of-day
2020-02-20 cutoff. The exact public-availability time of every allowed paper
still requires an immutable receipt.

### Reveal-only oracle

- ACTT-1:
  [NCT04280705](https://clinicaltrials.gov/study/NCT04280705),
  [PMID 32445440](https://pubmed.ncbi.nlm.nih.gov/32445440/), and
  [PMC7262788](https://pmc.ncbi.nlm.nih.gov/articles/PMC7262788/), DOI
  `10.1056/NEJMoa2007764`.
- Global WHO Solidarity:
  [ISRCTN83971151](https://www.isrctn.com/ISRCTN83971151), interim report
  [PMID 33264556](https://pubmed.ncbi.nlm.nih.gov/33264556/), and final report
  [PMID 35512728](https://pubmed.ncbi.nlm.nih.gov/35512728/) with
  [PMC9060606](https://pmc.ncbi.nlm.nih.gov/articles/PMC9060606/), DOI
  `10.1016/S0140-6736(22)00519-0`.

`NCT04315948` currently resolves to the European DisCoVeRy record. Although the
final Solidarity report links related registrations, that identifier must not be
substituted as the sole global WHO Solidarity oracle. The ISRCTN record is the
primary global registry identity in this source map.

### Decision-relevant falsification target

In adults hospitalized with COVID-19, does intravenous remdesivir produce a
clinically meaningful benefit across predeclared branches for recovery time,
all-cause mortality, progression to ventilation, baseline respiratory support,
treatment timing, and serious harm?

### Ambiguous-role criterion

At least these competing interpretations must remain live after reveal:

1. a modest, stage-dependent antiviral effect shortens recovery or prevents
   progression in some patients who are not yet ventilated;
2. the intervention does not establish a broad mortality benefit, particularly
   after ventilation; and
3. differences in endpoint, blinding, disease severity, treatment timing, and
   contemporaneous care prevent a single general translation.

The correct behavior is `NO_CALL`, not a binary effective/ineffective label. A
minimum information boundary for changing that state must require harmonized
severity and treatment-timing strata plus mortality or progression evidence
with adequate power and a design that can separate treatment effect from
discharge practice and evolving care. The exact classifier and adjudication
protocol remain to be independently authored and precommitted.

## Leakage and custody restrictions

The following are required before any historical execution or score:

1. Construct a positive allowlist of exact pre-cutoff source objects. Do not run
   an open-ended current search during scoring.
2. Preserve the exact raw bytes, canonical locator, submitted and executed query,
   retrieval route, public-availability timestamp, source version, pagination or
   truncation state, and SHA-256 for every admitted object.
3. Preserve historical registry versions. A current ClinicalTrials.gov or
   ISRCTN record can contain later status, results, derived references, outcome
   text, and corrections.
4. Exclude current Open Targets scores, current Mendelian-randomization rows,
   current citation graphs and counts, current MeSH or text-mined annotations,
   autocomplete, snippets containing later text, and search-ranking signals.
5. Place reveal records and executable oracle classifiers in a separately
   permissioned store. Commit their identities and digests before the candidate
   sees any case input; open them only after the candidate output is sealed.
6. Record publisher, sponsor, funder, and conflict metadata without treating
   those fields as automatic evidence rejection.
7. Run the frozen challenge without network access and verify input inventory
   equality before and after execution.
8. Treat retrieval failure, truncation, semantic mismatch, and absence of
   evidence as different states. None may be converted silently into a negative
   scientific result.
9. Record modern-model training exposure as unresolved contamination. Renaming
   cases or newly hashing familiar outcomes does not restore prospective
   blinding.

## ToolUniverse current-state caveat

The source review used read-only ToolUniverse wrappers for PubMed, Europe PMC,
ClinicalTrials.gov, and ISRCTN. These wrappers establish that the sources can be
retrieved; they do not establish historical admissibility. ToolUniverse calls
return current upstream state, and current records can expose reveal outcomes or
post-cutoff metadata. One attempted parallel PubMed retrieval also reached the
upstream rate limit; Europe PMC supplied the independent identifier check that
corrected ACTT-1 to PMID `32445440`. Transport success, a source label, or a
current publication date is not a knowledge-date attestation.

## Domain and role-confounding verdict

The three cases are defensible together only as a
`BIOMEDICAL_THERAPEUTIC_TRANSLATION_PILOT`. At a useful scientific resolution,
they belong to cardiovascular, neurodegeneration, and infectious-disease
subdomains. With one role assigned to each subdomain, role is perfectly
confounded with subdomain.

This trio can exercise ingestion, temporal separation, branch totality, bounded
rejection, and abstention. It cannot demonstrate cross-domain generality or
support a performance score. The minimum three-domain benchmark needs a
positive, failed-translation, and ambiguous control inside every declared
domain: at least nine independently reviewed controls. All remain known-hindsight
calibration and stay outside primary effect estimation.

## Exact nonclaims

This source map does **not** establish:

- that any candidate cutoff or source object has passed independent temporal
  attestation;
- that an exact input corpus, oracle, classifier, or external commitment has
  been frozen or hash-committed;
- semantic validity of any control, branch, role criterion, or minimum
  information boundary;
- absence of outcome leakage, search leakage, registry-history leakage, model
  training contamination, or hidden prior exposure;
- independent domain review, adjudicator agreement, custody independence,
  monotonic publication, or rollback resistance;
- prospective discovery performance, causal validity, clinical efficacy,
  treatment recommendation, target validation, or target invalidation;
- comparator superiority, calibrated abstention, a benchmark winner, or a 10x
  improvement in time or cost;
- generalization across three scientific domains, reproducibility by an
  independent group, early-career usability, adoption, publication merit,
  health impact, or lives saved;
- patient-data use, privacy certification, wet-lab authorization, biological
  material authority, clinical authority, or regulatory authority; or
- public registration, release, or scientific publication of these controls.

Until the receipts, frozen bytes, oracle commitments, executable classifiers,
and independent semantic review exist, the only supported status is:

`CANDIDATE_CALIBRATION_SOURCE_MAP_NOT_ADMITTED_NOT_SCORED`
