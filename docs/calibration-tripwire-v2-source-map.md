# Role-hidden calibration V2 source map

**Status:** candidate source map for a known-hindsight structural rehearsal;
not admitted to primary performance
**Exact historical byte custody:** `false` for every source and reveal object
**Independent temporal attestation:** `false`
**Fixed parameter:**
`OPEN_MACHINE_VERIFIABLE_TRANSLATION_FROM_FRAGMENTED_BIOMEDICAL_EVIDENCE_TO_NEXT_FALSIFIABLE_ACTION`

This map keeps the three historical therapeutic-translation controls from the
V1 pilot but changes what they test. The entrant sees opaque identifiers,
cutoff-bounded source objects, claims, information requirements, and features.
It does not receive a role label, a required behavior, or an outcome oracle.
After the structured action and complete branch table are sealed, the opening
reveals one positive, one failed-translation, and one ambiguous role.

The later role is not an ex-ante action label. A failed later translation can
make `REQUEST_INFORMATION` or a bounded continuation of already-running trials
reasonable before the outcome exists. Conversely, a positive later outcome
does not prove that every earlier proposal to proceed was well designed. V2
therefore reviews the pre-cutoff action under a committed rubric and separately
checks whether the frozen branch table routes the later observation correctly.

## Candidate control map

| Hidden-after-seal role | Case | Candidate cutoff | Defensible ex-ante action family | Proposed fixed-protocol opening coordinate | Exact historical bytes held? |
|---|---|---:|---|---|---|
| `POSITIVE` | PCSK9 inhibition before FOURIER | `2012-12-31T23:59:59Z` | `PROPOSE_FALSIFICATION`: a powered cardiovascular-outcomes test, not surrogate acceptance | `COMPLETE / CONFIRMED / BENEFIT / CONSISTENT` → `SUPPORTS_NEXT_FALSIFICATION` | No |
| `FAILED_TRANSLATION` | BACE1 inhibition with verubecestat before EPOCH and APECS outcomes | `2016-11-03T23:59:59Z` | `REQUEST_INFORMATION` or narrowly bounded non-adoption while the already-running outcome trials resolve the clinical claim | `COMPLETE / CONFIRMED / HARM / CONSISTENT` → `HARM_SIGNAL` | No |
| `AMBIGUOUS` | Remdesivir before ACTT-1 and WHO Solidarity outcomes | `2020-02-20T23:59:59Z` | `REQUEST_INFORMATION`: preserve the locked randomized tests and outcome-specific competing claims | `COMPLETE / UNKNOWN / UNKNOWN / INSUFFICIENT` → `UNRESOLVED` | No |

The proposed coordinates are steward encodings for exercising the fixed
72-coordinate protocol. They have not been independently classified from exact
reveal bytes and are not empirical conclusions. Endpoint, population, timing,
and estimand differences can make the coordinate itself debatable. In
particular, ACTT-1 recovery and Solidarity mortality estimates are not logically
contradictory merely because their summaries differ.

## PCSK9 before FOURIER

### Candidate pre-cutoff allowlist

- Human PCSK9 loss-of-function genetics, LDL cholesterol, and coronary events:
  [PMID 16554528](https://pubmed.ncbi.nlm.nih.gov/16554528/), DOI
  `10.1056/NEJMoa054013`.
- Early AMG 145 phase 1 and 2 reports:
  [PMID 23083772](https://pubmed.ncbi.nlm.nih.gov/23083772/),
  [PMID 23129602](https://pubmed.ncbi.nlm.nih.gov/23129602/),
  [PMID 23141813](https://pubmed.ncbi.nlm.nih.gov/23141813/),
  [PMID 23141812](https://pubmed.ncbi.nlm.nih.gov/23141812/), and
  [PMID 23128163](https://pubmed.ncbi.nlm.nih.gov/23128163/).
- Historical versions of early registrations `NCT01375751`, `NCT01380730`,
  `NCT01375777`, and `NCT01375764`, if exact pre-cutoff bytes and independent
  public-availability receipts can later be obtained.

These sources can motivate a pharmacologic cardiovascular-outcomes test while
leaving transport from lifelong genetic exposure to a drug intervention open.
They do not make LDL reduction interchangeable with clinical benefit.

### Reveal-only references

- FOURIER registration:
  [NCT01764633](https://clinicaltrials.gov/study/NCT01764633).
- Primary report:
  [PMID 28304224](https://pubmed.ncbi.nlm.nih.gov/28304224/), DOI
  `10.1056/NEJMoa1615664`.

The current registry representation reports first submission on 2013-01-08,
first posting on 2013-01-09, and study start on 2013-02-08, all after the
candidate cutoff. This ordering supports temporal separation at the metadata
level. It does not prove custody of the exact bytes that existed on those dates.

### Action and successor boundary

A defensible action must ask whether PCSK9 inhibition reduces a prespecified
cardiovascular-event endpoint in a bounded population, include sufficient power
and follow-up, retain safety and transport limits, and refuse surrogate
substitution. The later benefit coordinate routes to
`ADVANCE_FALSIFICATION`; it does not certify the target, authorize treatment,
or generalize beyond the tested intervention, population, endpoint, and time
horizon.

## Verubecestat before EPOCH and APECS outcomes

### Candidate pre-cutoff allowlist

- APP A673T human genetic evidence:
  [PMID 22801501](https://pubmed.ncbi.nlm.nih.gov/22801501/), DOI
  `10.1038/nature11283`.
- Compound-specific animal and human CNS amyloid target-engagement evidence:
  [PMID 27807285](https://pubmed.ncbi.nlm.nih.gov/27807285/), DOI
  `10.1126/scitranslmed.aad9704`.
- Only cutoff-valid historical versions of the EPOCH and APECS records:
  [NCT01739348](https://clinicaltrials.gov/study/NCT01739348) and
  [NCT01953601](https://clinicaltrials.gov/study/NCT01953601).

ClinicalTrials.gov history metadata identifies EPOCH version 47, posted
2016-10-07, and APECS version 42, posted 2016-10-04, as candidate pre-cutoff
versions. APECS version 43, posted 2016-11-04, is after the proposed cutoff and
must be excluded. This version ordering is a reconstruction from the current
registry service, not custody of the historical response bytes.

### Reveal-only references

- EPOCH primary report:
  [PMID 29719179](https://pubmed.ncbi.nlm.nih.gov/29719179/) and
  [PMC6776074](https://pmc.ncbi.nlm.nih.gov/articles/PMC6776074/).
- APECS primary report:
  [PMID 30970186](https://pubmed.ncbi.nlm.nih.gov/30970186/) and
  [PMC6776078](https://pmc.ncbi.nlm.nih.gov/articles/PMC6776078/).

### Action and successor boundary

At this cutoff, the decisive clinical trials were already running. The
failed-translation role must not force a hindsight `BOUNDED_REJECTION` answer.
A defensible ex-ante output can preserve both competing claims, refuse clinical
adoption based only on amyloid lowering, and await the already-prespecified
clinical endpoints with explicit target-engagement, exposure, missingness,
stopping, and disease-stage checks.

The candidate opening uses the protocol's harm-first branch because EPOCH
reported more treatment-related adverse events and APECS reported more adverse
events plus worse outcomes on some high-dose cognitive and functional measures.
That steward encoding routes to `STOP_FOR_SAFETY` and leaves target-claim state
`UNKNOWN`; it does not use the less conservative `TRANSLATION_FAILURE` branch to
exclude a claim while a harm signal is present. The coordinate has not been
independently adjudicated and does not reject BACE1 biology, all amyloid
hypotheses, other modalities, or prevention at another stage.

## Remdesivir before ACTT-1 and Solidarity outcomes

### Candidate pre-cutoff allowlist

- Broad-spectrum coronavirus preclinical evidence:
  [PMID 28659436](https://pubmed.ncbi.nlm.nih.gov/28659436/).
- SARS-CoV-2 cell-culture evidence:
  [PMID 32020029](https://pubmed.ncbi.nlm.nih.gov/32020029/) and
  [PMC7054408](https://pmc.ncbi.nlm.nih.gov/articles/PMC7054408/), DOI
  `10.1038/s41422-020-0282-0`.
- MERS-CoV rhesus-macaque evidence:
  [PMID 32054787](https://pubmed.ncbi.nlm.nih.gov/32054787/) and
  [PMC7104368](https://pmc.ncbi.nlm.nih.gov/articles/PMC7104368/), DOI
  `10.1073/pnas.1922083117`.
- Candidate first-posted versions of the two early China remdesivir trials:
  [NCT04252664](https://clinicaltrials.gov/study/NCT04252664) and
  [NCT04257656](https://clinicaltrials.gov/study/NCT04257656).

Current registry history metadata reports the first China-trial versions posted
on 2020-02-05 and 2020-02-06, before the cutoff. Their version-2 updates were
posted on 2020-02-24 and are excluded. ACTT-1 was submitted on 2020-02-20 but
first posted and began on 2020-02-21, so its record is not a public input at the
proposed end-of-day 2020-02-20 cutoff.

### Reveal-only references

- ACTT-1 registration:
  [NCT04280705](https://clinicaltrials.gov/study/NCT04280705).
- ACTT-1 primary report:
  [PMID 32445440](https://pubmed.ncbi.nlm.nih.gov/32445440/) and
  [PMC7262788](https://pmc.ncbi.nlm.nih.gov/articles/PMC7262788/), DOI
  `10.1056/NEJMoa2007764`.
- Global WHO Solidarity registration:
  [ISRCTN83971151](https://www.isrctn.com/ISRCTN83971151).
- Solidarity interim and final reports:
  [PMID 33264556](https://pubmed.ncbi.nlm.nih.gov/33264556/) and
  [PMID 35512728](https://pubmed.ncbi.nlm.nih.gov/35512728/), with
  [PMC9060606](https://pmc.ncbi.nlm.nih.gov/articles/PMC9060606/).

`NCT04315948` is the European DisCoVeRy record and must not replace the global
WHO Solidarity identity merely because later sources link related
registrations.

### Action and successor boundary

The candidate opening keeps target engagement `UNKNOWN` because the later clinical
reports do not independently establish the protocol's target-engagement construct.
The ex-ante action should retain competing hypotheses about recovery,
progression, mortality, baseline respiratory support, and treatment timing;
preserve randomized comparisons; and require outcome-specific resolution
rules. After reveal, different trial designs and estimands can support a bounded
`UNRESOLVED` successor rather than a binary effective/ineffective label. This
does not recommend remdesivir or decide any patient's care.

## Byte custody, licensing, and ToolUniverse limits

No exact historical source or reveal bytes are currently held under independent
custody. The identifiers and dates above were reconstructed from current
PubMed, PMC, ClinicalTrials.gov, ISRCTN, and ToolUniverse responses. A current
response can contain later status, result modules, linked publications,
corrections, derived references, citation data, or ranking signals. It can show
that a record is retrievable now; it cannot prove the exact representation
available at a historical cutoff.

ToolUniverse belongs only in a pre-run capture stage. The role-hidden candidate
run must remain offline and declare zero network requests. A future admissible
capture must preserve the exact response bytes, request parameters, submitted
and executed query, endpoint and adapter version, retrieval time, source-version
identifier, pagination and truncation state, response headers needed for
provenance, and SHA-256. A source-specific independent timestamp or archived
receipt is still required.

The fixture should store only the minimum metadata needed for the rehearsal and
should paraphrase scientific content. PubMed indexing metadata, PMC articles,
publisher articles, registry records, and APIs have different terms and reuse
conditions. No blanket license to redistribute full text, abstracts, figures,
tables, supplemental files, or API responses has been established. License and
redistribution review remain case-by-case and currently unverified.

## Leakage controls required before any historical run

1. Build a positive allowlist of exact pre-cutoff objects. Never perform an
   open-ended current search during candidate execution.
2. Keep reveal objects, role mappings, rubric material, and nonce values outside
   the entrant root and inaccessible to the candidate.
3. Commit the reveal payload and rubric before the candidate sees the view;
   preserve the view lock and submission seal with independent, monotonic
   witnesses before opening later zones.
4. Exclude post-cutoff registry versions, current result modules, linked later
   publications, citation graphs and counts, derived references, snippets,
   autocomplete, and search-ranking signals.
5. Record model-training exposure as unresolved. Opaque names and fresh hashes
   cannot make a familiar historical result prospective.
6. Distinguish missing evidence, transport failure, retrieval failure,
   operational failure, target-engagement failure, harm, inconsistent evidence,
   and a no-benefit translation. None can be silently collapsed into another.
7. Run the entrant policy without network access and recheck the exact root
   inventory before and after reading.
8. Preserve failures in the intention-to-test matrix instead of dropping or
   replacing cases.

## Domain balance

The trio is a `BIOMEDICAL_THERAPEUTIC_TRANSLATION_PILOT`, not a balanced domain
sample. Cardiovascular, neurodegeneration, and infectious disease each contain
only one role, so role is confounded with subdomain. A stronger calibration
matrix needs positive, failed-translation, and ambiguous controls inside each of
at least three domains: at least nine independently reviewed controls. Those
historical cases would still remain outside prospective and primary effect
estimation.

## Exact nonclaims

This source map does not establish:

- custody, authorship, integrity, independent timestamping, or actual pre-cutoff
  availability of any exact source or reveal bytes;
- complete or licensed redistribution of any article, abstract, registry
  version, API response, figure, table, or supplement;
- correctness or completeness of the candidate allowlists, cutoffs, current
  metadata, historical-version reconstruction, role assignments, coordinates,
  action families, branches, successors, or bounded claims;
- absence of outcome leakage, model-training contamination, identifier
  memorization, source-ranking leakage, or semantic recognition;
- independent domain review, source classification, reviewer identity,
  signatures, credentials, organizational independence, review blinding, phase
  ordering, custody independence, monotonic publication, or rollback
  resistance;
- prospective performance, primary performance, causal or target truth,
  efficacy, treatment recommendation, calibrated abstention, generalization,
  reproducibility, comparative speed or cost, adoption, publication merit,
  health impact, or lives saved; or
- privacy certification, use of patient-level data, clinical authority,
  regulatory authority, wet-lab authority, biological-material authority, study
  execution authority, scientific-claim authority, or release authority.

The only supported source status is:

```text
CANDIDATE_V2_SOURCE_MAP_CURRENT_REPRESENTATIONS_ONLY_EXACT_HISTORICAL_BYTE_CUSTODY_FALSE
```
