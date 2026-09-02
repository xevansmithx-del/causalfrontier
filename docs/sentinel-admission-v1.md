# Sentinel admission v1

## Purpose

The goal-claim firewall correctly treated its cohort and registry digests as
declarations because their preimage bytes were not supplied. Sentinel admission v1
closes that gap without pretending that software can decide whether a scientific
domain, control, source history, or organization is genuinely independent.

The fixed project parameter remains:

`OPEN_MACHINE_VERIFIABLE_TRANSLATION_FROM_FRAGMENTED_BIOMEDICAL_EVIDENCE_TO_NEXT_FALSIFIABLE_ACTION`

The boundary composes three exact read-only inputs:

1. a caller-supplied `sentinel-generation-plan.v1` that declares a freeze of the
   complete case, domain, role, generator-family, laboratory, cutoff, protocol,
   and inclusion geometry before generation;
2. a `sentinel-admission-manifest.v1` that inventories every resulting artifact
   byte; and
3. the immutable `goal-claim-plan.v1`, whose `cohort_checkpoint_sha256` must equal
   the raw sentinel-manifest digest.

The sentinel manifest binds the fixed goal-contract digest, not the goal-plan
digest. This avoids a plan/manifest hash cycle while proving that the manifest is
the exact preimage behind the goal plan's cohort checkpoint.

The strongest local state is:

```text
REVIEW_PACKET_COMPLETE_NOT_ADMITTED
```

It is not `ADMITTED`, `REGISTERED`, `PROSPECTIVE`, or `SCORING_READY`.

## Commands

The steward can validate the pre-generation lock before generating cases:

```bash
causalfrontier preflight-sentinel-generation-plan GENERATION_PLAN \
  --expected-generation-plan-sha256 GENERATION_PLAN_RAW_SHA256
```

After artifact generation, the composed admission preflight is:

```bash
causalfrontier preflight-sentinel-admission \
  SENTINEL_ROOT GENERATION_PLAN GOAL_CLAIM_PLAN \
  --expected-manifest-sha256 SENTINEL_MANIFEST_RAW_SHA256 \
  --expected-sequence 1 \
  --expected-generation-plan-sha256 GENERATION_PLAN_RAW_SHA256 \
  --expected-goal-claim-plan-sha256 GOAL_CLAIM_PLAN_RAW_SHA256
```

A valid structural result exits `3`, preserving abstention. Malformed, substituted,
unsafe, non-replayed, or authority-expanding input exits `2` without a JSON result.
The public verifier rebuilds the complete report from the exact three inputs; a
coherently rehashed projection cannot promote a false field.

## Frozen v1 geometry

V1 deliberately fixes one narrow, falsifiable sentinel geometry:

- exactly three declared scientific domains;
- exactly three declared generator-family clusters under the maximal-family rule;
- exactly ten primary cases and two case-linked laboratories per domain;
- exactly one positive, failed-translation, and ambiguous calibration case per
  domain; and
- thirty primary cases, nine controls, and six laboratories in total.

The controls form a three-by-three Latin square. Each domain uses all three
generator families once across its three control roles, and each role uses every
family exactly once across the three domains. Every domain's ten primary cases use
all three families, no family may contribute a majority, the two laboratories
receive five cases each, and every generator occurs in both laboratories with its
two cell counts differing by at most one. This blocks exact declared
domain/role/generator and generator/laboratory confounding. It does not prove that
the domains, generators, organizations, or laboratories are genuinely independent.

A generator family is defined conservatively as the maximal cluster sharing a
controller, source ancestry, template or scaffold, prompt program, generator
implementation, or hidden selection process. Wrapper names and different hashes do
not split one family.

## Closed artifact graph

The manifest binds a bounded, UTF-8, public/synthetic, no-follow inventory. The
current synthetic conformance fixture closes 326 artifact files, including:

- eight open admission, semantic-review, generator-audit, cutoff, provenance,
  privacy, control-scoring-protocol, and control-scoring-implementation artifacts;
- declared source trees, source files, dependency locks, build recipes,
  environments, tool/model inventories, input inventories, ancestry declarations,
  controller disclosures, and execution protocols for all three generators;
- exhaustive generator-pair audits;
- domain semantics, two-reviewer packets, control-methodology packets, and every
  domain-pair review;
- exact case payloads and role-specific primary/positive/failed/ambiguous packets;
- source bytes, availability declarations, source inventories, cutoff audits, and
  declared acyclic, source-to-payload provenance graph structures for all 39 cases.

The generation plan and goal plan are separate digest-checked predecessor inputs;
they are not artifacts inside the manifest. The software replays them before and
after the bundle read, but their claimed wall-clock order and custody are not
independently attested.

Every file is opened through no-follow directory descriptors, must be a bounded
single-link regular file, must match its declared digest, and must be referenced by
the closed artifact graph. The entire inventory and every byte are replayed before
return. All eight required protocol/policy artifacts must contain bytes, and every
artifact parsed as JSON must declare the JSON media type. Symlinks, hard links,
extra files, orphan declarations, traversal, duplicate JSON keys, floats, non-
finite numbers, prohibited private material, forward or cyclic provenance, and
second-read drift fail closed.

The API has no designated opening, result, winner, or score input. It accepts only
explicitly labelled external seed/oracle digest declarations, checks their local
uniqueness and disjointness, and rejects equality with an enumerated set of exact
bundle and predecessor digests. It does not receive or verify commitment preimages,
entropy, hiding, binding, timely publication, or custody. Arbitrary admitted bytes
can still encode hindsight, so content-level outcome isolation remains `NO_CALL`.

## Computable rejection versus external no-call

The local preflight returns structured rejection when exact evidence supports a
kill gate:

- any shared generator component identifier or exact component digest, including
  whole source-tree, per-file source, input, build, environment, controller, or
  execution artifacts;
- declared mechanism, governance, ancestry, controller-group, or store-group
  collision between generator families, compared case-insensitively, including a
  controller identifier reused as a store identifier or the reverse;
- an organization, controller group, or store group reused across generator,
  reviewer, laboratory, outcome-provider, adjudicator, or steward contexts;
- normalized domain-semantics collision after removing only the domain identifier;
- exact case decision-core collision after removing case/presentation identity; or
- an availability declaration whose parsed source identifier or date does not match
  its case/source link, or any declared source-availability or generator tool/model-
  knowledge date after the applicable case cutoff.

Every declared observation state must map exactly once, unknown states map to
`NO_CALL`, and role packets bind the exact branch-contract digest. Primary packets
link at least one observation state to `NEXT_FALSIFICATION` and one to `NO_CALL`;
positive packets link their recovery states to `NEXT_FALSIFICATION`;
failed-translation packets link failure states to `REJECT_TRANSLATION`; ambiguous
packets link their ambiguity states to `NO_CALL`. This is exact coverage and
linkage over authored states, not proof that those states or criteria are
scientifically exhaustive or correct.

All other independence conclusions remain `NO_CALL`. In particular, unequal bytes,
different labels, organization IDs, reviewer packets, self-declared dates, and a
successful pattern screen do not verify:

- domain or control semantic validity;
- generator, controller, reviewer, laboratory, store, outcome-provider, or
  adjudicator independence;
- exact public availability before a cutoff or absence of post-cutoff access;
- prospective timing, monotonic custody, or rollback resistance;
- content-level outcome isolation or training-contamination absence;
- privacy certification or patient-data absence; or
- scientific scoring, acceleration, impact, or a claim.

The software verifies packet closure and internally computable relationships.
Independent domain/control review, source-availability attestation, privacy review,
governance and conflict adjudication, two external monotonic anchors, and a later
authorized admission receipt remain external work.

## Control boundary

Every positive control binds a method-recovery criterion, decision transition,
replication rule, and sealed opening commitment. Every failed-translation control
binds the pre-cutoff expectation, terminal failure definition, stop criterion, and
operational-failure exclusion. Every ambiguous control binds at least two competing
interpretations, the correct `NO_CALL` rule, and a minimum-information boundary.

All controls are `KNOWN_HINDSIGHT_CALIBRATION_ONLY`. Their openings are not inputs
to admission, their semantics are not locally adjudicated, and they never enter a
primary effect. PCSK9 pre-FOURIER remains a known-hindsight method-recovery control;
it cannot become prospective because it is newly hashed.

## Bounded landscape check

A primary-source scan through 2026-09-01 found strong neighboring systems, not an
exhaustive novelty proof. [OSF Registrations](https://help.osf.io/article/330-welcome-to-registrations)
provides timestamped read-only preregistration; [ForecastBench](https://www.forecastbench.org/datasets/)
prospectively resolves future questions; [DARPA/COS SCORE](https://www.cos.io/score-objectives)
combines independent replication, reanalysis, and credibility assessment; and
[PaperQA2](https://arxiv.org/abs/2409.13740),
[Google's AI co-scientist](https://arxiv.org/abs/2502.18864),
[AI Scientist-v2](https://github.com/SakanaAI/AI-Scientist-v2),
[FutureHouse Robin](https://www.futurehouse.org/research/demonstrating-end-to-end-scientific-discovery-with-robin-a-multi-agent-system),
[Kosmos](https://arxiv.org/abs/2511.02824),
and [Google empirical research assistance](https://research.google/blog/accelerating-scientific-discovery-with-ai-powered-empirical-software/)
cover literature synthesis, multi-agent hypothesis generation, executable search,
or end-to-end research loops.

Within that bounded scan, no source documented the full conjunction of exact
prospective commitments, mandatory failed and ambiguous controls, independently
governed generator families, full artifact replay, explicit abstention, and
outcome-bound decision/action scoring. That conjunction is the research hypothesis;
it is not a claim of firstness, novelty, superiority, adoption, or impact.

## Current validation

The current focused sentinel slice passes 88 tests; the sentinel plus shared CLI
slice passes 92, including one test for every
fixed-false authority field. It covers exact replay, the raw goal-cohort preimage,
Latin-square and both-laboratory/per-cell balance, nonempty protocol bytes, JSON
media-type enforcement, branch-observation/role linkage, availability source/date
linkage, exact generator-component identity/content reuse, casefolded and cross-
dimension controller/store aliases, cross-role aliases, normalized collision and
cutoff rejection, provenance-graph reachability, safe filesystem behavior, privacy
patterns, coherent report forgery, no-network/no-subprocess behavior, and read-only
execution.

All four assertion-independent normal/optimized x `PYTHONHASHSEED` 1/77 probe
outputs are byte-identical: 7,054 bytes including the terminal newline, SHA-256
`16c6c6c559bdbf989fbbd379ca23936425c7da180082ec09984cda779d6a1690`.

These are synthetic software tests. No real cross-domain cohort has been admitted,
no external reviewer or source-availability authority has attested the packets, and
no comparator, outcome, resource, acceleration, or scientific result has been
measured.
