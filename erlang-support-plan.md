# Erlang Support Plan

## Decision

Build Erlang support from the current `main` branch. The previous native Erlang
frontend was intentionally abandoned; `backup/native-erlang-20260829` is a
historical snapshot only and is not part of the implementation, compatibility,
or rollback path.

The first implementation is a hybrid adapter for the real `server_flexible`
repository:

```text
Generic Tree-sitter baseline
    -> repository-wide files, modules, functions, tests, and coarse navigation

ELP targeted enrichment
    -> semantic evidence for changed functions and explicit review targets

rebar3 xref
    -> module-level callers, dependencies, and undefined-call diagnostics

Dialyzer
    -> typed cross-module diagnostics and review evidence
```

The product target is the project repository, not Erlang as an abstract
language benchmark. Erlang support is initially navigation and auxiliary review
context. It can become a primary source for blocking review decisions only
after the adoption gates in this document pass on real `server_flexible` cases.

## Goal

Provide useful, provenance-aware Erlang context through the existing CRG build,
incremental update, watch, CLI, and MCP review-context paths. The first target
workflows are:

- changed functions and their evidence-backed callers;
- changed modules and module-level dependents;
- changed headers, records, and types and their consumers;
- behaviour callbacks and implementing modules;
- Common Test and EUnit coverage related to changed code;
- impact results that remain useful when semantic tooling is unavailable.

The implementation must preserve the existing CRG contract: a Generic index is
always useful on its own, semantic enrichment is additive, and an unresolved
endpoint is preferable to a guessed endpoint.

## Scope

### Generic baseline

Add Erlang to the current Generic Tree-sitter path from the current `main`
baseline. The baseline owns:

- `.erl`, `.hrl`, and `.app.src` discovery and language identity;
- stable file, module, function, clause, test, record, and type nodes where
  syntax is sufficient;
- source spans, text search, containment, and coarse navigation;
- local syntactic call candidates and repository-local ownership checks;
- incremental file inventory and hash-based change detection.

Generic parsing must work without ELP, xref, Dialyzer, a project build, or
execution of project code. Syntax-only candidates must remain visibly
unresolved until a supported evidence source resolves them.

### Semantic adapters

Add independent adapters behind one review-context integration boundary:

- **ELP**: query only changed functions, explicit `callers_of`/`tests_for`/
  impact targets, and unresolved candidates selected by the review pipeline.
- **xref**: consume project-level module caller/dependency and undefined-call
  evidence. Do not turn module-level xref facts into function-level `CALLS`
  edges.
- **Dialyzer**: consume typed diagnostics and retain their original source
  location, warning kind, and toolchain identity. Dialyzer does not replace
  caller, dependency, or test relationships.

Adapters are optional. A missing, mismatched, failed, or timed-out adapter must
produce an observable diagnostic and leave the Generic graph intact.

### Review-context integration

Use the existing CRG graph, impact, change-detection, and review-context APIs.
Do not introduce an Erlang-only public query surface in the first delivery.
Relation evidence is attached to the existing node/edge model and carries
provenance in the existing metadata fields or the agreed adapter evidence
record. The first delivery does not persist the entire ELP workspace graph.

### Repository boundary

Analyze `server_flexible` as an external consumer repository. CRG must not
modify its source, generated outputs, release process, or build configuration.
The evaluated repository state is identified by a manifest containing its Git
revision, dependency/checkout state, toolchain identity, and generated-data
revision when generated sources are included.

## Non-goals

- Building an Erlang compiler, preprocessor, macro-expansion engine, or runtime
  evaluator.
- Treating generic syntax traversal as authoritative semantic resolution.
- Inferring arbitrary dynamic `M:F/A`, fun variables, message flow, or process
  topology without explicit evidence.
- Executing `rebar.config.script`, parse transforms, plugins, or project code
  during Generic indexing.
- Making the abandoned native frontend a compatibility layer or fallback.
- Converting all ELP state into a persistent CRG graph in the first delivery.
- Changing `server_flexible` or publishing an upstream pull request as part of
  this implementation.

## Relation and evidence contract

The implementation uses the existing CRG relation model. The ownership below
is the contract for promotion into review context:

| Evidence | Owner | Promotion rule |
| --- | --- | --- |
| File/module/function/test/record/type nodes and containment | Generic | Syntax-backed nodes are always available. |
| Local call candidates | Generic | Keep unresolved unless a target is proven. |
| Function-level `CALLS` | ELP or another explicit resolver | Promote only when the target module/function/arity is identified. |
| Module dependencies and module callers | xref plus Generic layout | Keep at module granularity; never fabricate function endpoints. |
| Includes, record/type consumers | Generic candidates, ELP confirmation when available | Preserve unresolved candidates as evidence, not resolved edges. |
| Behaviours and callback implementations | Generic attributes, ELP confirmation when available | Require the callback/implementation identity to be explicit. |
| Common Test and EUnit coverage | Generic test discovery, ELP confirmation when available | Do not emit `TESTED_BY` for name-only coincidence. |
| Type and cross-module diagnostics | Dialyzer | Preserve raw diagnostic identity and source location. |

Every promoted relation or diagnostic records, at minimum, its evidence source,
tool/version when applicable, analyzed source revision, generated-data revision
when applicable, query kind, and status. Reconciliation must be deterministic:
duplicate evidence is merged, conflicting evidence remains visible with its
provenance, and stale evidence is removed when its revision no longer matches.

## Toolchain and execution contract

The implementation must discover and record the project toolchain before using
semantic adapters:

- OTP version and executable path;
- ELP executable, version, and invocation mode when available;
- project-local `rebar3` path and version;
- xref and Dialyzer command lines, environment, dependency roots, and PLT
  identity;
- analyzed Git revision and generated-data revision.

The concrete ELP protocol, subprocess sandbox, timeout values, cache layout, and
concurrency mechanism are implementation-stage decisions. They are not
preconditions for this plan, but each must be documented in the toolchain and
adapter manifests before that adapter is enabled. Those manifests are part of
the adapter's reviewable deliverable.

Project commands that can evaluate configuration scripts, plugins, parse
transforms, generate files, access the network, or write outside the analysis
workspace must run in the controlled execution boundary defined by the adapter
manifest. Generic-only operation must never depend on that boundary.

## Fallback and consistency

The request path is deterministic:

1. Collect Generic nodes and syntax evidence.
2. Load only enrichment evidence whose repository, source, generated-data,
   configuration, toolchain, and query keys match.
3. Execute missing targeted adapter work under bounded failure handling.
4. Reconcile duplicate and conflicting evidence.
5. Calculate impact and assemble review context with diagnostics.

Fallback behavior is explicit:

1. Generic succeeds and ELP is missing: return Generic navigation plus
   `elp_unavailable`.
2. An ELP query fails or times out: keep prior valid evidence, mark that query
   unavailable, and continue the request.
3. xref is unavailable or its output is unusable: omit xref-derived module
   evidence and retain Generic/ELP results.
4. Dialyzer is unavailable or its PLT is stale: omit its diagnostics and retain
   the graph; never treat a stale PLT as current evidence.
5. Evidence from another source or generated-data revision is discarded or
   recomputed; it is never silently mixed with current evidence.

No fallback may promote a lower-confidence candidate into a resolved edge.
Disabling one adapter removes only its derived evidence and leaves Generic nodes,
text search, and coarse navigation available.

## Implementation phases

Each phase is independently mergeable and leaves the repository usable.

### Phase 1: Generic Erlang baseline

1. Add built-in Erlang file detection and the selected Tree-sitter grammar
   integration to the current parser registry.
2. Define stable Erlang identities for modules, functions, clauses, tests,
   records, and types, including multi-clause functions.
3. Add syntax-backed containment, include, behaviour, and local call evidence
   without claiming cross-file semantic resolution.
4. Integrate the baseline with full build, incremental update, watch, forget,
   and standalone postprocess paths.
5. Add Generic-only fixtures and regression tests for missing optional tools.

**Deliverable:** `server_flexible` can be indexed and queried for Erlang
navigation and coarse impact with no ELP, xref, Dialyzer, or project build.

### Phase 2: Evidence adapters

1. Implement the ELP adapter using targeted queries and the adapter manifest.
2. Implement xref module evidence and preserve raw command diagnostics.
3. Implement Dialyzer diagnostic ingestion with PLT/toolchain validation.
4. Implement one idempotent evidence reconciler shared by build, update, watch,
   forget, and standalone postprocess.
5. Add revision-keyed enrichment caching and explicit stale-cache handling.
6. Add focused tests for unavailable tools, mismatches, timeouts, malformed
   output, duplicate evidence, and conflicting evidence.

**Deliverable:** the same review-context interface returns Generic results and
adds valid adapter evidence when the configured tools are available.

### Phase 3: Review workflows and lifecycle parity

1. Feed resolved function/module/header/type/behaviour/test evidence into
   `get_review_context`, `get_impact_radius`, `detect_changes`, and the existing
   callers/tests queries.
2. Verify that initial build, incremental update, watch notification, forget,
   and standalone postprocess converge to the same graph and evidence state,
   modulo ordering and explicitly reported diagnostics.
3. Verify that watch initialization cannot miss a pending update while the
   initial Generic build or enrichment is running.
4. Bound result size and query work for large `server_flexible` changes.

**Deliverable:** Erlang review context is available through the normal CRG
workflows and degrades predictably when semantic tooling is unavailable.

### Phase 4: Real-project corpus and adoption gate

1. Freeze a small corpus from clean, fixed `server_flexible` revisions using
   the repository/toolchain/generated-data manifest.
2. Cover local and remote callers, shared headers/records, behaviours,
   supervisor/service static MFA, Common Test, EUnit, generated data, missing
   tools, and stale caches.
3. Record manually reviewed positive and negative expected relationships,
   intentionally unresolved dynamic behaviour, evidence source, and revision.
4. Run every case from a clean cache and after incremental update, watch,
   forget, and standalone postprocess.
5. Publish repeatable precision, recall, impact, latency, and diagnostic
   reports. Do not promote Erlang into primary review context until every gate
   below is green.

**Deliverable:** a reproducible evaluation report and an explicit adoption
decision for `server_flexible`.

## Adoption gates

Promotion requires all of the following on the fixed corpus:

- `100%` precision for every promoted relation kind, measured over all emitted
  resolved edges of that kind;
- caller/dependent `Recall@10` of at least `90%`, reported separately for
  function-level and module-level relationships;
- no unexplained false-positive `TESTED_BY` or impact edges;
- every manually confirmed critical dependent appears in the impact result;
- full-build and targeted-query p50/p95 latency fit the budget recorded in the
  corpus manifest;
- full-build, incremental, watch, forget, and standalone postprocess preserve
  the same relation and evidence contract;
- missing tools, version mismatches, malformed output, timeouts, and stale
  caches are observable and do not fail Generic indexing.

Until then, document Erlang as navigation and auxiliary review context only;
it must not be the sole source for a blocking review decision.

## Verification

The implementation records the exact command, revision, toolchain, cache state,
and elapsed time for each check. At minimum:

```text
CRG: full build, targeted callers/tests/impact/review-context queries
CRG: incremental update, watch, forget, standalone postprocess
ELP: cold-start and warm targeted query for every supported query kind
rebar3 xref: project-pinned invocation, structured evidence, and raw diagnostics
Dialyzer: project-pinned invocation, PLT validation, and raw diagnostics
pytest: focused Erlang/lifecycle suites and full suite with hermetic Git config
ruff and mypy: repository quality gates
```

Executed checks and unavailable checks must be reported separately. An external
tool that was not run is not a passing result.

## Rollback

The Generic Erlang baseline is the compatibility floor. ELP, xref, and Dialyzer
can be disabled independently; disabling an adapter removes only its derived
evidence and diagnostics. No rollback step restores or depends on the abandoned
native frontend.

## Exit criteria for implementation

Before changing production review behavior, the implementation turn must have:

1. A checked-in `server_flexible` repository/toolchain/generated-data manifest.
2. A working Generic-only Erlang baseline with focused regression tests.
3. Adapter manifests documenting invocation, failure, provenance, and cache
   contracts for each enabled tool.
4. Initial golden cases with manually reviewed expected results.
5. Baseline precision, Recall@10, impact, latency, and fallback measurements.
6. A Beads issue for each adapter, lifecycle path, and adoption gate that
   remains open.
