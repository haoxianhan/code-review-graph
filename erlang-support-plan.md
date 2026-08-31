# Erlang Support Plan

## Decision

Build Erlang support from the current `main` branch for the real
`server_flexible` repository. The previous native Erlang frontend was
intentionally abandoned; `backup/native-erlang-20260829` is a historical
snapshot only and is not an implementation, compatibility, or rollback path.

The supported implementation is a project-scoped hybrid pipeline:

```text
Generic Tree-sitter syntax index
    -> repository-wide files, modules, functions, tests, headers, and coarse layout

ELP CLI targeted semantic queries
    -> changed functions and explicit callers/tests/impact targets

rebar3 xref
    -> project module callers, dependencies, and undefined-call evidence

Dialyzer + a matching PLT
    -> typed cross-module diagnostics
```

The product target is the project repository (`server_flexible`), not Erlang as
an abstract language benchmark. The Generic index is an internal structural
stage. It is not a fallback Erlang support mode and must not make a project
appear healthy when the required semantic toolchain is absent or mismatched.

## Goal

Provide deterministic, provenance-aware Erlang context through the existing CRG
build, incremental update, watch, CLI, and MCP review-context paths for
`server_flexible`. The first supported workflows are:

- changed functions and evidence-backed callers;
- changed modules and module-level dependents;
- changed headers, records, and types and their consumers;
- behaviour callbacks and implementing modules;
- Common Test and EUnit coverage related to changed code;
- impact results with explicit unresolved dynamic behaviour.

Every Erlang project operation must first validate the complete required
toolchain. A missing executable, incompatible version, invalid project
configuration, stale cache, or PLT mismatch is an observable preflight error
and stops the Erlang operation. There is no Generic-only success result for a
configured `server_flexible` operation.

## Required toolchain baseline

The current machine is the baseline and must be recorded in the checked-in
manifest:

| Component | Requirement |
| --- | --- |
| Erlang/OTP | exact `27.3.4.16` runtime; record ERTS (`15.2.7.12` on the baseline machine) and executable path |
| `rebar3` | available project command; baseline `3.27.0` |
| `rebar3 xref` | required task, invoked from the pinned project checkout |
| ELP CLI | required executable and version; invocation must be recorded |
| Dialyzer | version `5.3.1.1` on the baseline machine |
| Dialyzer PLT | required, readable, and keyed to OTP, tool versions, dependencies, source revision, configuration, and generated-data revision |
| Git | required to identify the checked-out project revision and dependency state |

`erlang_ls` and `elp-ls` are not dependencies of this design. They are legacy
probes or alternative language-server candidates and must not be installed,
probed, or used as adoption gates.

## Scope

### Structural stage

Use the existing Generic Tree-sitter parser to discover `.erl`, `.hrl`, and
`.app.src` files and create stable file, module, function, clause, test,
record, type, and containment nodes. It may retain syntax-backed call,
include, behaviour, and ownership candidates, but candidates remain unresolved
until an approved semantic evidence source identifies the target.

The structural stage must not execute `rebar.config.script`, parse transforms,
plugins, project code, or network operations. It is a prerequisite for the
semantic adapters, not an independent Erlang support mode.

### Required semantic adapters

- **ELP CLI:** targeted `enrichment`, `callers_of`, `tests_for`, `impact`, and
  `references` queries. Promote function-level relations only when module,
  function, and arity are explicit.
- **xref:** consume project-level module callers/dependencies and undefined
  calls. Keep xref facts at module granularity; never fabricate function-level
  `CALLS` edges from a module fact.
- **Dialyzer:** consume typed diagnostics with source location, warning kind,
  PLT identity, and toolchain identity. Dialyzer does not replace caller,
  dependency, or test relationships.

All three adapters are required for the configured `server_flexible` profile.
Their manifests must declare `activation.required: true` and must not name a
`generic_graph` fallback.

### Repository boundary

Analyze `server_flexible` as an external consumer repository. CRG must not
modify its source, generated outputs, release process, or build configuration.
The manifest records the target revision, lockfiles, submodule checkouts,
generated-data revision, toolchain identity, configuration digest, and PLT
identity.

## Non-goals

- Restoring or maintaining the abandoned native frontend.
- Treating syntax traversal as authoritative semantic resolution.
- Inferring arbitrary dynamic `M:F/A`, fun variables, message flow, or process
  topology without explicit evidence.
- Executing project configuration scripts or code during structural indexing.
- Building an Erlang compiler, preprocessor, macro-expansion engine, or runtime
  evaluator.
- Persisting the complete ELP workspace graph in the first delivery.
- Changing `server_flexible` or publishing an upstream pull request.
- Supporting `erlang_ls` or `elp-ls` as alternate required implementations.

## Relation and evidence contract

| Evidence | Owner | Promotion rule |
| --- | --- | --- |
| File/module/function/test/record/type nodes and containment | Generic | Syntax-backed nodes are created during the structural stage. |
| Local call/include/behaviour candidates | Generic | Keep unresolved until explicit semantic evidence resolves them. |
| Function-level `CALLS`, `REFERENCES`, `TESTED_BY`, `IMPLEMENTS` | ELP | Require an identified target and matching source revision. |
| Module dependencies, module callers, undefined calls | xref | Keep module facts at module granularity and retain raw diagnostics. |
| Type and cross-module diagnostics | Dialyzer | Require a current matching PLT and preserve location/warning identity. |

Every promoted relation or diagnostic records evidence source, tool and version,
OTP version, repository, source revision, generated-data revision when
applicable, configuration digest, query kind/targets, analysis key, command,
duration, cache state, and status. Reconciliation is deterministic: duplicate
evidence is merged, conflicting evidence remains visible with provenance, and
stale evidence is rejected.

## Toolchain and execution contract

Before any semantic command runs, preflight must:

1. resolve the required executables without evaluating project code;
2. verify exact OTP `27.3.4.16`, the recorded `rebar3` and Dialyzer versions,
   and the ELP CLI version/invocation;
3. verify `rebar.config`, lockfiles, submodules, generated-data revision, and
   repository cleanliness against the manifest;
4. build or locate a PLT and verify its identity against the complete analysis
   key; and
5. validate adapter manifests and the controlled execution boundary.

Failure at any step returns a blocking diagnostic and no semantic result. The
preflight must never silently substitute another OTP installation, language
server, PLT, or structural-only result.

Commands that may evaluate configuration scripts, plugins, parse transforms,
generate files, access the network, or write outside the analysis workspace
run only in the adapter's controlled execution boundary. The boundary uses
argv execution, a restricted environment, explicit read/write roots, bounded
timeouts, and atomic cache writes. Generic parsing itself remains side-effect
free.

## Consistency and cache

The request path is deterministic:

1. run required toolchain preflight;
2. collect the structural graph and syntax evidence;
3. load only enrichment evidence whose repository, revision, generated data,
   configuration, toolchain, PLT, and query keys match;
4. execute missing targeted adapter work under bounded failure handling;
5. reconcile duplicate/conflicting evidence; and
6. calculate impact and assemble review context.

An adapter failure, timeout, malformed output, stale cache, or PLT mismatch is
blocking for the configured Erlang operation. Prior evidence may be retained
for diagnostics, but it must not be presented as current review context. A
cache key must include repository, source revision, generated-data revision,
configuration digest, OTP/tool versions, query kind/targets, and PLT identity.

## Implementation phases

Each phase is independently mergeable and leaves non-Erlang CRG workflows
usable. A phase is complete only when its required-tool preflight and focused
tests pass.

### Phase 1: Structural Erlang stage

1. Register Erlang file detection and the selected Tree-sitter grammar.
2. Define stable identities for modules, functions, clauses, tests, records,
   and types, including multi-clause functions.
3. Add syntax-backed containment, include, behaviour, and local call evidence
   without claiming semantic resolution.
4. Integrate the stage with full build, incremental update, watch, forget, and
   standalone postprocess paths.
5. Add fixtures proving that structural parsing cannot bypass required
   toolchain preflight for configured Erlang projects.

**Deliverable:** the structural stage is deterministic and side-effect free;
an Erlang project operation still fails clearly when required tools are absent.

### Phase 2: Required adapters

1. Implement ELP targeted queries and its strict adapter manifest.
2. Implement xref module evidence and raw command diagnostics.
3. Implement Dialyzer diagnostic ingestion and PLT identity validation.
4. Implement one idempotent evidence reconciler shared by build, update, watch,
   forget, and standalone postprocess.
5. Implement revision/toolchain/PLT-keyed cache rejection.
6. Add tests for missing tools, version mismatches, invalid configuration,
   malformed output, timeouts, duplicate/conflicting evidence, stale caches,
   and strict non-fallback behaviour.

**Deliverable:** the normal review-context interface returns semantic results
only after all required adapters pass preflight.

### Phase 3: Review workflows and lifecycle parity

1. Feed ELP/xref/Dialyzer evidence into the existing review-context, impact,
   change-detection, callers, and tests-for queries.
2. Verify initial build, incremental update, watch, forget, and standalone
   postprocess converge to one graph/evidence contract.
3. Verify watch initialization cannot miss pending updates while structural or
   semantic work is running.
4. Bound result size and query work for large `server_flexible` changes.
5. Verify every lifecycle path returns the same blocking preflight diagnostics
   for the same invalid toolchain.

**Deliverable:** project review workflows are deterministic and fail closed on
toolchain problems.

### Phase 4: Real-project corpus and adoption gate

1. Freeze clean, fixed `server_flexible` revisions with complete manifests.
2. Cover local/remote callers, headers/records, behaviours, supervisor MFA,
   Common Test, EUnit, generated data, dynamic unresolved calls, and stale
   caches.
3. Record manually reviewed positive, negative, and intentionally unresolved
   expectations with evidence provenance.
4. Run every case from a clean cache and after incremental update, watch,
   forget, and standalone postprocess.
5. Publish repeatable precision, recall, impact, latency, and diagnostic
   reports. Do not promote Erlang to primary blocking-review evidence until
   every gate below is green.

**Deliverable:** a reproducible `server_flexible` evaluation report and an
explicit adoption decision.

## Adoption gates

Promotion requires all of the following on the fixed corpus and exact
toolchain:

- `100%` precision for every promoted relation kind;
- caller/dependent `Recall@10` of at least `90%`, separately for function and
  module relationships;
- no unexplained false-positive `TESTED_BY` or impact edges;
- every manually confirmed critical dependent appears in impact results;
- full-build and targeted-query p50/p95 latency fit the corpus budget;
- full-build, incremental, watch, forget, and standalone postprocess preserve
  the same relation/evidence contract;
- missing tools, version mismatches, malformed output, timeouts, stale caches,
  and PLT mismatches are observable blocking failures;
- no result is labeled current when its provenance or toolchain key differs.

Until then, document Erlang as navigation and auxiliary review context only;
it must not be the sole source for a blocking review decision.

## Verification

Record the exact command, revision, toolchain, PLT identity, cache state, and
elapsed time for each check. At minimum:

```text
CRG: full build, targeted callers/tests/impact/review-context queries
CRG: incremental update, watch, forget, standalone postprocess
ELP: cold-start and warm targeted query for every supported query kind
rebar3 xref: project-pinned invocation, structured evidence, raw diagnostics
Dialyzer: project-pinned invocation, matching PLT validation, raw diagnostics
pytest: focused Erlang/lifecycle suites and full hermetic suite
ruff and mypy: repository quality gates
```

Executed checks and blocked checks are reported separately. A tool that was
not run is not a passing result.

## Rollback

Disable the Erlang project integration at the CRG configuration boundary and
remove its derived evidence/cache. Do not restore the abandoned native
frontend. Non-Erlang graph functionality remains unaffected. Re-enabling
requires the complete preflight to pass again.

## Exit criteria for implementation

Before changing production review behaviour, the implementation must have:

1. A checked-in `server_flexible` repository/toolchain/generated-data/PLT
   manifest pinned to OTP `27.3.4.16`.
2. A deterministic structural Erlang stage and focused tests.
3. Strict ELP, xref, and Dialyzer adapter manifests with enforced execution
   boundaries and no Generic fallback.
4. Initial golden cases with manually reviewed expected results.
5. Baseline precision, Recall@10, impact, latency, and strict-preflight
   measurements.
6. A Beads issue for every adapter, lifecycle path, and adoption gate that
   remains open.
