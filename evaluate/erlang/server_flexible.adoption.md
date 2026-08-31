# Erlang Adoption Evaluation: server_flexible

- Verdict: `blocked`
- Pass: `false`
- Target revision: `fd65517bb3d359d489520f1b3630493144962482`
- Generated-data revision: `53569`
- Clean baseline: `true`
- Read-only target: `true`

This is the current strict-policy evaluation of the fixed `server_flexible`
revision. The target checkout and submodule gitlinks matched the manifest. CRG
did not modify the target repository, generated outputs, or project
configuration.

## Toolchain

The required baseline was available during preflight:

| Component | Observed |
| --- | --- |
| Erlang/OTP | `27.3.4.16` (`ERTS 15.2.7.12`) |
| `rebar3` | `3.27.0` |
| Dialyzer | `5.3.1.1` |
| ELP CLI | `1.1.0+build-2026-01-15` |
| Dialyzer PLT | `_build/default/rebar3_27.3.4.16_plt`, SHA256 `e926642461efeadc3e571a2225d2c0ac69181a259d11946d608a658783e8254a` |

Generated-data markers were present and consistent: `DATA_REV=53569`,
structure revision `53569`, and config version
`2cdad7c1e46279b6a6275058ee344b86`.

## Corpus

The corpus declares local and remote callers, headers/records, behaviours,
supervisor MFA, Common Test, EUnit, generated data, unresolved dynamic calls,
and stale-cache cases. The corpus run was not reached because strict semantic
preflight rejected the project-level xref result. Consequently precision,
recall, Recall@10, impact coverage, and targeted latency are unmeasured in
this current run; no historical metric is carried forward as current evidence.

## Lifecycle And Adoption

The full-build lifecycle reached the required adapter preflight and executed
`rebar3 xref`, but xref returned non-zero after reporting the project's
undefined-call warnings. Strict policy treats that result as a blocking
`xref_failed` error. The lifecycle stopped before semantic adapter envelopes
could be verified, so incremental update, watch, forget, standalone
postprocess, and lifecycle parity were not run.

| Gate | Result | Reason |
| --- | --- | --- |
| Required tools available | pass | ELP, xref/rebar3, Dialyzer, and matching PLT were available |
| Generated-data consistency | pass | `DATA_REV=53569` and config markers matched the manifest |
| Full build | blocked | `erlang_semantic_execution_blocked`, `xref_failed` |
| Corpus precision/recall/impact | not run | full build was blocked before corpus queries |
| Incremental/watch/forget/postprocess | not run | lifecycle execution stopped at full build |
| Adoption | blocked | required semantic lifecycle and all adoption gates are incomplete |

The adoption verdict remains `auxiliary_review_context_only`. Erlang is not a
sole source of blocking-review evidence until every gate in
`erlang-support-plan.md` is green.

## Blocking Diagnostics

- `project_config_script_not_executed` (info): `rebar.config.script` was
  intentionally not executed during discovery.
- `full_build_failed` (error): full build failed with
  `RuntimeError: Erlang strict preflight blocked operation
  (erlang_semantic_execution_blocked, xref_failed)`.
- `graph_build_failed` (error): the same strict xref failure prevented graph
  construction and all downstream evaluation.

## Reproduction

Inputs:

- `server_flexible.manifest.json`
- `corpus.json`
- `server_flexible.performance.json`

Command used for the current report:

```text
CRG_SERIAL_PARSE=1 .venv/bin/python -m code_review_graph.eval.erlang_adoption --manifest evaluate/erlang/server_flexible.manifest.json --corpus evaluate/erlang/corpus.json --target /tmp/crg-server-flexible-exec2.1My0wH --probe-root . --output-dir /tmp/crg-adoption-report-final
```
