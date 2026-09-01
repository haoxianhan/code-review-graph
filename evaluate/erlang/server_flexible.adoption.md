# Erlang Adoption Evaluation: server_flexible

- Verdict: `auxiliary`
- Pass: `false`
- Target revision: `bff80c584614b455faf0b21eef9362980bec1c55` (`origin/develop`)
- Generated-data revision: `59381`
- Clean baseline: `true`
- Read-only target: `true`

This is the current strict-policy evaluation of the fixed `server_flexible`
revision. The target checkout and submodule gitlinks matched the manifest. CRG
did not modify the target repository, generated outputs, or project
configuration. The run used a disposable checkout at the pinned revision and
read the runtime key from the configured `.self_key` path without recording
its contents.

## Toolchain

The required baseline was available during preflight:

| Component | Observed |
| --- | --- |
| Erlang/OTP | `27.3.4.16` (`ERTS 15.2.7.12`) |
| `rebar3` | `3.27.0` |
| Dialyzer | `5.3.1.1` |
| ELP CLI | `1.1.0+build-2026-01-15` |
| Dialyzer PLT | `_build/dialyzer/.dialyzer.plt`, SHA256 `c971c38076838b17bf014a15342c993e18cdb001cef637f8f42a972bd83e46f2` |

Generated-data markers were present and consistent with the manifest:
`DATA_REV=59381` and structure revision `59381`.

The target was prepared with the project-authoritative commands
`./xserver.sh compile`, `./xserver.sh dialyzer`, and `rebar3 xref`. CRG did
not modify the consumer checkout; generated outputs and the project PLT were
observed as baseline inputs.

## Corpus

The corpus covers local and remote callers, headers/records, behaviours,
supervisor MFA, Common Test, EUnit, generated data, unresolved dynamic calls,
and stale-cache cases. All eight cases executed on this fixed baseline with
precision `1.0`, aggregate recall `1.0`, function/module Recall@10 `1.0`, zero
forbidden matches, and impact coverage `1.0`.

## Lifecycle And Adoption

Required ELP, xref, and Dialyzer adapters all executed successfully with valid
provenance. Full build, incremental update, forget, and standalone postprocess
produced evidence. A real watch smoke against the disposable checkout reached
processing but did not stop before the bounded 900-second window.

| Gate | Result | Evidence |
| --- | --- | --- |
| Required tools available | pass | ELP, xref/rebar3, Dialyzer, and matching PLT were available |
| Generated-data consistency | pass | `DATA_REV=59381` matched the manifest |
| Full build | pass | authoritative `./xserver.sh compile` completed |
| Corpus precision/recall/impact | pass | 8/8 cases executed; all relation and impact gates passed |
| Required semantic adapters | pass | ELP, xref, and Dialyzer executed with valid provenance |
| Incremental/forget/postprocess | pass | evidence and parity checks completed |
| Watch | fail | smoke did not stop before 900 seconds after an update |
| Latency budget | fail | full build p50 `484.452s`; incremental p50 `873.735s`; budget is `30s` |
| Adoption | auxiliary | lifecycle parity and latency gates are incomplete |

The adoption verdict remains `auxiliary_review_context_only`. Erlang is not a
sole source of blocking-review evidence until every gate in
`erlang-support-plan.md` is green.

## Diagnostics

- `project_config_script_not_executed` (info): `rebar.config.script` was
  intentionally not executed during discovery.
- `watch_stop_timeout` (error): the real disposable watch smoke did not stop
  before the configured 900-second bound after a source update.
- `latency_budget_exceeded` (warning): project preparation and semantic
  lifecycle work exceed the current corpus latency budget.

The successful evaluation used
`/tmp/crg-server-flexible-develop-latest-bff80` with `GIT_BRANCH=develop` and
`CLIENT_DATA_COMMIT_ID=59381`. The consumer checkout was not modified. The
watch failure was isolated to an evaluator-owned temporary mirror.

## Reproduction

Inputs:

- `server_flexible.manifest.json`
- `corpus.json`
- `server_flexible.performance.json`

```text
.venv/bin/code-review-graph eval --erlang-adoption --manifest evaluate/erlang/server_flexible.manifest.json --corpus evaluate/erlang/corpus.json --target-root /tmp/crg-server-flexible-develop-latest-bff80 --probe-root . --timeout 900 --json
```
