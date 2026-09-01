# Erlang Adoption Evaluation: server_flexible

- Verdict: `blocked`
- Pass: `false`
- Target revision: `db6f93e95b432efcd1e337159fc3e4a235084476` (`origin/develop`)
- Generated-data revision: `57057`
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
| Dialyzer PLT | `_build/dialyzer/.dialyzer.plt`, SHA256 `1730142f65c9296c34079f4242c7d7f08f1740fe6d619cf976f4b3abc4240a01` |

Generated-data markers were present and consistent: `DATA_REV=57057`,
structure revision `57057`, and config version
`a85752be96544fcc5518e193b4397c51`.

The target was prepared in a disposable worktree with the project-authoritative
commands `./xserver.sh compile` and `./xserver.sh dialyzer`. CRG does not modify
the consumer checkout; generated outputs and the project PLT are observed as
baseline inputs. `./xserver.sh dialyzer` includes the project compile step and
produced the matching `_build/dialyzer/.dialyzer.plt`.

## Corpus

The corpus declares local and remote callers, headers/records, behaviours,
supervisor MFA, Common Test, EUnit, generated data, unresolved dynamic calls,
and stale-cache cases. It has not yet been rerun on this fixed develop/data
baseline. Consequently precision, recall, Recall@10, impact coverage, and
targeted latency are unmeasured in this current run; no historical metric is
carried forward as current evidence.

## Lifecycle And Adoption

The prior lifecycle result was invalidated because it used a stale revision and
treated xref's warning exit code as command failure. The adapter now preserves
xref diagnostics when analysis completed and only blocks on an execution or
malformed-output failure. A complete lifecycle rerun on the fixed
`db6f93e95b432efcd1e337159fc3e4a235084476`/`57057` baseline is still required.

| Gate | Result | Reason |
| --- | --- | --- |
| Required tools available | pass | ELP, xref/rebar3, Dialyzer, and matching PLT were available |
| Generated-data consistency | pass | `DATA_REV=57057` and config markers matched the manifest |
| Full build | blocked | `./xserver.sh compile` failed during required P4 preparation (`P4 未登录`; `p4 login -s` could not reach `192.168.110.82:1667`) |
| Corpus precision/recall/impact | not run | fixed baseline rerun remains pending |
| Incremental/watch/forget/postprocess | not run | fixed baseline lifecycle rerun remains pending |
| Adoption | blocked | required semantic lifecycle and all adoption gates are incomplete |

The adoption verdict remains `auxiliary_review_context_only`. Erlang is not a
sole source of blocking-review evidence until every gate in
`erlang-support-plan.md` is green.

## Blocking Diagnostics

- `project_config_script_not_executed` (info): `rebar.config.script` was
  intentionally not executed during discovery.
- `project_compile_failed` (error): required `./xserver.sh compile` stopped at
  the project's P4 preparation step because the P4 session/server was not
  available. No semantic adapter was launched after this failure.
- `lifecycle_rerun_required` (warning): incremental, watch, forget, and
  standalone postprocess remain unmeasured until the project preparation
  prerequisite is available.

The failed attempt was made in `/tmp/crg-server-flexible-develop-20260901163430`
with `GIT_BRANCH=develop` and `CLIENT_DATA_COMMIT_ID=57057`. The consumer
checkout was not modified. Before retrying, the build environment must provide
an authenticated, reachable P4 session for the project-required generation
step; bypassing `./xserver.sh compile` would invalidate this baseline.

## Reproduction

Inputs:

- `server_flexible.manifest.json`
- `corpus.json`
- `server_flexible.performance.json`

Command used for the current report:

```text
CRG_SERIAL_PARSE=1 .venv/bin/python -m code_review_graph.eval.erlang_adoption --manifest evaluate/erlang/server_flexible.manifest.json --corpus evaluate/erlang/corpus.json --target /tmp/crg-server-flexible-exec2.1My0wH --probe-root . --output-dir /tmp/crg-adoption-report-final
```
