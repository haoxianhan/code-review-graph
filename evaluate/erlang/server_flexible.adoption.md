# Erlang Adoption Evaluation: server_flexible

This report evaluates the fixed `server_flexible` revision
`bc8a4424ffd70006ba482f15aa7c61199af34b71` with generated-data revision
`35021`. The target checkout was clean and its submodule gitlinks matched the
manifest. The target was read-only throughout the evaluation.

The current required toolchain baseline is OTP `27.3.4.16` (ERTS
`15.2.7.12`), `rebar3` `3.27.0`, Dialyzer `5.3.1.1`, and ELP CLI
`1.1.0+build-2026-01-15`. The historical report below predates the ELP
installation and is retained as a measurement record; it is not evidence that
the current strict preflight has passed.

## Corpus

The checked-in corpus contains manually reviewed callers, header/record,
behaviour, supervisor MFA, Common Test, EUnit, generated-data, unresolved,
fallback, and stale-cache cases. Against the existing pinned graph profile
(`/tmp/crg-profile.db`, 1,099 files, 47,694 nodes, 131,175 edges), the eight
resolved relation cases produced:

| Metric | Result | Gate |
| --- | ---: | --- |
| Resolved relation precision | 1.0 | pass |
| Resolved relation recall | 1.0 | pass |
| Function Recall@10 | 1.0 | pass |
| Module Recall@10 | 1.0 | pass |
| Impact coverage (depth 1) | 1.0 | pass |
| Forbidden relation matches | 0 | pass |
| Targeted-query p95 | 299.096 ms | pass, budget 2,000 ms |

The unresolved case retained one `CALLS` candidate for
`cfg_account_bag:find/1`. The fallback case observed `elp_unavailable`; the
stale-cache case observed two `CACHE_REJECTED` records for unkeyed generated
artifacts.

## Lifecycle And Adoption

The post-optimization lifecycle probe used disposable copies of the same clean
pinned checkout. Three full-build samples (including the full postprocess
boundary) were `28.169`, `27.448`, and `26.949 s`; the interpolated p95 is
`28.097 s`, below the `30 s` budget. Three one-file incremental samples were
`5.689`, `5.416`, and `5.091 s`, and two no-op samples were `0.233` and
`0.237 s`. A standalone postprocess sample was `10.403 s`. These measurements
cover the optimized stage behavior, but a complete evaluator rerun covering
watch, forget, and all lifecycle parity checks was not completed, so those
adoption gates remain unverified.

The performance report records the post-optimization samples and the commit
that produced them in `server_flexible.performance.json`. Restore-to-HEAD and
layout-only were not run in this pass.

The target's `erlang_ls.config` still references the historical OTP 25 path,
and the current checkout has a dirty `apps/server_mongodb` submodule. Adapter
runtime sandbox policy remains descriptive rather than enforced, and the
strict required-adapter lifecycle has not been rerun after installing ELP. The
adoption verdict remains `auxiliary_review_context_only`; Erlang is not a sole
blocking-review source.

Reproduction inputs:

- `server_flexible.manifest.json`
- `corpus.json`
- `server_flexible.performance.json`
- `CRG_SERIAL_PARSE=1 .venv/bin/python -m code_review_graph.eval.erlang_adoption --manifest evaluate/erlang/server_flexible.manifest.json --corpus evaluate/erlang/corpus.json --target /tmp/crg-server-flexible-pinned-1788067717 --probe-root . --output-dir /tmp/crg-adoption-report-core`
