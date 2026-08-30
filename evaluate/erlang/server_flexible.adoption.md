# Erlang Adoption Evaluation: server_flexible

This report evaluates the fixed `server_flexible` revision
`bc8a4424ffd70006ba482f15aa7c61199af34b71` with generated-data revision
`35021`. The target checkout was clean and its submodule gitlinks matched the
manifest. The target was read-only throughout the evaluation.

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

The complete evaluator was run against the same clean pinned checkout twice:
once with isolated watch smoke and once with watch disabled. The runs did not
produce a final envelope before the 20-minute and 15-minute bounded timeouts;
one run also emitted a `closed database` warning from the best-effort Erlang
header resolver. Therefore full-build, incremental, forget, standalone
postprocess, and lifecycle parity are not claimed by this report. The isolated
watch smoke itself is covered by the committed watch smoke test and focused
Erlang lifecycle suite.

The performance report records a full-build p95 of `55,398.869 ms` against the
`30,000 ms` budget. One-file incremental was `49,206.366 ms`, restore update
`48,900.230 ms`, and no-op update `24,334.089 ms`; layout-only was not run.

ELP, `erlang_ls`, and `elp-ls` were unavailable. Runtime OTP 27 differed from
the manifest's configured OTP 25, and adapter runtime sandbox policy remains
descriptive rather than enforced. The adoption verdict is therefore
`auxiliary_review_context_only`; Erlang is not a sole blocking-review source.

Reproduction inputs:

- `server_flexible.manifest.json`
- `corpus.json`
- `server_flexible.performance.json`
- `CRG_SERIAL_PARSE=1 .venv/bin/python -m code_review_graph.eval.erlang_adoption --manifest evaluate/erlang/server_flexible.manifest.json --corpus evaluate/erlang/corpus.json --target /tmp/crg-server-flexible-pinned-1788067717 --probe-root . --output-dir /tmp/crg-adoption-report-core`
