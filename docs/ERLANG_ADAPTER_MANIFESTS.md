# Erlang Adapter Manifests

The files under `evaluate/erlang/adapters/` are checked-in execution contracts
for the Erlang Generic, ELP, `rebar3 xref`, and Dialyzer paths. The parent
`evaluate/erlang/server_flexible.manifest.json` names every child file. They are
review artifacts, not a second configuration language for the target project.

## What a manifest records

Every adapter manifest uses `schema_version: 1` and `kind:
erlang_adapter_manifest`. The sections have deliberately fixed meanings:

- `invocation` is an argv template, executable/subcommand allowlist, cwd, and
  environment allowlist. Shell execution is forbidden. Generic is explicitly
  in-process and has no command.
- `timeout` defines the default and hard maximum, the timeout return code, and
  the required bounded action.
- `failure` and `output.malformed` map missing tools, non-zero exits, timeouts,
  and malformed output to an observable status and diagnostic code. The
  fallback is always the Generic graph; adapter evidence is never promoted
  from malformed output.
- `provenance` lists the fields that must be attached to evidence and
  diagnostics. In particular, source/generated-data revisions, configuration,
  query scope, command, duration, and cache state are retained.
- `cache` documents the canonical SHA-256 key and stale-entry policy. The
  Dialyzer key additionally includes `plt_identity`.
- `sandbox` describes readable and writable roots, project/config-script
  execution, target-write policy, and network policy. `rebar3` tasks are called
  out because they can load plugins or populate `_build` in an unconstrained
  process.
- `enforcement` states whether the policy is actually enforced by the current
  runtime.

## Runtime status

The current `ELPAdapter`, `XrefAdapter`, and `DialyzerAdapter` already use
argv-only subprocesses, a repository cwd, a bounded timeout, a reduced
environment, revision-aware cache keys, and fail-soft diagnostics. They do not
yet load these checked-in manifests or install an OS-level sandbox around
`rebar3`/ELP. Their manifests therefore set
`runtime_policy_enforced: false`, `status: described_only`, and the common
`adapter_manifest_policy_not_enforced` diagnostic. `inspect_adapter_manifests`
reports this as `degraded`; an absent or invalid manifest is `unavailable`.

The Generic parser is in-process, does not execute project code or use the
network, and writes only CRG graph state. Its policy is marked `intrinsic`.
This distinction keeps a valid Generic-only fallback available while making an
un-enforced semantic boundary visible to evaluation and review tooling.

## Validation

Use the evaluator helpers to validate all checked-in files:

```python
from code_review_graph.eval.erlang import load_adapter_manifests, load_manifest

manifest = load_manifest()
adapters = manifest["_adapter_manifests"]
assert set(adapters) == {"generic", "elp", "xref", "dialyzer"}
```

`validate_adapter_manifest` rejects missing identity fields, shell commands,
absolute/escaping sandbox paths, unbounded external timeouts, incomplete cache
keys, and failure paths without observable diagnostics. Validation is strict
for safety and provenance fields while allowing additive metadata for future
tool versions.
