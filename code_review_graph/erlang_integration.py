"""Lifecycle integration for optional Erlang semantic enrichment.

The Erlang parser is useful without any external tools.  This module is the
small, opt-in bridge for deployments that also want ELP, ``rebar3 xref`` or
Dialyzer evidence.  It deliberately keeps the adapter boundary separate from
the normal parser and query code:

* Generic indexing is never gated on this module.
* Disabled integration returns before toolchain discovery (and therefore
  never starts a subprocess).
* Semantic snapshots are persisted with their complete analysis key.
* Only evidence with two unique, repository-local endpoints is projected into
  ordinary graph edges.  Module-level xref facts remain module-level.

The lifecycle entry points can call :func:`run_erlang_integration` after a
build, incremental update, watch notification, or standalone postprocess.
The function is intentionally idempotent: generated ordinary edges are marked
and restored/removed before a fresh projection is written.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import time
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

from .erlang_semantic import (
    STATUS_DEGRADED,
    STATUS_FAILED,
    STATUS_MISMATCH,
    STATUS_OK,
    STATUS_STALE,
    STATUS_UNAVAILABLE,
    AnalysisKey,
    Diagnostic,
    EnrichmentQuery,
    EnrichmentResult,
    EvidenceCache,
    EvidenceRecord,
    Provenance,
    ToolchainIdentity,
    run_erlang_enrichment,
)
from .graph import GraphNode, GraphStore
from .parser import (
    EdgeInfo,
    normalize_erlang_atom,
    normalize_file_path,
    parse_erlang_mfa,
)

logger = logging.getLogger(__name__)

__all__ = [
    "ErlangIntegrationConfig",
    "ErlangIntegrationResult",
    "erlang_integration_requested",
    "maybe_run_erlang_integration",
    "run_erlang_integration",
]


_DEFAULT_TIMEOUT = 15.0
_MAX_TARGETS = 256
_MAX_EVIDENCE = 2_000
_MAX_PROVENANCE_CHARS = 8_000
_MAX_METADATA_CHARS = 32_000
_PROJECTION_MARKER = "_crg_erlang_semantic"
_PROJECTION_OWNED = "_crg_erlang_projection_owned"
_PROJECTION_ORIGINAL_EXTRA = "_crg_erlang_original_extra"
_STATUS_METADATA_KEY = "erlang_integration_status"
_SUMMARY_METADATA_KEY = "erlang_integration_summary"
_PROJECTION_ORIGINAL_TARGET = "_crg_erlang_original_target"
_PROJECTION_ORIGINAL_CONFIDENCE = "_crg_erlang_original_confidence"
_PROJECTION_ORIGINAL_TIER = "_crg_erlang_original_tier"
_PROJECTION_RELATIONS = frozenset(
    {"CALLS", "TESTED_BY", "IMPLEMENTS", "REFERENCES", "DEPENDS_ON"}
)
_ERLANG_TOOLS = frozenset({"elp", "xref", "dialyzer"})
_ERLANG_ENV_KEYS = frozenset(
    {
        "CRG_ERLANG_ENABLED",
        "CRG_ERLANG_QUERIES",
        "CRG_ERLANG_XREF",
        "CRG_ERLANG_DIALYZER",
        "CRG_ERLANG_CACHE_DIR",
        "CRG_ERLANG_TIMEOUT",
        "CRG_ERLANG_EXPECTED_OTP",
        "CRG_ERLANG_EXPECTED_OTP_VERSION",
        "CRG_ERLANG_PLT_PATH",
    }
)
_TRUE_VALUES = frozenset({"1", "true", "yes", "on", "enable", "enabled"})
_FALSE_VALUES = frozenset({"0", "false", "no", "off", "disable", "disabled"})
_MFA_RE = re.compile(r"^(?:(?P<module>[^:/]+):)?(?P<name>[^/]+)/(?P<arity>\d+)$")


def _canonical_root(value: str | Path) -> Path:
    try:
        return Path(value).expanduser().resolve(strict=False)
    except (OSError, RuntimeError, ValueError):
        return Path(value).expanduser().absolute()


def _scoped_metadata_key(base: str, root: Path) -> str:
    """Return a collision-resistant metadata key for one repository root."""
    identity = normalize_file_path(_canonical_root(root))
    digest = hashlib.sha256(identity.encode("utf-8")).hexdigest()
    return f"{base}:{digest[:32]}"


def _bounded_timeout(value: Any) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError, OverflowError):
        return _DEFAULT_TIMEOUT
    if parsed <= 0 or parsed != parsed or parsed == float("inf"):
        return _DEFAULT_TIMEOUT
    return min(parsed, 300.0)


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    normalized = raw.strip().casefold()
    if normalized in _TRUE_VALUES:
        return True
    if normalized in _FALSE_VALUES:
        return False
    return default


def _coerce_bool(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        normalized = value.strip().casefold()
        if normalized in _TRUE_VALUES:
            return True
        if normalized in _FALSE_VALUES:
            return False
    return default


def _normalise_target_values(value: Any) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        values: Sequence[Any] = (value,)
    else:
        try:
            values = tuple(value)
        except TypeError:
            values = (value,)
    return tuple(
        sorted(
            {
                str(item).strip()
                for item in values
                if str(item).strip()
            }
        )[:_MAX_TARGETS]
    )


def _normalise_queries(value: Any) -> tuple[EnrichmentQuery, ...]:
    """Coerce config/environment query forms to deterministic query objects."""
    if value is None or value == () or value == []:
        return ()
    if isinstance(value, Mapping):
        discriminator = {"tool", "query_kind", "kind", "query"}
        if discriminator.intersection(value):
            values: list[Any] = [value]
        else:
            values = [
                EnrichmentQuery("elp", str(kind), _normalise_target_values(targets))
                for kind, targets in value.items()
            ]
    elif isinstance(value, str):
        text = value.strip()
        if not text:
            return ()
        # Environment values conventionally use commas.  A JSON list is also
        # accepted so callers can preserve a target list containing commas.
        if text.startswith("["):
            try:
                parsed = json.loads(text)
            except (TypeError, ValueError, json.JSONDecodeError):
                parsed = None
            if isinstance(parsed, list):
                values = parsed
            else:
                values = [part for part in text.split(",") if part.strip()]
        else:
            values = [part for part in text.split(",") if part.strip()]
    elif isinstance(value, EnrichmentQuery):
        values = [value]
    elif isinstance(value, tuple) and len(value) in {2, 3} and all(
        isinstance(item, str) for item in value[:2]
    ) and value[0].casefold() in _ERLANG_TOOLS:
        values = [value]
    else:
        try:
            values = list(value)
        except TypeError:
            values = [value]

    result: dict[tuple[str, str, tuple[str, ...]], EnrichmentQuery] = {}
    for raw in values:
        try:
            query = raw if isinstance(raw, EnrichmentQuery) else EnrichmentQuery.from_value(raw)
        except (TypeError, ValueError):
            logger.warning("Ignoring malformed Erlang enrichment query: %r", raw)
            continue
        result[(query.tool, query.query_kind, query.targets)] = query
    return tuple(result[key] for key in sorted(result))


@dataclass(frozen=True)
class ErlangIntegrationConfig:
    """Opt-in settings for :func:`run_erlang_integration`.

    ``enabled`` intentionally defaults to ``False``.  A caller must either
    set it explicitly or set ``CRG_ERLANG_ENABLED``; merely having an OTP
    installation on ``PATH`` never causes project commands to run.
    """

    enabled: bool = False
    queries: tuple[EnrichmentQuery, ...] = ()
    include_xref: bool = False
    include_dialyzer: bool = False
    cache_dir: str | Path | None = None
    timeout: float = _DEFAULT_TIMEOUT
    expected_otp: str | None = None
    plt_path: str | Path | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "enabled", _coerce_bool(self.enabled))
        object.__setattr__(self, "queries", _normalise_queries(self.queries))
        object.__setattr__(self, "include_xref", _coerce_bool(self.include_xref))
        object.__setattr__(self, "include_dialyzer", _coerce_bool(self.include_dialyzer))
        object.__setattr__(self, "timeout", _bounded_timeout(self.timeout))
        if self.expected_otp is not None:
            value = str(self.expected_otp).strip()
            object.__setattr__(self, "expected_otp", value or None)

    @classmethod
    def from_environment(cls) -> "ErlangIntegrationConfig":
        """Read explicit opt-in settings from ``CRG_ERLANG_*`` variables."""
        queries = os.environ.get("CRG_ERLANG_QUERIES", "")
        expected_otp = (
            os.environ.get("CRG_ERLANG_EXPECTED_OTP")
            or os.environ.get("CRG_ERLANG_EXPECTED_OTP_VERSION")
        )
        return cls(
            enabled=_env_bool("CRG_ERLANG_ENABLED", False),
            queries=queries,
            include_xref=_env_bool("CRG_ERLANG_XREF", False),
            include_dialyzer=_env_bool("CRG_ERLANG_DIALYZER", False),
            cache_dir=os.environ.get("CRG_ERLANG_CACHE_DIR") or None,
            timeout=os.environ.get("CRG_ERLANG_TIMEOUT", _DEFAULT_TIMEOUT),
            expected_otp=expected_otp,
            plt_path=os.environ.get("CRG_ERLANG_PLT_PATH") or None,
        )

    # Short alias useful to callers that use the conventional name.
    from_env = from_environment

    @classmethod
    def from_value(cls, value: Any) -> "ErlangIntegrationConfig":
        if value is None:
            return cls.from_environment()
        if isinstance(value, cls):
            return value
        if not isinstance(value, Mapping):
            raise TypeError("Erlang integration config must be a mapping or config object")
        aliases = {
            "expected_otp_version": "expected_otp",
            "elp_expected_otp": "expected_otp",
            "xref": "include_xref",
            "dialyzer": "include_dialyzer",
            "cache": "cache_dir",
        }
        fields = {
            "enabled",
            "queries",
            "include_xref",
            "include_dialyzer",
            "cache_dir",
            "timeout",
            "expected_otp",
            "plt_path",
        }
        values: dict[str, Any] = {}
        for key, item in value.items():
            canonical = aliases.get(str(key), str(key))
            if canonical in fields:
                values[canonical] = item
        return cls(**values)

    def to_dict(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "queries": [query.to_dict() for query in self.queries],
            "include_xref": self.include_xref,
            "include_dialyzer": self.include_dialyzer,
            "cache_dir": str(self.cache_dir) if self.cache_dir is not None else None,
            "timeout": self.timeout,
            "expected_otp": self.expected_otp,
            "plt_path": str(self.plt_path) if self.plt_path is not None else None,
        }


@dataclass(frozen=True)
class ErlangIntegrationResult:
    """Bounded, serializable result returned by the integration boundary."""

    status: str
    evidence: tuple[EvidenceRecord, ...] = ()
    diagnostics: tuple[Diagnostic, ...] = ()
    provenance: Mapping[str, Any] = field(default_factory=dict)
    counts: Mapping[str, int] = field(default_factory=dict)
    toolchain: ToolchainIdentity | None = None

    @property
    def ok(self) -> bool:
        return self.status in {STATUS_OK, "disabled", "skipped"}

    @property
    def evidence_count(self) -> int:
        return len(self.evidence)

    @property
    def diagnostic_count(self) -> int:
        return len(self.diagnostics)

    def to_dict(self) -> dict[str, Any]:
        value: dict[str, Any] = {
            "status": self.status,
            "evidence": [item.to_dict() for item in self.evidence[:_MAX_EVIDENCE]],
            "diagnostics": [item.to_dict() for item in self.diagnostics[:_MAX_EVIDENCE]],
            "provenance": _bounded_json_value(dict(self.provenance), _MAX_PROVENANCE_CHARS),
            "counts": {str(key): int(item) for key, item in self.counts.items()},
        }
        if self.toolchain is not None:
            value["toolchain"] = self.toolchain.to_dict()
        return value


def erlang_integration_requested(
    config: ErlangIntegrationConfig | Mapping[str, Any] | None = None,
    *,
    run_erlang: bool | None = None,
) -> bool:
    """Return whether a lifecycle caller explicitly requested Erlang work.

    An omitted configuration is deliberately different from an explicit
    disabled config.  This lets ordinary Generic builds preserve semantic
    state while still allowing ``CRG_ERLANG_ENABLED=0`` (or
    ``ErlangIntegrationConfig(enabled=False)``) to perform cleanup.
    """
    if run_erlang is not None:
        return bool(run_erlang)
    if config is not None:
        return True
    # Configuration knobs other than ENABLED are inert until the caller makes
    # an explicit opt-in.  Treating (for example) a timeout-only environment
    # as an invocation would parse the default ``enabled=False`` config and
    # destructively clear valid semantic evidence.  An explicit ENABLED=0 is
    # still a requested lifecycle pass so it can perform intentional cleanup.
    return "CRG_ERLANG_ENABLED" in os.environ


def maybe_run_erlang_integration(
    repo_root: str | Path,
    store: GraphStore,
    *,
    config: ErlangIntegrationConfig | Mapping[str, Any] | None = None,
    run_erlang: bool | None = None,
    changed_files: Iterable[str] | None = None,
    query_targets: str | Sequence[str] | None = None,
    toolchain: ToolchainIdentity | None = None,
    runner: Any | None = None,
) -> ErlangIntegrationResult | None:
    """Run the optional bridge only when a caller explicitly opts in.

    Adapter failures are represented as a degraded result so a Generic build
    remains usable.  ``KeyboardInterrupt``/``SystemExit`` are intentionally
    allowed to reach the caller.
    """
    if not erlang_integration_requested(config, run_erlang=run_erlang):
        return None
    try:
        return run_erlang_integration(
            repo_root,
            store,
            config=config,
            changed_files=changed_files,
            query_targets=query_targets,
            toolchain=toolchain,
            runner=runner,
        )
    except Exception as exc:  # Optional enrichment must not break Generic data.
        root = _canonical_root(repo_root)
        logger.warning("Erlang integration failed at lifecycle boundary: %s", exc)
        return _failure_result(
            root,
            code="erlang_lifecycle_failed",
            message=f"Erlang integration failed: {type(exc).__name__}: {exc}",
        )


def _bounded_json_value(value: Any, max_chars: int) -> Any:
    """Keep metadata summaries finite without affecting typed evidence."""
    try:
        serialized = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    except (TypeError, ValueError):
        return {}
    if len(serialized) <= max_chars:
        return value
    # Summaries are diagnostic metadata, so retaining a deterministic marker is
    # more useful than truncating in the middle of JSON.
    return {
        "truncated": True,
        "sha256": hashlib.sha256(serialized.encode()).hexdigest(),
    }


def _base_provenance(
    root: Path,
    *,
    status: str,
    toolchain: ToolchainIdentity | None,
) -> dict[str, Any]:
    if toolchain is None:
        return {"repository": normalize_file_path(root), "status": status}
    value = toolchain.to_dict()
    value.update({"status": status, "fingerprint": toolchain.fingerprint})
    return value


def _lifecycle_provenance(
    root: Path,
    *,
    status: str,
    query_kind: str = "lifecycle",
) -> Provenance:
    """Build a bounded provenance record when no usable toolchain exists."""
    key = AnalysisKey(
        repository=normalize_file_path(root),
        source_revision=None,
        generated_data_revision=None,
        configuration_digest=None,
        tool="erlang_integration",
        tool_version=None,
        otp_version=None,
        query_kind=query_kind,
        query_targets=(),
    )
    return Provenance.from_key(key, source="erlang_integration", status=status)


def _make_diagnostic(
    toolchain: ToolchainIdentity,
    *,
    tool: str,
    query_kind: str,
    code: str,
    message: str,
    status: str = STATUS_FAILED,
    metadata: Mapping[str, Any] | None = None,
) -> Diagnostic:
    key = AnalysisKey.from_toolchain(toolchain, tool, query_kind)
    provenance = Provenance.from_key(key, source="erlang_integration", status=status)
    return Diagnostic(
        code=code,
        message=message[:2_000],
        provenance=provenance,
        severity="warning" if status not in {STATUS_STALE, STATUS_UNAVAILABLE} else "info",
        metadata=dict(metadata or {}),
    )


def _snapshot_records_status(
    store: GraphStore,
    root: Path,
) -> tuple[tuple[EvidenceRecord, ...], tuple[Diagnostic, ...], bool]:
    """Read prior Erlang records without allowing storage failures to escape.

    The boolean distinguishes an empty snapshot from a failed read.  An empty
    snapshot is a normal first run; a failed read means existing semantic
    projections must be left untouched until the store is readable again.
    """
    try:
        snapshot = store.get_semantic_snapshot(repository=normalize_file_path(root))
    except Exception as exc:  # SQLite and backend-specific errors are optional-path failures.
        logger.warning("Could not read Erlang semantic snapshot: %s", exc)
        return (), (), True
    raw_evidence = snapshot.get("evidence", ()) if isinstance(snapshot, Mapping) else ()
    raw_diagnostics = snapshot.get("diagnostics", ()) if isinstance(snapshot, Mapping) else ()
    evidence = tuple(
        item
        for item in raw_evidence
        if isinstance(item, EvidenceRecord) and item.provenance.tool.casefold() in _ERLANG_TOOLS
    )
    diagnostics = tuple(
        item
        for item in raw_diagnostics
        if isinstance(item, Diagnostic) and item.provenance.tool.casefold() in _ERLANG_TOOLS
    )
    return evidence, diagnostics, False


def _snapshot_records(
    store: GraphStore,
    root: Path,
) -> tuple[tuple[EvidenceRecord, ...], tuple[Diagnostic, ...]]:
    """Compatibility wrapper for callers that only need decoded records."""
    evidence, diagnostics, _failed = _snapshot_records_status(store, root)
    return evidence, diagnostics


def _path_target(root: Path, value: str) -> str:
    candidate = Path(value)
    if not candidate.is_absolute():
        candidate = root / candidate
    return normalize_file_path(candidate)


def _collect_changed_targets(
    store: GraphStore,
    root: Path,
    changed_files: Iterable[str] | None,
) -> tuple[str, ...]:
    targets: set[str] = set()
    for raw in changed_files or ():
        value = str(raw).strip()
        if not value:
            continue
        # A qualified symbol is already a useful ELP target.  Existing files
        # are handled below; this branch also accepts ``module:function/arity``.
        if "::" in value and not Path(value).exists():
            targets.add(value)
            continue
        path = _path_target(root, value)
        try:
            nodes = store.get_nodes_by_file(path)
        except Exception:
            nodes = []
        for node in nodes:
            if getattr(node, "language", "").casefold() != "erlang":
                continue
            # Module ``Class`` nodes identify a container, not a callable
            # target.  ELP's targeted enrichment path should receive changed
            # function/test/type identities; module-level work is owned by
            # the explicit xref option or an explicit query target.
            if getattr(node, "kind", "") in {"Function", "Test", "Type"}:
                targets.add(str(node.qualified_name))
        if not nodes and (":" in value or "::" in value):
            targets.add(value)
    return tuple(sorted(targets)[:_MAX_TARGETS])


def _query_values(
    config: ErlangIntegrationConfig,
    *,
    changed_targets: tuple[str, ...],
    query_targets: str | Sequence[str] | None,
) -> tuple[EnrichmentQuery, ...]:
    explicit_targets = _normalise_target_values(query_targets)
    derived = tuple(sorted(set(explicit_targets) | set(changed_targets)))
    values: list[EnrichmentQuery] = []
    for query in config.queries:
        if query.tool == "elp" and not query.targets and derived:
            values.append(EnrichmentQuery(query.tool, query.query_kind, derived))
        else:
            values.append(query)
    if explicit_targets and not any(
        item.tool == "elp" and item.targets == explicit_targets for item in values
    ):
        values.append(EnrichmentQuery("elp", "enrichment", explicit_targets))
    # Lifecycle callers pass changed files rather than hand-writing query
    # specs.  Keep that path targeted: a changed Erlang function gets one
    # bounded enrichment query, while a full build with no explicit targets
    # remains a no-op for optional tooling.
    if not values and changed_targets:
        values.append(EnrichmentQuery("elp", "enrichment", changed_targets))
    unique = {(item.tool, item.query_kind, item.targets): item for item in values}
    return tuple(unique[key] for key in sorted(unique))


def _module_name(node: GraphNode) -> str | None:
    extra = node.extra if isinstance(node.extra, Mapping) else {}
    # Parser File nodes keep ``erlang_module`` for file metadata.  Only the
    # module Class node is a valid endpoint for module-level evidence.
    if node.kind != "Class" or extra.get("erlang_kind") != "module":
        return None
    value = extra.get("erlang_module")
    if isinstance(value, str) and value:
        return value
    return node.name or None


def _node_belongs_to_root(node: GraphNode, root: Path | None) -> bool:
    """Return whether an Erlang graph node belongs to the requested checkout."""
    if root is None:
        return True
    raw_path = getattr(node, "file_path", None)
    if not isinstance(raw_path, str) or not raw_path:
        return False
    expected = _canonical_root(root)
    value = normalize_file_path(raw_path)
    # ``Path.is_absolute`` on POSIX does not recognize a Windows drive path;
    # compare those spellings textually so a graph moved between hosts still
    # cannot leak same-named MFA endpoints across repositories.
    if re.match(r"^[A-Za-z]:/", value):
        expected_value = normalize_file_path(expected).casefold().rstrip("/")
        value_folded = value.casefold().rstrip("/")
        return value_folded == expected_value or value_folded.startswith(expected_value + "/")
    candidate = Path(value)
    if not candidate.is_absolute():
        if ".." in PurePosixPath(value).parts:
            return False
        candidate = expected / candidate
    try:
        candidate.resolve(strict=False).relative_to(expected)
    except (OSError, RuntimeError, ValueError):
        return False
    return True


class _ErlangNodeIndex:
    """Indexes only repository Erlang nodes for unique endpoint resolution."""

    def __init__(self, nodes: Iterable[GraphNode], root: Path | None = None) -> None:
        self.root = _canonical_root(root) if root is not None else None
        self.exact: dict[str, GraphNode] = {}
        self.modules: dict[str, list[GraphNode]] = {}
        self.symbols: dict[tuple[str | None, str, int | None], list[GraphNode]] = {}
        for node in nodes:
            if getattr(node, "language", "").casefold() != "erlang":
                continue
            if not _node_belongs_to_root(node, self.root):
                continue
            self.exact[str(node.qualified_name)] = node
            declared_module = _module_name(node)
            # The File node also carries ``erlang_module`` as metadata, but it
            # is not a module endpoint.  Index only the module Class node so
            # one source module does not look ambiguous with its own file.
            is_module_node = declared_module is not None
            if declared_module and is_module_node:
                self.modules.setdefault(declared_module, []).append(node)
            module = declared_module
            if module is None and getattr(node, "parent_name", None):
                # Function/type nodes carry their module in ``parent_name``;
                # only module-level Erlang nodes use ``erlang_module`` extra.
                module = str(node.parent_name)
            if node.kind not in {"Function", "Test", "Type", "Class"}:
                continue
            arity = None
            extra = node.extra if isinstance(node.extra, Mapping) else {}
            raw_arity = extra.get("arity")
            try:
                arity = int(raw_arity) if raw_arity is not None else None
            except (TypeError, ValueError, OverflowError):
                arity = None
            if arity is None:
                match = re.search(r"/(\d+)$", str(node.qualified_name))
                if match:
                    try:
                        arity = int(match.group(1))
                    except (TypeError, ValueError, OverflowError):
                        arity = None
            self.symbols.setdefault((module, node.name, arity), []).append(node)
            self.symbols.setdefault((None, node.name, arity), []).append(node)

    @staticmethod
    def _unquote(value: str) -> str:
        return normalize_erlang_atom(value)

    @staticmethod
    def _unique(values: Iterable[GraphNode]) -> GraphNode | None:
        unique = {node.qualified_name: node for node in values}
        return next(iter(unique.values())) if len(unique) == 1 else None

    def resolve(self, raw: str, *, module_level: bool = False) -> GraphNode | None:
        value = str(raw).strip()
        if not value:
            return None
        exact = self.exact.get(value) or self.exact.get(normalize_file_path(value))
        if exact is None and "::" in value and self.root is not None:
            path_part, suffix = value.split("::", 1)
            candidate = Path(path_part)
            if not candidate.is_absolute():
                candidate = self.root / candidate
            exact = self.exact.get(
                f"{normalize_file_path(candidate)}::{suffix}"
            )
        if exact is not None:
            if not module_level or _module_name(exact) is not None:
                return exact
        if module_level:
            module = self._unquote(value)
            if "::" in module:
                module = module.rsplit("::", 1)[-1]
            if "/" in module and module.rsplit("/", 1)[-1].isdigit():
                module = module.rsplit("/", 1)[0]
            return self._unique(
                node
                for name, nodes in self.modules.items()
                if name == module
                for node in nodes
                if _module_name(node) == module
            )

        # Strip a path-qualified prefix while retaining the module/function
        # spelling used by ELP and xref JSON adapters.
        if "::" in value:
            if self.root is not None:
                path_part, suffix = value.split("::", 1)
                candidate = Path(path_part)
                if not candidate.is_absolute():
                    candidate = self.root / candidate
                value = f"{normalize_file_path(candidate)}::{suffix}"
            suffix = value.rsplit("::", 1)[-1]
            exact_suffix = [
                node for qname, node in self.exact.items()
                if qname.rsplit("::", 1)[-1] == suffix
            ]
            found = self._unique(exact_suffix)
            if found is not None:
                return found
            value = suffix
        parsed = parse_erlang_mfa(value)
        if parsed is not None:
            module, name, arity = parsed
            return self._unique(self.symbols.get((module, name, arity), ())) or self._unique(
                self.symbols.get((None, name, arity), ())
                if module is None
                else ()
            )
        # A function endpoint without arity is intentionally unresolved.  The
        # relation contract requires an explicit function identity; guessing
        # from a unique name would make overloads and test helpers unsafe.
        return None


def _safe_extra(raw: Any) -> dict[str, Any]:
    if isinstance(raw, Mapping):
        return dict(raw)
    if isinstance(raw, (str, bytes, bytearray)):
        try:
            value = json.loads(raw)
        except (TypeError, ValueError, json.JSONDecodeError, UnicodeError):
            return {}
        return dict(value) if isinstance(value, Mapping) else {}
    return {}


def _projection_provenance(record: EvidenceRecord) -> dict[str, Any]:
    source = record.provenance
    value = {
        "source": source.source,
        "tool": source.tool,
        "tool_version": source.tool_version,
        "otp_version": source.otp_version,
        "repository": source.repository,
        "source_revision": source.source_revision,
        "generated_data_revision": source.generated_data_revision,
        "configuration_digest": source.configuration_digest,
        "query_kind": source.query_kind,
        "query_targets": list(source.query_targets),
        "analysis_key": source.analysis_key,
        "status": source.status,
    }
    return _bounded_json_value(value, _MAX_PROVENANCE_CHARS)


def _projection_belongs_to_root(row: Any, extra: Mapping[str, Any], root: Path | None) -> bool:
    """Return whether a marked edge belongs to the requested checkout."""
    if root is None:
        return True
    expected = _canonical_root(root)
    explicit_repositories: list[str] = []
    for key in ("_crg_erlang_repository", "repository"):
        value = extra.get(key)
        if isinstance(value, str) and value:
            explicit_repositories.append(value)
    provenance = extra.get("semantic_provenance")
    if isinstance(provenance, Mapping):
        value = provenance.get("repository")
        if isinstance(value, str) and value:
            explicit_repositories.append(value)

    # A repository marker is authoritative.  Do not reinterpret a relative
    # source path against the requested root when the marker explicitly names
    # another checkout; that is the cross-repository deletion hazard this
    # guard exists to prevent.
    if explicit_repositories:
        ownership: list[bool] = []
        for value in explicit_repositories:
            try:
                ownership.append(_canonical_root(value) == expected)
            except (OSError, RuntimeError, TypeError, ValueError):
                ownership.append(False)
        return all(ownership)

    candidates: list[str] = []
    for key in ("file_path", "source_qualified"):
        value = row[key] if key in row.keys() else None
        if isinstance(value, str) and value:
            candidates.append(value.split("::", 1)[0])
    ownership: list[bool] = []
    for value in candidates:
        try:
            candidate = Path(value)
            if not candidate.is_absolute():
                candidate = expected / candidate
            candidate = candidate.resolve(strict=False)
            candidate.relative_to(expected)
            ownership.append(True)
        except (OSError, RuntimeError, ValueError):
            ownership.append(False)
    # Legacy rows have no authoritative repository marker.  When both source
    # fields are present they must agree; otherwise a foreign source path can
    # be paired with a relative local file path and get deleted during cleanup.
    return bool(ownership) and all(ownership)


def _clear_projection(store: GraphStore, root: Path | None = None) -> int:
    """Restore Generic edges enriched in a prior run for *root* only."""
    conn = store._conn
    rows = conn.execute(
        "SELECT id, target_qualified, extra, confidence, confidence_tier "
        "FROM edges WHERE extra LIKE ?",
        (f"%{_PROJECTION_MARKER}%",),
    ).fetchall()
    changed = 0
    for row in rows:
        extra = _safe_extra(row["extra"])
        if not extra.get(_PROJECTION_MARKER):
            continue
        if not _projection_belongs_to_root(row, extra, root):
            continue
        if bool(extra.get(_PROJECTION_OWNED, False)):
            conn.execute("DELETE FROM edges WHERE id = ?", (row["id"],))
            changed += 1
            continue
        original_extra = extra.get(_PROJECTION_ORIGINAL_EXTRA)
        if not isinstance(original_extra, Mapping):
            original_extra = {
                key: value
                for key, value in extra.items()
                if not str(key).startswith("_crg_erlang_")
                and key not in {
                    "semantic_provenance",
                    "semantic_evidence_id",
                    "semantic_evidence_ids",
                }
            }
        original_target = extra.get(
            _PROJECTION_ORIGINAL_TARGET,
            row["target_qualified"],
        )
        original_confidence = extra.get(
            _PROJECTION_ORIGINAL_CONFIDENCE,
            row["confidence"],
        )
        original_tier = extra.get(
            _PROJECTION_ORIGINAL_TIER,
            row["confidence_tier"],
        )
        conn.execute(
            "UPDATE edges SET target_qualified = ?, extra = ?, confidence = ?, "
            "confidence_tier = ?, updated_at = ? WHERE id = ?",
            (
                str(original_target),
                json.dumps(dict(original_extra), sort_keys=True, separators=(",", ":")),
                (
                    float(original_confidence)
                    if isinstance(original_confidence, (int, float))
                    else 1.0
                ),
                str(original_tier or "EXTRACTED"),
                time.time(),
                row["id"],
            ),
        )
        changed += 1
    return changed


def _clear_projection_safely(
    store: GraphStore,
    root: Path | None = None,
) -> tuple[int, Exception | None]:
    """Clear integration-owned edges in one transaction.

    This is used by lifecycle disable paths, where a corrupt/locked optional
    semantic store must not make the Generic graph build fail.  The normal
    projection path owns its surrounding transaction and calls
    :func:`_clear_projection` directly.
    """
    try:
        store._begin_immediate()
        changed = _clear_projection(store, root)
        store._conn.commit()
        store._invalidate_cache()
        return changed, None
    except Exception as exc:  # SQLite errors are optional-path failures.
        try:
            store._conn.rollback()
        except Exception:
            pass
        logger.warning("Could not clear Erlang semantic edge projections: %s", exc)
        return 0, exc


def _clear_semantic_tools(
    store: GraphStore,
    tools: Iterable[str],
    *,
    repository: str | None = None,
) -> tuple[dict[str, int], Exception | None]:
    """Remove persisted records for adapters explicitly disabled by config."""
    wanted = tuple(sorted({str(tool).casefold() for tool in tools if str(tool).strip()}))
    counts = {"evidence": 0, "diagnostics": 0, "runs": 0}
    if not wanted:
        return counts, None
    placeholders = ",".join("?" for _ in wanted)
    repository_value = str(repository) if repository else None
    try:
        store._begin_immediate()
        for table, key in (
            ("semantic_evidence", "evidence"),
            ("semantic_diagnostics", "diagnostics"),
            ("semantic_runs", "runs"),
        ):
            where = f"lower(tool) IN ({placeholders})"
            params: tuple[Any, ...] = wanted
            if repository_value:
                where += " AND repository = ?"
                params += (repository_value,)
            cursor = store._conn.execute(
                f"DELETE FROM {table} WHERE {where}",  # nosec B608
                params,
            )
            counts[key] = max(0, cursor.rowcount)
        store._conn.commit()
        return counts, None
    except Exception as exc:  # Optional semantic persistence must be fail-soft.
        try:
            store._conn.rollback()
        except Exception:
            pass
        logger.warning("Could not clear disabled Erlang semantic records: %s", exc)
        return counts, exc


def _candidate_existing_edge(
    store: GraphStore,
    *,
    kind: str,
    source: str,
    target: str,
    file_path: str,
    line: int,
    raw_target: str,
) -> Any | None:
    rows = store._conn.execute(
        "SELECT * FROM edges WHERE kind = ? AND source_qualified = ? "
        "AND file_path = ? AND line = ? ORDER BY id",
        (kind, source, file_path, line),
    ).fetchall()
    for row in rows:
        if row["target_qualified"] == target:
            return row
    # Tool output often omits source locations.  If there is exactly one edge
    # for this source/target pair, reuse it rather than creating a duplicate
    # call site on every enrichment pass.  A positive adapter line is an
    # explicit location, though; never move a generic edge from another call
    # site just because the endpoints happen to match.
    all_rows = store._conn.execute(
        "SELECT * FROM edges WHERE kind = ? AND source_qualified = ? "
        "AND target_qualified = ? ORDER BY id",
        (kind, source, target),
    ).fetchall()
    if line <= 0 and len(all_rows) == 1:
        return all_rows[0]
    raw = str(raw_target).strip()
    tail = raw.rsplit("::", 1)[-1].rsplit(":", 1)[-1]
    candidate_pool = rows if line > 0 else (all_rows or rows)
    candidates = [
        row
        for row in candidate_pool
        if row["target_qualified"] in {raw, tail, raw.rsplit("/", 1)[0]}
    ]
    return candidates[0] if len(candidates) == 1 else None


def _project_evidence(
    store: GraphStore,
    evidence: Iterable[EvidenceRecord],
    *,
    root: Path | None = None,
) -> dict[str, int]:
    """Project unique, explicit semantic endpoints into ordinary edges."""
    # An index read failure must not be interpreted as an empty repository:
    # doing so would commit removal of every previous semantic projection.
    # Let the lifecycle boundary convert the failure into a degraded result
    # while the projection transaction remains untouched.
    nodes = store.get_all_nodes(exclude_files=False)
    index = _ErlangNodeIndex(nodes, root=root)
    grouped: dict[tuple[str, str, str, str, int], list[EvidenceRecord]] = {}
    skipped = 0
    ambiguous = 0
    for record in evidence:
        kind = str(record.kind).upper()
        if kind not in _PROJECTION_RELATIONS:
            skipped += 1
            continue
        if record.status != STATUS_OK or record.provenance.status != STATUS_OK:
            skipped += 1
            continue
        module_level = bool(record.metadata.get("module_level"))
        if record.provenance.tool.casefold() == "xref" and kind == "DEPENDS_ON":
            module_level = True
        if (
            kind == "DEPENDS_ON"
            and record.provenance.tool.casefold() == "xref"
            and not module_level
        ):
            skipped += 1
            continue
        source_node = index.resolve(record.source, module_level=module_level)
        target_node = index.resolve(record.target, module_level=module_level)
        if source_node is None or target_node is None:
            # Distinguish an ambiguous endpoint from an unavailable external
            # module for diagnostics/metrics without exposing guesses.
            if source_node is None and record.source in index.exact:
                ambiguous += 1
            elif target_node is None and record.target in index.exact:
                ambiguous += 1
            else:
                skipped += 1
            continue
        raw_file_path = record.file_path or source_node.file_path
        if root is not None and not Path(str(raw_file_path)).is_absolute():
            file_path = _path_target(root, str(raw_file_path))
        else:
            file_path = normalize_file_path(str(raw_file_path))
        try:
            line = max(0, int(record.line or 0))
        except (TypeError, ValueError, OverflowError):
            line = 0
        key = (kind, source_node.qualified_name, target_node.qualified_name, file_path, line)
        grouped.setdefault(key, []).append(record)

    projected = 0
    merged = 0
    store._begin_immediate()
    try:
        _clear_projection(store, root)
        for key in sorted(grouped):
            kind, source, target, file_path, line = key
            records = sorted(grouped[key], key=lambda item: item.evidence_id)
            primary = records[0]
            evidence_ids = [item.evidence_id for item in records[:32]]
            metadata: dict[str, Any] = {
                _PROJECTION_MARKER: True,
                _PROJECTION_OWNED: True,
                "_crg_erlang_repository": normalize_file_path(root) if root else None,
                "semantic_evidence_id": primary.evidence_id,
                "semantic_evidence_ids": evidence_ids,
                "semantic_provenance": _projection_provenance(primary),
                "semantic_query_kind": primary.provenance.query_kind,
                "semantic_tool": primary.provenance.tool,
                "confidence": 1.0,
                "confidence_tier": "INFERRED",
            }
            if bool(primary.metadata.get("module_level")):
                metadata["module_level"] = True
            existing = _candidate_existing_edge(
                store,
                kind=kind,
                source=source,
                target=target,
                file_path=file_path,
                line=line,
                raw_target=primary.target,
            )
            if existing is None:
                store.upsert_edge(
                    EdgeInfo(
                        kind=kind,
                        source=source,
                        target=target,
                        file_path=file_path,
                        line=line,
                        extra=metadata,
                    )
                )
            else:
                original_extra = _safe_extra(existing["extra"])
                # A marker that survived an interrupted transaction is
                # restored by _clear_projection before this point.  Keep the
                # original Generic payload so a later run can restore it.
                metadata[_PROJECTION_OWNED] = False
                metadata[_PROJECTION_ORIGINAL_EXTRA] = original_extra
                metadata[_PROJECTION_ORIGINAL_TARGET] = existing["target_qualified"]
                metadata[_PROJECTION_ORIGINAL_CONFIDENCE] = existing["confidence"]
                metadata[_PROJECTION_ORIGINAL_TIER] = existing["confidence_tier"]
                store._conn.execute(
                    "UPDATE edges SET target_qualified = ?, extra = ?, confidence = ?, "
                    "confidence_tier = ?, updated_at = ? WHERE id = ?",
                    (
                        target,
                        json.dumps(metadata, sort_keys=True, separators=(",", ":")),
                        1.0,
                        "INFERRED",
                        time.time(),
                        existing["id"],
                    ),
                )
            projected += 1
            merged += max(0, len(records) - 1)
        store._conn.commit()
        store._invalidate_cache()
    except BaseException:
        store._conn.rollback()
        raise
    return {
        "projected_edges": projected,
        "projection_merged": merged,
        "projection_skipped": skipped,
        "projection_ambiguous": ambiguous,
    }


def _persist_enrichment(
    store: GraphStore,
    enrichment: EnrichmentResult,
    previous: Iterable[EvidenceRecord],
    previous_diagnostics: Iterable[Diagnostic] = (),
) -> dict[str, int]:
    counts = {
        "persisted_runs": 0,
        "persisted_evidence": 0,
        "persisted_diagnostics": 0,
        "stale_removed": 0,
        "persistence_failures": 0,
    }
    scopes: set[tuple[str, str, tuple[str, ...]]] = set()
    for result in enrichment.adapter_results:
        try:
            key = result.provenance.key()
            scopes.add((key.tool, key.query_kind, key.query_targets))
            snapshot: Any = result
            if not result.ok:
                # ``replace=False`` deliberately preserves old rows, but the
                # run envelope otherwise reports zero evidence even when that
                # old evidence is still being served.  Include matching prior
                # records in the envelope so status and counts describe the
                # effective snapshot consistently after timeout/failure.
                retained = tuple(
                    record
                    for record in previous
                    if record.provenance.key() == key
                )
                retained_diagnostics = tuple(
                    diagnostic
                    for diagnostic in previous_diagnostics
                    if diagnostic.provenance.key() == key
                )
                if retained or retained_diagnostics:
                    payload = result.to_dict()
                    if retained:
                        payload["evidence"] = [record.to_dict() for record in retained]
                    if retained_diagnostics:
                        payload["diagnostics"] = [
                            diagnostic.to_dict() for diagnostic in retained_diagnostics
                        ] + list(payload.get("diagnostics", ()))
                    snapshot = payload
            saved = store.store_semantic_snapshot(
                snapshot,
                analysis_key=key,
                # A failed/timeout run must retain its previous valid evidence.
                replace=result.ok,
                # GraphStore's broad scope purge predates targeted Erlang
                # queries and would delete a different target with the same
                # query kind.  The target-aware helper below purges only rows
                # whose revision/tool identity is stale.
                purge_stale=False,
            )
            counts["persisted_runs"] += saved.get("runs", 0)
            counts["persisted_evidence"] += saved.get("evidence", 0)
            counts["persisted_diagnostics"] += saved.get("diagnostics", 0)
            counts["stale_removed"] += saved.get("stale_removed", 0)
            counts["stale_removed"] += _purge_stale_analysis_scope(store, key)
        except Exception as exc:  # SQLite/backend errors must not break Generic builds.
            counts["persistence_failures"] += 1
            logger.warning("Erlang semantic snapshot persistence failed: %s", exc)

    # Remove old revisions for scopes not queried in this pass as well.  This
    # keeps a changed Git revision from leaving invisible stale evidence when a
    # caller asks only for a narrow target.
    seen_scopes: set[tuple[str, str, tuple[str, ...]]] = set(scopes)
    for record in previous:
        provenance = record.provenance
        tool = provenance.tool.casefold()
        if tool not in _ERLANG_TOOLS:
            continue
        scope = (tool, provenance.query_kind.casefold(), provenance.query_targets)
        if scope in seen_scopes:
            continue
        try:
            current_key = AnalysisKey.from_toolchain(
                enrichment.toolchain,
                tool,
                provenance.query_kind,
                provenance.query_targets,
            )
            counts["stale_removed"] += _purge_stale_analysis_scope(store, current_key)
            seen_scopes.add(scope)
        except Exception as exc:  # Optional stale cleanup is best effort.
            logger.warning("Erlang stale evidence cleanup failed: %s", exc)
    return counts


def _purge_stale_analysis_scope(store: GraphStore, key: AnalysisKey) -> int:
    """Remove stale revisions without deleting sibling targeted queries.

    ``semantic_evidence`` and ``semantic_diagnostics`` index tool/query scope
    but keep query targets inside ``record_json``.  A SQL scope purge therefore
    cannot distinguish ``callers_of(A)`` from ``callers_of(B)``.  Inspect the
    bounded provenance columns/JSON and remove rows only when the source,
    generated-data, configuration, OTP, or tool identity is no longer the
    current one.  Rows from the same revision are retained regardless of
    target, allowing a narrow incremental refresh to coexist with prior
    targeted evidence.
    """
    repository = str(key.repository)
    tool = str(key.tool).casefold()
    query_kind = str(key.query_kind).casefold()
    conn = store._conn

    def stale_identity(row: Any, provenance: Mapping[str, Any]) -> bool:
        if str(row["analysis_key"]) == key.cache_key:
            return False
        observed = {
            "repository": provenance.get("repository", row["repository"]),
            "tool": provenance.get("tool", row["tool"]),
            "source_revision": provenance.get("source_revision", row["source_revision"]),
            "generated_data_revision": provenance.get(
                "generated_data_revision", row["generated_data_revision"]
            ),
            "configuration_digest": provenance.get(
                "configuration_digest", row["configuration_digest"]
            ),
            "otp_version": provenance.get("otp_version", row["otp_version"]),
            "tool_version": provenance.get("tool_version"),
            "plt_identity": provenance.get("plt_identity"),
        }
        if str(observed["repository"] or "") != repository:
            return False
        if str(observed["tool"] or "").casefold() != tool:
            return False
        if (
            observed["source_revision"] == key.source_revision
            and observed["generated_data_revision"] == key.generated_data_revision
            and observed["configuration_digest"] == key.configuration_digest
            and observed["otp_version"] == key.otp_version
            and observed["plt_identity"] == key.plt_identity
            and (
                observed["tool_version"] is None
                or observed["tool_version"] == key.tool_version
            )
        ):
            return False
        return True

    removed = 0
    store._begin_immediate()
    try:
        for table, identity_column, json_column in (
            ("semantic_evidence", "evidence_id", "record_json"),
            ("semantic_diagnostics", "diagnostic_id", "record_json"),
            ("semantic_runs", None, "provenance_json"),
        ):
            rows = conn.execute(
                f"SELECT * FROM {table} WHERE repository = ? AND tool = ? "
                "AND query_kind = ?",  # nosec B608 -- fixed table names
                (repository, tool, query_kind),
            ).fetchall()
            for row in rows:
                if row["analysis_key"] == key.cache_key:
                    continue
                raw = row[json_column]
                provenance = _safe_extra(raw)
                if not stale_identity(row, provenance):
                    continue
                if identity_column is None:
                    cursor = conn.execute(
                        f"DELETE FROM {table} WHERE analysis_key = ?",  # nosec B608
                        (row["analysis_key"],),
                    )
                else:
                    cursor = conn.execute(
                        f"DELETE FROM {table} WHERE analysis_key = ? AND {identity_column} = ?",  # nosec B608
                        (row["analysis_key"], row[identity_column]),
                    )
                removed += max(0, cursor.rowcount)
        conn.commit()
    except BaseException:
        conn.rollback()
        raise
    return removed


def _cache_dir(root: Path, value: str | Path | None) -> Path:
    if value is None:
        return root / ".code-review-graph" / "erlang-cache"
    path = Path(value).expanduser()
    return path if path.is_absolute() else root / path


def _disable_integration(
    store: GraphStore,
    root: Path,
) -> tuple[dict[str, int], tuple[Exception, ...], bool]:
    """Remove optional Erlang state while preserving Generic graph rows.

    ``edges`` has no repository column because a GraphStore is normally scoped
    to one checkout, so marked semantic projections are cleared as a whole.
    Normalized semantic tables do carry repository and are restricted to the
    requested checkout to avoid deleting another repository's evidence when a
    shared store is used by a caller.
    """
    counts = {
        "cleared_edges": 0,
        "cleared_evidence": 0,
        "cleared_diagnostics": 0,
        "cleared_runs": 0,
        "cleanup_failures": 0,
    }
    errors: list[Exception] = []
    had_state = False
    try:
        had_state = bool(
            store.get_metadata(_scoped_metadata_key(_STATUS_METADATA_KEY, root))
        )
        had_state = had_state or bool(store.get_metadata(_STATUS_METADATA_KEY))
        had_state = had_state or bool(
            store._conn.execute(
                "SELECT 1 FROM edges WHERE extra LIKE ? LIMIT 1",
                (f"%{_PROJECTION_MARKER}%",),
            ).fetchone()
        )
    except Exception as exc:
        # State detection is only used to avoid adding metadata on a pristine
        # disabled invocation; cleanup itself remains best effort.
        logger.debug("Could not inspect prior Erlang integration state: %s", exc)

    cleared_edges, edge_error = _clear_projection_safely(store, root)
    counts["cleared_edges"] = cleared_edges
    if edge_error is not None:
        errors.append(edge_error)

    semantic_counts, semantic_error = _clear_semantic_tools(
        store,
        _ERLANG_TOOLS,
        repository=normalize_file_path(root),
    )
    counts["cleared_evidence"] = semantic_counts["evidence"]
    counts["cleared_diagnostics"] = semantic_counts["diagnostics"]
    counts["cleared_runs"] = semantic_counts["runs"]
    if semantic_error is not None:
        errors.append(semantic_error)
    counts["cleanup_failures"] = len(errors)
    return counts, tuple(errors), had_state or any(
        counts[key]
        for key in (
            "cleared_edges",
            "cleared_evidence",
            "cleared_diagnostics",
            "cleared_runs",
        )
    )


def _repository_mismatch_result(
    root: Path,
    toolchain: ToolchainIdentity,
) -> ErlangIntegrationResult:
    expected = normalize_file_path(root)
    actual = str(toolchain.repository)
    provenance = _lifecycle_provenance(root, status=STATUS_MISMATCH, query_kind="repository")
    diagnostic = Diagnostic(
        code="erlang_repository_mismatch",
        message=(
            "Erlang toolchain repository does not match the GraphStore checkout; "
            "semantic execution was skipped."
        ),
        provenance=provenance,
        severity="warning",
        metadata={"expected_repository": expected, "actual_repository": actual[:512]},
    )
    return ErlangIntegrationResult(
        status=STATUS_MISMATCH,
        diagnostics=(diagnostic,),
        provenance={
            "repository": expected,
            "status": STATUS_MISMATCH,
            "expected_repository": expected,
            "actual_repository": actual[:512],
        },
        counts={
            "queries": 0,
            "evidence": 0,
            "diagnostics": 1,
            "repository_mismatches": 1,
            "projected_edges": 0,
        },
        toolchain=toolchain,
    )


def _failure_result(
    root: Path,
    *,
    code: str,
    message: str,
    status: str = STATUS_DEGRADED,
    toolchain: ToolchainIdentity | None = None,
    counts: Mapping[str, int] | None = None,
) -> ErlangIntegrationResult:
    """Return a bounded optional-path failure without touching Generic data."""
    if toolchain is not None:
        try:
            provenance = Provenance.from_key(
                AnalysisKey.from_toolchain(toolchain, "erlang_integration", "lifecycle"),
                source="erlang_integration",
                status=status,
            )
        except Exception:
            provenance = _lifecycle_provenance(root, status=status)
    else:
        provenance = _lifecycle_provenance(root, status=status)
    diagnostic = Diagnostic(
        code=code,
        message=str(message)[:2_000],
        provenance=provenance,
        severity="warning",
    )
    result_counts = {
        "queries": 0,
        "evidence": 0,
        "diagnostics": 1,
        "projected_edges": 0,
    }
    if counts:
        result_counts.update({str(key): int(value) for key, value in counts.items()})
    result_provenance = _base_provenance(root, status=status, toolchain=toolchain)
    return ErlangIntegrationResult(
        status=status,
        diagnostics=(diagnostic,),
        provenance=result_provenance,
        counts=result_counts,
        toolchain=toolchain,
    )


def _repository_matches(root: Path, toolchain: ToolchainIdentity) -> bool:
    """Compare repository identities after resolving symlinks and case rules."""
    try:
        observed = _canonical_root(toolchain.repository)
        return os.path.normcase(str(observed)) == os.path.normcase(str(root))
    except (AttributeError, TypeError, ValueError, OSError, RuntimeError):
        return False


def _active_tools(queries: Iterable[EnrichmentQuery]) -> frozenset[str]:
    return frozenset(
        query.tool.casefold()
        for query in queries
        if query.tool.casefold() in _ERLANG_TOOLS
    )


def _lifecycle_diagnostic(
    root: Path,
    *,
    code: str,
    message: str,
    status: str = STATUS_FAILED,
    metadata: Mapping[str, Any] | None = None,
) -> Diagnostic:
    return Diagnostic(
        code=code,
        message=str(message)[:2_000],
        provenance=_lifecycle_provenance(root, status=status),
        severity="info" if status in {STATUS_STALE, STATUS_UNAVAILABLE} else "warning",
        metadata=dict(metadata or {}),
    )


def _save_integration_metadata(
    store: GraphStore,
    *,
    root: Path,
    status: str,
    summary: Mapping[str, Any] | None = None,
) -> Exception | None:
    """Persist optional status metadata without turning it into a hard error."""
    try:
        if summary is not None:
            store.set_metadata(
                _scoped_metadata_key(_SUMMARY_METADATA_KEY, root),
                json.dumps(
                    _bounded_json_value(dict(summary), _MAX_METADATA_CHARS),
                    sort_keys=True,
                    separators=(",", ":"),
                ),
            )
        store.set_metadata(_scoped_metadata_key(_STATUS_METADATA_KEY, root), status)
        # Keep the old scalar keys for standalone stores.  A shared store has
        # no unambiguous scalar status, so remove them instead of letting the
        # most recently processed checkout overwrite another one's status.
        try:
            expected_root = _canonical_root(root)
            has_foreign = False
            for path in store.get_file_marker_paths():
                candidate = Path(path).expanduser()
                if not candidate.is_absolute():
                    candidate = expected_root / candidate
                try:
                    candidate.resolve(strict=False).relative_to(expected_root)
                except (OSError, RuntimeError, ValueError):
                    has_foreign = True
                    break
        except (OSError, RuntimeError, ValueError):
            has_foreign = True
        if has_foreign:
            store._conn.execute(
                "DELETE FROM metadata WHERE key IN (?, ?)",
                (_STATUS_METADATA_KEY, _SUMMARY_METADATA_KEY),
            )
            store._conn.commit()
        else:
            store.set_metadata(_STATUS_METADATA_KEY, status)
            if summary is not None:
                store.set_metadata(
                    _SUMMARY_METADATA_KEY,
                    json.dumps(
                        _bounded_json_value(dict(summary), _MAX_METADATA_CHARS),
                        sort_keys=True,
                        separators=(",", ":"),
                    ),
                )
    except Exception as exc:
        logger.warning("Could not save Erlang integration metadata: %s", exc)
        return exc
    return None


def run_erlang_integration(
    repo_root: str | Path,
    store: GraphStore,
    *,
    config: ErlangIntegrationConfig | Mapping[str, Any] | None = None,
    changed_files: Iterable[str] | None = None,
    query_targets: str | Sequence[str] | None = None,
    toolchain: ToolchainIdentity | None = None,
    runner: Any | None = None,
) -> ErlangIntegrationResult:
    """Run optional Erlang enrichment and reconcile it into ``store``.

    The function is fail-soft by design.  Adapter failures become diagnostics,
    Generic graph rows remain available, and previously valid evidence is kept
    for an unavailable/timeout query.  External project commands are executed
    only after the caller opts in through ``config.enabled``.
    """
    root = _canonical_root(repo_root)
    try:
        settings = ErlangIntegrationConfig.from_value(config)
    except Exception as exc:
        return _failure_result(
            root,
            code="erlang_invalid_config",
            message=f"Invalid Erlang integration configuration: {type(exc).__name__}: {exc}",
        )
    if not settings.enabled:
        cleanup_counts, cleanup_errors, had_state = _disable_integration(store, root)
        diagnostics = tuple(
            _lifecycle_diagnostic(
                root,
                code="erlang_disable_cleanup_failed",
                message=f"Could not fully clear disabled Erlang state: {type(exc).__name__}: {exc}",
                metadata={"exception": type(exc).__name__},
            )
            for exc in cleanup_errors
        )
        counts = {
            "queries": 0,
            "evidence": 0,
            "diagnostics": len(diagnostics),
            "projected_edges": 0,
            **cleanup_counts,
        }
        result = ErlangIntegrationResult(
            status=STATUS_DEGRADED if cleanup_errors else "disabled",
            diagnostics=diagnostics,
            provenance=_base_provenance(root, status="disabled", toolchain=None),
            counts=counts,
        )
        # Preserve the historical pristine-disabled behavior (no metadata),
        # while making a real disable observable after prior enrichment.
        if had_state or cleanup_errors:
            _save_integration_metadata(
                store,
                root=root,
                status=result.status,
                summary={
                    "status": result.status,
                    "repository": normalize_file_path(root),
                    "counts": counts,
                },
            )
        return result

    # An injected toolchain is trusted only for the checkout it describes.
    # Reject this before even checking graph contents so an empty repository
    # cannot mask a cross-repository configuration error.
    if toolchain is not None and not _repository_matches(root, toolchain):
        return _repository_mismatch_result(root, toolchain)

    try:
        has_erlang_nodes = store.has_nodes_for_language("erlang")
    except Exception as exc:
        # A store that cannot answer the language check is not a safe basis
        # for launching a project tool.  Generic lifecycle callers can still
        # report their primary build result independently.
        logger.warning("Could not determine whether the graph contains Erlang nodes")
        return _failure_result(
            root,
            code="erlang_graph_read_failed",
            message=f"Could not inspect Generic Erlang nodes: {type(exc).__name__}: {exc}",
        )
    if not has_erlang_nodes:
        # A forget or a repository switch can leave semantic rows behind after
        # the last Erlang node disappears.  Reconcile that optional state while
        # keeping the Generic graph untouched; table cleanup is repository
        # scoped and projection cleanup is root-aware.
        cleanup_counts, cleanup_errors, had_state = _disable_integration(store, root)
        diagnostics = tuple(
            _lifecycle_diagnostic(
                root,
                code="erlang_no_nodes_cleanup_failed",
                message=(
                    "Could not clear Erlang state after the Generic graph became "
                    f"Erlang-free: {type(exc).__name__}: {exc}"
                ),
                metadata={"exception": type(exc).__name__},
            )
            for exc in cleanup_errors
        )
        counts = {
            "queries": 0,
            "changed_targets": 0,
            "evidence": 0,
            "diagnostics": len(diagnostics),
            "projected_edges": 0,
            **cleanup_counts,
        }
        if had_state or cleanup_errors:
            _save_integration_metadata(
                store,
                root=root,
                status="degraded" if cleanup_errors else "skipped",
                summary={
                    "status": "degraded" if cleanup_errors else "skipped",
                    "repository": normalize_file_path(root),
                    "counts": counts,
                },
            )
        return ErlangIntegrationResult(
            status="degraded" if cleanup_errors else "skipped",
            diagnostics=diagnostics,
            provenance=_base_provenance(
                root,
                status="degraded" if cleanup_errors else "skipped",
                toolchain=None,
            ),
            counts=counts,
        )

    changed_targets = _collect_changed_targets(store, root, changed_files)
    queries = _query_values(
        settings,
        changed_targets=changed_targets,
        query_targets=query_targets,
    )
    # No requested work is a useful no-op for lifecycle callers.  In
    # particular, do not discover OTP merely because an enabled config object
    # was installed for a repository containing no changed Erlang target.
    if not queries and not settings.include_xref and not settings.include_dialyzer:
        return ErlangIntegrationResult(
            status="skipped",
            provenance=_base_provenance(root, status="skipped", toolchain=None),
            counts={
                "queries": 0,
                "changed_targets": len(changed_targets),
                "evidence": 0,
                "diagnostics": 0,
                "projected_edges": 0,
            },
        )

    from .erlang_semantic import discover_toolchain

    if toolchain is None:
        try:
            toolchain = discover_toolchain(
                root,
                runner=runner,
                timeout=settings.timeout,
                plt_path=settings.plt_path,
            )
        except Exception as exc:
            return _failure_result(
                root,
                code="erlang_toolchain_discovery_failed",
                message=f"Toolchain discovery failed: {type(exc).__name__}: {exc}",
            )
    if not _repository_matches(root, toolchain):
        return _repository_mismatch_result(root, toolchain)
    previous, previous_diagnostics, snapshot_failed = _snapshot_records_status(store, root)
    if snapshot_failed:
        return _failure_result(
            root,
            code="erlang_snapshot_read_failed",
            message="Semantic snapshot could not be read; existing projections were preserved.",
            toolchain=toolchain,
        )
    cache = EvidenceCache(_cache_dir(root, settings.cache_dir))
    try:
        enrichment = run_erlang_enrichment(
            root,
            toolchain=toolchain,
            queries=queries,
            previous=previous,
            previous_diagnostics=previous_diagnostics,
            cache=cache,
            runner=runner,
            timeout=settings.timeout,
            include_xref=settings.include_xref,
            include_dialyzer=settings.include_dialyzer,
            plt_path=settings.plt_path,
            expected_otp_version=settings.expected_otp,
        )
    except Exception as exc:
        return _failure_result(
            root,
            code="erlang_enrichment_failed",
            message=f"Erlang enrichment failed: {type(exc).__name__}: {exc}",
            toolchain=toolchain,
        )
    # Compute the configured adapter set before exposing the result.  The
    # enrichment reconciler intentionally retains unrequested scopes for
    # incremental callers; an integration config that omits an adapter means
    # that adapter is disabled for this lifecycle pass.
    active_tools = _active_tools(queries)
    if settings.include_xref:
        active_tools = active_tools | {"xref"}
    if settings.include_dialyzer:
        active_tools = active_tools | {"dialyzer"}
    active_evidence = tuple(
        record
        for record in enrichment.evidence
        if record.provenance.tool.casefold() in active_tools
    )
    active_diagnostics = tuple(
        diagnostic
        for diagnostic in enrichment.diagnostics
        if (
            diagnostic.provenance.tool.casefold() in active_tools
            or diagnostic.provenance.tool.casefold() not in _ERLANG_TOOLS
        )
    )
    counts: dict[str, int] = {
        "queries": len(enrichment.adapter_results),
        "changed_targets": len(changed_targets),
        "evidence": len(active_evidence),
        "diagnostics": len(active_diagnostics),
        "conflicts": len(enrichment.conflicts),
        "cache_hits": sum(1 for _key, value in enrichment.cache_results if value.hit),
        "cache_misses": sum(1 for _key, value in enrichment.cache_results if not value.hit),
        "cache_stale": sum(1 for _key, value in enrichment.cache_results if value.stale),
    }
    try:
        counts.update(
            _persist_enrichment(
                store,
                enrichment,
                previous,
                previous_diagnostics,
            )
        )
    except Exception as exc:
        counts.update({"persistence_failures": 1})
        logger.warning("Erlang semantic persistence failed: %s", exc)

    # Omitted adapters are explicitly disabled by this integration config.
    # Remove only their persisted evidence; Generic nodes/edges are untouched.
    disabled_tools = _ERLANG_TOOLS - active_tools
    disabled_counts, disabled_error = _clear_semantic_tools(
        store,
        disabled_tools,
        repository=normalize_file_path(root),
    )
    counts.update(
        {
            "cleared_evidence": disabled_counts["evidence"],
            "cleared_diagnostics": disabled_counts["diagnostics"],
            "cleared_runs": disabled_counts["runs"],
        }
    )
    if disabled_error is not None:
        counts["persistence_failures"] = counts.get("persistence_failures", 0) + 1

    # Do not re-project records belonging to an adapter disabled above.  The
    # projection routine first restores/removes all prior marked edges, so a
    # disabled adapter's derived edges disappear while Generic edges return.
    active_evidence = tuple(
        record
        for record in enrichment.evidence
        if record.provenance.tool.casefold() in active_tools
    )
    projection_error = False
    try:
        counts.update(_project_evidence(store, active_evidence, root=root))
    except Exception as exc:
        projection_error = True
        counts.update(
            {
                "projected_edges": 0,
                "projection_failures": 1,
                "projection_skipped": 0,
                "projection_ambiguous": 0,
            }
        )
        logger.warning("Erlang semantic edge projection failed: %s", exc)

    diagnostics = list(active_diagnostics)
    if counts.get("persistence_failures", 0):
        diagnostics.append(
            _make_diagnostic(
                toolchain,
                tool="erlang_integration",
                query_kind="persistence",
                code="erlang_snapshot_persistence_failed",
                message="One or more Erlang semantic snapshots could not be persisted.",
                status=STATUS_FAILED,
                metadata={"failures": counts["persistence_failures"]},
            )
        )
    if projection_error:
        diagnostics.append(
            _make_diagnostic(
                toolchain,
                tool="erlang_integration",
                query_kind="projection",
                code="erlang_edge_projection_failed",
                message="Erlang semantic evidence was retained but edge projection failed.",
                status=STATUS_FAILED,
            )
        )
    if disabled_error is not None:
        diagnostics.append(
            _lifecycle_diagnostic(
                root,
                code="erlang_disabled_cleanup_failed",
                message=(
                    "Could not clear disabled adapter state: "
                    f"{type(disabled_error).__name__}: {disabled_error}"
                ),
                metadata={"exception": type(disabled_error).__name__},
            )
        )

    status = enrichment.status
    if counts.get("persistence_failures", 0) or projection_error:
        status = STATUS_DEGRADED
    provenance = _base_provenance(root, status=status, toolchain=toolchain)
    counts["diagnostics"] = len(diagnostics)
    result = ErlangIntegrationResult(
        status=status,
        evidence=active_evidence,
        diagnostics=tuple(diagnostics),
        provenance=provenance,
        counts=counts,
        toolchain=toolchain,
    )

    # Keep a compact, deterministic summary for status/query callers.  The
    # complete records live in semantic_* tables; this metadata value is only
    # an inexpensive indication that enrichment ran and what it produced.
    summary = {
        "status": result.status,
        "repository": toolchain.repository,
        "source_revision": toolchain.source_revision,
        "generated_data_revision": toolchain.generated_data_revision,
        "configuration_digest": toolchain.configuration_digest,
        "toolchain_fingerprint": toolchain.fingerprint,
        "counts": dict(result.counts),
    }
    _save_integration_metadata(store, root=root, status=result.status, summary=summary)
    return result
