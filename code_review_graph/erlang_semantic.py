"""Optional semantic evidence for the Generic Erlang graph.

The Generic Tree-sitter parser is deliberately independent from this module.
This module only discovers project tooling, executes bounded optional commands,
and turns explicit tool output into revision-keyed evidence.  It never mutates
the graph itself; callers can decide when and how to promote the returned
records into ``GraphStore``.

The public boundary is intentionally small:

* :func:`discover_toolchain` creates a reproducible toolchain identity.
* :class:`ELPAdapter`, :class:`XrefAdapter`, and :class:`DialyzerAdapter`
  return :class:`AdapterResult` values and do not raise for tool failures.
* :class:`EvidenceReconciler` merges duplicate evidence while retaining
  conflicting evidence and dropping records from another revision.
* :class:`EvidenceCache` persists only records whose :class:`AnalysisKey`
  matches exactly.

The concrete ELP protocol is kept configurable through ``command_builder``.
The default builder expects a bounded JSON command-line interface, which is a
safe adapter contract while deployments choose their ELP invocation mode.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
import time
from collections import defaultdict
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Protocol

logger = logging.getLogger(__name__)

__all__ = [
    "AdapterResult",
    "AnalysisKey",
    "EnrichmentQuery",
    "EnrichmentResult",
    "CommandResult",
    "Diagnostic",
    "DialyzerAdapter",
    "ELPAdapter",
    "EvidenceCache",
    "EvidenceRecord",
    "EvidenceReconciler",
    "ReconciliationResult",
    "ToolInfo",
    "ToolchainDiscovery",
    "ToolchainIdentity",
    "XrefAdapter",
    "compute_configuration_digest",
    "compute_generated_data_revision",
    "compute_plt_identity",
    "discover_toolchain",
    "run_erlang_enrichment",
    "STATUS_FAILED",
    "STATUS_DEGRADED",
    "STATUS_MALFORMED",
    "STATUS_MISMATCH",
    "STATUS_OK",
    "STATUS_STALE",
    "STATUS_TIMEOUT",
    "STATUS_UNAVAILABLE",
]


# Status values are strings on purpose: they are persisted in manifests and
# consumed by review-context clients that may not import this module.
STATUS_OK = "ok"
STATUS_UNAVAILABLE = "unavailable"
STATUS_MISMATCH = "mismatch"
STATUS_TIMEOUT = "timeout"
STATUS_FAILED = "failed"
STATUS_DEGRADED = "degraded"
STATUS_MALFORMED = "malformed"
STATUS_STALE = "stale"

_MAX_OUTPUT_CHARS = 2_000_000
_DEFAULT_TIMEOUT_SECONDS = 15.0
_MAX_DIAGNOSTIC_TEXT = 2_000
_MAX_CACHE_FILE_BYTES = 20_000_000
_VERSION_RE = re.compile(r"(?<!\d)(\d+(?:\.\d+){0,3})(?!\d)")
_LOCATION_RE = re.compile(
    r"^(?P<file>.+?):(?P<line>\d+)(?::(?P<column>\d+))?:\s*"
    r"(?:(?P<severity>warning|error|notice)\s*:\s*)?"
    r"(?P<message>.*)$",
    re.IGNORECASE,
)
_XREF_UNDEFINED_RE = re.compile(
    r"(?:undefined\s+(?:call|function)|call\s+to\s+undefined\s+function)\s*"
    r"(?P<target>[A-Za-z0-9_@'?-]+(?::[A-Za-z0-9_@'?-]+)?/\d+)",
    re.IGNORECASE,
)
_XREF_RELATION_RE = re.compile(
    r"^\s*(?P<source>[A-Za-z0-9_@'?-]+)\s*(?:->|calls?|uses?|depends\s+on)\s*"
    r"(?P<target>[A-Za-z0-9_@'?-]+)\s*$",
    re.IGNORECASE,
)


def _canonical_json(value: Any) -> str:
    """Serialize JSON-compatible values with stable ordering."""
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        default=str,
    )


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _canonical_path(value: str | Path) -> str:
    """Return a stable POSIX spelling without requiring the path to exist."""
    try:
        return Path(value).expanduser().resolve(strict=False).as_posix()
    except (OSError, RuntimeError, ValueError):
        return Path(value).expanduser().absolute().as_posix()


def _canonical_command(command: Sequence[str] | None) -> tuple[str, ...]:
    if command is None:
        return ()
    return tuple(str(part) for part in command)


def _bounded_text(value: Any, limit: int = _MAX_DIAGNOSTIC_TEXT) -> str:
    text = value.decode("utf-8", "replace") if isinstance(value, bytes) else str(value or "")
    text = text.strip()
    return text[:limit]


def _normalise_targets(targets: str | Sequence[str] | None) -> tuple[str, ...]:
    if targets is None:
        return ()
    if isinstance(targets, str):
        values: Sequence[str] = (targets,)
    else:
        values = tuple(str(item) for item in targets)
    # Query order must not affect cache identity.  Empty targets are never a
    # useful semantic query and are omitted from the key.
    return tuple(sorted({item.strip() for item in values if item.strip()}))


def _safe_timeout(value: float | int | None) -> float:
    try:
        timeout = float(value if value is not None else _DEFAULT_TIMEOUT_SECONDS)
    except (TypeError, ValueError):
        timeout = _DEFAULT_TIMEOUT_SECONDS
    if not (timeout > 0.0) or timeout != timeout or timeout == float("inf"):
        return _DEFAULT_TIMEOUT_SECONDS
    return min(timeout, 300.0)


def _redacted_environment(environment: Mapping[str, str] | None) -> tuple[tuple[str, str], ...]:
    """Keep only deterministic, non-secret environment metadata."""
    if not environment:
        return ()
    pairs: list[tuple[str, str]] = []
    for raw_key, raw_value in environment.items():
        key = str(raw_key)
        if any(token in key.upper() for token in ("PASSWORD", "SECRET", "TOKEN", "KEY")):
            continue
        pairs.append((key, str(raw_value)))
    return tuple(sorted(pairs))


_CONTROLLED_ENVIRONMENT_KEYS = frozenset(
    {
        "PATH",
        "HOME",
        "USER",
        "LANG",
        "LC_ALL",
        "ERL_LIBS",
        "ERL_AFLAGS",
        "ERL_ZFLAGS",
        "REBAR_COLOR",
        "REBAR_GLOBAL_CONFIG",
        "REBAR_CACHE_DIR",
        "ELP_HOME",
        # ELP installations may be built against a specific OTP release.  A
        # deployment can provide that identity when the executable does not
        # expose it through its version output.
        "ELP_OTP_VERSION",
    }
)


def _controlled_environment(overrides: Mapping[str, str] | None = None) -> dict[str, str]:
    """Build a small environment suitable for project-tool subprocesses."""
    result = {
        key: value
        for key, value in os.environ.items()
        if key in _CONTROLLED_ENVIRONMENT_KEYS
    }
    result.update({str(key): str(value) for key, value in (overrides or {}).items()})
    return result


@dataclass(frozen=True)
class CommandResult:
    """Normalized subprocess result accepted by all adapters."""

    returncode: int
    stdout: str = ""
    stderr: str = ""
    duration_seconds: float = 0.0

    @classmethod
    def from_process(cls, process: Any, duration_seconds: float = 0.0) -> "CommandResult":
        return cls(
            returncode=int(getattr(process, "returncode", 1)),
            stdout=_bounded_text(getattr(process, "stdout", ""), _MAX_OUTPUT_CHARS),
            stderr=_bounded_text(getattr(process, "stderr", ""), _MAX_OUTPUT_CHARS),
            duration_seconds=max(0.0, float(duration_seconds)),
        )


class CommandRunner(Protocol):
    def __call__(
        self,
        command: Sequence[str],
        *,
        cwd: Path,
        env: Mapping[str, str],
        timeout: float,
    ) -> CommandResult | subprocess.CompletedProcess[str]: ...


def run_command(
    command: Sequence[str],
    *,
    cwd: Path,
    env: Mapping[str, str] | None = None,
    timeout: float = _DEFAULT_TIMEOUT_SECONDS,
) -> CommandResult:
    """Run one bounded command with no shell and no inherited stdin."""
    started = time.perf_counter()
    try:
        process = subprocess.run(
            list(command),
            cwd=str(cwd),
            env=dict(env) if env is not None else None,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=_safe_timeout(timeout),
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        elapsed = time.perf_counter() - started
        return CommandResult(
            returncode=124,
            stdout=_bounded_text(getattr(exc, "stdout", ""), _MAX_OUTPUT_CHARS),
            stderr=_bounded_text(getattr(exc, "stderr", ""), _MAX_OUTPUT_CHARS),
            duration_seconds=elapsed,
        )
    except (FileNotFoundError, OSError) as exc:
        return CommandResult(
            returncode=127,
            stderr=_bounded_text(exc),
            duration_seconds=time.perf_counter() - started,
        )
    except Exception as exc:
        return CommandResult(
            returncode=125,
            stderr=_bounded_text(exc),
            duration_seconds=time.perf_counter() - started,
        )
    return CommandResult.from_process(process, time.perf_counter() - started)


@dataclass(frozen=True)
class ToolInfo:
    """Identity and invocation details for one optional executable."""

    name: str
    executable: str | None = None
    version: str | None = None
    invocation: tuple[str, ...] = ()
    invocation_mode: str | None = None
    status: str = STATUS_UNAVAILABLE

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "executable": self.executable,
            "version": self.version,
            "invocation": list(self.invocation),
            "invocation_mode": self.invocation_mode,
            "status": self.status,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ToolInfo":
        return cls(
            name=str(value.get("name", "")),
            executable=str(value["executable"]) if value.get("executable") else None,
            version=str(value["version"]) if value.get("version") else None,
            invocation=_canonical_command(value.get("invocation")),
            invocation_mode=(
                str(value["invocation_mode"]) if value.get("invocation_mode") else None
            ),
            status=str(value.get("status", STATUS_UNAVAILABLE)),
        )


@dataclass(frozen=True)
class ToolchainIdentity:
    """Reproducible project/toolchain identity used by semantic evidence."""

    repository: str
    source_revision: str | None = None
    generated_data_revision: str | None = None
    configuration_digest: str | None = None
    otp_version: str | None = None
    otp_executable: str | None = None
    elp_executable: str | None = None
    elp_version: str | None = None
    elp_otp_version: str | None = None
    elp_invocation: tuple[str, ...] = ()
    elp_invocation_mode: str | None = None
    rebar3_executable: str | None = None
    rebar3_version: str | None = None
    rebar3_invocation: tuple[str, ...] = ()
    xref_command: tuple[str, ...] = ()
    dialyzer_command: tuple[str, ...] = ()
    dependency_roots: tuple[str, ...] = ()
    plt_identity: str | None = None
    environment: tuple[tuple[str, str], ...] = ()
    tools: tuple[ToolInfo, ...] = ()
    diagnostics: tuple[str, ...] = ()

    @property
    def git_revision(self) -> str | None:
        """Compatibility alias used by repository manifests."""
        return self.source_revision

    @property
    def repository_root(self) -> str:
        return self.repository

    @property
    def config_digest(self) -> str | None:
        return self.configuration_digest

    def tool(self, name: str) -> ToolInfo | None:
        wanted = name.casefold()
        for info in self.tools:
            if info.name.casefold() == wanted:
                return info
        aliases = {
            "otp": (self.otp_executable, self.otp_version),
            "elp": (self.elp_executable, self.elp_version),
            "rebar3": (self.rebar3_executable, self.rebar3_version),
            "xref": (self.rebar3_executable, self.rebar3_version),
            "dialyzer": (self.rebar3_executable, self.rebar3_version),
        }
        executable, version = aliases.get(wanted, (None, None))
        if executable or version:
            return ToolInfo(
                name=wanted,
                executable=executable,
                version=version,
                status=STATUS_OK if executable else STATUS_UNAVAILABLE,
            )
        return None

    def to_dict(self, *, include_diagnostics: bool = True) -> dict[str, Any]:
        value: dict[str, Any] = {
            "repository": self.repository,
            "source_revision": self.source_revision,
            "generated_data_revision": self.generated_data_revision,
            "configuration_digest": self.configuration_digest,
            "otp_version": self.otp_version,
            "otp_executable": self.otp_executable,
            "elp_executable": self.elp_executable,
            "elp_version": self.elp_version,
            "elp_otp_version": self.elp_otp_version,
            "elp_invocation": list(self.elp_invocation),
            "elp_invocation_mode": self.elp_invocation_mode,
            "rebar3_executable": self.rebar3_executable,
            "rebar3_version": self.rebar3_version,
            "rebar3_invocation": list(self.rebar3_invocation),
            "xref_command": list(self.xref_command),
            "dialyzer_command": list(self.dialyzer_command),
            "dependency_roots": list(self.dependency_roots),
            "plt_identity": self.plt_identity,
            "environment": {key: value for key, value in self.environment},
            "tools": [tool.to_dict() for tool in self.tools],
        }
        if include_diagnostics:
            value["diagnostics"] = list(self.diagnostics)
        return value

    @property
    def fingerprint(self) -> str:
        return _digest(self.to_dict(include_diagnostics=False))

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ToolchainIdentity":
        raw_env = value.get("environment", {})
        env = (
            tuple(sorted((str(k), str(v)) for k, v in raw_env.items()))
            if isinstance(raw_env, Mapping)
            else ()
        )
        raw_tools = value.get("tools", ())
        tools = (
            tuple(ToolInfo.from_dict(item) for item in raw_tools if isinstance(item, Mapping))
            if isinstance(raw_tools, (list, tuple))
            else ()
        )
        return cls(
            repository=str(value.get("repository", "")),
            source_revision=(
                str(value["source_revision"]) if value.get("source_revision") else None
            ),
            generated_data_revision=(
                str(value["generated_data_revision"])
                if value.get("generated_data_revision")
                else None
            ),
            configuration_digest=(
                str(value["configuration_digest"]) if value.get("configuration_digest") else None
            ),
            otp_version=str(value["otp_version"]) if value.get("otp_version") else None,
            otp_executable=(str(value["otp_executable"]) if value.get("otp_executable") else None),
            elp_executable=str(value["elp_executable"]) if value.get("elp_executable") else None,
            elp_version=str(value["elp_version"]) if value.get("elp_version") else None,
            elp_otp_version=(
                str(value["elp_otp_version"])
                if value.get("elp_otp_version") else None
            ),
            elp_invocation=_canonical_command(value.get("elp_invocation")),
            elp_invocation_mode=(
                str(value["elp_invocation_mode"]) if value.get("elp_invocation_mode") else None
            ),
            rebar3_executable=(
                str(value["rebar3_executable"]) if value.get("rebar3_executable") else None
            ),
            rebar3_version=(str(value["rebar3_version"]) if value.get("rebar3_version") else None),
            rebar3_invocation=_canonical_command(value.get("rebar3_invocation")),
            xref_command=_canonical_command(value.get("xref_command")),
            dialyzer_command=_canonical_command(value.get("dialyzer_command")),
            dependency_roots=(
                tuple(str(item) for item in value.get("dependency_roots", ()))
                if isinstance(value.get("dependency_roots", ()), (list, tuple, set, frozenset))
                else ()
            ),
            plt_identity=str(value["plt_identity"]) if value.get("plt_identity") else None,
            environment=env,
            tools=tools,
            diagnostics=tuple(str(item) for item in value.get("diagnostics", ())),
        )


@dataclass(frozen=True)
class ToolchainDiscovery:
    """Discovery result with a structured identity and non-fatal diagnostics."""

    identity: ToolchainIdentity
    diagnostics: tuple[str, ...] = ()


@dataclass(frozen=True)
class AnalysisKey:
    """Complete cache key for one semantic query."""

    repository: str
    source_revision: str | None
    generated_data_revision: str | None
    configuration_digest: str | None
    tool: str
    tool_version: str | None
    otp_version: str | None
    query_kind: str
    query_targets: tuple[str, ...] = ()
    # PLT contents affect Dialyzer diagnostics.  Keep the field optional for
    # compatibility with callers that construct keys directly; adapters set it
    # from the discovered toolchain where applicable.
    plt_identity: str | None = None

    @classmethod
    def from_toolchain(
        cls,
        toolchain: ToolchainIdentity,
        tool: str,
        query_kind: str,
        targets: str | Sequence[str] | None = None,
    ) -> "AnalysisKey":
        info = toolchain.tool(tool)
        return cls(
            repository=toolchain.repository,
            source_revision=toolchain.source_revision,
            generated_data_revision=toolchain.generated_data_revision,
            configuration_digest=toolchain.configuration_digest,
            tool=tool.casefold(),
            tool_version=info.version if info else None,
            otp_version=toolchain.otp_version,
            query_kind=query_kind.strip().casefold(),
            query_targets=_normalise_targets(targets),
            plt_identity=(
                toolchain.plt_identity
                if tool.casefold() == "dialyzer"
                else None
            ),
        )

    @property
    def cache_key(self) -> str:
        return _digest(self.to_dict())

    @property
    def fingerprint(self) -> str:
        return self.cache_key

    @property
    def query_target(self) -> str | None:
        """Return the singular target used by legacy query callers."""
        return self.query_targets[0] if len(self.query_targets) == 1 else None

    def to_dict(self) -> dict[str, Any]:
        return {
            "repository": self.repository,
            "source_revision": self.source_revision,
            "generated_data_revision": self.generated_data_revision,
            "configuration_digest": self.configuration_digest,
            "tool": self.tool,
            "tool_version": self.tool_version,
            "otp_version": self.otp_version,
            "query_kind": self.query_kind,
            "query_targets": list(self.query_targets),
            "plt_identity": self.plt_identity,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "AnalysisKey":
        return cls(
            repository=str(value.get("repository", "")),
            source_revision=(
                str(value["source_revision"]) if value.get("source_revision") else None
            ),
            generated_data_revision=(
                str(value["generated_data_revision"])
                if value.get("generated_data_revision")
                else None
            ),
            configuration_digest=(
                str(value["configuration_digest"]) if value.get("configuration_digest") else None
            ),
            tool=str(value.get("tool", "")).casefold(),
            tool_version=str(value["tool_version"]) if value.get("tool_version") else None,
            otp_version=str(value["otp_version"]) if value.get("otp_version") else None,
            query_kind=str(value.get("query_kind", "")).casefold(),
            query_targets=_normalise_targets(value.get("query_targets")),
            plt_identity=str(value["plt_identity"]) if value.get("plt_identity") else None,
        )

    def matches(self, other: "AnalysisKey") -> bool:
        return self.to_dict() == other.to_dict()


@dataclass(frozen=True)
class Provenance:
    """Source metadata attached to every promoted relation or diagnostic."""

    source: str
    tool: str
    tool_version: str | None
    otp_version: str | None
    repository: str
    source_revision: str | None
    generated_data_revision: str | None
    configuration_digest: str | None
    query_kind: str
    query_targets: tuple[str, ...] = ()
    status: str = STATUS_OK
    analysis_key: str | None = None
    command: tuple[str, ...] = ()
    duration_seconds: float | None = None
    cache_state: str | None = None
    details: Mapping[str, Any] = field(default_factory=dict)
    # Dialyzer evidence is only valid for the exact PLT content used to
    # produce it.  Kept at the end for positional-construction compatibility.
    plt_identity: str | None = None

    @classmethod
    def from_key(
        cls,
        key: AnalysisKey,
        *,
        source: str | None = None,
        status: str = STATUS_OK,
        command: Sequence[str] | None = None,
        duration_seconds: float | None = None,
        cache_state: str | None = None,
        details: Mapping[str, Any] | None = None,
    ) -> "Provenance":
        return cls(
            source=source or key.tool,
            tool=key.tool,
            tool_version=key.tool_version,
            otp_version=key.otp_version,
            repository=key.repository,
            source_revision=key.source_revision,
            generated_data_revision=key.generated_data_revision,
            configuration_digest=key.configuration_digest,
            query_kind=key.query_kind,
            query_targets=key.query_targets,
            plt_identity=key.plt_identity,
            status=status,
            analysis_key=key.cache_key,
            command=_canonical_command(command),
            duration_seconds=duration_seconds,
            cache_state=cache_state,
            details=dict(details or {}),
        )

    def key(self) -> AnalysisKey:
        return AnalysisKey(
            repository=self.repository,
            source_revision=self.source_revision,
            generated_data_revision=self.generated_data_revision,
            configuration_digest=self.configuration_digest,
            tool=self.tool.casefold(),
            tool_version=self.tool_version,
            otp_version=self.otp_version,
            query_kind=self.query_kind.casefold(),
            query_targets=self.query_targets,
            plt_identity=self.plt_identity,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "tool": self.tool,
            "tool_version": self.tool_version,
            "otp_version": self.otp_version,
            "repository": self.repository,
            "source_revision": self.source_revision,
            "generated_data_revision": self.generated_data_revision,
            "configuration_digest": self.configuration_digest,
            "query_kind": self.query_kind,
            "query_targets": list(self.query_targets),
            "plt_identity": self.plt_identity,
            "status": self.status,
            "analysis_key": self.analysis_key,
            "command": list(self.command),
            "duration_seconds": self.duration_seconds,
            "cache_state": self.cache_state,
            "details": dict(self.details),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "Provenance":
        return cls(
            source=str(value.get("source", "unknown")),
            tool=str(value.get("tool", "unknown")),
            tool_version=str(value["tool_version"]) if value.get("tool_version") else None,
            otp_version=str(value["otp_version"]) if value.get("otp_version") else None,
            repository=str(value.get("repository", "")),
            source_revision=(
                str(value["source_revision"]) if value.get("source_revision") else None
            ),
            generated_data_revision=(
                str(value["generated_data_revision"])
                if value.get("generated_data_revision")
                else None
            ),
            configuration_digest=(
                str(value["configuration_digest"]) if value.get("configuration_digest") else None
            ),
            query_kind=str(value.get("query_kind", "")),
            query_targets=_normalise_targets(value.get("query_targets")),
            plt_identity=str(value["plt_identity"]) if value.get("plt_identity") else None,
            status=str(value.get("status", STATUS_OK)),
            analysis_key=str(value["analysis_key"]) if value.get("analysis_key") else None,
            command=_canonical_command(value.get("command")),
            duration_seconds=(
                float(value["duration_seconds"])
                if value.get("duration_seconds") is not None
                else None
            ),
            cache_state=str(value["cache_state"]) if value.get("cache_state") else None,
            details=(dict(value["details"]) if isinstance(value.get("details"), Mapping) else {}),
        )


@dataclass(frozen=True)
class EvidenceRecord:
    """One explicit relation candidate returned by a semantic adapter."""

    kind: str
    source: str
    target: str
    provenance: Provenance
    file_path: str | None = None
    line: int | None = None
    column: int | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)
    status: str = STATUS_OK
    provenance_chain: tuple[Provenance, ...] = ()

    @property
    def relation(self) -> str:
        return self.kind

    @property
    def source_qualified(self) -> str:
        return self.source

    @property
    def target_qualified(self) -> str:
        return self.target

    @property
    def extra(self) -> Mapping[str, Any]:
        return self.metadata

    @property
    def query_kind(self) -> str:
        return self.provenance.query_kind

    @property
    def identity(self) -> tuple[Any, ...]:
        return (
            self.kind,
            self.source,
            self.target,
            self.file_path,
            self.line,
            self.column,
            self.provenance.query_kind,
        )

    @property
    def conflict_identity(self) -> tuple[Any, ...]:
        return (
            self.kind,
            self.source,
            self.file_path,
            self.line,
            self.column,
            self.provenance.query_kind,
        )

    @property
    def evidence_id(self) -> str:
        return _digest(
            {
                "kind": self.kind,
                "source": self.source,
                "target": self.target,
                "file_path": self.file_path,
                "line": self.line,
                "column": self.column,
                "query_kind": self.provenance.query_kind,
            }
        )

    def with_provenance_chain(self, chain: Iterable[Provenance]) -> "EvidenceRecord":
        unique: dict[str, Provenance] = {}
        for item in chain:
            if item == self.provenance:
                continue
            unique[_canonical_json(item.to_dict())] = item
        ordered = tuple(unique[key] for key in sorted(unique))
        return replace(self, provenance_chain=ordered)

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "source": self.source,
            "target": self.target,
            "file_path": self.file_path,
            "line": self.line,
            "column": self.column,
            "metadata": dict(self.metadata),
            "status": self.status,
            "evidence_id": self.evidence_id,
            "provenance": self.provenance.to_dict(),
            "provenance_chain": [item.to_dict() for item in self.provenance_chain],
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "EvidenceRecord":
        raw_chain = value.get("provenance_chain", ())
        chain = (
            tuple(Provenance.from_dict(item) for item in raw_chain if isinstance(item, Mapping))
            if isinstance(raw_chain, (list, tuple))
            else ()
        )
        raw_provenance = value.get("provenance", {})
        provenance = (
            Provenance.from_dict(raw_provenance)
            if isinstance(raw_provenance, Mapping)
            else Provenance(
                source="unknown",
                tool="unknown",
                tool_version=None,
                otp_version=None,
                repository="",
                source_revision=None,
                generated_data_revision=None,
                configuration_digest=None,
                query_kind="",
                status=STATUS_MALFORMED,
            )
        )
        return cls(
            kind=str(value.get("kind", "")),
            source=str(value.get("source", "")),
            target=str(value.get("target", "")),
            provenance=provenance,
            file_path=str(value["file_path"]) if value.get("file_path") else None,
            line=int(value["line"]) if value.get("line") is not None else None,
            column=int(value["column"]) if value.get("column") is not None else None,
            metadata=(
                dict(value["metadata"]) if isinstance(value.get("metadata"), Mapping) else {}
            ),
            status=str(value.get("status", provenance.status)),
            provenance_chain=chain,
        )


@dataclass(frozen=True)
class Diagnostic:
    """A tool or cache diagnostic preserved in review context."""

    code: str
    message: str
    provenance: Provenance
    severity: str = "warning"
    file_path: str | None = None
    line: int | None = None
    column: int | None = None
    raw: str | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    @property
    def identity(self) -> tuple[Any, ...]:
        return (
            self.code,
            self.message,
            self.severity,
            self.file_path,
            self.line,
            self.column,
            self.provenance.source,
            self.provenance.tool,
            self.provenance.query_kind,
            self.provenance.query_targets,
        )

    @property
    def diagnostic_id(self) -> str:
        return _digest(
            {
                "code": self.code,
                "message": self.message,
                "severity": self.severity,
                "file_path": self.file_path,
                "line": self.line,
                "column": self.column,
                "source": self.provenance.source,
                "tool": self.provenance.tool,
                "query_kind": self.provenance.query_kind,
                "query_targets": list(self.provenance.query_targets),
            }
        )

    @property
    def status(self) -> str:
        return self.provenance.status

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "message": self.message,
            "severity": self.severity,
            "file_path": self.file_path,
            "line": self.line,
            "column": self.column,
            "raw": self.raw,
            "metadata": dict(self.metadata),
            "diagnostic_id": self.diagnostic_id,
            "provenance": self.provenance.to_dict(),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "Diagnostic":
        raw_provenance = value.get("provenance", {})
        provenance = (
            Provenance.from_dict(raw_provenance)
            if isinstance(raw_provenance, Mapping)
            else Provenance(
                source="unknown",
                tool="unknown",
                tool_version=None,
                otp_version=None,
                repository="",
                source_revision=None,
                generated_data_revision=None,
                configuration_digest=None,
                query_kind="",
                status=STATUS_MALFORMED,
            )
        )
        return cls(
            code=str(value.get("code", "unknown")),
            message=str(value.get("message", "")),
            provenance=provenance,
            severity=str(value.get("severity", "warning")),
            file_path=str(value["file_path"]) if value.get("file_path") else None,
            line=int(value["line"]) if value.get("line") is not None else None,
            column=int(value["column"]) if value.get("column") is not None else None,
            raw=str(value["raw"]) if value.get("raw") is not None else None,
            metadata=(
                dict(value["metadata"]) if isinstance(value.get("metadata"), Mapping) else {}
            ),
        )


@dataclass(frozen=True)
class AdapterResult:
    """Non-throwing result from one optional semantic adapter invocation."""

    tool: str
    status: str
    provenance: Provenance
    evidence: tuple[EvidenceRecord, ...] = ()
    diagnostics: tuple[Diagnostic, ...] = ()
    command: tuple[str, ...] = ()
    stdout: str = ""
    stderr: str = ""

    @property
    def ok(self) -> bool:
        return self.status == STATUS_OK

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "status": self.status,
            "provenance": self.provenance.to_dict(),
            "evidence": [item.to_dict() for item in self.evidence],
            "diagnostics": [item.to_dict() for item in self.diagnostics],
            "command": list(self.command),
            "stdout": self.stdout,
            "stderr": self.stderr,
        }


@dataclass(frozen=True)
class ReconciliationResult:
    evidence: tuple[EvidenceRecord, ...]
    diagnostics: tuple[Diagnostic, ...]
    stale_evidence: tuple[EvidenceRecord, ...] = ()
    conflicts: tuple[tuple[str, ...], ...] = ()

    @property
    def evidence_count(self) -> int:
        return len(self.evidence)

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence": [item.to_dict() for item in self.evidence],
            "diagnostics": [item.to_dict() for item in self.diagnostics],
            "stale_evidence": [item.to_dict() for item in self.stale_evidence],
            "conflicts": [list(item) for item in self.conflicts],
        }


def _provenance_matches_key(provenance: Provenance, key: AnalysisKey) -> bool:
    if provenance.analysis_key:
        return provenance.analysis_key == key.cache_key
    # Older serialized evidence may not carry the digest.  Compare all fields
    # that are available, conservatively requiring the query kind and source
    # revision to match.
    return (
        provenance.repository == key.repository
        and provenance.tool.casefold() == key.tool.casefold()
        and provenance.query_kind.casefold() == key.query_kind.casefold()
        and provenance.source_revision == key.source_revision
        and provenance.generated_data_revision == key.generated_data_revision
        and provenance.configuration_digest == key.configuration_digest
        and provenance.tool_version == key.tool_version
        and provenance.otp_version == key.otp_version
        and provenance.plt_identity == key.plt_identity
        and (
            not key.query_targets
            or not provenance.query_targets
            or provenance.query_targets == key.query_targets
        )
    )


class EvidenceReconciler:
    """Merge adapter output deterministically and reject stale revisions."""

    def reconcile(
        self,
        incoming: Iterable[EvidenceRecord] = (),
        *,
        analysis_key: AnalysisKey | None = None,
        previous: Iterable[EvidenceRecord] = (),
        diagnostics: Iterable[Diagnostic] = (),
        previous_diagnostics: Iterable[Diagnostic] = (),
        replace_queries: Iterable[str] = (),
        unavailable_queries: Iterable[str] = (),
    ) -> ReconciliationResult:
        """Return a stable snapshot.

        ``replace_queries`` denotes successful refreshes: old records for the
        query are replaced.  ``unavailable_queries`` preserves matching old
        records while exposing the adapter diagnostic, which is the required
        timeout/failure fallback behavior.
        """
        incoming_list = list(incoming)
        previous_list = list(previous)
        replace_set = {str(item).casefold() for item in replace_queries}
        unavailable_set = {str(item).casefold() for item in unavailable_queries}
        stale: list[EvidenceRecord] = []
        retained: list[EvidenceRecord] = []

        for record in previous_list:
            query = record.provenance.query_kind.casefold()
            if analysis_key is not None and not _provenance_matches_key(
                record.provenance, analysis_key
            ):
                stale.append(record)
                continue
            if query in replace_set and query not in unavailable_set:
                continue
            retained.append(record)

        valid_incoming: list[EvidenceRecord] = []
        for record in incoming_list:
            if analysis_key is not None and not _provenance_matches_key(
                record.provenance, analysis_key
            ):
                stale.append(record)
            elif record.status == STATUS_OK and record.provenance.status == STATUS_OK:
                valid_incoming.append(record)

        # A query that completed successfully replaces matching previous data,
        # even if it returned zero relations.
        all_records = retained + valid_incoming
        grouped: dict[tuple[Any, ...], list[EvidenceRecord]] = defaultdict(list)
        for record in all_records:
            grouped[record.identity].append(record)

        merged: list[EvidenceRecord] = []
        for identity in sorted(grouped, key=lambda item: _canonical_json(item)):
            records = grouped[identity]
            records.sort(key=lambda item: _canonical_json(item.provenance.to_dict()))
            primary = records[0]
            chain = [record.provenance for record in records[1:]]
            merged_metadata: dict[str, Any] = {}
            for record in records:
                for metadata_key, metadata_value in record.metadata.items():
                    if metadata_key not in merged_metadata:
                        merged_metadata[metadata_key] = metadata_value
                    elif merged_metadata[metadata_key] != metadata_value:
                        values = merged_metadata[metadata_key]
                        if not isinstance(values, list):
                            values = [values]
                        if metadata_value not in values:
                            values.append(metadata_value)
                        merged_metadata[metadata_key] = sorted(
                            values, key=_canonical_json
                        )
            if len(records) > 1:
                primary = primary.with_provenance_chain(chain)
            if merged_metadata != dict(primary.metadata):
                primary = replace(primary, metadata=merged_metadata)
            merged.append(primary)

        # Keep conflicts visible.  The conflict group is metadata, not a
        # replacement target, so consumers can make their own promotion choice.
        conflict_groups: list[tuple[str, ...]] = []
        by_conflict: dict[tuple[Any, ...], list[int]] = defaultdict(list)
        for index, record in enumerate(merged):
            by_conflict[record.conflict_identity].append(index)
        for conflict_identity, indexes in sorted(
            by_conflict.items(), key=lambda item: _canonical_json(item[0])
        ):
            targets = sorted({merged[index].target for index in indexes})
            if len(targets) < 2:
                continue
            conflict_id = _digest({"identity": conflict_identity, "targets": targets})
            conflict_groups.append((conflict_id, *targets))
            for index in indexes:
                metadata = dict(merged[index].metadata)
                metadata["conflict_group"] = conflict_id
                metadata["conflict_targets"] = targets
                merged[index] = replace(merged[index], metadata=metadata)

        # Diagnostics follow the same revision/query rules as evidence.  Keep
        # a prior diagnostic only when its query is still current; a successful
        # refresh replaces the old diagnostic, while an unavailable refresh
        # leaves it visible alongside the new unavailable diagnostic.
        diagnostic_list = list(diagnostics)
        for diagnostic in previous_diagnostics:
            query = diagnostic.provenance.query_kind.casefold()
            if analysis_key is not None and not _provenance_matches_key(
                diagnostic.provenance, analysis_key
            ):
                continue
            if query in replace_set and query not in unavailable_set:
                continue
            diagnostic_list.append(diagnostic)
        if stale:
            grouped_stale = sorted(
                {
                    record.provenance.analysis_key or record.provenance.source_revision or "unknown"
                    for record in stale
                }
            )
            if analysis_key is not None:
                stale_provenance = Provenance.from_key(
                    analysis_key,
                    source="reconciler",
                    status=STATUS_STALE,
                    details={"stale_keys": grouped_stale},
                )
                diagnostic_list.append(
                    Diagnostic(
                        code="evidence_stale",
                        message=(
                            "Semantic evidence was discarded because its revision "
                            "key did not match."
                        ),
                        provenance=stale_provenance,
                        severity="info",
                        metadata={"stale_keys": grouped_stale},
                    )
                )

        unique_diagnostics: dict[tuple[Any, ...], Diagnostic] = {}
        for diagnostic in diagnostic_list:
            unique_diagnostics.setdefault(diagnostic.identity, diagnostic)
        ordered_diagnostics = tuple(
            unique_diagnostics[key]
            for key in sorted(unique_diagnostics, key=lambda item: _canonical_json(item))
        )
        ordered_evidence = tuple(
            sorted(
                merged,
                key=lambda item: (
                    item.kind,
                    item.source,
                    item.target,
                    item.file_path or "",
                    item.line if item.line is not None else -1,
                    item.column if item.column is not None else -1,
                    item.provenance.query_kind,
                ),
            )
        )
        return ReconciliationResult(
            evidence=ordered_evidence,
            diagnostics=ordered_diagnostics,
            stale_evidence=tuple(sorted(stale, key=lambda item: item.evidence_id)),
            conflicts=tuple(conflict_groups),
        )


@dataclass(frozen=True)
class CacheLoadResult:
    status: str
    evidence: tuple[EvidenceRecord, ...] = ()
    diagnostics: tuple[Diagnostic, ...] = ()
    message: str | None = None
    # ``status`` remains ``miss`` for all non-hit paths so callers that only
    # understand the original cache contract keep working.  ``stale`` tells a
    # caller that recomputation is required because an older or incompatible
    # entry was found.
    stale: bool = False

    @property
    def hit(self) -> bool:
        return self.status == "hit"

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "evidence": [item.to_dict() for item in self.evidence],
            "diagnostics": [item.to_dict() for item in self.diagnostics],
            "message": self.message,
            "stale": self.stale,
        }


@dataclass(frozen=True)
class EnrichmentQuery:
    """One bounded semantic query requested by the enrichment boundary."""

    tool: str
    query_kind: str
    targets: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        tool = str(self.tool).strip().casefold()
        query_kind = str(self.query_kind).strip().casefold()
        if not tool:
            raise ValueError("enrichment query tool must not be empty")
        if not query_kind:
            raise ValueError("enrichment query kind must not be empty")
        object.__setattr__(self, "tool", tool)
        object.__setattr__(self, "query_kind", query_kind)
        object.__setattr__(self, "targets", _normalise_targets(self.targets))

    @property
    def kind(self) -> str:
        """Alias for callers that use ``kind`` in query specifications."""
        return self.query_kind

    @property
    def query_targets(self) -> tuple[str, ...]:
        return self.targets

    @classmethod
    def from_value(cls, value: Any) -> "EnrichmentQuery":
        """Coerce a query object, mapping, or ``(tool, kind, targets)`` tuple."""
        if isinstance(value, cls):
            return value
        if isinstance(value, Mapping):
            tool = value.get("tool", "elp")
            query_kind = value.get("query_kind", value.get("kind", value.get("query")))
            targets = value.get(
                "targets",
                value.get("query_targets", value.get("target")),
            )
            if query_kind is None:
                raise ValueError("enrichment query mapping requires query_kind")
            return cls(str(tool), str(query_kind), _normalise_targets(targets))
        if isinstance(value, str):
            # A bare query name is an ELP query; this keeps the common targeted
            # call site concise while all non-ELP work remains explicit.
            return cls("elp", value)
        if isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
            parts = tuple(value)
            if len(parts) == 2:
                return cls(str(parts[0]), str(parts[1]))
            if len(parts) == 3:
                return cls(str(parts[0]), str(parts[1]), _normalise_targets(parts[2]))
        raise ValueError(
            "enrichment query must be EnrichmentQuery, mapping, string, or "
            "(tool, query_kind[, targets])"
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "query_kind": self.query_kind,
            "query_targets": list(self.targets),
        }


@dataclass(frozen=True)
class EnrichmentResult:
    """Immutable output of :func:`run_erlang_enrichment`.

    The result deliberately contains no ``GraphStore`` references.  Build,
    incremental, watch, and standalone postprocess callers can therefore use
    the same adapter/reconciliation boundary and decide independently how
    evidence is projected into their existing graph metadata and edges.
    """

    toolchain: ToolchainIdentity
    evidence: tuple[EvidenceRecord, ...] = ()
    diagnostics: tuple[Diagnostic, ...] = ()
    adapter_results: tuple[AdapterResult, ...] = ()
    cache_results: tuple[tuple[str, CacheLoadResult], ...] = ()
    stale_evidence: tuple[EvidenceRecord, ...] = ()
    conflicts: tuple[tuple[str, ...], ...] = ()
    discovery_diagnostics: tuple[str, ...] = ()
    status: str = STATUS_OK

    @property
    def ok(self) -> bool:
        """Whether all invoked enrichment work completed successfully."""
        return self.status == STATUS_OK

    @property
    def cache_state(self) -> Mapping[str, str]:
        """Return a compact, deterministic view of cache outcomes."""
        return {
            key: ("hit" if value.hit else "stale" if value.stale else value.status)
            for key, value in self.cache_results
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "toolchain": self.toolchain.to_dict(),
            "evidence": [item.to_dict() for item in self.evidence],
            "diagnostics": [item.to_dict() for item in self.diagnostics],
            "adapter_results": [item.to_dict() for item in self.adapter_results],
            "cache_results": {
                key: value.to_dict() for key, value in self.cache_results
            },
            "stale_evidence": [item.to_dict() for item in self.stale_evidence],
            "conflicts": [list(item) for item in self.conflicts],
            "discovery_diagnostics": list(self.discovery_diagnostics),
        }


class EvidenceCache:
    """Small JSON cache keyed by :class:`AnalysisKey.cache_key`."""

    schema_version = 1

    def __init__(self, directory: str | Path) -> None:
        self.directory = Path(directory).expanduser().resolve()

    def path_for(self, key: AnalysisKey) -> Path:
        return self.directory / f"{key.cache_key}.json"

    @staticmethod
    def _same_query_scope(left: AnalysisKey, right: AnalysisKey) -> bool:
        return (
            left.repository == right.repository
            and left.tool == right.tool
            and left.query_kind == right.query_kind
            and left.query_targets == right.query_targets
        )

    def _has_stale_scope(self, key: AnalysisKey) -> bool:
        """Detect an older revision entry when the current hash path is absent."""
        if not self.directory.is_dir():
            return False
        try:
            paths = sorted(self.directory.glob("*.json"))[:1024]
        except OSError:
            return False
        current = self.path_for(key)
        for path in paths:
            if path == current:
                continue
            try:
                if path.stat().st_size > _MAX_CACHE_FILE_BYTES:
                    continue
                payload = json.loads(path.read_text(encoding="utf-8"))
                raw_key = payload.get("analysis_key") if isinstance(payload, Mapping) else None
                if isinstance(raw_key, Mapping):
                    cached_key = AnalysisKey.from_dict(raw_key)
                    if self._same_query_scope(cached_key, key):
                        return True
            except (OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError):
                continue
        return False

    def load(self, key: AnalysisKey) -> CacheLoadResult:
        path = self.path_for(key)
        if not path.is_file():
            stale_scope = self._has_stale_scope(key)
            return CacheLoadResult(
                # A cache miss is still a miss from the caller's point of
                # view.  ``message`` carries the actionable stale hint while
                # keeping the long-standing miss contract intact.
                status="miss",
                message=(
                    "an older cache entry exists for this query"
                    if stale_scope
                    else None
                ),
                stale=stale_scope,
            )
        try:
            if path.stat().st_size > _MAX_CACHE_FILE_BYTES:
                return CacheLoadResult(
                    status=STATUS_MALFORMED,
                    message="cache entry is too large",
                    stale=True,
                )
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            return CacheLoadResult(
                status=STATUS_MALFORMED,
                message=_bounded_text(exc),
                stale=True,
            )
        if not isinstance(payload, Mapping):
            return CacheLoadResult(
                status=STATUS_MALFORMED,
                message="cache envelope is not an object",
                stale=True,
            )
        if payload.get("schema_version") != self.schema_version:
            return CacheLoadResult(
                status="miss",
                message="cache schema version is not supported",
                stale=True,
            )
        raw_key = payload.get("analysis_key")
        if not isinstance(raw_key, Mapping):
            return CacheLoadResult(
                status=STATUS_MALFORMED,
                message="cache key is missing",
                stale=True,
            )
        try:
            cached_key = AnalysisKey.from_dict(raw_key)
        except (TypeError, ValueError, KeyError) as exc:
            return CacheLoadResult(
                status=STATUS_MALFORMED,
                message=_bounded_text(exc),
                stale=True,
            )
        if not cached_key.matches(key):
            return CacheLoadResult(
                status="miss",
                message="analysis key mismatch",
                stale=True,
            )
        raw_evidence = payload.get("evidence", ())
        raw_diagnostics = payload.get("diagnostics", ())
        if not isinstance(raw_evidence, list) or not isinstance(raw_diagnostics, list):
            return CacheLoadResult(
                status=STATUS_MALFORMED,
                message="cache records are not lists",
                stale=True,
            )
        if any(not isinstance(item, Mapping) for item in (*raw_evidence, *raw_diagnostics)):
            return CacheLoadResult(
                status=STATUS_MALFORMED,
                message="cache contains a non-object record",
                stale=True,
            )
        try:
            parsed_evidence = tuple(EvidenceRecord.from_dict(item) for item in raw_evidence)
            parsed_diagnostics = tuple(Diagnostic.from_dict(item) for item in raw_diagnostics)
        except (TypeError, ValueError, KeyError) as exc:
            return CacheLoadResult(
                status=STATUS_MALFORMED,
                message=_bounded_text(exc),
                stale=True,
            )
        if any(not _provenance_matches_key(item.provenance, key) for item in parsed_evidence):
            return CacheLoadResult(
                status="miss",
                message="cache evidence provenance does not match the analysis key",
                stale=True,
            )
        if any(
            not _provenance_matches_key(item.provenance, key)
            for item in parsed_diagnostics
        ):
            return CacheLoadResult(
                status="miss",
                message="cache record provenance does not match the analysis key",
                stale=True,
            )
        return CacheLoadResult(
            status="hit",
            evidence=tuple(
                item for item in parsed_evidence
                if item.status == STATUS_OK and item.provenance.status == STATUS_OK
            ),
            diagnostics=parsed_diagnostics,
        )

    def save(
        self,
        key: AnalysisKey,
        evidence: Iterable[EvidenceRecord] = (),
        diagnostics: Iterable[Diagnostic] = (),
    ) -> Path:
        """Atomically write one deterministic cache envelope."""
        self.directory.mkdir(parents=True, exist_ok=True)
        evidence_values = tuple(evidence)
        diagnostic_values = tuple(diagnostics)
        if any(
            not _provenance_matches_key(item.provenance, key)
            for item in evidence_values
        ):
            raise ValueError("cannot cache evidence from a different analysis key")
        if any(
            not _provenance_matches_key(item.provenance, key)
            for item in diagnostic_values
        ):
            raise ValueError("cannot cache diagnostics from a different analysis key")
        payload = {
            "schema_version": self.schema_version,
            "analysis_key": key.to_dict(),
            "evidence": [
                item.to_dict()
                for item in sorted(evidence_values, key=lambda item: item.evidence_id)
            ],
            "diagnostics": [
                item.to_dict()
                for item in sorted(diagnostic_values, key=lambda item: item.diagnostic_id)
            ],
        }
        destination = self.path_for(key)
        fd, temporary = tempfile.mkstemp(
            prefix=f".{key.cache_key}.", suffix=".tmp", dir=self.directory
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, destination)
        except BaseException:
            try:
                os.unlink(temporary)
            except OSError:
                pass
            raise
        return destination


def compute_plt_identity(path: str | Path) -> str | None:
    """Hash a PLT file without treating a missing file as current evidence."""
    candidate = Path(path).expanduser()
    if not candidate.is_file():
        return None
    digest = hashlib.sha256()
    try:
        with candidate.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError:
        return None
    return digest.hexdigest()


def _hash_paths(root: Path, paths: Iterable[Path]) -> str | None:
    digest = hashlib.sha256()
    found = False
    count = 0
    for path in sorted({path.resolve() for path in paths}, key=lambda item: item.as_posix()):
        if count >= 4096:
            break
        if path.is_file():
            found = True
            try:
                relative = path.relative_to(root).as_posix()
                digest.update(relative.encode("utf-8", "replace"))
                digest.update(b"\0")
                with path.open("rb") as handle:
                    for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                        digest.update(chunk)
            except (OSError, ValueError):
                continue
            count += 1
        elif path.is_dir():
            children: list[Path] = []
            try:
                children = [child for child in path.rglob("*") if child.is_file()]
            except OSError:
                continue
            nested = _hash_paths(root, children)
            if nested:
                found = True
                digest.update(path.relative_to(root).as_posix().encode("utf-8", "replace"))
                digest.update(nested.encode("ascii"))
    return digest.hexdigest() if found else None


def compute_configuration_digest(repo_root: str | Path) -> str | None:
    """Hash configuration files that can alter semantic command output."""
    root = Path(repo_root).expanduser().resolve()
    names = (
        "rebar.config",
        "rebar.config.script",
        "erlang_ls.config",
        "elp.toml",
        ".elp.toml",
        "rebar.lock",
        "mix.exs",
    )
    return _hash_paths(root, (root / name for name in names))


def compute_generated_data_revision(
    repo_root: str | Path,
    paths: Iterable[str | Path] | None = None,
) -> str | None:
    """Return a content digest for explicit generated data or a marker file."""
    root = Path(repo_root).expanduser().resolve()
    if paths is not None:
        resolved = [Path(path) if Path(path).is_absolute() else root / Path(path) for path in paths]
        return _hash_paths(root, resolved)
    marker_names = (
        ".code-review-graph/generated-data-revision",
        "generated-data-revision",
        ".generated-revision",
        "GENERATION_REVISION",
    )
    for name in marker_names:
        marker = root / name
        if marker.is_file():
            try:
                value = marker.read_text(encoding="utf-8").strip()
            except OSError:
                continue
            if value:
                return value
    return None


def _extract_version(output: str, *, tool: str) -> str | None:
    text = output.strip()
    if tool == "otp":
        # ``erl`` prints a bare release when queried with system_info; prefer
        # that exact token over an unrelated runtime version in stderr.
        match = re.search(r"\b(\d{2,3})(?:\.\d+)?\b", text)
        return match.group(1) if match else None
    match = _VERSION_RE.search(text)
    return match.group(1) if match else None


def _find_executable(
    repo_root: Path, local_names: Sequence[str], path_names: Sequence[str]
) -> str | None:
    for name in local_names:
        candidate = repo_root / name
        if candidate.is_file():
            return _canonical_path(candidate)
    for name in path_names:
        found = shutil.which(name)
        if found:
            return _canonical_path(found)
    return None


def _default_discovery_runner(
    command: Sequence[str],
    *,
    cwd: Path,
    env: Mapping[str, str],
    timeout: float,
) -> CommandResult:
    return run_command(command, cwd=cwd, env=env, timeout=timeout)


def _discover_version(
    executable: str | None,
    command: Sequence[str],
    *,
    tool: str,
    cwd: Path,
    env: Mapping[str, str],
    timeout: float,
    runner: CommandRunner,
    diagnostics: list[str],
) -> str | None:
    if executable is None:
        diagnostics.append(f"{tool}_unavailable: executable was not found")
        return None
    try:
        started = time.perf_counter()
        raw = runner(command, cwd=cwd, env=env, timeout=timeout)
        result = (
            raw
            if isinstance(raw, CommandResult)
            else CommandResult.from_process(
                raw,
                time.perf_counter() - started,
            )
        )
    except subprocess.TimeoutExpired:
        diagnostics.append(f"{tool}_timeout: version command exceeded timeout")
        return None
    except (FileNotFoundError, OSError) as exc:
        diagnostics.append(f"{tool}_failed: {_bounded_text(exc)}")
        return None
    except Exception as exc:
        diagnostics.append(f"{tool}_failed: {_bounded_text(exc)}")
        return None
    if result.returncode == 124:
        diagnostics.append(f"{tool}_timeout: version command exceeded timeout")
        return None
    if result.returncode == 127:
        diagnostics.append(f"{tool}_unavailable: executable could not be invoked")
        return None
    if result.returncode != 0:
        diagnostics.append(f"{tool}_failed: {_bounded_text(result.stderr or result.stdout)}")
        return None
    version = _extract_version(result.stdout or result.stderr, tool=tool)
    if version is None:
        diagnostics.append(f"{tool}_version_unknown: command returned no parseable version")
    return version


def _git_revision(
    root: Path, runner: CommandRunner, env: Mapping[str, str], timeout: float
) -> str | None:
    try:
        raw = runner(("git", "rev-parse", "--verify", "HEAD"), cwd=root, env=env, timeout=timeout)
        result = raw if isinstance(raw, CommandResult) else CommandResult.from_process(raw)
    except Exception:
        return None
    return result.stdout.strip() if result.returncode == 0 and result.stdout.strip() else None


def discover_toolchain(
    repo_root: str | Path,
    *,
    runner: CommandRunner | None = None,
    timeout: float = 2.0,
    environment: Mapping[str, str] | None = None,
    source_revision: str | None = None,
    generated_data_revision: str | None = None,
    generated_data_paths: Iterable[str | Path] | None = None,
    plt_path: str | Path | None = None,
) -> ToolchainIdentity:
    """Discover optional Erlang tooling without evaluating project code."""
    root = Path(repo_root).expanduser().resolve()
    command_runner = runner or _default_discovery_runner
    safe_timeout = _safe_timeout(timeout)
    supplied_env = _controlled_environment(environment)
    # The subprocess receives only explicitly supplied variables plus a small
    # set needed to locate executables.  This avoids leaking the full parent
    # environment into project commands and makes manifests reproducible.
    command_env = dict(supplied_env)
    diagnostics: list[str] = []

    otp_executable = _find_executable(root, (), ("erl",))
    elp_executable = _find_executable(root, ("elp", "bin/elp"), ("elp",))
    rebar3_executable = _find_executable(root, ("rebar3", "rebar3.cmd"), ("rebar3",))
    otp_command = (
        (
            otp_executable,
            "-noshell",
            "-eval",
            'io:format("~s", [erlang:system_info(otp_release)]), halt().',
        )
        if otp_executable
        else ()
    )
    elp_command = (elp_executable, "--version") if elp_executable else ()
    rebar3_command = (rebar3_executable, "--version") if rebar3_executable else ()
    otp_version = _discover_version(
        otp_executable,
        otp_command,
        tool="otp",
        cwd=root,
        env=command_env,
        timeout=safe_timeout,
        runner=command_runner,
        diagnostics=diagnostics,
    )
    elp_version = _discover_version(
        elp_executable,
        elp_command,
        tool="elp",
        cwd=root,
        env=command_env,
        timeout=safe_timeout,
        runner=command_runner,
        diagnostics=diagnostics,
    )
    rebar3_version = _discover_version(
        rebar3_executable,
        rebar3_command,
        tool="rebar3",
        cwd=root,
        env=command_env,
        timeout=safe_timeout,
        runner=command_runner,
        diagnostics=diagnostics,
    )
    # ELP does not consistently print the OTP release it was compiled for.
    # Preserve an explicitly supplied deployment hint in the manifest so the
    # adapter can enforce the OTP compatibility check later.
    elp_otp_version = supplied_env.get("ELP_OTP_VERSION")
    if source_revision is None:
        source_revision = _git_revision(root, command_runner, command_env, safe_timeout)
    if generated_data_revision is None:
        generated_data_revision = compute_generated_data_revision(root, generated_data_paths)
    configuration_digest = compute_configuration_digest(root)
    dependency_roots = tuple(
        _canonical_path(path)
        for path in (root / "deps", root / "_build" / "default" / "lib", root / "apps")
        if path.is_dir()
    )
    plt_identity = compute_plt_identity(plt_path) if plt_path is not None else None
    xref_command = (rebar3_executable, "xref") if rebar3_executable else ()
    dialyzer_command = (rebar3_executable, "dialyzer") if rebar3_executable else ()
    tools = (
        ToolInfo(
            "otp",
            otp_executable,
            otp_version,
            otp_command,
            "erl",
            STATUS_OK if otp_version else STATUS_UNAVAILABLE,
        ),
        ToolInfo(
            "elp",
            elp_executable,
            elp_version,
            elp_command,
            "cli",
            STATUS_OK if elp_version else STATUS_UNAVAILABLE,
        ),
        ToolInfo(
            "rebar3",
            rebar3_executable,
            rebar3_version,
            rebar3_command,
            "cli",
            STATUS_OK if rebar3_version else STATUS_UNAVAILABLE,
        ),
    )
    return ToolchainIdentity(
        repository=_canonical_path(root),
        source_revision=source_revision,
        generated_data_revision=generated_data_revision,
        configuration_digest=configuration_digest,
        otp_version=otp_version,
        otp_executable=otp_executable,
        elp_executable=elp_executable,
        elp_version=elp_version,
        elp_otp_version=elp_otp_version,
        elp_invocation=elp_command,
        elp_invocation_mode="cli" if elp_executable else None,
        rebar3_executable=rebar3_executable,
        rebar3_version=rebar3_version,
        rebar3_invocation=rebar3_command,
        xref_command=xref_command,
        dialyzer_command=dialyzer_command,
        dependency_roots=dependency_roots,
        plt_identity=plt_identity,
        environment=_redacted_environment(supplied_env),
        tools=tools,
        diagnostics=tuple(diagnostics),
    )


def _make_provenance(
    key: AnalysisKey,
    *,
    status: str,
    command: Sequence[str],
    result: CommandResult | None = None,
    details: Mapping[str, Any] | None = None,
) -> Provenance:
    return Provenance.from_key(
        key,
        source=key.tool,
        status=status,
        command=command,
        duration_seconds=result.duration_seconds if result else None,
        details=details,
    )


def _diagnostic(
    key: AnalysisKey,
    *,
    code: str,
    message: str,
    status: str,
    command: Sequence[str] = (),
    result: CommandResult | None = None,
    severity: str = "warning",
    file_path: str | None = None,
    line: int | None = None,
    column: int | None = None,
    raw: str | None = None,
    metadata: Mapping[str, Any] | None = None,
) -> Diagnostic:
    return Diagnostic(
        code=code,
        message=_bounded_text(message),
        severity=severity,
        file_path=file_path,
        line=line,
        column=column,
        raw=_bounded_text(raw) if raw else None,
        metadata=dict(metadata or {}),
        provenance=_make_provenance(key, status=status, command=command, result=result),
    )


def _normalise_relation_kind(value: Any, *, default: str) -> str:
    kind = str(value or default).strip().upper().replace("-", "_")
    aliases = {
        "CALL": "CALLS",
        "CALLER": "CALLS",
        "CALLERS": "CALLS",
        "DEPENDENCY": "DEPENDS_ON",
        "DEPENDENCIES": "DEPENDS_ON",
        "MODULE_CALL": "DEPENDS_ON",
        "MODULE_CALLS": "DEPENDS_ON",
    }
    return aliases.get(kind, kind)


def _iter_relation_values(payload: Any, *, default_kind: str) -> Iterable[Mapping[str, Any]]:
    if isinstance(payload, Mapping):
        for key in ("evidence", "relations", "edges", "results", "calls", "dependencies"):
            values = payload.get(key)
            if isinstance(values, list):
                for value in values:
                    if isinstance(value, Mapping):
                        item = dict(value)
                        item.setdefault(
                            "kind", default_kind if key != "dependencies" else "DEPENDS_ON"
                        )
                        yield item
        # A single relation envelope is also accepted.
        if any(key in payload for key in ("source", "source_qualified", "caller", "from")):
            yield payload
    elif isinstance(payload, list):
        for value in payload:
            if isinstance(value, Mapping):
                yield value


def _relation_from_mapping(
    value: Mapping[str, Any],
    *,
    key: AnalysisKey,
    provenance: Provenance,
    default_kind: str,
    module_level: bool = False,
) -> EvidenceRecord | None:
    source_value = next(
        (
            value.get(name)
            for name in ("source", "source_qualified", "caller", "from")
            if value.get(name) is not None
        ),
        None,
    )
    target_value = next(
        (
            value.get(name)
            for name in ("target", "target_qualified", "callee", "to")
            if value.get(name) is not None
        ),
        None,
    )
    if source_value is None or target_value is None:
        return None
    source = str(source_value).strip()
    target = str(target_value).strip()
    if not source or not target:
        return None
    kind = _normalise_relation_kind(
        value.get("kind") or value.get("relation"), default=default_kind
    )
    if module_level:
        # xref cannot identify a function endpoint reliably.  Normalize even
        # malformed/overly-rich JSON output to the module-level contract.
        kind = "DEPENDS_ON"
    metadata: dict[str, Any] = {
        str(name): item
        for name, item in value.items()
        if name
        not in {
            "kind",
            "relation",
            "source",
            "source_qualified",
            "caller",
            "from",
            "target",
            "target_qualified",
            "callee",
            "to",
            "file_path",
            "file",
            "line",
            "line_number",
            "column",
            "metadata",
        }
    }
    if isinstance(value.get("metadata"), Mapping):
        metadata.update(value["metadata"])
    if module_level:
        metadata["module_level"] = True
    file_value = value.get("file_path", value.get("file"))
    line_value = value.get("line", value.get("line_number"))
    column_value = value.get("column")
    try:
        line = int(line_value) if line_value is not None else None
    except (TypeError, ValueError):
        line = None
    try:
        column = int(column_value) if column_value is not None else None
    except (TypeError, ValueError):
        column = None
    return EvidenceRecord(
        kind=kind,
        source=source,
        target=target,
        file_path=str(file_value) if file_value else None,
        line=line,
        column=column,
        metadata=metadata,
        provenance=provenance,
    )


def _diagnostics_from_payload(
    payload: Any,
    *,
    key: AnalysisKey,
    provenance: Provenance,
    default_code: str,
) -> list[Diagnostic]:
    if not isinstance(payload, Mapping):
        return []
    values: list[Any] = []
    for field_name in ("diagnostics", "warnings", "errors"):
        candidate = payload.get(field_name)
        if isinstance(candidate, list):
            values.extend(candidate)
        elif isinstance(candidate, str) and candidate.strip():
            values.extend(candidate.splitlines())
    result: list[Diagnostic] = []
    for value in values:
        if isinstance(value, Mapping):
            message = str(value.get("message", value.get("text", ""))).strip()
            if not message:
                continue
            file_path = value.get("file_path", value.get("file"))
            line = value.get("line", value.get("line_number"))
            column = value.get("column")
            try:
                line = int(line) if line is not None else None
            except (TypeError, ValueError):
                line = None
            try:
                column = int(column) if column is not None else None
            except (TypeError, ValueError):
                column = None
            result.append(
                Diagnostic(
                    code=str(value.get("code", default_code)),
                    message=message,
                    severity=str(value.get("severity", "warning")),
                    file_path=str(file_path) if file_path else None,
                    line=line,
                    column=column,
                    raw=str(value.get("raw")) if value.get("raw") else None,
                    metadata=(
                        dict(value["metadata"])
                        if isinstance(value.get("metadata"), Mapping)
                        else {}
                    ),
                    provenance=provenance,
                )
            )
        elif str(value).strip():
            result.append(
                Diagnostic(
                    code=default_code,
                    message=str(value).strip(),
                    provenance=provenance,
                )
            )
    return result


def _parse_json_output(
    output: str,
    *,
    key: AnalysisKey,
    provenance: Provenance,
    default_kind: str,
    module_level: bool = False,
) -> tuple[list[EvidenceRecord], list[Diagnostic], bool]:
    try:
        payload = json.loads(output)
    except json.JSONDecodeError as exc:
        raise ValueError(f"JSON output is malformed: {exc.msg}") from exc
    evidence = [
        relation
        for value in _iter_relation_values(payload, default_kind=default_kind)
        if (
            relation := _relation_from_mapping(
                value,
                key=key,
                provenance=provenance,
                default_kind=default_kind,
                module_level=module_level,
            )
        )
        is not None
    ]
    diagnostics = _diagnostics_from_payload(
        payload,
        key=key,
        provenance=provenance,
        default_code=f"{key.tool}_diagnostic",
    )
    recognized = isinstance(payload, list) or (
        isinstance(payload, Mapping)
        and any(
            key_name in payload
            for key_name in (
                "evidence",
                "relations",
                "edges",
                "results",
                "calls",
                "dependencies",
                "diagnostics",
                "warnings",
                "errors",
            )
        )
    )
    return evidence, diagnostics, recognized


def _command_result(
    runner: CommandRunner,
    command: Sequence[str],
    *,
    root: Path,
    environment: Mapping[str, str],
    timeout: float,
) -> CommandResult:
    started = time.perf_counter()
    try:
        raw = runner(command, cwd=root, env=environment, timeout=_safe_timeout(timeout))
    except subprocess.TimeoutExpired as exc:
        return CommandResult(
            returncode=124,
            stdout=_bounded_text(getattr(exc, "stdout", ""), _MAX_OUTPUT_CHARS),
            stderr=_bounded_text(getattr(exc, "stderr", ""), _MAX_OUTPUT_CHARS),
            duration_seconds=time.perf_counter() - started,
        )
    except (FileNotFoundError, OSError) as exc:
        return CommandResult(
            returncode=127,
            stderr=_bounded_text(exc),
            duration_seconds=time.perf_counter() - started,
        )
    except Exception as exc:
        return CommandResult(
            returncode=125,
            stderr=_bounded_text(exc),
            duration_seconds=time.perf_counter() - started,
        )
    return (
        raw
        if isinstance(raw, CommandResult)
        else CommandResult.from_process(
            raw,
            time.perf_counter() - started,
        )
    )


class _BaseAdapter:
    tool_name = "semantic"

    def __init__(
        self,
        toolchain: ToolchainIdentity,
        *,
        runner: CommandRunner | None = None,
        timeout: float = _DEFAULT_TIMEOUT_SECONDS,
        environment: Mapping[str, str] | None = None,
    ) -> None:
        self.toolchain = toolchain
        self.runner = runner or _default_discovery_runner
        self.timeout = _safe_timeout(timeout)
        self.environment = dict(environment or dict(toolchain.environment))

    def _key(self, query_kind: str, targets: str | Sequence[str] | None = None) -> AnalysisKey:
        return AnalysisKey.from_toolchain(self.toolchain, self.tool_name, query_kind, targets)

    def _unavailable(self, key: AnalysisKey, code: str, message: str) -> AdapterResult:
        provenance = _make_provenance(key, status=STATUS_UNAVAILABLE, command=())
        diagnostic = Diagnostic(code=code, message=message, provenance=provenance)
        return AdapterResult(
            tool=self.tool_name,
            status=STATUS_UNAVAILABLE,
            provenance=provenance,
            diagnostics=(diagnostic,),
        )


CommandBuilder = Callable[[str, str, tuple[str, ...]], Sequence[str]]


class ELPAdapter(_BaseAdapter):
    """Run targeted ELP queries through a configurable JSON command."""

    tool_name = "elp"
    supported_queries = frozenset({"callers_of", "tests_for", "impact", "references", "enrichment"})

    def __init__(
        self,
        toolchain: ToolchainIdentity,
        *,
        command_builder: CommandBuilder | None = None,
        expected_otp_version: str | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(toolchain, **kwargs)
        self.command_builder = command_builder or self._default_command
        self.expected_otp_version = expected_otp_version

    @staticmethod
    def _default_command(
        executable: str, query_kind: str, targets: tuple[str, ...]
    ) -> Sequence[str]:
        return (executable, "query", "--format", "json", query_kind, *targets)

    def query(
        self,
        repo_root: str | Path,
        query_kind: str,
        targets: str | Sequence[str] | None = None,
    ) -> AdapterResult:
        root = Path(repo_root).expanduser().resolve()
        normalized_query = query_kind.strip().casefold()
        key = self._key(normalized_query, targets)
        executable = self.toolchain.elp_executable
        if executable is None:
            return self._unavailable(key, "elp_unavailable", "ELP executable is not configured")
        expected_otp = self.expected_otp_version or self.toolchain.elp_otp_version
        if (
            expected_otp
            and self.toolchain.otp_version
            and expected_otp != self.toolchain.otp_version
        ):
            provenance = _make_provenance(
                key,
                status=STATUS_MISMATCH,
                command=(),
                details={
                    "expected_otp_version": expected_otp,
                    "actual_otp_version": self.toolchain.otp_version,
                },
            )
            return AdapterResult(
                tool=self.tool_name,
                status=STATUS_MISMATCH,
                provenance=provenance,
                diagnostics=(
                    Diagnostic(
                        code="elp_otp_mismatch",
                        message=(
                            "ELP and OTP versions do not match; semantic query "
                            "was skipped."
                        ),
                        provenance=provenance,
                        metadata={
                            "expected": expected_otp,
                            "actual": self.toolchain.otp_version,
                        },
                    ),
                ),
            )
        if normalized_query not in self.supported_queries:
            return self._unavailable(
                key, "elp_query_unsupported", f"ELP query is unsupported: {query_kind}"
            )
        command = tuple(
            str(item)
            for item in self.command_builder(executable, normalized_query, key.query_targets)
        )
        result = _command_result(
            self.runner,
            command,
            root=root,
            environment=self.environment,
            timeout=self.timeout,
        )
        status = STATUS_OK
        if result.returncode == 124:
            status = STATUS_TIMEOUT
        elif result.returncode == 127:
            status = STATUS_UNAVAILABLE
        elif result.returncode != 0:
            status = STATUS_FAILED
        provenance = _make_provenance(key, status=status, command=command, result=result)
        diagnostics: list[Diagnostic] = []
        evidence: list[EvidenceRecord] = []
        if status != STATUS_OK:
            diagnostics.append(
                _diagnostic(
                    key,
                    code=f"elp_{status}",
                    message=result.stderr or f"ELP exited with status {result.returncode}",
                    status=status,
                    command=command,
                    result=result,
                    raw=result.stderr or result.stdout,
                )
            )
        elif result.stdout.strip():
            try:
                evidence, diagnostics, recognized = _parse_json_output(
                    result.stdout,
                    key=key,
                    provenance=provenance,
                    default_kind="CALLS",
                )
            except ValueError as exc:
                status = STATUS_MALFORMED
                provenance = _make_provenance(key, status=status, command=command, result=result)
                diagnostics.append(
                    _diagnostic(
                        key,
                        code="elp_malformed_output",
                        message=str(exc),
                        status=status,
                        command=command,
                        result=result,
                        raw=result.stdout,
                    )
                )
            if status == STATUS_OK and not recognized:
                status = STATUS_MALFORMED
                provenance = _make_provenance(
                    key, status=status, command=command, result=result
                )
                diagnostics.append(
                    _diagnostic(
                        key,
                        code="elp_no_evidence",
                        message="ELP output contained no recognized evidence.",
                        status=status,
                        command=command,
                        result=result,
                        raw=result.stdout,
                    )
                )
        if result.stderr.strip():
            diagnostics.append(
                _diagnostic(
                    key,
                    code="elp_stderr",
                    message=_bounded_text(result.stderr),
                    status=status,
                    command=command,
                    result=result,
                    raw=result.stderr,
                    severity="info",
                )
            )
        # Make sure every parsed record points at the final status/provenance.
        if status != STATUS_OK:
            evidence = []
        return AdapterResult(
            tool=self.tool_name,
            status=status,
            provenance=provenance,
            evidence=tuple(evidence),
            diagnostics=tuple(diagnostics),
            command=command,
            stdout=result.stdout,
            stderr=result.stderr,
        )


class XrefAdapter(_BaseAdapter):
    """Collect module-level dependency/caller evidence from rebar3 xref."""

    tool_name = "xref"

    def __init__(
        self, toolchain: ToolchainIdentity, *, command: Sequence[str] | None = None, **kwargs: Any
    ) -> None:
        super().__init__(toolchain, **kwargs)
        self.command = tuple(command or toolchain.xref_command)

    def collect(
        self,
        repo_root: str | Path,
        *,
        targets: str | Sequence[str] | None = None,
    ) -> AdapterResult:
        root = Path(repo_root).expanduser().resolve()
        key = self._key("module_dependencies", targets)
        if not self.command:
            return self._unavailable(
                key, "xref_unavailable", "rebar3 xref command is not configured"
            )
        result = _command_result(
            self.runner,
            self.command,
            root=root,
            environment=self.environment,
            timeout=self.timeout,
        )
        status = STATUS_OK
        if result.returncode == 124:
            status = STATUS_TIMEOUT
        elif result.returncode == 127:
            status = STATUS_UNAVAILABLE
        elif result.returncode != 0:
            status = STATUS_FAILED
        provenance = _make_provenance(key, status=status, command=self.command, result=result)
        evidence: list[EvidenceRecord] = []
        diagnostics: list[Diagnostic] = []
        if status == STATUS_OK and result.stdout.strip():
            recognized = False
            try:
                if result.stdout.lstrip().startswith(("{", "[")):
                    evidence, diagnostics, recognized = _parse_json_output(
                        result.stdout,
                        key=key,
                        provenance=provenance,
                        default_kind="DEPENDS_ON",
                        module_level=True,
                    )
                else:
                    for raw_line in result.stdout.splitlines():
                        line = raw_line.strip()
                        if not line:
                            continue
                        undefined = _XREF_UNDEFINED_RE.search(line)
                        if undefined:
                            diagnostics.append(
                                _diagnostic(
                                    key,
                                    code="xref_undefined_call",
                                    message=line,
                                    status=status,
                                    command=self.command,
                                    result=result,
                                    raw=line,
                                )
                            )
                            continue
                        relation = _XREF_RELATION_RE.match(line)
                        if relation:
                            item = _relation_from_mapping(
                                {
                                    "kind": "DEPENDS_ON",
                                    "source": relation.group("source"),
                                    "target": relation.group("target"),
                                },
                                key=key,
                                provenance=provenance,
                                default_kind="DEPENDS_ON",
                                module_level=True,
                            )
                            if item is not None:
                                evidence.append(item)
                                recognized = True
                    if not recognized:
                        status = STATUS_MALFORMED
                        provenance = _make_provenance(
                            key, status=status, command=self.command, result=result
                        )
                        diagnostics.append(
                            _diagnostic(
                                key,
                                code="xref_no_evidence",
                                message="xref output contained no recognized module evidence",
                                status=status,
                                command=self.command,
                                result=result,
                                raw=result.stdout,
                                severity="info",
                            )
                        )
            except ValueError as exc:
                status = STATUS_MALFORMED
                provenance = _make_provenance(
                    key, status=status, command=self.command, result=result
                )
                diagnostics.append(
                    _diagnostic(
                        key,
                        code="xref_malformed_output",
                        message=str(exc),
                        status=status,
                        command=self.command,
                        result=result,
                        raw=result.stdout,
                    )
                )
        elif status != STATUS_OK:
            diagnostics.append(
                _diagnostic(
                    key,
                    code=f"xref_{status}",
                    message=result.stderr or f"xref exited with status {result.returncode}",
                    status=status,
                    command=self.command,
                    result=result,
                    raw=result.stderr or result.stdout,
                )
            )
        if result.stderr.strip():
            diagnostics.append(
                _diagnostic(
                    key,
                    code="xref_stderr",
                    message=_bounded_text(result.stderr),
                    status=status,
                    command=self.command,
                    result=result,
                    raw=result.stderr,
                    severity="info",
                )
            )
        if status != STATUS_OK:
            evidence = []
        return AdapterResult(
            tool=self.tool_name,
            status=status,
            provenance=provenance,
            evidence=tuple(evidence),
            diagnostics=tuple(diagnostics),
            command=self.command,
            stdout=result.stdout,
            stderr=result.stderr,
        )


class DialyzerAdapter(_BaseAdapter):
    """Ingest typed Dialyzer diagnostics after validating PLT identity."""

    tool_name = "dialyzer"

    def __init__(
        self,
        toolchain: ToolchainIdentity,
        *,
        command: Sequence[str] | None = None,
        plt_path: str | Path | None = None,
        expected_plt_identity: str | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(toolchain, **kwargs)
        self.command = tuple(command or toolchain.dialyzer_command)
        self.plt_path = Path(plt_path).expanduser() if plt_path is not None else None
        self.expected_plt_identity = expected_plt_identity or toolchain.plt_identity

    def collect(
        self,
        repo_root: str | Path,
        *,
        targets: str | Sequence[str] | None = None,
    ) -> AdapterResult:
        root = Path(repo_root).expanduser().resolve()
        key = self._key("diagnostics", targets)
        if not self.command:
            return self._unavailable(
                key, "dialyzer_unavailable", "Dialyzer command is not configured"
            )
        if self.expected_plt_identity is not None:
            if self.plt_path is None:
                provenance = _make_provenance(key, status=STATUS_STALE, command=self.command)
                return AdapterResult(
                    tool=self.tool_name,
                    status=STATUS_STALE,
                    provenance=provenance,
                    diagnostics=(
                        Diagnostic(
                            code="dialyzer_plt_unknown",
                            message=(
                                "Dialyzer PLT identity cannot be validated; "
                                "diagnostics were discarded."
                            ),
                            provenance=provenance,
                        ),
                    ),
                    command=self.command,
                )
            actual = compute_plt_identity(self.plt_path)
            if actual is None or actual != self.expected_plt_identity:
                provenance = _make_provenance(
                    key,
                    status=STATUS_STALE,
                    command=self.command,
                    details={
                        "expected_plt_identity": self.expected_plt_identity,
                        "actual_plt_identity": actual,
                    },
                )
                return AdapterResult(
                    tool=self.tool_name,
                    status=STATUS_STALE,
                    provenance=provenance,
                    diagnostics=(
                        Diagnostic(
                            code="dialyzer_plt_stale",
                            message="Dialyzer PLT identity does not match the analyzed toolchain.",
                            provenance=provenance,
                            metadata={"expected": self.expected_plt_identity, "actual": actual},
                        ),
                    ),
                    command=self.command,
                )
        result = _command_result(
            self.runner,
            self.command,
            root=root,
            environment=self.environment,
            timeout=self.timeout,
        )
        status = STATUS_OK
        if result.returncode == 124:
            status = STATUS_TIMEOUT
        elif result.returncode == 127:
            status = STATUS_UNAVAILABLE
        elif result.returncode != 0:
            status = STATUS_FAILED
        provenance = _make_provenance(key, status=status, command=self.command, result=result)
        diagnostics: list[Diagnostic] = []
        if status == STATUS_OK or (status == STATUS_FAILED and result.stdout.strip()):
            for raw_line in result.stdout.splitlines():
                line = raw_line.strip()
                if not line:
                    continue
                match = _LOCATION_RE.match(line)
                if match:
                    severity = (match.group("severity") or "warning").casefold()
                    diagnostics.append(
                        Diagnostic(
                            code="dialyzer_warning",
                            message=match.group("message").strip(),
                            severity=severity,
                            file_path=match.group("file"),
                            line=int(match.group("line")),
                            column=int(match.group("column")) if match.group("column") else None,
                            raw=line,
                            provenance=provenance,
                        )
                    )
                elif line.lower().startswith(("warning:", "error:")):
                    diagnostics.append(
                        Diagnostic(
                            code="dialyzer_warning",
                            message=line,
                            severity="error" if line.lower().startswith("error:") else "warning",
                            raw=line,
                            provenance=provenance,
                        )
                    )
        if status not in {STATUS_OK, STATUS_FAILED}:
            diagnostics.append(
                _diagnostic(
                    key,
                    code=f"dialyzer_{status}",
                    message=result.stderr or f"Dialyzer exited with status {result.returncode}",
                    status=status,
                    command=self.command,
                    result=result,
                    raw=result.stderr or result.stdout,
                )
            )
        elif status == STATUS_FAILED and result.stderr.strip():
            diagnostics.append(
                _diagnostic(
                    key,
                    code="dialyzer_failed",
                    message=_bounded_text(result.stderr),
                    status=status,
                    command=self.command,
                    result=result,
                    raw=result.stderr,
                )
            )
        return AdapterResult(
            tool=self.tool_name,
            status=status,
            provenance=provenance,
            diagnostics=tuple(diagnostics),
            command=self.command,
            stdout=result.stdout,
            stderr=result.stderr,
        )


QueryValue = EnrichmentQuery | Mapping[str, Any] | str | Sequence[Any]


def _query_scope(query: EnrichmentQuery) -> str:
    """Return a stable human-readable key for an enrichment query."""
    target_suffix = ",".join(query.targets)
    return f"{query.tool}:{query.query_kind}:{target_suffix}"


def _coerce_query_values(
    queries: Iterable[QueryValue] | Mapping[str, Any] | None,
    *,
    targets: str | Sequence[str] | None,
    include_xref: bool,
    include_dialyzer: bool,
) -> tuple[EnrichmentQuery, ...]:
    """Normalize the ergonomic query forms accepted by the public helper."""
    values: list[EnrichmentQuery] = []
    if isinstance(queries, Mapping):
        # A mapping with a query discriminator describes one query.  Any other
        # mapping is treated as ``query_kind -> targets`` for ELP, which is the
        # most useful shorthand at call sites handling changed functions.
        discriminator_keys = {"tool", "query_kind", "kind", "query"}
        if discriminator_keys.intersection(queries):
            values.append(EnrichmentQuery.from_value(queries))
        else:
            for query_kind, query_targets in queries.items():
                values.append(
                    EnrichmentQuery(
                        "elp", str(query_kind), _normalise_targets(query_targets)
                    )
                )
    elif queries is not None:
        # Accept one tuple/mapping as a convenience in addition to an
        # iterable of query specs.  Strings are already handled by
        # ``EnrichmentQuery.from_value`` and must not be split into characters.
        if isinstance(queries, (str, EnrichmentQuery)):
            values.append(EnrichmentQuery.from_value(queries))
        elif isinstance(queries, Sequence) and not isinstance(queries, (bytes, bytearray)):
            sequence_values = tuple(queries)
            is_single_tuple = (
                isinstance(queries, tuple)
                and len(sequence_values) in {2, 3}
                and isinstance(sequence_values[0], str)
                and isinstance(sequence_values[1], str)
                and sequence_values[0].strip().casefold()
                in {"elp", "xref", "dialyzer"}
            )
            if is_single_tuple:
                values.append(EnrichmentQuery.from_value(sequence_values))
            else:
                values.extend(EnrichmentQuery.from_value(value) for value in sequence_values)
        else:
            values.extend(EnrichmentQuery.from_value(value) for value in queries)

    if targets is not None:
        values.append(EnrichmentQuery("elp", "enrichment", _normalise_targets(targets)))
    if include_xref:
        values.append(EnrichmentQuery("xref", "module_dependencies"))
    if include_dialyzer:
        values.append(EnrichmentQuery("dialyzer", "diagnostics"))

    unique: dict[tuple[str, str, tuple[str, ...]], EnrichmentQuery] = {}
    for query in values:
        identity = (query.tool, query.query_kind, query.targets)
        unique.setdefault(identity, query)
    return tuple(
        unique[key]
        for key in sorted(unique, key=lambda item: (item[0], item[1], item[2]))
    )


def _scope_matches(record: EvidenceRecord | Diagnostic, query: EnrichmentQuery) -> bool:
    provenance = record.provenance
    if provenance.tool.casefold() != query.tool:
        return False
    if provenance.query_kind.casefold() != query.query_kind:
        return False
    # A record without targets is a project-wide result.  For a targeted query
    # only exact target metadata is eligible; this prevents one ELP target's
    # stale snapshot from replacing another target's evidence.
    if query.targets:
        return provenance.query_targets == query.targets
    return not provenance.query_targets


def _provenance_matches_toolchain(
    provenance: Provenance,
    toolchain: ToolchainIdentity,
) -> bool:
    """Check revision/tool identity for evidence outside the requested scopes."""
    if provenance.repository != toolchain.repository:
        return False
    if provenance.source_revision != toolchain.source_revision:
        return False
    if provenance.generated_data_revision != toolchain.generated_data_revision:
        return False
    if provenance.configuration_digest != toolchain.configuration_digest:
        return False
    if toolchain.otp_version != provenance.otp_version:
        return False
    info = toolchain.tool(provenance.tool)
    if info is not None and info.version != provenance.tool_version:
        return False
    if provenance.tool.casefold() == "dialyzer":
        return provenance.plt_identity == toolchain.plt_identity
    return True


def _cache_provenance(
    provenance: Provenance,
    *,
    cache_state: str,
) -> Provenance:
    return replace(provenance, cache_state=cache_state)


def _cache_record(record: EvidenceRecord | Diagnostic) -> EvidenceRecord | Diagnostic:
    provenance = _cache_provenance(record.provenance, cache_state="hit")
    return replace(record, provenance=provenance)


def _adapter_failure(
    toolchain: ToolchainIdentity,
    query: EnrichmentQuery,
    message: str,
) -> AdapterResult:
    """Turn an injected adapter exception into observable bounded output."""
    key = AnalysisKey.from_toolchain(
        toolchain, query.tool, query.query_kind, query.targets
    )
    provenance = _make_provenance(key, status=STATUS_FAILED, command=())
    diagnostic = _diagnostic(
        key,
        code=f"{query.tool}_failed",
        message=message,
        status=STATUS_FAILED,
    )
    return AdapterResult(
        tool=query.tool,
        status=STATUS_FAILED,
        provenance=provenance,
        diagnostics=(diagnostic,),
    )


def run_erlang_enrichment(
    repo_root: str | Path,
    *,
    toolchain: ToolchainIdentity | None = None,
    queries: Iterable[QueryValue] | Mapping[str, Any] | None = None,
    targets: str | Sequence[str] | None = None,
    previous: Iterable[EvidenceRecord] = (),
    previous_diagnostics: Iterable[Diagnostic] = (),
    cache: EvidenceCache | str | Path | None = None,
    runner: CommandRunner | None = None,
    timeout: float = _DEFAULT_TIMEOUT_SECONDS,
    environment: Mapping[str, str] | None = None,
    elp_adapter: ELPAdapter | None = None,
    xref_adapter: XrefAdapter | None = None,
    dialyzer_adapter: DialyzerAdapter | None = None,
    include_xref: bool = False,
    include_dialyzer: bool = False,
    plt_path: str | Path | None = None,
    expected_otp_version: str | None = None,
) -> EnrichmentResult:
    """Run bounded Erlang semantic enrichment and reconcile its evidence.

    This is the integration boundary shared by build, incremental, watch, and
    standalone postprocess callers.  It intentionally has no ``GraphStore``
    dependency: callers receive immutable records and decide how (or whether)
    to project them into graph edges.  ELP is run only for explicit ``queries``
    or ``targets``.  xref and Dialyzer are opt-in because both may execute
    project-level rebar3 tasks.
    """
    root = Path(repo_root).expanduser().resolve()
    if toolchain is None:
        toolchain = discover_toolchain(
            root,
            runner=runner,
            timeout=timeout,
            environment=environment,
            plt_path=plt_path,
        )
    cache_store: EvidenceCache | None
    if isinstance(cache, EvidenceCache):
        cache_store = cache
    elif cache is None:
        cache_store = None
    else:
        cache_store = EvidenceCache(cache)

    query_values = _coerce_query_values(
        queries,
        targets=targets,
        include_xref=include_xref,
        include_dialyzer=include_dialyzer,
    )
    previous_evidence = tuple(previous)
    previous_diagnostic_values = tuple(previous_diagnostics)
    adapters: dict[str, Any] = {}

    def get_adapter(tool: str) -> Any | None:
        if tool in adapters:
            return adapters[tool]
        adapter: Any | None
        if tool == "elp":
            adapter = elp_adapter or ELPAdapter(
                toolchain,
                runner=runner,
                timeout=timeout,
                environment=environment,
                expected_otp_version=expected_otp_version,
            )
        elif tool == "xref":
            adapter = xref_adapter or XrefAdapter(
                toolchain,
                runner=runner,
                timeout=timeout,
                environment=environment,
            )
        elif tool == "dialyzer":
            adapter = dialyzer_adapter or DialyzerAdapter(
                toolchain,
                runner=runner,
                timeout=timeout,
                environment=environment,
                plt_path=plt_path,
            )
        else:
            adapter = None
        if adapter is not None:
            adapters[tool] = adapter
        return adapter

    all_evidence: list[EvidenceRecord] = []
    all_diagnostics: list[Diagnostic] = []
    stale_evidence: list[EvidenceRecord] = []
    adapter_results: list[AdapterResult] = []
    cache_results: list[tuple[str, CacheLoadResult]] = []
    failures = False
    processed_scopes: set[tuple[str, str, tuple[str, ...]]] = set()
    reconciler = EvidenceReconciler()

    for query in query_values:
        scope = (query.tool, query.query_kind, query.targets)
        processed_scopes.add(scope)
        key = AnalysisKey.from_toolchain(
            toolchain, query.tool, query.query_kind, query.targets
        )
        scoped_previous = tuple(
            record for record in previous_evidence if _scope_matches(record, query)
        )
        scoped_previous_diagnostics = tuple(
            diagnostic
            for diagnostic in previous_diagnostic_values
            if _scope_matches(diagnostic, query)
        )
        cache_result = (
            cache_store.load(key)
            if cache_store is not None
            else CacheLoadResult("miss")
        )
        scope_name = _query_scope(query)
        cache_results.append((scope_name, cache_result))
        cache_stale_diagnostic: Diagnostic | None = None
        replace_queries: tuple[str, ...] = ()
        unavailable_queries: tuple[str, ...] = ()

        if cache_result.hit:
            incoming = tuple(
                item
                for item in (_cache_record(record) for record in cache_result.evidence)
                if isinstance(item, EvidenceRecord)
            )
            diagnostics = tuple(
                item
                for item in (_cache_record(diagnostic) for diagnostic in cache_result.diagnostics)
                if isinstance(item, Diagnostic)
            )
            provenance = Provenance.from_key(
                key,
                source=query.tool,
                status=STATUS_OK,
                cache_state="hit",
            )
            adapter_result = AdapterResult(
                tool=query.tool,
                status=STATUS_OK,
                provenance=provenance,
                evidence=incoming,
                diagnostics=diagnostics,
                command=(),
            )
            replace_queries = (query.query_kind,)
        else:
            if cache_result.stale or cache_result.message:
                cache_code = (
                    "cache_stale"
                    if cache_result.stale
                    else f"cache_{cache_result.status}"
                )
                cache_stale_diagnostic = _diagnostic(
                    key,
                    code=cache_code,
                    message=cache_result.message or "Cached semantic evidence was not usable.",
                    status=STATUS_STALE if cache_result.stale else STATUS_MALFORMED,
                    severity="info",
                )
            adapter = get_adapter(query.tool)
            if adapter is None:
                adapter_result = _adapter_failure(
                    toolchain,
                    query,
                    f"Unsupported Erlang semantic adapter: {query.tool}",
                )
            else:
                try:
                    if query.tool == "elp":
                        adapter_result = adapter.query(root, query.query_kind, query.targets)
                    else:
                        adapter_result = adapter.collect(root, targets=query.targets)
                except Exception as exc:  # injected adapters must not break Generic indexing
                    adapter_result = _adapter_failure(
                        toolchain,
                        query,
                        f"{type(exc).__name__}: {_bounded_text(exc)}",
                    )
            incoming = adapter_result.evidence if adapter_result.ok else ()
            diagnostics = adapter_result.diagnostics
            replace_queries = (query.query_kind,) if adapter_result.ok else ()
            unavailable_queries = (
                () if adapter_result.ok else (query.query_kind,)
            )
            if adapter_result.ok and cache_store is not None:
                try:
                    cache_store.save(key, incoming, diagnostics)
                except (OSError, ValueError, TypeError) as exc:
                    failures = True
                    diagnostics = tuple(diagnostics) + (
                        _diagnostic(
                            key,
                            code="cache_save_failed",
                            message=f"{type(exc).__name__}: {_bounded_text(exc)}",
                            status=STATUS_FAILED,
                            severity="warning",
                        ),
                    )
                    adapter_result = replace(
                        adapter_result,
                        diagnostics=diagnostics,
                    )

        if not adapter_result.ok:
            failures = True
        query_diagnostics = list(diagnostics)
        if cache_stale_diagnostic is not None:
            query_diagnostics.append(cache_stale_diagnostic)
        query_reconciled = reconciler.reconcile(
            incoming,
            analysis_key=key,
            previous=scoped_previous,
            diagnostics=query_diagnostics,
            previous_diagnostics=scoped_previous_diagnostics,
            replace_queries=replace_queries,
            unavailable_queries=unavailable_queries,
        )
        all_evidence.extend(query_reconciled.evidence)
        all_diagnostics.extend(query_reconciled.diagnostics)
        stale_evidence.extend(query_reconciled.stale_evidence)
        adapter_results.append(adapter_result)

    # Evidence belonging to a scope that was not requested remains untouched;
    # this matters when an incremental update refreshes only one changed target.
    for record in previous_evidence:
        if record.provenance.analysis_key and not _provenance_matches_toolchain(
            record.provenance, toolchain
        ):
            stale_evidence.append(record)
            continue
        scope = (
            record.provenance.tool.casefold(),
            record.provenance.query_kind.casefold(),
            record.provenance.query_targets,
        )
        if not any(
            scope[0] == query_tool
            and scope[1] == query_kind
            and (not query_targets or not scope[2] or scope[2] == query_targets)
            for query_tool, query_kind, query_targets in processed_scopes
        ):
            all_evidence.append(record)
    for diagnostic in previous_diagnostic_values:
        if diagnostic.provenance.analysis_key and not _provenance_matches_toolchain(
            diagnostic.provenance, toolchain
        ):
            continue
        scope = (
            diagnostic.provenance.tool.casefold(),
            diagnostic.provenance.query_kind.casefold(),
            diagnostic.provenance.query_targets,
        )
        if not any(
            scope[0] == query_tool
            and scope[1] == query_kind
            and (not query_targets or not scope[2] or scope[2] == query_targets)
            for query_tool, query_kind, query_targets in processed_scopes
        ):
            all_diagnostics.append(diagnostic)

    final = reconciler.reconcile(all_evidence, diagnostics=all_diagnostics)
    stale_unique = {item.evidence_id: item for item in stale_evidence}
    return EnrichmentResult(
        toolchain=toolchain,
        evidence=final.evidence,
        diagnostics=final.diagnostics,
        adapter_results=tuple(
            sorted(adapter_results, key=lambda item: (item.tool, item.provenance.query_kind))
        ),
        cache_results=tuple(sorted(cache_results, key=lambda item: item[0])),
        stale_evidence=tuple(stale_unique[key] for key in sorted(stale_unique)),
        conflicts=final.conflicts,
        discovery_diagnostics=toolchain.diagnostics,
        status=STATUS_DEGRADED if failures else STATUS_OK,
    )
