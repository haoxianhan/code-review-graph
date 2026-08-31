"""Conservative Erlang preprocessor header and record resolution.

The generic Erlang parser deliberately keeps ``-include`` and record
references textual.  This module is the small repository-local reconciliation
pass for those two relations.  Resolution is evidence based: headers are
selected from the source directory, the owning application's ``include``
directory, or explicitly configured include roots.  Record declarations are
then restricted to the successfully resolved include closure (plus the source
file itself), so a duplicate record name in a sibling application cannot be
mistaken for the one in use.

The pass is intentionally independent of the optional ELP/xref integration and
is safe to run repeatedly.  Every managed edge retains ``erlang_raw_target``;
canonical endpoints are restored to that spelling before each reconciliation.
"""

from __future__ import annotations

import json
import logging
import os
import re
from collections import defaultdict
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Iterable

from .parser import normalize_file_path

if False:  # pragma: no cover - typing-only import without runtime cycle
    from .graph import GraphStore

logger = logging.getLogger(__name__)

_MAX_CANDIDATES = 20
_MANAGED_IMPORT_KINDS = frozenset({"pp_include", "pp_include_lib"})
_WINDOWS_ABSOLUTE_RE = re.compile(r"^[A-Za-z]:/|^//")
_REBAR_INCLUDE_RE = re.compile(
    r"\{\s*i\s*,\s*[\"']([^\"']+)[\"']\s*\}",
    re.IGNORECASE,
)
_LS_INCLUDE_RE = re.compile(
    r"^\s*[-]?\s*include_dirs\s*:\s*(.*)$", re.IGNORECASE,
)
_INFER_ROOT_COMPONENTS = frozenset({
    "src", "include", "test", "tests", "priv", "ebin", "deps", "lib",
})


def _json_extra(raw: Any) -> dict[str, Any]:
    if isinstance(raw, dict):
        return dict(raw)
    try:
        value = json.loads(raw or "{}")
    except (
        TypeError,
        ValueError,
        UnicodeError,
        json.JSONDecodeError,
        RecursionError,
    ):
        return {}
    return dict(value) if isinstance(value, dict) else {}


def _raw_target(extra: dict[str, Any], current: Any) -> str:
    value = extra.get("erlang_raw_target")
    return value if isinstance(value, str) and value else str(current)


def _normal_path(value: str | Path) -> str:
    return normalize_file_path(Path(value).expanduser().resolve(strict=False))


def _absolute_graph_path(value: str | Path, root: Path | None) -> Path:
    """Interpret a graph path as an absolute path for resolver lookups.

    Parser-produced rows are absolute, but older/custom stores commonly keep
    repository-relative paths.  ``Path.resolve`` alone interprets those rows
    relative to the process cwd, which is unrelated to the checkout being
    reconciled.  Anchor relative rows to the explicit repository root while
    keeping the original spelling for graph identities.
    """
    raw = str(value).replace("\\", "/")
    path = Path(raw).expanduser()
    # ``Path`` on POSIX does not recognize a Windows drive-qualified spelling
    # as absolute.  Treat drive/UNC rows as foreign textual paths rather than
    # silently rebasing them under the requested checkout.
    windows_absolute = bool(_WINDOWS_ABSOLUTE_RE.match(raw))
    if not path.is_absolute() and not windows_absolute and root is not None:
        path = root / path
    if windows_absolute:
        return path
    return path.resolve(strict=False)


def _normal_graph_path(value: str | Path, root: Path | None) -> str:
    return normalize_file_path(_absolute_graph_path(value, root))


def _inside(path: str | Path, root: Path | None) -> bool:
    if root is None:
        return True
    normalized = normalize_file_path(path)
    if _WINDOWS_ABSOLUTE_RE.match(normalized):
        root_normalized = normalize_file_path(root.resolve(strict=False))
        return (
            bool(_WINDOWS_ABSOLUTE_RE.match(root_normalized))
            and (
                normalized == root_normalized
                or normalized.startswith(root_normalized.rstrip("/") + "/")
            )
        )
    try:
        Path(path).expanduser().resolve(strict=False).relative_to(root.resolve())
    except (OSError, RuntimeError, ValueError):
        return False
    return True


def _path_in_scope(path: str | Path, root: Path | None) -> bool:
    """Return whether a graph path belongs to *root*.

    Graph paths are normally absolute, but hand-built/legacy stores can keep
    relative file paths.  Interpret those relative to the requested root so a
    shared ``GraphStore`` cannot accidentally make an out-of-root row look
    local merely because the process current directory differs.
    """
    if root is None:
        return True
    value = _absolute_graph_path(path, root)
    return _inside(value, root)


def _infer_repo_root(store: "GraphStore") -> Path | None:
    """Infer a root for standalone post-processing.

    Normal graph databases live in ``<root>/.code-review-graph/graph.db``.
    Direct ``GraphStore`` users may choose another filename; in that case the
    database parent is the least surprising bounded root and path matching is
    still additionally constrained by indexed nodes.
    """
    try:
        db_path = Path(store.db_path).expanduser().resolve(strict=False)
    except (AttributeError, OSError, RuntimeError):
        db_path = None

    # A database can intentionally live outside the checkout (``CRG_DATA_DIR``
    # and registry-backed stores do this routinely).  Inferring the data
    # directory as the repository root would silently filter every absolute
    # graph row out of the resolver.  Prefer an existing conventional root
    # only when the indexed paths actually belong to it.
    db_root: Path | None = None
    if db_path is not None:
        db_root = (
            db_path.parent.parent
            if db_path.parent.name == ".code-review-graph"
            else db_path.parent
        )

    try:
        rows = store._conn.execute(
            "SELECT file_path FROM nodes WHERE lower(language) = 'erlang' "
            "UNION "
            "SELECT e.file_path FROM edges e "
            "JOIN nodes n ON n.qualified_name = e.source_qualified "
            "WHERE lower(n.language) = 'erlang'"
        ).fetchall()
    except Exception:  # pragma: no cover - defensive boundary for custom stores
        rows = []

    absolute_paths: list[Path] = []
    for row in rows:
        try:
            raw = str(row["file_path"] or row[0] or "").replace("\\", "/")
        except (AttributeError, IndexError, TypeError):
            continue
        if not raw or _WINDOWS_ABSOLUTE_RE.match(raw):
            continue
        path = Path(raw).expanduser()
        if not path.is_absolute():
            continue
        try:
            absolute_paths.append(path.resolve(strict=False))
        except (OSError, RuntimeError):
            continue

    def belongs(path: Path, candidate: Path) -> bool:
        try:
            path.relative_to(candidate)
        except ValueError:
            return False
        return True

    if absolute_paths:
        # ``commonpath`` raises for mixed Windows/POSIX drives; those rows have
        # no trustworthy single root and are intentionally left unscoped.
        try:
            common = Path(os.path.commonpath([str(path) for path in absolute_paths]))
        except (OSError, RuntimeError, ValueError):
            return None
        if common in absolute_paths:
            common = common.parent
        # A single ``repo/src/file.erl`` row has ``repo/src`` as its common
        # path.  Normalize the conventional source-directory suffix so the
        # sibling ``include`` directory remains visible.
        while common.name.casefold() in _INFER_ROOT_COMPONENTS:
            common = common.parent
        if common == Path(common.anchor):
            # Never let an external store make the resolver recursively scan a
            # filesystem root.  Absolute rows can still be handled safely with
            # an unscoped pass; configured include discovery is simply skipped.
            return None

        # Locate an explicit project marker before deciding whether a common
        # parent is a real monorepo root.  This lets a checkout laid out as
        # ``<repo>/apps/<app>`` infer ``<repo>`` while keeping a plain
        # temporary directory named ``apps`` from claiming sibling checkouts.
        marked_root: Path | None = None
        for ancestor in (common, *common.parents):
            if any(
                (ancestor / marker).exists()
                for marker in (
                    ".git",
                    ".svn",
                    ".code-review-graph",
                    "rebar.config",
                    "erlang_ls.config",
                )
            ):
                marked_root = ancestor
                break
            if ancestor == Path(ancestor.anchor):
                break

        # A shared database commonly sits in a broad temporary/cache
        # directory while holding rows from sibling checkouts.  If the path
        # layout points at multiple independent roots, do not promote their
        # common parent (for example ``/tmp`` or a directory merely named
        # ``apps``/``lib``) to a repository boundary.  A marker above the
        # common path is required to prove that the directory is an intended
        # monorepo root; otherwise the resolver remains fail-closed.
        layout_roots: set[Path] = set()
        for path in absolute_paths:
            parent = path.parent
            if parent.name.casefold() in _INFER_ROOT_COMPONENTS:
                layout_roots.add(parent.parent)
            else:
                layout_roots.add(parent)
        if (
            len(layout_roots) > 1
            and common not in layout_roots
            and marked_root is None
        ):
            return None
        if marked_root is not None:
            return marked_root
        # A colocated custom database is still a valid fallback when every
        # indexed path belongs to its parent.  This branch is intentionally
        # after the independent-root check above so a shared ``/tmp/graph.db``
        # cannot claim two sibling repositories.
        if db_root is not None and all(belongs(path, db_root) for path in absolute_paths):
            return db_root if db_root == common else common
        return common

    # Relative-only legacy stores have no independent repository identity.  The
    # database parent remains the least surprising fallback, preserving the
    # historical behavior for direct GraphStore users that colocate the DB.
    return db_root


def _strip_erlang_comments(text: str) -> str:
    """Remove Erlang ``%`` comments while preserving quoted strings/atoms."""
    output: list[str] = []
    quote: str | None = None
    escaped = False
    index = 0
    while index < len(text):
        char = text[index]
        if quote is not None:
            output.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            index += 1
            continue
        if char in {"'", '"'}:
            quote = char
            output.append(char)
            index += 1
            continue
        if char == "%":
            while index < len(text) and text[index] not in "\r\n":
                index += 1
            continue
        output.append(char)
        index += 1
    return "".join(output)


def _strip_yaml_comment(value: str) -> str:
    """Strip a YAML comment that starts outside a quoted scalar."""
    quote: str | None = None
    escaped = False
    for index, char in enumerate(value):
        if quote is not None:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            continue
        if char in {"'", '"'}:
            quote = char
        elif char == "#" and (index == 0 or value[index - 1].isspace()):
            return value[:index]
    return value


def _split_yaml_sequence(value: str) -> list[str]:
    """Split a small YAML flow sequence without evaluating arbitrary YAML."""
    parts: list[str] = []
    current: list[str] = []
    quote: str | None = None
    escaped = False
    depth = 0
    for char in value:
        if quote is not None:
            current.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            continue
        if char in {"'", '"'}:
            quote = char
            current.append(char)
        elif char == "[":
            depth += 1
            current.append(char)
        elif char == "]":
            depth = max(0, depth - 1)
            current.append(char)
        elif char == "," and depth == 0:
            parts.append("".join(current).strip())
            current = []
        else:
            current.append(char)
    parts.append("".join(current).strip())
    return parts


def _yaml_include_values(raw: str) -> list[str]:
    """Read scalar/flow-list values from an ``include_dirs`` YAML value."""
    value = _strip_yaml_comment(raw).strip()
    if not value or value in {"[]", "|", ">"}:
        return []
    if value.startswith("[") and value.endswith("]"):
        value = value[1:-1]
        values = _split_yaml_sequence(value)
    else:
        values = [value]
    cleaned: list[str] = []
    for item in values:
        item = _strip_yaml_comment(item).strip()
        if len(item) >= 2 and item[0] == item[-1] and item[0] in {"'", '"'}:
            item = item[1:-1]
        if item:
            cleaned.append(item)
    return cleaned


def _descriptor_root(path: str) -> Path:
    descriptor = Path(path)
    if descriptor.parent.name.casefold() in {"src", "include", "test"}:
        return descriptor.parent.parent
    return descriptor.parent


def _conventional_app_roots(
    files: Iterable[str],
    root: Path | None,
) -> tuple[Path, ...]:
    """Infer conventional ``apps/<name>``/``lib/<name>`` roots from paths."""
    roots: set[Path] = set()
    if root is not None:
        roots.add(root.resolve(strict=False))
    for raw in files:
        try:
            path = _absolute_graph_path(raw, root)
        except (OSError, RuntimeError):
            continue
        parts = path.parts
        for marker in ("apps", "lib"):
            indexes = [index for index, part in enumerate(parts[:-1]) if part.casefold() == marker]
            if indexes:
                index = indexes[-1]
                if index + 1 < len(parts) - 0:
                    roots.add(Path(*parts[: index + 2]))
                    break
        else:
            # A project laid out as ``project/src`` or ``project/include``
            # still has an application root even without ``apps/``.
            parent = path.parent
            if parent.name.casefold() in {"src", "include", "test"}:
                roots.add(parent.parent)
    return tuple(sorted(roots, key=lambda item: (len(item.parts), str(item))))


def _parse_configured_include_dirs(
    root: Path | None,
) -> tuple[tuple[Path, Path | None], ...]:
    """Read literal include roots from common Erlang project config files.

    This is deliberately a tiny, non-evaluating reader.  Malformed or dynamic
    terms are ignored; only existing directories inside the requested root are
    admitted.  ``CRG_ERLANG_INCLUDE_DIRS`` is supported as an explicit escape
    hatch for generated layouts and is likewise root-bounded.
    """
    if root is None or not root.is_dir():
        return ()
    # Preserve the scope that contributed each include directory.  A nested
    # application may have a private ``rebar.config`` whose ``{i, ...}``
    # paths must not become repository-global search roots.
    candidates: list[tuple[Path, Path | None]] = []

    def add(raw: str, base: Path, *, scope: Path | None = None) -> None:
        value = raw.strip().strip("\"'").replace("\\", "/")
        if not value or "$" in value or "*" in value or "{" in value:
            return
        candidate = Path(value)
        if not candidate.is_absolute():
            candidate = base / candidate
        try:
            resolved = candidate.resolve(strict=False)
            resolved.relative_to(root.resolve())
        except (OSError, RuntimeError, ValueError):
            return
        if not resolved.is_dir():
            return
        normalized_scope = (
            scope.resolve(strict=False) if scope is not None else None
        )
        entry = (resolved, normalized_scope)
        if entry not in candidates:
            candidates.append(entry)

    env_value = os.environ.get("CRG_ERLANG_INCLUDE_DIRS", "")
    for raw in env_value.split(os.pathsep):
        if raw.strip():
            add(raw, root)

    # Parse all rebar configs below the repository.  A nested application
    # config is scoped to that config's parent, matching rebar's ``{i, ...}``
    # path semantics.
    try:
        config_paths = sorted(root.rglob("rebar.config"))
    except (OSError, RuntimeError):
        config_paths = []
    for config in config_paths:
        if any(part in {".git", "_build", "node_modules"} for part in config.parts):
            continue
        try:
            text = config.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        # ``%`` starts an Erlang comment outside quoted strings/atoms.  Strip
        # comments before applying the literal matcher so commented-out include
        # options cannot become active resolver roots.
        for match in _REBAR_INCLUDE_RE.finditer(_strip_erlang_comments(text)):
            # rebar resolves relative ``{i, ...}`` paths from the config's
            # directory.  Keep that directory as a source-application scope.
            add(match.group(1), config.parent, scope=config.parent)

    # erlang_ls.config is YAML in the supported layout contract.  Avoid a
    # mandatory YAML dependency here; the common scalar/list forms are enough
    # to recognize explicit include roots without executing project code.
    ls_path = root / "erlang_ls.config"
    try:
        lines = ls_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        lines = []
    in_include_block = False
    include_indent = 0
    for line in lines:
        uncommented = _strip_yaml_comment(line).rstrip()
        match = _LS_INCLUDE_RE.match(uncommented)
        if match:
            in_include_block = True
            include_indent = len(line) - len(line.lstrip())
            for value in _yaml_include_values(match.group(1)):
                add(value, ls_path.parent, scope=ls_path.parent)
            continue
        if in_include_block:
            if not uncommented.strip():
                continue
            list_item = re.match(r"^\s*[-]\s*(.*?)\s*$", uncommented)
            if list_item:
                item_indent = len(line) - len(line.lstrip())
                # YAML permits an indentationless sequence (``key:\n- item``)
                # as well as the usual indented form.  A sibling top-level key
                # without a dash closes the block.
                if item_indent >= include_indent:
                    for value in _yaml_include_values(list_item.group(1)):
                        add(value, ls_path.parent, scope=ls_path.parent)
                continue
            # Only sequence items belong to this tiny contract.  Closing on
            # any other non-blank line prevents a later list nested under an
            # unrelated YAML key from being mistaken for include roots.
            in_include_block = False
    return tuple(candidates)


def _app_and_include_indexes(
    file_paths: set[str],
    node_rows: list[Any],
    root: Path | None,
) -> tuple[
    dict[str, tuple[Path, ...]],
    dict[str, Path],
    tuple[tuple[Path, Path | None], ...],
]:
    """Build application-name, file-owner, and include-root indexes."""
    app_roots: dict[str, set[Path]] = defaultdict(set)
    descriptors: list[tuple[str, Path]] = []
    for row in node_rows:
        if row["kind"] != "File" or not str(row["file_path"]).casefold().endswith(".app.src"):
            continue
        extra = _json_extra(row["extra"])
        name = extra.get("erlang_application")
        if isinstance(name, str) and name:
            descriptor = _absolute_graph_path(row["file_path"], root)
            app_root = _descriptor_root(str(descriptor))
            app_roots[name].add(app_root)
            descriptors.append((name, app_root))

    # Conventional roots provide useful application names when a project has
    # no .app.src (common for small libraries and generated fixtures).
    for app_root in _conventional_app_roots(file_paths, root):
        if root is not None:
            try:
                rel = app_root.relative_to(root.resolve())
            except ValueError:
                continue
            if rel.parts and rel.parts[0].casefold() in {"apps", "lib"} and len(rel.parts) >= 2:
                app_roots.setdefault(rel.parts[1], set()).add(app_root)

    app_map = {
        name: tuple(sorted(roots, key=str)) for name, roots in app_roots.items()
    }

    # Select the deepest owning app root for each indexed file.  Root-level
    # files naturally fall back to the repository root.
    all_roots = sorted(
        {item for values in app_map.values() for item in values},
        key=lambda item: len(item.parts),
        reverse=True,
    )
    owner: dict[str, Path] = {}
    for file_path in file_paths:
        path = _absolute_graph_path(file_path, root)
        owner[file_path] = next(
            (candidate for candidate in all_roots if _inside(path, candidate)),
            root.resolve(strict=False) if root is not None else path.parent,
        )

    # Keep only explicitly configured roots here.  Conventional application
    # ``include`` directories are added in ``_candidate_headers`` for the
    # owning source file; treating every app include directory as global would
    # make duplicate headers ambiguous (or cross-link a sibling app).
    return app_map, owner, _parse_configured_include_dirs(root)


def _candidate_headers(
    raw: str,
    source_file: str,
    *,
    include_lib: bool,
    app_map: dict[str, tuple[Path, ...]],
    owner: dict[str, Path],
    configured_roots: tuple[tuple[Path, Path | None], ...],
    headers: set[str],
    header_paths: dict[str, str],
    root: Path | None,
    normalize_path: Callable[[str | Path], str] | None = None,
    inside_path: Callable[[str | Path, Path | None], bool] | None = None,
) -> list[str]:
    target = raw.strip().strip("\"'").replace("\\", "/")
    if target.startswith("<") and target.endswith(">"):
        target = target[1:-1]
    if not target:
        return []
    source_path = _absolute_graph_path(source_file, root)
    candidates: list[Path] = []
    if include_lib:
        pieces = PurePosixPath(target).parts
        if len(pieces) < 2:
            return []
        app_name = pieces[0]
        relative = Path(*pieces[1:])
        # Application names are case-sensitive Erlang atoms.  A duplicate
        # name remains ambiguous even if only one root currently has a file.
        roots = app_map.get(app_name, ())
        for app_root in roots:
            candidates.append(app_root / relative)
            if relative.parts and relative.parts[0].casefold() != "include":
                candidates.append(app_root / "include" / relative)
    else:
        candidates.append(source_path.parent / target)
        source_owner = owner.get(source_file)
        if source_owner is not None:
            candidates.append(source_owner / target)
            candidates.append(source_owner / "include" / target)
        # Configured roots are explicit and may be global.  Nested config
        # entries carry a scope so a sibling application's private include
        # directory cannot leak into this source's search path.  They are
        # allowed to produce ambiguity; silently picking one would be unsafe.
        configured_dirs: set[Path] = set()
        for configured in configured_roots:
            # Keep the helper tolerant of older injected callers that pass a
            # bare ``Path`` tuple instead of the scoped internal form.
            if isinstance(configured, tuple):
                directory, scope = configured
            else:  # pragma: no cover - compatibility with injected callers
                directory, scope = configured, None  # type: ignore[assignment]
            if scope is not None and not (
                inside_path(source_path, scope)
                if inside_path is not None
                else _inside(source_path, scope)
            ):
                continue
            # Only an entry applicable to this source suppresses the
            # conventional root/include fallback below.  A sibling app may
            # configure the same physical directory with a private scope;
            # recording it before this check would make unrelated root-level
            # sources lose their valid fallback candidate.
            configured_dirs.add(directory)
            candidates.append(directory / target)
        if root is not None:
            # A root-level ``include`` is a conventional explicit project
            # include root, but only when it is the source's own project root.
            root_include = root / "include"
            if (
                inside_path(source_path, root)
                if inside_path is not None
                else _inside(source_path, root)
            ) and root_include not in configured_dirs:
                candidates.append(root_include / target)

    result: set[str] = set()
    # Erlang include paths are resolved by the compiler with the host
    # filesystem's exact spelling.  A case-folded fallback would manufacture a
    # relation on Linux (for example ``shared.hrl`` -> ``SHARED.HRL``), so keep
    # the resolver strictly exact and leave spelling mismatches unresolved.
    for candidate in candidates:
        candidate_text = str(candidate).replace("\\", "/")
        try:
            if _WINDOWS_ABSOLUTE_RE.match(candidate_text):
                normalized = candidate_text
            else:
                candidate_path = Path(candidate_text).expanduser()
                if not candidate_path.is_absolute() and root is not None:
                    candidate_path = root / candidate_path
                normalized = normalize_file_path(os.path.normpath(str(candidate_path)))
            if normalized not in headers:
                # Preserve existing symlink behavior without resolving every
                # nonexistent include candidate.  A failed or foreign path
                # remains unresolved, which is the conservative contract.
                if _WINDOWS_ABSOLUTE_RE.match(candidate_text) or not candidate_path.exists():
                    continue
                normalized = (
                    normalize_path(candidate)
                    if normalize_path is not None
                    else _normal_graph_path(candidate, root)
                )
        except (OSError, RuntimeError, ValueError):
            continue
        if normalized in headers:
            result.add(header_paths.get(normalized, normalized))
    return sorted(result)


def _include_lib_app_is_ambiguous(raw: str, app_map: dict[str, tuple[Path, ...]]) -> bool:
    """Return whether an ``include_lib`` names more than one app root.

    Application identity is the evidence used to select an ``include_lib``
    target.  A missing header in one duplicate app must not silently turn an
    otherwise ambiguous application name into a unique file match.
    """
    target = raw.strip().strip("\"'").replace("\\", "/")
    if target.startswith("<") and target.endswith(">"):
        target = target[1:-1]
    pieces = PurePosixPath(target).parts
    return len(pieces) >= 2 and len(app_map.get(pieces[0], ())) > 1


def _set_resolution_metadata(
    extra: dict[str, Any],
    candidates: list[str],
    *,
    ambiguous: bool,
) -> None:
    for key in (
        "ambiguous_targets", "ambiguous_target_count", "ambiguous_targets_truncated",
        "unresolved_targets", "unresolved_target_count", "unresolved_targets_truncated",
    ):
        extra.pop(key, None)
    prefix = "ambiguous" if ambiguous else "unresolved"
    extra[f"{prefix}_targets"] = candidates[:_MAX_CANDIDATES]
    extra[f"{prefix}_target_count"] = len(candidates)
    extra[f"{prefix}_targets_truncated"] = len(candidates) > _MAX_CANDIDATES


def _update_edge(conn: Any, row: Any, target: str, extra: dict[str, Any]) -> bool:
    encoded = json.dumps(extra, sort_keys=True)
    old_extra = _json_extra(row["extra"])
    if row["target_qualified"] == target and old_extra == extra:
        return False
    conn.execute(
        "UPDATE edges SET target_qualified = ?, extra = ? WHERE id = ?",
        (target, encoded, row["id"]),
    )
    return True


def resolve_erlang_header_records(
    store: "GraphStore",
    repo_root: str | Path | None = None,
) -> dict[str, Any]:
    """Resolve Erlang ``IMPORTS_FROM`` headers and record ``REFERENCES``.

    The returned counters are telemetry only; callers should treat an
    unresolved/ambiguous edge as intentionally raw graph data.
    """
    conn = store._conn
    if repo_root is not None:
        root = Path(repo_root).expanduser().resolve(strict=False)
    else:
        root = _infer_repo_root(store)
        if root is None:
            # A shared/external store may contain several unrelated checkouts.
            # Without a trustworthy boundary, resolving against every row can
            # rebind one repository's textual include/record edge to another
            # repository's header.  Keep the graph untouched until the caller
            # supplies an explicit root (build lifecycle callers do).
            return {
                "files_indexed": 0,
                "imports_updated": 0,
                "imports_resolved": 0,
                "records_updated": 0,
                "records_resolved": 0,
                "ambiguous": 0,
                "unresolved": 0,
            }
    scope_cache: dict[str, bool] = {}
    normalized_path_cache: dict[str, str] = {}
    inside_cache: dict[tuple[str, str], bool] = {}

    def in_scope(value: str | Path) -> bool:
        key = str(value)
        cached = scope_cache.get(key)
        if cached is not None:
            return cached
        result = _path_in_scope(key, root)
        scope_cache[key] = result
        return result

    def normalized_path(value: str | Path) -> str:
        key = str(value)
        cached = normalized_path_cache.get(key)
        if cached is not None:
            return cached
        result = _normal_graph_path(key, root)
        normalized_path_cache[key] = result
        return result

    def inside_path(value: str | Path, boundary: Path | None) -> bool:
        key = (str(value), str(boundary))
        cached = inside_cache.get(key)
        if cached is not None:
            return cached
        result = _inside(value, boundary)
        inside_cache[key] = result
        return result

    all_node_rows = conn.execute(
        "SELECT * FROM nodes WHERE language = 'erlang'",
    ).fetchall()
    # A GraphStore may intentionally contain several repository checkouts.
    # Resolver writes must be scoped to the requested checkout just like
    # incremental stale-file reconciliation; otherwise resolving one root can
    # rebind another root's textual include/record edges to local headers.
    node_rows = [
        row for row in all_node_rows
        if in_scope(str(row["file_path"]))
    ]
    file_paths = {str(row["file_path"]) for row in node_rows}
    header_paths = {
        normalized_path(path): path
        for path in file_paths
        if path.casefold().endswith(".hrl") and in_scope(path)
    }
    headers = set(header_paths)
    if not node_rows:
        return {
            "files_indexed": 0,
            "imports_updated": 0,
            "imports_resolved": 0,
            "records_updated": 0,
            "records_resolved": 0,
            "ambiguous": 0,
            "unresolved": 0,
        }

    app_map, owner, configured_roots = _app_and_include_indexes(file_paths, node_rows, root)

    declarations: dict[tuple[str, str], list[str]] = defaultdict(list)
    for row in node_rows:
        if row["kind"] != "Type":
            continue
        extra = _json_extra(row["extra"])
        if extra.get("erlang_kind") != "record":
            continue
        identity = extra.get("record_identity")
        name = str(row["name"])
        if isinstance(identity, str) and identity.startswith("#"):
            name = identity[1:].split("{", 1)[0] or name
        declarations[(normalized_path(row["file_path"]), name)].append(
            str(row["qualified_name"])
        )

    include_graph: dict[str, set[str]] = defaultdict(set)
    all_import_rows = conn.execute(
        "SELECT id, source_qualified, target_qualified, file_path, extra "
        "FROM edges WHERE kind = 'IMPORTS_FROM'",
    ).fetchall()
    import_rows = [
        row for row in all_import_rows
        if in_scope(str(row["file_path"]))
    ]
    imports_updated = imports_resolved = 0
    records_updated = records_resolved = 0
    ambiguous = unresolved = 0

    # Reconcile include endpoints first; record resolution consumes this graph.
    for row in import_rows:
        extra = _json_extra(row["extra"])
        import_kind = extra.get("erlang_import_kind")
        if import_kind not in _MANAGED_IMPORT_KINDS:
            continue
        raw = _raw_target(extra, row["target_qualified"])
        extra["erlang_raw_target"] = raw
        candidates = _candidate_headers(
            raw,
            str(row["file_path"]),
            include_lib=import_kind == "pp_include_lib",
            app_map=app_map,
            owner=owner,
            configured_roots=configured_roots,
            headers=headers,
            header_paths=header_paths,
            root=root,
            normalize_path=normalized_path,
            inside_path=inside_path,
        )
        if import_kind == "pp_include_lib" and _include_lib_app_is_ambiguous(
            raw, app_map
        ):
            # Keep every application-root spelling in the preview, including
            # a path that is currently missing.  The application name itself
            # is ambiguous evidence, so a sole existing file must not be
            # promoted into a resolved endpoint.
            target = raw.strip().strip("\"'").replace("\\", "/")
            if target.startswith("<") and target.endswith(">"):
                target = target[1:-1]
            pieces = PurePosixPath(target).parts
            relative = Path(*pieces[1:])
            app_roots = app_map.get(pieces[0], ())
            preview = set(candidates)
            for app_root in app_roots:
                possible = [app_root / relative]
                if relative.parts and relative.parts[0].casefold() != "include":
                    possible.append(app_root / "include" / relative)
                for path in possible:
                    try:
                        normalized = _normal_graph_path(path, root)
                    except (OSError, RuntimeError):
                        continue
                    preview.add(header_paths.get(normalized, normalized))
            candidates = sorted(preview)
        if len(candidates) == 1:
            for key in (
                "ambiguous_targets", "ambiguous_target_count", "ambiguous_targets_truncated",
                "unresolved_targets", "unresolved_target_count", "unresolved_targets_truncated",
            ):
                extra.pop(key, None)
            target = candidates[0]
            include_graph[normalized_path(row["file_path"])].add(
                normalized_path(target)
            )
            imports_resolved += row["target_qualified"] != target
        else:
            _set_resolution_metadata(extra, candidates, ambiguous=len(candidates) > 1)
            target = raw
            if candidates:
                ambiguous += 1
            else:
                unresolved += 1
        if _update_edge(conn, row, target, extra):
            imports_updated += 1

    # Compute transitive include closure once, bounded by indexed header files.
    closure_cache: dict[str, set[str]] = {}

    def closure(source: str) -> set[str]:
        cached = closure_cache.get(source)
        if cached is not None:
            return cached
        seen = {source}
        stack = [source]
        while stack:
            current = stack.pop()
            for target in include_graph.get(current, ()):
                if target not in seen:
                    seen.add(target)
                    stack.append(target)
        closure_cache[source] = seen
        return seen

    all_record_rows = conn.execute(
        "SELECT id, source_qualified, target_qualified, file_path, extra "
        "FROM edges WHERE kind = 'REFERENCES'",
    ).fetchall()
    record_rows = [
        row for row in all_record_rows
        if in_scope(str(row["file_path"]))
    ]
    for row in record_rows:
        extra = _json_extra(row["extra"])
        if extra.get("erlang_reference_kind") != "record":
            continue
        raw = _raw_target(extra, row["target_qualified"])
        extra["erlang_raw_target"] = raw
        record_name = raw.strip().strip("'\"").lstrip("#").split("{", 1)[0]
        source_file = normalized_path(row["file_path"])
        candidate_qns: list[str] = []
        for file_path in closure(source_file):
            candidate_qns.extend(declarations.get((file_path, record_name), ()))
        # A record declaration in the source itself is valid even when no
        # include edge exists.  ``closure`` already includes source_file.
        candidate_qns = sorted(set(candidate_qns))
        if len(candidate_qns) == 1:
            target = candidate_qns[0]
            for key in (
                "ambiguous_targets", "ambiguous_target_count", "ambiguous_targets_truncated",
                "unresolved_targets", "unresolved_target_count", "unresolved_targets_truncated",
            ):
                extra.pop(key, None)
            records_resolved += row["target_qualified"] != target
        else:
            _set_resolution_metadata(extra, candidate_qns, ambiguous=len(candidate_qns) > 1)
            target = raw
            if candidate_qns:
                ambiguous += 1
            else:
                unresolved += 1
        if _update_edge(conn, row, target, extra):
            records_updated += 1

    if imports_updated or records_updated:
        conn.commit()
        store._invalidate_cache()
    result = {
        "files_indexed": len(file_paths),
        "imports_updated": imports_updated,
        "imports_resolved": imports_resolved,
        "records_updated": records_updated,
        "records_resolved": records_resolved,
        "ambiguous": ambiguous,
        "unresolved": unresolved,
    }
    logger.info("Erlang header/record resolution: %s", result)
    return result


# A short alias keeps callers readable and gives downstream integrations a
# stable name if they do not care about the implementation detail.
resolve_erlang_headers_records = resolve_erlang_header_records

__all__ = ["resolve_erlang_header_records", "resolve_erlang_headers_records"]
