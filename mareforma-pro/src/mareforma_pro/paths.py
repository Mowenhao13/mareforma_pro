"""Deterministic bwrap path resolution for rootless observations."""

from __future__ import annotations

from dataclasses import dataclass, field
import posixpath
from typing import Iterable, Mapping

from .evidence import OPAQUE_UNMAPPED_SANDBOX, OPAQUE_UNMAPPED_TMPFS, normalize_mount_map

DEFAULT_IGNORE_SYSTEM_PREFIXES = (
    "/proc",
    "/sys",
    "/dev",
    "/usr",
    "/lib",
    "/lib64",
    "/bin",
    "/sbin",
    "/etc",
)


def match_prefix(path: str, prefix: str) -> str | None:
    """Match a directory prefix with a boundary, never with a string prefix."""
    if prefix == "/":
        return path.lstrip("/")
    if path == prefix:
        return ""
    if path.startswith(prefix + "/"):
        return path[len(prefix) + 1 :]
    return None


@dataclass(frozen=True)
class Resolution:
    resolved: str | None
    opaque_reason: str | None = None
    ignored: bool = False


@dataclass(frozen=True)
class MountResolver:
    """Resolve sandbox paths to host paths using the longest exact mount."""

    mount_map: Mapping[str, str] = field(default_factory=dict)
    tmpfs_mounts: tuple[str, ...] = ()
    root_passthrough: bool = False
    ignore_system_prefixes: tuple[str, ...] = DEFAULT_IGNORE_SYSTEM_PREFIXES
    _entries: tuple[tuple[str, str, str | None], ...] = field(
        init=False, repr=False, compare=False
    )

    def __post_init__(self) -> None:
        mounts = normalize_mount_map(self.mount_map)
        entries: list[tuple[str, str, str | None]] = []
        for sandbox, host in mounts.items():
            entries.append((sandbox, "bind", host))
        for path in self.tmpfs_mounts:
            entries.append((posixpath.normpath(path), "tmpfs", None))
        # Longest first. If both a bind and tmpfs name the same path, tmpfs wins
        # because an undeclared temporary mount is the safer interpretation.
        entries.sort(key=lambda item: (len(item[0]), 1 if item[1] == "tmpfs" else 0), reverse=True)
        object.__setattr__(self, "mount_map", mounts)
        object.__setattr__(self, "_entries", tuple(entries))

    def resolve(self, path_in_namespace: str) -> Resolution:
        if not path_in_namespace:
            return Resolution(None, OPAQUE_UNMAPPED_SANDBOX)
        norm = posixpath.normpath(path_in_namespace)
        if norm.endswith(" (deleted)"):
            norm = norm[: -len(" (deleted)")]
        if not norm.startswith("/"):
            return Resolution(None, OPAQUE_UNMAPPED_SANDBOX)

        for mount_point, kind, host_prefix in self._entries:
            relative = match_prefix(norm, mount_point)
            if relative is None:
                continue
            if kind == "bind" and host_prefix is not None:
                resolved = host_prefix if relative == "" else posixpath.join(host_prefix, relative)
                return Resolution(posixpath.normpath(resolved))
            return Resolution(None, OPAQUE_UNMAPPED_TMPFS)

        for prefix in self.ignore_system_prefixes:
            if match_prefix(norm, posixpath.normpath(prefix)) is not None:
                return Resolution(None, None, True)

        if self.root_passthrough:
            return Resolution(norm)

        return Resolution(None, OPAQUE_UNMAPPED_SANDBOX)

    @classmethod
    def from_mounts(
        cls,
        mount_map: Mapping[str, str] | None = None,
        *,
        tmpfs_mounts: Iterable[str] = (),
        root_passthrough: bool = False,
    ) -> "MountResolver":
        return cls(
            mount_map=dict(mount_map or {}),
            tmpfs_mounts=tuple(tmpfs_mounts),
            root_passthrough=root_passthrough,
        )
