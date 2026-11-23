"""Application-neutral task context discovery for supervised workers.

The observer does not know which task-runner it is supervising. A worker
publishes task boundaries through named environment variables, and the caller
maps those names to the fields Mareforma needs. The default names are generic
``MAREFORMA_*`` variables; an application can point the same fields at its own
variables without changing the worker source.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping


_CONTEXT_FIELDS = (
    "task_id",
    "execution_id",
    "attempt",
    "attempt_dir",
    "execution_epoch",
    "parent_scope_id",
    "traceparent",
)

_DEFAULT_ENV_NAMES: dict[str, str | None] = {
    "task_id": "MAREFORMA_TASK_ID",
    "execution_id": "MAREFORMA_EXECUTION_ID",
    "attempt": "MAREFORMA_ATTEMPT",
    "attempt_dir": "MAREFORMA_ATTEMPT_DIR",
    "execution_epoch": "MAREFORMA_EXECUTION_EPOCH",
    "parent_scope_id": "MAREFORMA_PARENT_SCOPE_ID",
    "traceparent": "MAREFORMA_TRACEPARENT",
}


def _clean_name(value: Any) -> str | None:
    if value is None:
        return None
    name = str(value).strip()
    if not name:
        return None
    if "\x00" in name or "=" in name:
        raise ValueError("task context environment names must not contain NUL or '='")
    return name


@dataclass(frozen=True)
class TaskContextSpec:
    """Map task fields to environment variables set by the target worker.

    ``task_id_env`` is required because it is the only field that can open or
    close a task scope. The other fields are optional. The names are opaque to
    Mareforma: a caller may use ``MAREFORMA_TASK_ID`` for a new integration, or
    point the field at an existing application variable when wrapping an
    unchanged worker.
    """

    task_id_env: str | None = _DEFAULT_ENV_NAMES["task_id"]
    execution_id_env: str | None = _DEFAULT_ENV_NAMES["execution_id"]
    attempt_env: str | None = _DEFAULT_ENV_NAMES["attempt"]
    attempt_dir_env: str | None = _DEFAULT_ENV_NAMES["attempt_dir"]
    execution_epoch_env: str | None = _DEFAULT_ENV_NAMES["execution_epoch"]
    parent_scope_id_env: str | None = _DEFAULT_ENV_NAMES["parent_scope_id"]
    traceparent_env: str | None = _DEFAULT_ENV_NAMES["traceparent"]

    def __post_init__(self) -> None:
        cleaned = {
            "task_id": _clean_name(self.task_id_env),
            "execution_id": _clean_name(self.execution_id_env),
            "attempt": _clean_name(self.attempt_env),
            "attempt_dir": _clean_name(self.attempt_dir_env),
            "execution_epoch": _clean_name(self.execution_epoch_env),
            "parent_scope_id": _clean_name(self.parent_scope_id_env),
            "traceparent": _clean_name(self.traceparent_env),
        }
        if not cleaned["task_id"]:
            raise ValueError("task_id_env must name a non-empty environment variable")
        object.__setattr__(self, "task_id_env", cleaned["task_id"])
        for key in _CONTEXT_FIELDS[1:]:
            object.__setattr__(self, f"{key}_env", cleaned[key])

    def to_mapping(self) -> dict[str, str | None]:
        """Return the JSON-compatible mapping consumed by the autohook.

        Every field is present so an explicit ``None`` disables an optional
        field instead of letting the autohook fall back to its default name.
        """
        return {
            field: getattr(self, f"{field}_env")
            for field in _CONTEXT_FIELDS
        }

    @classmethod
    def from_mapping(
        cls, value: Mapping[str, Any] | None
    ) -> "TaskContextSpec":
        """Build a spec from an optional mapping of field names to env names."""
        if value is None:
            return cls()
        if not isinstance(value, Mapping):
            raise ValueError("task_context must be a mapping")
        kwargs: dict[str, Any] = {}
        for field in _CONTEXT_FIELDS:
            if field in value:
                kwargs[f"{field}_env"] = value[field]
            elif f"{field}_env" in value:
                kwargs[f"{field}_env"] = value[f"{field}_env"]
        return cls(**kwargs)


__all__ = ["TaskContextSpec"]
