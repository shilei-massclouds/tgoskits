"""Explicit pipe scenario-model selection without changing v4 identity."""

from pathlib import Path

import adapter
import blocking_adapter
import poll_adapter
from linux_oracle.persistence import PersistentStateError, read_json


DEFAULT_MODEL = "simple-single"
MODEL_NAMES = (DEFAULT_MODEL, "blocking")
DEFAULT_SPEC = adapter.SPEC
_BY_MODEL = {
    DEFAULT_MODEL: adapter.SPEC,
    "blocking": poll_adapter.SPEC,
}
_BY_ADAPTER_ID = {
    adapter.SPEC.adapter_id: adapter.SPEC,
    blocking_adapter.SPEC.adapter_id: blocking_adapter.SPEC,
    poll_adapter.SPEC.adapter_id: poll_adapter.SPEC,
}


def spec_for_model(model: str):
    try:
        return _BY_MODEL[model]
    except KeyError as error:
        raise ValueError(f"unknown pipe scenario model: {model}") from error


def spec_for_adapter_id(adapter_id: str):
    try:
        return _BY_ADAPTER_ID[adapter_id]
    except KeyError as error:
        raise ValueError(f"unknown pipe adapter id: {adapter_id}") from error


def spec_for_common_failure(path: Path):
    metadata = read_json(path / "metadata.json")
    adapter_id = metadata.get("adapter_id") if isinstance(metadata, dict) else None
    if not isinstance(adapter_id, str):
        raise PersistentStateError("common pipe failure adapter identity is missing")
    try:
        return spec_for_adapter_id(adapter_id)
    except ValueError as error:
        raise PersistentStateError(str(error)) from error


__all__ = [
    "DEFAULT_MODEL",
    "DEFAULT_SPEC",
    "MODEL_NAMES",
    "spec_for_adapter_id",
    "spec_for_common_failure",
    "spec_for_model",
]
