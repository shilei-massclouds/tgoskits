"""Explicit scenario-model selection without changing legacy adapter identity."""

from pathlib import Path

import adapter
import blocking_adapter
from linux_oracle.persistence import PersistentStateError, read_json


DEFAULT_MODEL = "simple-single"
MODEL_NAMES = (DEFAULT_MODEL, "blocking")
DEFAULT_SPEC = adapter.SPEC
_BY_MODEL = {
    DEFAULT_MODEL: adapter.SPEC,
    "blocking": blocking_adapter.SPEC,
}
_BY_ADAPTER_ID = {spec.adapter_id: spec for spec in _BY_MODEL.values()}


def spec_for_model(model: str):
    try:
        return _BY_MODEL[model]
    except KeyError as error:
        raise ValueError(f"unknown eventfd scenario model: {model}") from error


def spec_for_adapter_id(adapter_id: str):
    try:
        return _BY_ADAPTER_ID[adapter_id]
    except KeyError as error:
        raise ValueError(f"unknown eventfd adapter id: {adapter_id}") from error


def spec_for_failure(path: Path):
    metadata = read_json(path / "metadata.json")
    adapter_id = metadata.get("adapter_id") if isinstance(metadata, dict) else None
    if not isinstance(adapter_id, str):
        raise PersistentStateError("failure adapter identity is missing")
    try:
        return spec_for_adapter_id(adapter_id)
    except ValueError as error:
        raise PersistentStateError(str(error)) from error


__all__ = [
    "DEFAULT_MODEL",
    "DEFAULT_SPEC",
    "MODEL_NAMES",
    "spec_for_adapter_id",
    "spec_for_failure",
    "spec_for_model",
]
