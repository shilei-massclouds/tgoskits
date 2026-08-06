"""Strict resumable attribution and minimization task storage."""

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, Mapping, Tuple

from .persistence import (
    PersistentStateError,
    atomic_replace_file,
    atomic_save_directory,
    is_digest,
    read_json,
    sorted_unique_digests,
    validate_exact_keys,
    write_json,
)
from .spec import AdapterSpec


SCHEMA_VERSION = 1
TASK_KINDS = ("attribution", "minimization")
TASK_STATES = ("pending", "running", "completed", "unstable")


@dataclass(frozen=True)
class Task:
    path: Path
    metadata: Dict
    inputs: Tuple[bytes, ...]


class TaskStore:
    def __init__(self, spec: AdapterSpec, campaign_root: Path, kind: str):
        if kind not in TASK_KINDS:
            raise ValueError(f"unknown task kind: {kind}")
        self.spec = spec
        self.kind = kind
        directory = (
            spec.campaign.attribution_task_directory
            if kind == "attribution"
            else spec.campaign.minimization_task_directory
        )
        self.root = campaign_root / directory

    def create(
        self,
        task_id: str,
        inputs: Iterable[bytes],
        context: Mapping[str, object] | None = None,
    ) -> Task:
        if not task_id or Path(task_id).name != task_id:
            raise PersistentStateError("invalid task id")
        encoded_inputs = tuple(inputs)
        if not encoded_inputs:
            raise PersistentStateError("task requires at least one input")
        digests = []
        for encoded in encoded_inputs:
            document = self.spec.codec.parse(encoded)
            self.spec.codec.validate_entry(document)
            if self.spec.codec.serialize(document) != encoded:
                raise PersistentStateError("task input is not canonical")
            digests.append(hashlib.sha256(encoded).hexdigest())
        if digests != sorted(set(digests)):
            raise PersistentStateError("task inputs must be unique and digest sorted")
        metadata = {
            "schema_name": f"linux-oracle-{self.kind}-job",
            "schema_version": SCHEMA_VERSION,
            "adapter_id": self.spec.adapter_id,
            "scenario_sha256": combined_digest(digests),
            "target_set_id": self.spec.coverage.target_set_id,
            "task_id": task_id,
            "state": "pending",
            "input_digests": digests,
            "context": dict(context or {}),
            "result": None,
        }
        path = self.root / task_id

        def save(temporary: Path) -> None:
            input_root = temporary / "inputs"
            input_root.mkdir()
            suffix = Path(self.spec.artifacts.scenario_filename).suffix or ".input"
            for digest, encoded in zip(digests, encoded_inputs):
                (input_root / f"{digest}{suffix}").write_bytes(encoded)
            write_json(temporary / "metadata.json", metadata)

        atomic_save_directory(path, save)
        return self.load(path)

    def recoverable(self) -> Tuple[Task, ...]:
        if not self.root.exists():
            return ()
        if self.root.is_symlink() or not self.root.is_dir():
            raise PersistentStateError("task root is not a regular directory")
        tasks = tuple(self.load(path) for path in sorted(self.root.iterdir()))
        return tuple(
            task
            for task in tasks
            if task.metadata["state"] in ("pending", "running")
            or self._retryable_representative_proof(task)
        )

    def claim(self, task: Task) -> Task:
        if self._retryable_representative_proof(task):
            metadata = dict(task.metadata)
            metadata["state"] = "running"
            metadata["result"] = None
            atomic_replace_file(
                task.path / "metadata.json",
                lambda temporary: write_json(temporary, metadata),
            )
            return self.load(task.path)
        if task.metadata["state"] not in ("pending", "running"):
            raise PersistentStateError("only recoverable tasks may be claimed")
        return self.transition(task, "running")

    def _retryable_representative_proof(self, task: Task) -> bool:
        return (
            self.kind == "attribution"
            and self.spec.outcomes is not None
            and task.metadata["state"] == "unstable"
            and task.metadata["result"] == {"category": "representative-proof"}
        )

    def transition(self, task: Task, state: str, result=None) -> Task:
        if state not in TASK_STATES:
            raise PersistentStateError("invalid task state")
        metadata = dict(task.metadata)
        metadata["state"] = state
        if result is not None or state in ("completed", "unstable"):
            metadata["result"] = result
        atomic_replace_file(
            task.path / "metadata.json",
            lambda temporary: write_json(temporary, metadata),
        )
        return self.load(task.path)

    def load(self, path: Path) -> Task:
        if path.is_symlink() or not path.is_dir():
            raise PersistentStateError("task path is not a regular directory")
        actual = {child.name for child in path.iterdir()}
        if actual != {"inputs", "metadata.json"}:
            raise PersistentStateError("task directory shape is invalid")
        metadata = read_json(path / "metadata.json")
        expected = {
            "schema_name",
            "schema_version",
            "adapter_id",
            "scenario_sha256",
            "target_set_id",
            "task_id",
            "state",
            "input_digests",
            "context",
            "result",
        }
        validate_exact_keys(metadata, expected, "task metadata")
        if (
            metadata["schema_name"] != f"linux-oracle-{self.kind}-job"
            or metadata["schema_version"] != SCHEMA_VERSION
            or metadata["adapter_id"] != self.spec.adapter_id
            or metadata["target_set_id"] != self.spec.coverage.target_set_id
            or metadata["task_id"] != path.name
            or metadata["state"] not in TASK_STATES
            or not sorted_unique_digests(metadata["input_digests"])
            or not isinstance(metadata["context"], dict)
        ):
            raise PersistentStateError("task metadata is invalid")
        if metadata["scenario_sha256"] != combined_digest(
            metadata["input_digests"]
        ):
            raise PersistentStateError("task combined digest mismatch")
        input_root = path / "inputs"
        if input_root.is_symlink() or not input_root.is_dir():
            raise PersistentStateError("task input root is invalid")
        suffix = Path(self.spec.artifacts.scenario_filename).suffix or ".input"
        expected_names = [
            f"{digest}{suffix}" for digest in metadata["input_digests"]
        ]
        if sorted(child.name for child in input_root.iterdir()) != expected_names:
            raise PersistentStateError("task input directory shape is invalid")
        inputs = []
        for digest, name in zip(metadata["input_digests"], expected_names):
            input_path = input_root / name
            if input_path.is_symlink() or not input_path.is_file():
                raise PersistentStateError("task input is not a regular file")
            encoded = input_path.read_bytes()
            if hashlib.sha256(encoded).hexdigest() != digest:
                raise PersistentStateError("task input digest mismatch")
            document = self.spec.codec.parse(encoded)
            self.spec.codec.validate_entry(document)
            if self.spec.codec.serialize(document) != encoded:
                raise PersistentStateError("task input is not canonical")
            inputs.append(encoded)
        return Task(path, metadata, tuple(inputs))


def combined_digest(digests: Iterable[str]) -> str:
    values = tuple(digests)
    if not all(is_digest(value) for value in values):
        raise PersistentStateError("task contains an invalid digest")
    return hashlib.sha256("".join(values).encode("ascii")).hexdigest()
