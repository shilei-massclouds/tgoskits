"""Persistent monotonic Linux outcome evidence for concurrent scenarios."""

import base64
import fcntl
import hashlib
import json
import os
import struct
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Tuple

from .outcomes import AllowedAlternative, AllowedScenario, AllowedTrace


_SCHEMA_NAME = "linux-oracle-concurrent-outcomes"
_SCHEMA_VERSION = 1
_RESULT_SIZE = 112


class OutcomeStoreError(RuntimeError):
    """Persistent outcome evidence is missing, malformed, or inconsistent."""


@dataclass(frozen=True)
class StoredScenario:
    """All Linux outcomes observed for one canonical scenario."""

    scenario_sha256: str
    operation_count: int
    alternatives: Tuple[AllowedAlternative, ...]
    kernel_releases: Tuple[str, ...]


class OutcomeStore:
    """Atomically merge Linux observations into per-scenario evidence files."""

    def __init__(self, root: Path) -> None:
        self.root = root

    def merge(
        self,
        scenario_keys: Tuple[str, ...],
        trace: AllowedTrace,
        *,
        kernel_release: str,
    ) -> AllowedTrace:
        if len(scenario_keys) != len(trace.scenarios):
            raise OutcomeStoreError("scenario key count does not match trace")
        if not kernel_release or any(character.isspace() for character in kernel_release):
            raise OutcomeStoreError("kernel release is invalid")
        self.root.mkdir(parents=True, exist_ok=True)
        lock_path = self.root / ".lock"
        with lock_path.open("a+b") as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            merged = []
            for key, scenario in zip(scenario_keys, trace.scenarios):
                evidence = self._merge_scenario(
                    key,
                    scenario,
                    kernel_release=kernel_release,
                )
                merged.append(
                    AllowedScenario(
                        scenario.scenario_index,
                        scenario.operation_count,
                        tuple(
                            AllowedAlternative(
                                _rebase_payload(
                                    alternative.payload,
                                    scenario.scenario_index,
                                )
                            )
                            for alternative in evidence.alternatives
                        ),
                    )
                )
            return AllowedTrace(trace.version, trace.corpus_digest, tuple(merged))

    def load(self, scenario_key: str) -> StoredScenario:
        _validate_digest(scenario_key)
        path = self.root / f"{scenario_key}.json"
        if path.is_symlink() or not path.is_file():
            raise OutcomeStoreError(f"outcome evidence is unavailable: {scenario_key}")
        return _decode(path, scenario_key)

    def _merge_scenario(
        self,
        scenario_key: str,
        scenario: AllowedScenario,
        *,
        kernel_release: str,
    ) -> StoredScenario:
        _validate_digest(scenario_key)
        path = self.root / f"{scenario_key}.json"
        recordings: Dict[bytes, int] = {}
        releases = {kernel_release}
        if path.exists():
            if path.is_symlink() or not path.is_file():
                raise OutcomeStoreError("outcome evidence path is not a regular file")
            encoded = _load_document(path, scenario_key)
            if encoded["operation_count"] != scenario.operation_count:
                raise OutcomeStoreError("scenario operation count changed")
            releases.update(encoded["kernel_releases"])
            for alternative in encoded["alternatives"]:
                payload = alternative["payload"]
                recordings[payload] = (
                    recordings.get(payload, 0) + alternative["recordings"]
                )
        for alternative in scenario.alternatives:
            payload = _canonical_payload(
                alternative.payload,
                expected_index=scenario.scenario_index,
            )
            recordings[payload] = recordings.get(payload, 0) + 1
        document = {
            "schema_name": _SCHEMA_NAME,
            "schema_version": _SCHEMA_VERSION,
            "scenario_sha256": scenario_key,
            "operation_count": scenario.operation_count,
            "kernel_releases": sorted(releases),
            "alternatives": [
                {
                    "payload_base64": base64.b64encode(payload).decode("ascii"),
                    "recordings": recordings[payload],
                }
                for payload in sorted(recordings)
            ],
        }
        _atomic_write_json(path, document)
        return StoredScenario(
            scenario_key,
            scenario.operation_count,
            tuple(AllowedAlternative(payload) for payload in sorted(recordings)),
            tuple(sorted(releases)),
        )


def _decode(path: Path, scenario_key: str) -> StoredScenario:
    document = _load_document(path, scenario_key)
    payloads = sorted(
        {alternative["payload"] for alternative in document["alternatives"]}
    )
    return StoredScenario(
        scenario_key,
        document["operation_count"],
        tuple(
            AllowedAlternative(payload)
            for payload in payloads
        ),
        tuple(document["kernel_releases"]),
    )


def _load_document(path: Path, scenario_key: str) -> dict:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise OutcomeStoreError(f"cannot load outcome evidence: {error}") from error
    expected = {
        "schema_name",
        "schema_version",
        "scenario_sha256",
        "operation_count",
        "kernel_releases",
        "alternatives",
    }
    if (
        not isinstance(document, dict)
        or set(document) != expected
        or document["schema_name"] != _SCHEMA_NAME
        or document["schema_version"] != _SCHEMA_VERSION
        or document["scenario_sha256"] != scenario_key
        or not isinstance(document["operation_count"], int)
        or document["operation_count"] <= 0
        or not _sorted_unique_strings(document["kernel_releases"])
        or not isinstance(document["alternatives"], list)
        or not document["alternatives"]
    ):
        raise OutcomeStoreError("outcome evidence identity is invalid")
    decoded = []
    for alternative in document["alternatives"]:
        if (
            not isinstance(alternative, dict)
            or set(alternative) != {"payload_base64", "recordings"}
            or not isinstance(alternative["payload_base64"], str)
            or not isinstance(alternative["recordings"], int)
            or alternative["recordings"] <= 0
        ):
            raise OutcomeStoreError("outcome alternative is invalid")
        try:
            payload = base64.b64decode(
                alternative["payload_base64"], validate=True
            )
        except (ValueError, base64.binascii.Error) as error:
            raise OutcomeStoreError("outcome payload is invalid") from error
        if not payload:
            raise OutcomeStoreError("outcome payload is empty")
        decoded.append(
            {
                "raw_payload": payload,
                "payload": _canonical_payload(payload),
                "recordings": alternative["recordings"],
            }
        )
    raw_payloads = tuple(alternative["raw_payload"] for alternative in decoded)
    if raw_payloads != tuple(sorted(set(raw_payloads))):
        raise OutcomeStoreError("outcome alternatives are not canonical")
    document["alternatives"] = decoded
    return document


def _atomic_write_json(path: Path, document: dict) -> None:
    temporary_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            delete=False,
        ) as temporary:
            temporary_path = Path(temporary.name)
            json.dump(document, temporary, sort_keys=True, indent=2)
            temporary.write("\n")
            temporary.flush()
            os.fsync(temporary.fileno())
        os.replace(temporary_path, path)
    except OSError as error:
        raise OutcomeStoreError(f"cannot save outcome evidence: {error}") from error
    finally:
        if temporary_path is not None and temporary_path.exists():
            temporary_path.unlink()


def _validate_digest(value: str) -> None:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
        or hashlib.sha256(bytes.fromhex(value)).digest_size != 32
    ):
        raise OutcomeStoreError("scenario digest is invalid")


def _canonical_payload(payload: bytes, *, expected_index: int = None) -> bytes:
    if not payload or len(payload) % _RESULT_SIZE != 0:
        raise OutcomeStoreError("outcome payload is not a result vector")
    canonical = bytearray(payload)
    indexes = {
        struct.unpack_from("<I", payload, offset)[0]
        for offset in range(0, len(payload), _RESULT_SIZE)
    }
    if len(indexes) != 1:
        raise OutcomeStoreError("outcome payload mixes scenario indexes")
    (scenario_index,) = tuple(indexes)
    if expected_index is not None and scenario_index != expected_index:
        raise OutcomeStoreError("outcome payload scenario index is invalid")
    for offset in range(0, len(canonical), _RESULT_SIZE):
        struct.pack_into("<I", canonical, offset, 0)
    return bytes(canonical)


def _rebase_payload(payload: bytes, scenario_index: int) -> bytes:
    canonical = _canonical_payload(payload, expected_index=0)
    rebased = bytearray(canonical)
    for offset in range(0, len(rebased), _RESULT_SIZE):
        struct.pack_into("<I", rebased, offset, scenario_index)
    return bytes(rebased)


def _sorted_unique_strings(value: object) -> bool:
    return (
        isinstance(value, list)
        and bool(value)
        and all(isinstance(item, str) and item for item in value)
        and value == sorted(set(value))
    )


__all__ = ["OutcomeStore", "OutcomeStoreError", "StoredScenario"]
