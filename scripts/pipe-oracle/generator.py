import hashlib
import struct
from typing import List, Tuple

GENERATOR_VERSION = "1"

MAX_INPUT_BYTES = 4096
MAX_OPS_PER_SCENARIO = 32
MAX_LOGICAL_SLOTS = 16

# Operation kinds
OP_PIPE2 = 0
OP_READ = 1
OP_WRITE = 2
OP_DUP = 3
OP_CLOSE = 4
OP_POLL = 5
OP_SET_SIZE = 6
OP_GET_SIZE = 7
OP_FIONREAD = 8


def expand_input(data: bytes) -> List[List[str]]:
    if len(data) == 0:
        return _fixed_seed_scenarios(0)
    if len(data) > MAX_INPUT_BYTES:
        data = data[:MAX_INPUT_BYTES]
    seed = _bytes_to_seed(data)
    rng = _Rng(seed)
    n_scenarios = max(1, rng.range(1, 5))
    scenarios: List[List[str]] = []
    for _ in range(n_scenarios):
        n_ops = max(1, rng.range(1, MAX_OPS_PER_SCENARIO + 1))
        scenario = _generate_scenario_ops(rng, n_ops)
        scenarios.append(scenario)
    return scenarios


def canonicalize_input(data: bytes) -> Tuple[str, str]:
    ops_text = ops_to_text(expand_input(data))
    digest = hashlib.sha256(ops_text.encode("utf-8")).hexdigest()
    return ops_text, digest


def _fixed_seed_scenarios(seed: int) -> List[List[str]]:
    rng = _Rng(seed)
    scenario = _generate_scenario_ops(rng, max(1, rng.range(1, 6)))
    return [scenario]


def _bytes_to_seed(data: bytes) -> int:
    if len(data) >= 8:
        return struct.unpack("<Q", data[:8])[0]
    padded = data + b"\x00" * (8 - len(data))
    return struct.unpack("<Q", padded)[0]


class _Rng:
    def __init__(self, seed: int):
        self.state = seed & 0xFFFFFFFFFFFFFFFF

    def next(self) -> int:
        self.state = (self.state * 6364136223846793005 + 1442695040888963407) & 0xFFFFFFFFFFFFFFFF
        return self.state

    def range(self, lo: int, hi: int) -> int:
        if lo >= hi:
            return lo
        return lo + (self.next() % (hi - lo))


def _generate_scenario_ops(rng: _Rng, n_ops: int) -> List[str]:
    ops: List[str] = []
    logical_slots = [0] * MAX_LOGICAL_SLOTS  # 0 = free, 1 = reader, 2 = writer

    for _ in range(n_ops):
        valid_ops = _available_ops(logical_slots)
        op = valid_ops[rng.range(0, len(valid_ops))]
        line = _emit_op(rng, op, logical_slots)
        if line:
            ops.append(line)
    return ops


def _available_ops(slots: List[int]) -> List[int]:
    has_reader = 1 in slots
    has_writer = 2 in slots
    has_any = any(t != 0 for t in slots)
    free_slots = slots.count(0)
    ops = []
    if free_slots >= 2:
        ops.append(OP_PIPE2)
    if has_reader:
        ops += [OP_READ, OP_CLOSE, OP_POLL, OP_FIONREAD]
    if has_writer:
        ops += [OP_WRITE, OP_CLOSE, OP_POLL, OP_SET_SIZE, OP_GET_SIZE]
    if has_any and free_slots >= 1:
        ops += [OP_DUP]
    return ops


def _emit_op(
    rng: _Rng,
    op: int,
    slots: List[int],
) -> str:
    if op == OP_PIPE2:
        free_slots = [index for index, slot_type in enumerate(slots) if slot_type == 0]
        read_index = rng.range(0, len(free_slots))
        read_slot = free_slots.pop(read_index)
        write_slot = free_slots[rng.range(0, len(free_slots))]
        slots[read_slot] = 1
        slots[write_slot] = 2
        return f"pipe2 {read_slot} {write_slot}"

    if op == OP_READ:
        readers = [i for i, t in enumerate(slots) if t == 1]
        if not readers:
            return ""
        fd = readers[rng.range(0, len(readers))]
        size = rng.range(0, 8193)
        return f"read {fd} {size}"

    if op == OP_WRITE:
        writers = [i for i, t in enumerate(slots) if t == 2]
        if not writers:
            return ""
        fd = writers[rng.range(0, len(writers))]
        size = rng.range(0, 8193)
        byte = rng.range(0, 256)
        return f"write {fd} {size} {byte}"

    if op == OP_DUP:
        targets = [i for i, t in enumerate(slots) if t != 0]
        free_slots = [i for i, t in enumerate(slots) if t == 0]
        if not targets or not free_slots:
            return ""
        src = targets[rng.range(0, len(targets))]
        new_fd = free_slots[rng.range(0, len(free_slots))]
        slots[new_fd] = slots[src]
        return f"dup {src} {new_fd}"

    if op == OP_CLOSE:
        targets = [i for i, t in enumerate(slots) if t != 0]
        if not targets:
            return ""
        fd = targets[rng.range(0, len(targets))]
        slots[fd] = 0
        return f"close {fd}"

    if op == OP_POLL:
        targets = [i for i, t in enumerate(slots) if t != 0]
        if not targets:
            return ""
        fd = targets[rng.range(0, len(targets))]
        events = 1 if slots[fd] == 1 else 4
        return f"poll {fd} {events}"

    if op == OP_SET_SIZE:
        writers = [i for i, t in enumerate(slots) if t == 2]
        if not writers:
            return ""
        fd = writers[rng.range(0, len(writers))]
        size = rng.range(1, 1048577)
        return f"set-size {fd} {size}"

    if op == OP_GET_SIZE:
        writers = [i for i, t in enumerate(slots) if t == 2]
        if not writers:
            return ""
        fd = writers[rng.range(0, len(writers))]
        return f"get-size {fd}"

    if op == OP_FIONREAD:
        readers = [i for i, t in enumerate(slots) if t == 1]
        if not readers:
            return ""
        fd = readers[rng.range(0, len(readers))]
        return f"fionread {fd}"

    return ""


def ops_to_text(scenarios: List[List[str]]) -> str:
    lines = ["version 1"]
    for i, scenario in enumerate(scenarios):
        lines.append(f"scenario generated-{i + 1:04d}")
        for op in scenario:
            lines.append(op)
    return "\n".join(lines) + "\n"
