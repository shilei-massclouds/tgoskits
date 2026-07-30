import struct
from typing import List, Tuple

GENERATOR_VERSION = "1"

MAX_INPUT_BYTES = 4096
MAX_OPS_PER_SCENARIO = 32

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
    logical_slots: List[int] = []  # 0 = free, 1 = reader, 2 = writer

    def alloc_slot(slot_type: int) -> int:
        for i, t in enumerate(logical_slots):
            if t == 0:
                logical_slots[i] = slot_type
                return i
        logical_slots.append(slot_type)
        return len(logical_slots) - 1

    def free_slot(slot: int):
        if 0 <= slot < len(logical_slots):
            logical_slots[slot] = 0

    for _ in range(n_ops):
        valid_ops = _available_ops(logical_slots)
        if not valid_ops:
            op = OP_PIPE2
        else:
            op = valid_ops[rng.range(0, len(valid_ops))]
        line = _emit_op(rng, op, logical_slots, alloc_slot, free_slot)
        if line:
            ops.append(line)
    return ops


def _available_ops(slots: List[int]) -> List[int]:
    has_reader = 1 in slots
    has_writer = 2 in slots
    has_any = len(slots) > 0 and any(t != 0 for t in slots)
    ops = [OP_PIPE2]
    if has_reader:
        ops += [OP_READ, OP_CLOSE, OP_POLL, OP_FIONREAD]
    if has_writer:
        ops += [OP_WRITE, OP_CLOSE, OP_POLL, OP_SET_SIZE, OP_GET_SIZE]
    if has_any:
        ops += [OP_DUP]
    return ops


def _emit_op(
    rng: _Rng,
    op: int,
    slots: List[int],
    alloc_slot,
    free_slot,
) -> str:
    if op == OP_PIPE2:
        flags = rng.range(0, 4)
        flag_str = f"flags={flags}" if flags else ""
        return f"pipe2 {flag_str}"

    elif op == OP_READ:
        readers = [i for i, t in enumerate(slots) if t == 1]
        if not readers:
            return ""
        fd = readers[rng.range(0, len(readers))]
        size = rng.range(0, 8193)
        return f"read fd={fd} size={size}"

    elif op == OP_WRITE:
        writers = [i for i, t in enumerate(slots) if t == 2]
        if not writers:
            return ""
        fd = writers[rng.range(0, len(writers))]
        size = rng.range(0, 8193)
        return f"write fd={fd} size={size}"

    elif op == OP_DUP:
        targets = [i for i, t in enumerate(slots) if t != 0]
        if not targets:
            return ""
        src = targets[rng.range(0, len(targets))]
        new_type = slots[src]
        new_fd = alloc_slot(new_type)
        return f"dup fd={src} newfd={new_fd}"

    elif op == OP_CLOSE:
        targets = [i for i, t in enumerate(slots) if t != 0]
        if not targets:
            return ""
        fd = targets[rng.range(0, len(targets))]
        free_slot(fd)
        return f"close fd={fd}"

    elif op == OP_POLL:
        targets = [i for i, t in enumerate(slots) if t != 0]
        if not targets:
            return ""
        fd = targets[rng.range(0, len(targets))]
        events = rng.range(1, 4)
        return f"poll fd={fd} events={events}"

    elif op == OP_SET_SIZE:
        writers = [i for i, t in enumerate(slots) if t == 2]
        if not writers:
            return ""
        fd = writers[rng.range(0, len(writers))]
        size = rng.range(1, 1048577)
        return f"set-size fd={fd} size={size}"

    elif op == OP_GET_SIZE:
        writers = [i for i, t in enumerate(slots) if t == 2]
        if not writers:
            return ""
        fd = writers[rng.range(0, len(writers))]
        return f"get-size fd={fd}"

    elif op == OP_FIONREAD:
        readers = [i for i, t in enumerate(slots) if t == 1]
        if not readers:
            return ""
        fd = readers[rng.range(0, len(readers))]
        return f"fionread fd={fd}"

    return ""


def ops_to_text(scenarios: List[List[str]]) -> str:
    lines: List[str] = []
    for i, scenario in enumerate(scenarios):
        lines.append(f"# scenario {i + 1}")
        for op in scenario:
            lines.append(op)
    return "\n".join(lines) + "\n"
