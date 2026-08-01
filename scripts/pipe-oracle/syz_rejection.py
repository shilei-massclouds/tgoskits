"""Stable semantic rejection types for pinned syzkaller conversion."""

from enum import Enum


class SyzRejectionCategory(str, Enum):
    UNSUPPORTED_CALL = "unsupported-call"
    PSEUDO_SYSCALL = "pseudo-syscall"
    CALL_PROPERTIES = "call-properties"
    INVALID_ARITY = "invalid-arity"
    UNSUPPORTED_ARGUMENT = "unsupported-argument"
    UNSUPPORTED_CONSTANT = "unsupported-constant"
    UNSUPPORTED_RESULT = "unsupported-result"
    DUPLICATE_RESULT = "duplicate-result"
    UNDEFINED_RESOURCE = "undefined-resource"
    RESOURCE_ARITHMETIC = "resource-arithmetic"
    USE_AFTER_CLOSE = "use-after-close"
    SLOT_LIMIT = "slot-limit"
    POINTER_SHAPE = "pointer-shape"
    MEMORY_OVERLAP = "memory-overlap"
    BUFFER_SHAPE = "buffer-shape"
    NON_UNIFORM_PAYLOAD = "non-uniform-payload"
    VECTOR_SHAPE = "vector-shape"
    POLL_SHAPE = "poll-shape"
    BLOCKING_IO = "blocking-io"
    ENTRY_LIMIT = "entry-limit"


class SyzConversionError(ValueError):
    """A stable rejection for a well-formed but unsupported syzkaller AST."""

    def __init__(
        self,
        line_number: int,
        category: SyzRejectionCategory,
        detail: str,
    ):
        self.line_number = line_number
        self.category = category
        self.detail = detail
        super().__init__(f"line {line_number}: {category.value}: {detail}")


__all__ = ["SyzConversionError", "SyzRejectionCategory"]
