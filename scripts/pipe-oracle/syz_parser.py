"""Strict parser for the serialized syzkaller program language."""

import base64
import binascii
import re
from enum import Enum
from typing import List

from syz_ast import (
    SyzArgument,
    SyzArray,
    SyzAuto,
    SyzCall,
    SyzCallProperty,
    SyzInteger,
    SyzNil,
    SyzPointer,
    SyzProgram,
    SyzResource,
    SyzResultCapture,
    SyzString,
    SyzStruct,
    SyzUnion,
)


class SyzSyntaxCategory(str, Enum):
    INVALID_ENCODING = "invalid-encoding"
    INVALID_TOKEN = "invalid-token"
    INVALID_INTEGER = "invalid-integer"
    INVALID_STRING = "invalid-string"
    UNEXPECTED_TOKEN = "unexpected-token"
    INCOMPLETE_CALL = "incomplete-call"
    TRAILING_DATA = "trailing-data"
    EMPTY_PROGRAM = "empty-program"


class SyzSyntaxError(ValueError):
    """A stable source location and category for malformed ``.syz`` text."""

    def __init__(
        self,
        line_number: int,
        column: int,
        category: SyzSyntaxCategory,
        detail: str,
    ):
        self.line_number = line_number
        self.column = column
        self.category = category
        self.detail = detail
        super().__init__(
            f"line {line_number}:{column}: {category.value}: {detail}"
        )


def parse_syz_program(encoded: bytes) -> SyzProgram:
    """Parse one official serialized syzkaller program without type repair."""

    try:
        text = encoded.decode("utf-8")
    except UnicodeDecodeError as error:
        line_number = encoded[: error.start].count(b"\n") + 1
        line_start = encoded.rfind(b"\n", 0, error.start) + 1
        raise SyzSyntaxError(
            line_number,
            error.start - line_start + 1,
            SyzSyntaxCategory.INVALID_ENCODING,
            "program is not UTF-8",
        ) from error

    calls = []
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        line = _strip_comment(raw_line, line_number)
        if not line.strip():
            continue
        calls.append(_LineParser(line, line_number).parse_call())
    if not calls:
        raise SyzSyntaxError(
            1,
            1,
            SyzSyntaxCategory.EMPTY_PROGRAM,
            "program contains no calls",
        )
    return SyzProgram(tuple(calls))


def _strip_comment(line: str, line_number: int) -> str:
    quote = None
    escaped = False
    for index, character in enumerate(line):
        if quote == "'":
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == quote:
                quote = None
        elif quote == '"':
            if character == quote:
                quote = None
        elif character in ("'", '"'):
            quote = character
        elif character == "#":
            return line[:index]
    if quote is not None:
        raise SyzSyntaxError(
            line_number,
            len(line) + 1,
            SyzSyntaxCategory.INVALID_STRING,
            "unterminated string",
        )
    return line


class _LineParser:
    def __init__(self, line: str, line_number: int):
        self.line = line
        self.line_number = line_number
        self.offset = 0

    def parse_call(self) -> SyzCall:
        first = self._parse_identifier()
        self._skip_spaces()
        assignment = None
        if self._consume_if("="):
            if not _VARIABLE.fullmatch(first):
                self._fail(
                    SyzSyntaxCategory.UNEXPECTED_TOKEN,
                    "assignment target must be an rN variable",
                )
            assignment = first
            name = self._parse_identifier()
        else:
            name = first

        self._expect("(", SyzSyntaxCategory.INCOMPLETE_CALL)
        arguments = self._parse_delimited_arguments(")")
        properties: List[SyzCallProperty] = []
        self._skip_spaces()
        if self._consume_if("("):
            properties = self._parse_properties()
            self._expect(")", SyzSyntaxCategory.INCOMPLETE_CALL)
        self._skip_spaces()
        if not self._at_end():
            self._fail(
                SyzSyntaxCategory.TRAILING_DATA,
                f"unexpected trailing data {self.line[self.offset:]!r}",
            )
        return SyzCall(
            name,
            tuple(arguments),
            assignment,
            tuple(properties),
            self.line_number,
        )

    def _parse_argument(self) -> SyzArgument:
        self._skip_spaces()
        character = self._peek()
        if character == "<":
            self._expect("<")
            name = self._parse_identifier()
            if not _VARIABLE.fullmatch(name):
                self._fail(
                    SyzSyntaxCategory.UNEXPECTED_TOKEN,
                    "result capture must name an rN variable",
                )
            self._expect("=")
            self._expect(">")
            return SyzResultCapture(name, self._parse_argument())
        if character == "&":
            return self._parse_pointer()
        if character in ("'", '"'):
            return self._parse_string()
        if character == "{":
            self._expect("{")
            return SyzStruct(tuple(self._parse_delimited_arguments("}")))
        if character == "[":
            self._expect("[")
            return SyzArray(tuple(self._parse_delimited_arguments("]")))
        if character == "@":
            self._expect("@")
            field = self._parse_identifier()
            value = self._parse_argument() if self._consume_if("=") else None
            return SyzUnion(field, value)

        token = self._parse_identifier()
        if token == "nil":
            return SyzNil()
        if token == "AUTO":
            return SyzAuto()
        if _VARIABLE.fullmatch(token):
            divisor = None
            addend = None
            if self._consume_if("/"):
                divisor = self._parse_integer_token().value
            if self._consume_if("+"):
                addend = self._parse_integer_token().value
            return SyzResource(token, divisor, addend)
        if _looks_like_integer(token):
            return _integer(token, self.line_number, self.offset - len(token) + 1)
        self._fail(
            SyzSyntaxCategory.INVALID_TOKEN,
            f"unsupported argument token {token!r}",
        )

    def _parse_pointer(self) -> SyzPointer:
        self._expect("&")
        auto = False
        address = None
        region_size = None
        if self._starts_identifier("AUTO"):
            token = self._parse_identifier()
            if token != "AUTO":
                self._fail(SyzSyntaxCategory.INVALID_TOKEN, "invalid AUTO pointer")
            auto = True
        else:
            self._expect("(")
            address = self._parse_integer_token().value
            if self._consume_if("/"):
                region_size = self._parse_integer_token().value
            self._expect(")")

        value = None
        any_pointer = False
        if self._consume_if("="):
            if self._starts_identifier("ANY"):
                token = self._parse_identifier()
                if token != "ANY":
                    self._fail(SyzSyntaxCategory.INVALID_TOKEN, "invalid ANY pointer")
                self._expect("=")
                any_pointer = True
            value = self._parse_argument()
        return SyzPointer(auto, address, region_size, value, any_pointer)

    def _parse_string(self) -> SyzString:
        quote = self._peek()
        start_column = self.offset + 1
        self.offset += 1
        base64_encoded = False
        data = bytearray()
        if quote == '"':
            start = self.offset
            while not self._at_end() and self._peek() != '"':
                self.offset += 1
            if self._at_end():
                self._fail(SyzSyntaxCategory.INVALID_STRING, "unterminated string")
            contents = self.line[start : self.offset]
            self.offset += 1
            if contents.startswith("$"):
                base64_encoded = True
                try:
                    padding = "=" * (-len(contents[1:]) % 4)
                    data.extend(base64.b64decode(contents[1:] + padding, validate=True))
                except (binascii.Error, ValueError) as error:
                    raise SyzSyntaxError(
                        self.line_number,
                        start_column,
                        SyzSyntaxCategory.INVALID_STRING,
                        "invalid base64 string",
                    ) from error
            else:
                try:
                    data.extend(bytes.fromhex(contents))
                except ValueError as error:
                    raise SyzSyntaxError(
                        self.line_number,
                        start_column,
                        SyzSyntaxCategory.INVALID_STRING,
                        "double-quoted strings must contain hexadecimal bytes",
                    ) from error
        else:
            while not self._at_end() and self._peek() != "'":
                character = self._take()
                if character != "\\":
                    data.extend(character.encode("utf-8"))
                    continue
                if self._at_end():
                    self._fail(SyzSyntaxCategory.INVALID_STRING, "trailing escape")
                escape = self._take()
                if escape == "x":
                    digits = self.line[self.offset : self.offset + 2]
                    if len(digits) != 2 or not _HEX_BYTE.fullmatch(digits):
                        self._fail(SyzSyntaxCategory.INVALID_STRING, "invalid hex escape")
                    data.append(int(digits, 16))
                    self.offset += 2
                elif escape in _ESCAPES:
                    data.append(_ESCAPES[escape])
                else:
                    self._fail(
                        SyzSyntaxCategory.INVALID_STRING,
                        f"invalid escape \\{escape}",
                    )
            if self._at_end():
                self._fail(SyzSyntaxCategory.INVALID_STRING, "unterminated string")
            self.offset += 1

        declared_size = None
        if self._consume_if("/"):
            declared_size = self._parse_integer_token().value
        return SyzString(bytes(data), declared_size, base64_encoded)

    def _parse_delimited_arguments(self, closing: str) -> List[SyzArgument]:
        arguments = []
        self._skip_spaces()
        if self._consume_if(closing):
            return arguments
        while True:
            arguments.append(self._parse_argument())
            if self._consume_if(closing):
                return arguments
            self._expect(",", SyzSyntaxCategory.INCOMPLETE_CALL)

    def _parse_properties(self) -> List[SyzCallProperty]:
        properties = []
        self._skip_spaces()
        if self._peek() == ")":
            return properties
        while True:
            name = self._parse_identifier()
            value = None
            if self._consume_if(":"):
                value = self._parse_integer_token().value
            properties.append(SyzCallProperty(name, value))
            if self._peek() == ")":
                return properties
            self._expect(",", SyzSyntaxCategory.INCOMPLETE_CALL)

    def _parse_integer_token(self) -> SyzInteger:
        token = self._parse_identifier()
        return _integer(token, self.line_number, self.offset - len(token) + 1)

    def _parse_identifier(self) -> str:
        self._skip_spaces()
        start = self.offset
        while not self._at_end() and (
            self._peek().isalnum() or self._peek() in ("_", "$")
        ):
            self.offset += 1
        if start == self.offset:
            self._fail(
                SyzSyntaxCategory.UNEXPECTED_TOKEN,
                f"expected identifier, found {self._peek()!r}",
            )
        token = self.line[start : self.offset]
        self._skip_spaces()
        return token

    def _starts_identifier(self, value: str) -> bool:
        self._skip_spaces()
        end = self.offset + len(value)
        return self.line[self.offset : end] == value and (
            end == len(self.line)
            or not (self.line[end].isalnum() or self.line[end] in ("_", "$"))
        )

    def _consume_if(self, token: str) -> bool:
        self._skip_spaces()
        if self.line.startswith(token, self.offset):
            self.offset += len(token)
            self._skip_spaces()
            return True
        return False

    def _expect(
        self,
        token: str,
        category: SyzSyntaxCategory = SyzSyntaxCategory.UNEXPECTED_TOKEN,
    ) -> None:
        if not self._consume_if(token):
            self._fail(category, f"expected {token!r}, found {self._peek()!r}")

    def _skip_spaces(self) -> None:
        while not self._at_end() and self._peek() in (" ", "\t"):
            self.offset += 1

    def _peek(self) -> str:
        return "" if self._at_end() else self.line[self.offset]

    def _take(self) -> str:
        character = self._peek()
        self.offset += 1
        return character

    def _at_end(self) -> bool:
        return self.offset >= len(self.line)

    def _fail(self, category: SyzSyntaxCategory, detail: str):
        raise SyzSyntaxError(self.line_number, self.offset + 1, category, detail)


def _integer(token: str, line_number: int, column: int) -> SyzInteger:
    try:
        if token.lower().startswith("0x"):
            if len(token) == 2:
                raise ValueError
            value = int(token[2:], 16)
        elif len(token) > 1 and token.startswith("0"):
            if any(character not in "01234567" for character in token):
                raise ValueError
            value = int(token, 8)
        else:
            value = int(token, 10)
    except ValueError as error:
        raise SyzSyntaxError(
            line_number,
            column,
            SyzSyntaxCategory.INVALID_INTEGER,
            f"invalid integer {token!r}",
        ) from error
    if value < 0 or value > 0xFFFFFFFFFFFFFFFF:
        raise SyzSyntaxError(
            line_number,
            column,
            SyzSyntaxCategory.INVALID_INTEGER,
            f"integer outside unsigned 64-bit range: {token!r}",
        )
    return SyzInteger(value, token)


def _looks_like_integer(token: str) -> bool:
    return bool(token) and token[0].isdigit()


_VARIABLE = re.compile(r"r[0-9]+")
_HEX_BYTE = re.compile(r"[0-9a-fA-F]{2}")
_ESCAPES = {
    "a": 7,
    "b": 8,
    "f": 12,
    "n": 10,
    "r": 13,
    "t": 9,
    "v": 11,
    "'": 39,
    '"': 34,
    "\\": 92,
}
