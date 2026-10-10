"""Bounded symbolic interpretation of pickle operations (see ADR-0001).

Only a supported subset of pickle semantics is modeled, enough to trace which
callable a ``REDUCE`` invokes and with which arguments. Nothing is imported,
called, or deserialized: globals are represented as ``_Global`` names and the
result of an invocation is an opaque ``_CallResult``. Semantics that are not
modeled are reported as limitations rather than assumed to be safe.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .results import AnalysisResult, Invocation, Limitation

# Intentional resource-exhaustion guardrails for symbolic analysis, not pickle
# semantic limits. They are initial defaults and may be revisited with
# real-world and resource testing.
MAX_STACK = 100_000
MAX_MEMO = 100_000


class PickleInterpreter:
    """Symbolically executes opcodes fed to :meth:`step`, one at a time."""

    def __init__(self) -> None:
        self._stack: list[Any] = []
        self._memo: dict[int, Any] = {}
        self._results: list[AnalysisResult] = []
        self._stopped = False
        self._current_opcode = ""

    def step(self, name: str, arg: Any, offset: int) -> list[AnalysisResult]:
        """Interpret one opcode and return the results it produced, in order.

        Interpretation stops permanently once an opcode cannot be modeled.
        """
        self._results = []
        self._current_opcode = name
        if not self._stopped:
            try:
                self._dispatch_opcode(name, arg, offset)
            except _InterpretationStoppedError:
                self._stopped = True
        return self._results

    def _dispatch_opcode(self, name: str, arg: Any, offset: int) -> None:
        match name:
            case "PROTO" | "FRAME" | "STOP":
                pass
            case (
                "INT"
                | "BININT"
                | "BININT1"
                | "BININT2"
                | "LONG"
                | "LONG1"
                | "LONG4"
                | "FLOAT"
                | "BINFLOAT"
                | "STRING"
                | "BINSTRING"
                | "SHORT_BINSTRING"
                | "UNICODE"
                | "BINUNICODE"
                | "SHORT_BINUNICODE"
                | "BINUNICODE8"
                | "BINBYTES"
                | "SHORT_BINBYTES"
                | "BINBYTES8"
                | "BYTEARRAY8"
            ):
                self._push_to_stack(arg, offset)
            case "NONE":
                self._push_to_stack(None, offset)
            case "NEWTRUE":
                self._push_to_stack(True, offset)
            case "NEWFALSE":
                self._push_to_stack(False, offset)

            case "MARK":
                self._push_to_stack(_MARK, offset)
            case "POP":
                if self._stack and self._stack[-1] is _MARK:
                    self._stack.pop()
                else:
                    self._pop_from_stack(offset)
            case "POP_MARK":
                self._pop_from_stack_since_mark(offset)
            case "DUP":
                self._push_to_stack(self._peek_stack(offset), offset)

            case "PUT" | "BINPUT" | "LONG_BINPUT":
                self._memoize(arg, self._peek_stack(offset), offset)
            case "MEMOIZE":
                self._memoize(len(self._memo), self._peek_stack(offset), offset)
            case "GET" | "BINGET" | "LONG_BINGET":
                if arg in self._memo:
                    self._push_to_stack(self._memo[arg], offset)
                else:
                    self._report_limitation(
                        f"Memo entry {arg} read before it was stored", offset
                    )
                    self._push_to_stack(_UNKNOWN, offset)

            case "GLOBAL":
                module, _, attr = str(arg).partition(" ")
                self._push_to_stack(_Global(module, attr), offset)
            case "STACK_GLOBAL":
                attr = self._pop_from_stack(offset)
                module = self._pop_from_stack(offset)
                if isinstance(module, str) and isinstance(attr, str):
                    self._push_to_stack(_Global(module, attr), offset)
                else:
                    self._report_limitation(
                        "STACK_GLOBAL operands are not static strings", offset
                    )
                    self._push_to_stack(_UNKNOWN, offset)

            case "EMPTY_TUPLE":
                self._push_to_stack((), offset)
            case "TUPLE":
                self._push_to_stack(
                    tuple(self._pop_from_stack_since_mark(offset)), offset
                )
            case "TUPLE1" | "TUPLE2" | "TUPLE3":
                items = [self._pop_from_stack(offset) for _ in range(int(name[-1]))]
                items.reverse()
                self._push_to_stack(tuple(items), offset)
            case "EMPTY_LIST":
                self._push_to_stack(_SymbolicList(), offset)
            case "LIST":
                self._push_to_stack(
                    _SymbolicList(self._pop_from_stack_since_mark(offset)), offset
                )
            case "APPEND":
                item = self._pop_from_stack(offset)
                self._top_container(_SymbolicList, offset).items.append(item)
            case "APPENDS":
                items = self._pop_from_stack_since_mark(offset)
                self._top_container(_SymbolicList, offset).items.extend(items)
            case "EMPTY_DICT":
                self._push_to_stack(_SymbolicDict(), offset)
            case "DICT":
                items = self._pop_from_stack_since_mark(offset)
                self._push_to_stack(_SymbolicDict(_pairs(items)), offset)
            case "SETITEM":
                value = self._pop_from_stack(offset)
                key = self._pop_from_stack(offset)
                self._top_container(_SymbolicDict, offset).items.append((key, value))
            case "SETITEMS":
                items = self._pop_from_stack_since_mark(offset)
                self._top_container(_SymbolicDict, offset).items.extend(_pairs(items))
            case "EMPTY_SET":
                self._push_to_stack(_SymbolicSet(), offset)
            case "ADDITEMS":
                items = self._pop_from_stack_since_mark(offset)
                self._top_container(_SymbolicSet, offset).items.extend(items)
            case "FROZENSET":
                self._push_to_stack(
                    ("frozenset", tuple(self._pop_from_stack_since_mark(offset))),
                    offset,
                )

            case "REDUCE":
                args = self._pop_from_stack(offset)
                func = self._pop_from_stack(offset)
                self._reduce(func, args, name, offset)
            case "NEWOBJ":
                args = self._pop_from_stack(offset)
                cls = self._pop_from_stack(offset)
                self._report_limitation(
                    "Object construction (__new__) is not interpreted", offset
                )
                self._push_to_stack(_CallResult(cls, args), offset)
            case "NEWOBJ_EX":
                kwargs = self._pop_from_stack(offset)
                args = self._pop_from_stack(offset)
                cls = self._pop_from_stack(offset)
                self._report_limitation(
                    "Object construction (__new__ with keyword arguments) "
                    "is not interpreted",
                    offset,
                )
                self._push_to_stack(_CallResult(cls, (args, kwargs)), offset)
            case "BUILD":
                self._pop_from_stack(offset)
                self._report_limitation(
                    "State application (__setstate__ or attribute update) "
                    "is not interpreted",
                    offset,
                )
            case "INST":
                module, _, attr = str(arg).partition(" ")
                items = self._pop_from_stack_since_mark(offset)
                self._report_limitation(
                    f"Class instantiation of {module}.{attr} is not interpreted",
                    offset,
                )
                self._push_to_stack(
                    _CallResult(_Global(module, attr), tuple(items)), offset
                )
            case "OBJ":
                items = self._pop_from_stack_since_mark(offset)
                if not items:
                    self._report_limitation("OBJ has no class on the stack", offset)
                    raise _InterpretationStoppedError
                self._report_limitation(
                    "Class instantiation (OBJ) is not interpreted", offset
                )
                self._push_to_stack(_CallResult(items[0], tuple(items[1:])), offset)
            case "PERSID":
                self._report_limitation(
                    f"Persistent ID {arg!r} is resolved by the application "
                    "and is not interpreted",
                    offset,
                )
                self._push_to_stack(_UNKNOWN, offset)
            case "BINPERSID":
                self._pop_from_stack(offset)
                self._report_limitation(
                    "Persistent ID is resolved by the application "
                    "and is not interpreted",
                    offset,
                )
                self._push_to_stack(_UNKNOWN, offset)
            case "EXT1" | "EXT2" | "EXT4":
                self._report_limitation(
                    f"Extension code {arg} is resolved through an external "
                    "registry and is not interpreted",
                    offset,
                )
                self._push_to_stack(_UNKNOWN, offset)
            case _:
                self._report_limitation(
                    f"Unsupported pickle opcode {name}; analysis halted", offset
                )
                raise _InterpretationStoppedError

    def _reduce(self, func: Any, args: Any, op: str, offset: int) -> None:
        if isinstance(func, _Global):
            static_args = (
                args
                if isinstance(args, tuple) and not _contains_unknown(args)
                else None
            )
            self._results.append(Invocation(func.qualified, static_args, op, offset))
            if static_args is None:
                self._report_limitation(
                    f"Arguments to {func.qualified} are not fully statically resolved",
                    offset,
                )
        else:
            self._report_limitation(
                "REDUCE callable could not be statically resolved", offset
            )
        self._push_to_stack(_CallResult(func, args), offset)

    def _report_limitation(self, description: str, offset: int) -> None:
        self._results.append(Limitation(description, offset, self._current_opcode))

    def _push_to_stack(self, value: Any, offset: int) -> None:
        if len(self._stack) >= MAX_STACK:
            self._report_limitation("Symbolic stack size bound exceeded", offset)
            raise _InterpretationStoppedError
        self._stack.append(value)

    def _pop_from_stack(self, offset: int) -> Any:
        if not self._stack:
            self._report_limitation("Stack underflow", offset)
            raise _InterpretationStoppedError
        value = self._stack.pop()
        if value is _MARK:
            self._report_limitation(
                "Unexpected mark where a value was expected", offset
            )
            raise _InterpretationStoppedError
        return value

    def _pop_from_stack_since_mark(self, offset: int) -> list:
        items: list = []
        while self._stack:
            value = self._stack.pop()
            if value is _MARK:
                items.reverse()
                return items
            items.append(value)
        self._report_limitation("Mark not found on stack", offset)
        raise _InterpretationStoppedError

    def _peek_stack(self, offset: int) -> Any:
        if not self._stack or self._stack[-1] is _MARK:
            self._report_limitation("Stack underflow", offset)
            raise _InterpretationStoppedError
        return self._stack[-1]

    def _memoize(self, index: int, value: Any, offset: int) -> None:
        if len(self._memo) >= MAX_MEMO and index not in self._memo:
            self._report_limitation("Memo size bound exceeded", offset)
            raise _InterpretationStoppedError
        self._memo[index] = value

    def _top_container(self, container_type: type, offset: int) -> Any:
        target = self._stack[-1] if self._stack else None
        if not isinstance(target, container_type):
            self._report_limitation(
                f"Target of container update is not a known {container_type.__name__}",
                offset,
            )
            raise _InterpretationStoppedError
        return target


class _InterpretationStoppedError(Exception):
    """Interpretation cannot continue."""


@dataclass(frozen=True)
class _Global:
    module: str
    name: str

    @property
    def qualified(self) -> str:
        return f"{self.module}.{self.name}"


@dataclass(frozen=True)
class _Unknown:
    """A value that cannot be determined statically."""


@dataclass(frozen=True)
class _CallResult:
    """Opaque result of a traced invocation; never evaluated."""

    callable: Any
    arguments: Any


@dataclass
class _SymbolicList:
    items: list = field(default_factory=list)


@dataclass
class _SymbolicDict:
    items: list = field(default_factory=list)  # list of (key, value) pairs


@dataclass
class _SymbolicSet:
    items: list = field(default_factory=list)


class _Mark:
    """Stack marker pushed by ``MARK``."""


_MARK = _Mark()
_UNKNOWN = _Unknown()


def _pairs(items: list) -> list[tuple[Any, Any]]:
    return list(zip(items[::2], items[1::2], strict=False))


def _contains_unknown(value: Any) -> bool:
    if value is _UNKNOWN:
        return True
    if isinstance(value, tuple):
        return any(_contains_unknown(item) for item in value)
    if isinstance(value, (_SymbolicList, _SymbolicSet)):
        return any(_contains_unknown(item) for item in value.items)
    if isinstance(value, _SymbolicDict):
        return any(_contains_unknown(item) for pair in value.items for item in pair)
    return False
