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

from .results import Event, Invocation, Limitation

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
        self._events: list[Event] = []
        self._stopped = False

    def step(self, name: str, arg: Any, pos: int) -> list[Event]:
        """Interpret one opcode and return the events it produced, in order.

        Interpretation stops permanently once an opcode cannot be modeled.
        """
        self._events = []
        if not self._stopped:
            try:
                self._dispatch(name, arg, pos)
            except _Stop:
                self._stopped = True
        return self._events

    def _dispatch(self, name: str, arg: Any, pos: int) -> None:
        match name:
            case "PROTO" | "FRAME" | "STOP":
                pass
            case (
                "INT" | "BININT" | "BININT1" | "BININT2" | "LONG" | "LONG1"
                | "LONG4" | "FLOAT" | "BINFLOAT" | "STRING" | "BINSTRING"
                | "SHORT_BINSTRING" | "UNICODE" | "BINUNICODE"
                | "SHORT_BINUNICODE" | "BINUNICODE8" | "BINBYTES"
                | "SHORT_BINBYTES" | "BINBYTES8" | "BYTEARRAY8"
            ):
                self._push(arg, pos)
            case "NONE":
                self._push(None, pos)
            case "NEWTRUE":
                self._push(True, pos)
            case "NEWFALSE":
                self._push(False, pos)

            case "MARK":
                self._push(_MARK, pos)
            case "POP":
                if self._stack and self._stack[-1] is _MARK:
                    self._stack.pop()
                else:
                    self._pop(pos)
            case "POP_MARK":
                self._pop_mark(pos)
            case "DUP":
                self._push(self._peek(pos), pos)

            case "PUT" | "BINPUT" | "LONG_BINPUT":
                self._memoize(arg, self._peek(pos), pos)
            case "MEMOIZE":
                self._memoize(len(self._memo), self._peek(pos), pos)
            case "GET" | "BINGET" | "LONG_BINGET":
                if arg in self._memo:
                    self._push(self._memo[arg], pos)
                else:
                    self._limit(f"Memo entry {arg} read before it was stored", pos)
                    self._push(_UNKNOWN, pos)

            case "GLOBAL":
                module, _, attr = str(arg).partition(" ")
                self._push(_Global(module, attr), pos)
            case "STACK_GLOBAL":
                attr = self._pop(pos)
                module = self._pop(pos)
                if isinstance(module, str) and isinstance(attr, str):
                    self._push(_Global(module, attr), pos)
                else:
                    self._limit("STACK_GLOBAL operands are not static strings", pos)
                    self._push(_UNKNOWN, pos)

            case "EMPTY_TUPLE":
                self._push((), pos)
            case "TUPLE":
                self._push(tuple(self._pop_mark(pos)), pos)
            case "TUPLE1" | "TUPLE2" | "TUPLE3":
                items = [self._pop(pos) for _ in range(int(name[-1]))]
                items.reverse()
                self._push(tuple(items), pos)
            case "EMPTY_LIST":
                self._push(_SymbolicList(), pos)
            case "LIST":
                self._push(_SymbolicList(self._pop_mark(pos)), pos)
            case "APPEND":
                item = self._pop(pos)
                self._container(_SymbolicList, pos).items.append(item)
            case "APPENDS":
                items = self._pop_mark(pos)
                self._container(_SymbolicList, pos).items.extend(items)
            case "EMPTY_DICT":
                self._push(_SymbolicDict(), pos)
            case "DICT":
                items = self._pop_mark(pos)
                self._push(_SymbolicDict(_pairs(items)), pos)
            case "SETITEM":
                value = self._pop(pos)
                key = self._pop(pos)
                self._container(_SymbolicDict, pos).items.append((key, value))
            case "SETITEMS":
                items = self._pop_mark(pos)
                self._container(_SymbolicDict, pos).items.extend(_pairs(items))
            case "EMPTY_SET":
                self._push(_SymbolicSet(), pos)
            case "ADDITEMS":
                items = self._pop_mark(pos)
                self._container(_SymbolicSet, pos).items.extend(items)
            case "FROZENSET":
                self._push(("frozenset", tuple(self._pop_mark(pos))), pos)

            case "REDUCE":
                args = self._pop(pos)
                func = self._pop(pos)
                self._reduce(func, args, name, pos)
            case "NEWOBJ":
                args = self._pop(pos)
                cls = self._pop(pos)
                self._limit(
                    "NEWOBJ stack effect modeled; object construction "
                    "(__new__) is not interpreted",
                    pos,
                )
                self._push(_CallResult(cls, args), pos)
            case "BUILD":
                self._pop(pos)
                self._limit(
                    "BUILD stack effect modeled; state application "
                    "(__setstate__ or attribute update) is not interpreted",
                    pos,
                )
            case _:
                self._limit(f"Unsupported pickle opcode {name}; analysis halted", pos)
                raise _Stop

    def _reduce(self, func: Any, args: Any, op: str, pos: int) -> None:
        if isinstance(func, _Global):
            static_args = args if isinstance(args, tuple) else None
            self._events.append(Invocation(func.qualified, static_args, op, pos))
            if static_args is None:
                self._limit(
                    f"Arguments to {func.qualified} are not a static tuple", pos
                )
        else:
            self._limit("REDUCE callable could not be statically resolved", pos)
        self._push(_CallResult(func, args), pos)

    def _limit(self, description: str, pos: int) -> None:
        self._events.append(Limitation(description, pos))

    def _push(self, value: Any, pos: int) -> None:
        if len(self._stack) >= MAX_STACK:
            self._limit("Symbolic stack size bound exceeded", pos)
            raise _Stop
        self._stack.append(value)

    def _pop(self, pos: int) -> Any:
        if not self._stack:
            self._limit("Stack underflow", pos)
            raise _Stop
        value = self._stack.pop()
        if value is _MARK:
            self._limit("Unexpected mark where a value was expected", pos)
            raise _Stop
        return value

    def _pop_mark(self, pos: int) -> list:
        items: list = []
        while self._stack:
            value = self._stack.pop()
            if value is _MARK:
                items.reverse()
                return items
            items.append(value)
        self._limit("Mark not found on stack", pos)
        raise _Stop

    def _peek(self, pos: int) -> Any:
        if not self._stack or self._stack[-1] is _MARK:
            self._limit("Stack underflow", pos)
            raise _Stop
        return self._stack[-1]

    def _memoize(self, index: int, value: Any, pos: int) -> None:
        if len(self._memo) >= MAX_MEMO and index not in self._memo:
            self._limit("Memo size bound exceeded", pos)
            raise _Stop
        self._memo[index] = value

    def _container(self, kind: type, pos: int) -> Any:
        target = self._stack[-1] if self._stack else None
        if not isinstance(target, kind):
            self._limit(
                f"Target of container update is not a known {kind.__name__}", pos
            )
            raise _Stop
        return target


class _Stop(Exception):
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
