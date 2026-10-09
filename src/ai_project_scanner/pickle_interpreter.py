"""Bounded symbolic interpretation of pickle operations (see ADR-0001).

Only a supported subset of pickle semantics is modeled, enough to trace which
callable a ``REDUCE`` invokes and with which arguments. Nothing is imported,
called, or deserialized: globals are represented as ``Global`` names and the
result of an invocation is an opaque ``CallResult``. Unsupported semantics are
recorded as limitations rather than assumed to be safe.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .results import Invocation

MAX_STACK = 100_000
MAX_MEMO = 100_000


@dataclass(frozen=True)
class Global:
    module: str
    name: str

    @property
    def qualified(self) -> str:
        return f"{self.module}.{self.name}"


@dataclass(frozen=True)
class Unknown:
    """A value that cannot be determined statically."""


@dataclass(frozen=True)
class CallResult:
    """Opaque result of a traced invocation; never evaluated."""

    callable: Any
    arguments: Any


@dataclass
class SymList:
    items: list = field(default_factory=list)


@dataclass
class SymDict:
    items: list = field(default_factory=list)  # list of (key, value) pairs


@dataclass
class SymSet:
    items: list = field(default_factory=list)


@dataclass
class _Mark:
    pass


_UNKNOWN = Unknown()
_MARK = _Mark()

_LITERALS = {
    "INT", "BININT", "BININT1", "BININT2", "LONG", "LONG1", "LONG4",
    "FLOAT", "BINFLOAT", "STRING", "BINSTRING", "SHORT_BINSTRING",
    "UNICODE", "BINUNICODE", "SHORT_BINUNICODE", "BINUNICODE8",
    "BINBYTES", "SHORT_BINBYTES", "BINBYTES8", "BYTEARRAY8",
}
_PUT = {"PUT", "BINPUT", "LONG_BINPUT"}
_GET = {"GET", "BINGET", "LONG_BINGET"}
_IGNORED = {"PROTO", "FRAME", "STOP"}


class _Stop(Exception):
    """Interpretation cannot continue."""


class PickleInterpreter:
    def __init__(self) -> None:
        self.stack: list[Any] = []
        self.memo: dict[int, Any] = {}
        self.invocations: list[Invocation] = []
        self.limitations: list[str] = []
        self.stopped = False

    def _limit(self, msg: str, pos: int) -> None:
        self.limitations.append(f"{msg} (byte offset {pos})")

    def _push(self, value: Any, pos: int) -> None:
        if len(self.stack) >= MAX_STACK:
            self._limit("Symbolic stack size bound exceeded", pos)
            raise _Stop
        self.stack.append(value)

    def _pop(self, pos: int) -> Any:
        if not self.stack:
            self._limit("Stack underflow", pos)
            raise _Stop
        value = self.stack.pop()
        if value is _MARK:
            self._limit("Unexpected mark where a value was expected", pos)
            raise _Stop
        return value

    def _pop_mark(self, pos: int) -> list:
        items: list = []
        while self.stack:
            value = self.stack.pop()
            if value is _MARK:
                items.reverse()
                return items
            items.append(value)
        self._limit("Mark not found on stack", pos)
        raise _Stop

    def _peek(self, pos: int) -> Any:
        if not self.stack or self.stack[-1] is _MARK:
            self._limit("Stack underflow", pos)
            raise _Stop
        return self.stack[-1]

    def step(self, name: str, arg: Any, pos: int) -> None:
        """Interpret one opcode. Stops permanently on unsupported semantics."""
        if self.stopped:
            return
        try:
            self._step(name, arg, pos)
        except _Stop:
            self.stopped = True

    def _step(self, name: str, arg: Any, pos: int) -> None:
        if name in _IGNORED:
            return
        if name in _LITERALS:
            self._push(arg, pos)
        elif name == "NONE":
            self._push(None, pos)
        elif name == "NEWTRUE":
            self._push(True, pos)
        elif name == "NEWFALSE":
            self._push(False, pos)
        elif name == "MARK":
            self._push(_MARK, pos)
        elif name == "POP":
            if self.stack and self.stack[-1] is _MARK:
                self.stack.pop()
            else:
                self._pop(pos)
        elif name == "POP_MARK":
            self._pop_mark(pos)
        elif name == "DUP":
            self._push(self._peek(pos), pos)
        elif name in _PUT:
            self._memoize(arg, self._peek(pos), pos)
        elif name == "MEMOIZE":
            self._memoize(len(self.memo), self._peek(pos), pos)
        elif name in _GET:
            if arg in self.memo:
                self._push(self.memo[arg], pos)
            else:
                self._limit(f"Memo entry {arg} read before it was stored", pos)
                self._push(_UNKNOWN, pos)
        elif name == "GLOBAL":
            module, _, attr = str(arg).partition(" ")
            self._push(Global(module, attr), pos)
        elif name == "STACK_GLOBAL":
            attr = self._pop(pos)
            module = self._pop(pos)
            if isinstance(module, str) and isinstance(attr, str):
                self._push(Global(module, attr), pos)
            else:
                self._limit("STACK_GLOBAL operands are not static strings", pos)
                self._push(_UNKNOWN, pos)
        elif name == "EMPTY_TUPLE":
            self._push((), pos)
        elif name == "TUPLE":
            self._push(tuple(self._pop_mark(pos)), pos)
        elif name in ("TUPLE1", "TUPLE2", "TUPLE3"):
            n = int(name[-1])
            items = [self._pop(pos) for _ in range(n)]
            items.reverse()
            self._push(tuple(items), pos)
        elif name == "EMPTY_LIST":
            self._push(SymList(), pos)
        elif name == "LIST":
            self._push(SymList(self._pop_mark(pos)), pos)
        elif name == "APPEND":
            item = self._pop(pos)
            self._container(SymList, pos).items.append(item)
        elif name == "APPENDS":
            items = self._pop_mark(pos)
            self._container(SymList, pos).items.extend(items)
        elif name == "EMPTY_DICT":
            self._push(SymDict(), pos)
        elif name == "DICT":
            items = self._pop_mark(pos)
            self._push(SymDict(list(zip(items[::2], items[1::2], strict=False))), pos)
        elif name == "SETITEM":
            value = self._pop(pos)
            key = self._pop(pos)
            self._container(SymDict, pos).items.append((key, value))
        elif name == "SETITEMS":
            items = self._pop_mark(pos)
            self._container(SymDict, pos).items.extend(
                zip(items[::2], items[1::2], strict=False)
            )
        elif name == "EMPTY_SET":
            self._push(SymSet(), pos)
        elif name == "ADDITEMS":
            items = self._pop_mark(pos)
            self._container(SymSet, pos).items.extend(items)
        elif name == "FROZENSET":
            self._push(("frozenset", tuple(self._pop_mark(pos))), pos)
        elif name == "REDUCE":
            args = self._pop(pos)
            func = self._pop(pos)
            self._reduce(func, args, name, pos)
        elif name == "BUILD":
            self._pop(pos)
        elif name == "NEWOBJ":
            args = self._pop(pos)
            cls = self._pop(pos)
            self._push(CallResult(cls, args), pos)
        else:
            self._limit(f"Unsupported pickle opcode {name}; analysis halted", pos)
            raise _Stop

    def _memoize(self, index: int, value: Any, pos: int) -> None:
        if len(self.memo) >= MAX_MEMO and index not in self.memo:
            self._limit("Memo size bound exceeded", pos)
            raise _Stop
        self.memo[index] = value

    def _container(self, kind: type, pos: int) -> Any:
        target = self.stack[-1] if self.stack else None
        if not isinstance(target, kind):
            self._limit(
                f"Target of container update is not a known {kind.__name__}", pos
            )
            raise _Stop
        return target

    def _reduce(self, func: Any, args: Any, op: str, pos: int) -> None:
        if isinstance(func, Global):
            if isinstance(args, tuple):
                self.invocations.append(
                    Invocation(func.qualified, args, op, pos)
                )
            else:
                self.invocations.append(
                    Invocation(func.qualified, None, op, pos)
                )
                self._limit(
                    f"Arguments to {func.qualified} are not a static tuple", pos
                )
        else:
            self._limit("REDUCE callable could not be statically resolved", pos)
        self._push(CallResult(func, args), pos)
