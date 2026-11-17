"""Duplicate-key preserving JSON object and helpers.

``json.loads`` silently drops all but the last value of a duplicated key,
which would let a sensitive value survive sanitizing. ``DupDict`` keeps
every pair so the sanitizer can process all of them, and ``dumps`` emits
them back faithfully.
"""

from __future__ import annotations

import json


class DupDict(dict):
    """A dict that also retains the full ordered pair list."""

    __slots__ = ("pairs",)

    def __init__(self, pairs=()):
        super().__init__()
        self.pairs = []
        for key, value in pairs:
            self.pairs.append((key, value))
            super().__setitem__(key, value)

    def replace_pairs(self, new_pairs) -> None:
        self.pairs = list(new_pairs)
        super().clear()
        for key, value in self.pairs:
            super().__setitem__(key, value)


def loads(text: str) -> object:
    return json.loads(text, object_pairs_hook=DupDict)


def _dump(obj, ensure_ascii: bool) -> str:
    if isinstance(obj, DupDict):
        inner = ",".join(
            json.dumps(key, ensure_ascii=ensure_ascii) + ":" + _dump(value, ensure_ascii)
            for key, value in obj.pairs
        )
        return "{" + inner + "}"
    if isinstance(obj, dict):
        inner = ",".join(
            json.dumps(key, ensure_ascii=ensure_ascii) + ":" + _dump(value, ensure_ascii)
            for key, value in obj.items()
        )
        return "{" + inner + "}"
    if isinstance(obj, (list, tuple)):
        return "[" + ",".join(_dump(item, ensure_ascii) for item in obj) + "]"
    return json.dumps(obj, ensure_ascii=ensure_ascii)


def dumps(obj, ensure_ascii: bool = False) -> str:
    return _dump(obj, ensure_ascii)
