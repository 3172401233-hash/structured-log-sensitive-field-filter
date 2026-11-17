"""Path rules and field semantics for the sanitizer."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field


class Action(enum.IntEnum):
    """Sanitizing action, ordered by strictness (higher wins conflicts)."""

    KEEP = 0
    HASH = 1
    PARTIAL = 2
    SCAN = 3
    REDACT = 4


class Semantic(enum.Enum):
    """Field semantics used when no explicit path rule matches."""

    CREDENTIAL = "credential"
    TOKEN = "token"
    PII = "pii"
    CORRELATION = "correlation"
    FREE_TEXT = "free_text"


DEFAULT_ACTION_BY_SEMANTIC = {
    Semantic.CREDENTIAL: Action.REDACT,
    Semantic.TOKEN: Action.REDACT,
    Semantic.PII: Action.REDACT,
    Semantic.CORRELATION: Action.HASH,
    Semantic.FREE_TEXT: Action.SCAN,
}


def _split_pattern(pattern: str) -> tuple:
    if not pattern or not pattern.strip():
        raise ValueError("empty path pattern")
    parts = []
    for raw in pattern.strip().split("."):
        if raw == "":
            raise ValueError("empty path segment in %r" % pattern)
        if raw == "*" or raw == "**":
            parts.append(raw)
            continue
        if raw.endswith("[*]"):
            parts.append(raw[:-3])
            parts.append("*")
            continue
        parts.append(raw)
    return tuple(parts)


def _segment_matches(pattern_seg, path_seg) -> bool:
    if pattern_seg == "*":
        return True
    if isinstance(path_seg, int):
        return pattern_seg == str(path_seg)
    return pattern_seg == path_seg


def _match_segments(pattern: tuple, path: tuple) -> bool:
    if not pattern:
        return not path
    head = pattern[0]
    if head == "**":
        if _match_segments(pattern[1:], path):
            return True
        return bool(path) and _match_segments(pattern, path[1:])
    if not path:
        return False
    return _segment_matches(head, path[0]) and _match_segments(pattern[1:], path[1:])


@dataclass(frozen=True)
class PathRule:
    """A rule binding a path pattern to an action.

    Pattern syntax: dot-separated segments; ``*`` matches any single key or
    array index, ``**`` matches any number of segments, ``name[*]`` matches
    every element of an array field.
    """

    pattern: str
    action: Action
    keep_prefix: int = 0
    keep_suffix: int = 0
    reason: str = ""
    _segments: tuple = field(init=False, repr=False, compare=False)

    def __post_init__(self):
        object.__setattr__(self, "_segments", _split_pattern(self.pattern))
        if self.action is Action.PARTIAL:
            if self.keep_prefix < 0 or self.keep_suffix < 0:
                raise ValueError("keep_prefix/keep_suffix must be >= 0")
            if self.keep_prefix == 0 and self.keep_suffix == 0:
                raise ValueError("PARTIAL rule must keep a prefix or suffix")

    def matches(self, path: tuple) -> bool:
        return _match_segments(self._segments, path)

    @property
    def specificity(self) -> tuple:
        literal = sum(1 for s in self._segments if s not in ("*", "**"))
        wildcards = sum(1 for s in self._segments if s in ("*", "**"))
        return (literal, -wildcards, len(self._segments))


@dataclass
class FieldSemantics:
    """Maps field names (any depth) to their semantic category."""

    mapping: dict

    def __post_init__(self):
        normalized = {}
        for name, semantic in self.mapping.items():
            if not isinstance(semantic, Semantic):
                semantic = Semantic(semantic)
            normalized[name] = semantic
        self.mapping = normalized

    def semantic_for(self, key) -> "Semantic | None":
        if isinstance(key, str):
            return self.mapping.get(key)
        return None
