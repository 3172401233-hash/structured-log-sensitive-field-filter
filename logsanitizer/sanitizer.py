"""Core structured-log sanitizer."""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass, field

from .audit import AuditReport
from .dupdict import DupDict, loads as _loads, dumps as _dumps
from .freetext import scan_text
from .rules import (
    Action,
    DEFAULT_ACTION_BY_SEMANTIC,
    FieldSemantics,
    PathRule,
    Semantic,
)

REDACTED = "[REDACTED]"
CIRCULAR = "[CircularReference]"
DEPTH_TRUNCATED = "[Truncated:max_depth]"
BUDGET_TRUNCATED = "[Truncated:node_budget]"
STRING_TRUNCATION_MARK = "...[truncated]"


@dataclass
class SanitizerConfig:
    path_rules: list = field(default_factory=list)
    field_semantics: FieldSemantics = field(
        default_factory=lambda: FieldSemantics({})
    )
    correlation_key: bytes = b"logsanitizer-correlation"
    audit_salt: str = "logsanitizer-audit"
    max_depth: int = 64
    max_string_length: int = 8192
    max_nodes: int = 100000
    hash_length: int = 16
    scan_all_strings: bool = False


def _type_placeholder(value):
    if isinstance(value, bool):
        return False
    if isinstance(value, int):
        return 0
    if isinstance(value, float):
        return 0.0
    if isinstance(value, str):
        return REDACTED
    if isinstance(value, list):
        return []
    if isinstance(value, tuple):
        return ()
    if isinstance(value, dict):
        return {}
    return None


def _format_path(path) -> str:
    parts = []
    for seg in path:
        if isinstance(seg, int):
            if parts:
                parts[-1] = parts[-1] + "[%d]" % seg
            else:
                parts.append("[%d]" % seg)
        else:
            parts.append(str(seg))
    return ".".join(parts) if parts else "<root>"


class Sanitizer:
    def __init__(self, config: SanitizerConfig | None = None):
        self.config = config or SanitizerConfig()
        self._rules = sorted(
            self.config.path_rules,
            key=lambda r: (r.specificity, r.action),
            reverse=True,
        )

    def sanitize(self, obj):
        report = AuditReport(salt=self.config.audit_salt)
        budget = [self.config.max_nodes]
        result = self._walk(obj, (), report, set(), budget)
        report.finalize()
        return result, report

    def sanitize_json(self, text: str):
        obj = _loads(text)
        result, report = self.sanitize(obj)
        return _dumps(result), report

    def _resolve(self, path, key, report) -> tuple:
        """Return (action, rule_or_none). Stricter action wins conflicts."""
        matched = [r for r in self._rules if r.matches(path)]
        chosen = None
        if matched:
            chosen = matched[0]
            for rival in matched[1:]:
                if rival.specificity == chosen.specificity and rival.action != chosen.action:
                    report.record_conflict(
                        _format_path(path), chosen.action.name, rival.action.name
                    )
                else:
                    break
        semantic = self.config.field_semantics.semantic_for(key)
        if semantic is not None:
            semantic_action = DEFAULT_ACTION_BY_SEMANTIC[semantic]
            if chosen is None or semantic_action > chosen.action:
                if chosen is not None:
                    report.record_conflict(
                        _format_path(path), semantic_action.name, chosen.action.name
                    )
                return semantic_action, None
        if chosen is not None:
            return chosen.action, chosen
        return Action.KEEP, None

    def _pseudonym(self, value) -> str:
        if isinstance(value, str) and value.startswith("corr:"):
            return value
        if isinstance(value, str):
            payload = value.encode("utf-8")
        else:
            payload = repr(value).encode("utf-8")
        digest = hmac.new(
            self.config.correlation_key, payload, hashlib.sha256
        ).hexdigest()
        return "corr:" + digest[: self.config.hash_length]

    def _partial(self, value, rule, path, report):
        if not isinstance(value, str):
            report.record(_format_path(path), Action.REDACT.name, value)
            return _type_placeholder(value)
        prefix = value[: rule.keep_prefix]
        suffix = value[-rule.keep_suffix:] if rule.keep_suffix else ""
        kept = len(prefix) + len(suffix)
        masked_len = max(len(value) - kept, 3)
        report.record(_format_path(path), Action.PARTIAL.name, value)
        return prefix + "*" * masked_len + suffix

    def _scan(self, value, path, report):
        if not isinstance(value, str):
            return value
        result = scan_text(value)
        if result.findings:
            report.record(_format_path(path), Action.SCAN.name, value)
        if result.needs_manual_review:
            report.record_manual_review(_format_path(path), result.review_reasons)
        return result.text

    def _apply(self, action, rule, value, path, report):
        if action is Action.REDACT:
            report.record(_format_path(path), Action.REDACT.name, value)
            return _type_placeholder(value)
        if action is Action.HASH:
            report.record(_format_path(path), Action.HASH.name, value)
            return self._pseudonym(value)
        if action is Action.PARTIAL:
            return self._partial(value, rule, path, report)
        if action is Action.SCAN:
            return self._scan(value, path, report)
        return value

    def _walk(self, obj, path, report, active, budget):
        budget[0] -= 1
        if budget[0] < 0:
            report.record_truncation(_format_path(path), "node_budget_exceeded")
            return BUDGET_TRUNCATED
        if len(path) > self.config.max_depth:
            report.record_truncation(_format_path(path), "max_depth_exceeded")
            return DEPTH_TRUNCATED

        if isinstance(obj, DupDict):
            return self._walk_dup(obj, path, report, active, budget)
        if isinstance(obj, dict):
            return self._walk_dict(obj, path, report, active, budget)
        if isinstance(obj, (list, tuple)):
            return self._walk_list(obj, path, report, active, budget)
        if isinstance(obj, str):
            if len(obj) > self.config.max_string_length:
                report.record_truncation(_format_path(path), "string_too_long")
                obj = obj[: self.config.max_string_length] + STRING_TRUNCATION_MARK
            if self.config.scan_all_strings:
                return self._scan(obj, path, report)
            return obj
        return obj

    def _enter(self, obj, path, report, active) -> bool:
        oid = id(obj)
        if oid in active:
            report.record_circular(_format_path(path))
            return False
        active.add(oid)
        return True

    def _walk_dict(self, obj, path, report, active, budget):
        if not self._enter(obj, path, report, active):
            return CIRCULAR
        try:
            out = {}
            for key, value in obj.items():
                child_path = path + (key,)
                action, rule = self._resolve(child_path, key, report)
                if action is Action.KEEP:
                    out[key] = self._walk(value, child_path, report, active, budget)
                else:
                    out[key] = self._apply(action, rule, value, child_path, report)
            return out
        finally:
            active.discard(id(obj))

    def _walk_dup(self, obj, path, report, active, budget):
        if not self._enter(obj, path, report, active):
            return CIRCULAR
        try:
            new_pairs = []
            for key, value in obj.pairs:
                child_path = path + (key,)
                action, rule = self._resolve(child_path, key, report)
                if action is Action.KEEP:
                    new_pairs.append(
                        (key, self._walk(value, child_path, report, active, budget))
                    )
                else:
                    new_pairs.append(
                        (key, self._apply(action, rule, value, child_path, report))
                    )
            out = DupDict()
            out.replace_pairs(new_pairs)
            return out
        finally:
            active.discard(id(obj))

    def _walk_list(self, obj, path, report, active, budget):
        if not self._enter(obj, path, report, active):
            return CIRCULAR
        try:
            out = []
            for index, value in enumerate(obj):
                child_path = path + (index,)
                out.append(self._walk(value, child_path, report, active, budget))
            return out
        finally:
            active.discard(id(obj))


def sanitize_json(text: str, config: SanitizerConfig | None = None):
    """Convenience helper: sanitize a JSON log string, return (json, report)."""
    return Sanitizer(config).sanitize_json(text)
