"""Irreversible audit summary for sanitizing runs."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field


def _canonical(value) -> str:
    try:
        return json.dumps(value, sort_keys=True, ensure_ascii=False, default=str)
    except (TypeError, ValueError):
        return repr(value)


@dataclass
class AuditEntry:
    path: str
    action: str
    value_digest: str


@dataclass
class AuditReport:
    """Collects per-field digests and aggregate statistics.

    Digests are salted SHA-256 hashes; the original values cannot be
    recovered from the report.
    """

    salt: str
    entries: list = field(default_factory=list)
    conflicts: list = field(default_factory=list)
    manual_review: list = field(default_factory=list)
    truncations: list = field(default_factory=list)
    circular_references: list = field(default_factory=list)
    action_counts: dict = field(default_factory=dict)
    log_digest: str = ""

    def digest_value(self, value) -> str:
        payload = self.salt + "\x00" + _canonical(value)
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]

    def record(self, path: str, action: str, original) -> None:
        self.entries.append(
            AuditEntry(path=path, action=action, value_digest=self.digest_value(original))
        )
        self.action_counts[action] = self.action_counts.get(action, 0) + 1

    def record_conflict(self, path: str, chosen: str, discarded: str) -> None:
        self.conflicts.append(
            {"path": path, "chosen": chosen, "discarded": discarded}
        )

    def record_manual_review(self, path: str, reasons: list) -> None:
        self.manual_review.append({"path": path, "reasons": list(reasons)})

    def record_truncation(self, path: str, reason: str) -> None:
        self.truncations.append({"path": path, "reason": reason})

    def record_circular(self, path: str) -> None:
        self.circular_references.append(path)

    def finalize(self) -> None:
        chain = hashlib.sha256()
        chain.update(self.salt.encode("utf-8"))
        for entry in self.entries:
            chain.update(entry.path.encode("utf-8"))
            chain.update(b"\x00")
            chain.update(entry.action.encode("utf-8"))
            chain.update(b"\x00")
            chain.update(entry.value_digest.encode("utf-8"))
            chain.update(b"\x00")
        self.log_digest = chain.hexdigest()

    def to_dict(self) -> dict:
        return {
            "entries": [vars(e) for e in self.entries],
            "conflicts": list(self.conflicts),
            "manual_review": list(self.manual_review),
            "truncations": list(self.truncations),
            "circular_references": list(self.circular_references),
            "action_counts": dict(self.action_counts),
            "log_digest": self.log_digest,
        }
