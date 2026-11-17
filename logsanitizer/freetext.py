"""Free-text scanning for credentials, identifiers and combined info."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
PHONE_RE = re.compile(r"(?<!\d)1[3-9]\d{9}(?!\d)")
ID_CARD_RE = re.compile(r"(?<![0-9A-Za-z])\d{17}[\dXx](?![0-9A-Za-z])")
CREDIT_CARD_RE = re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)")
JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}")
ASSIGNMENT_RE = re.compile(
    r"(?i)\b(password|passwd|pwd|secret|api[_-]?key|access[_-]?token|"
    r"auth[_-]?token|session[_-]?token|private[_-]?key)\b"
    r"\s*[:=]\s*"
    r"([\"']?)([^\s\"',;}{]{4,})\2"
)
BEARER_RE = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{8,}")

CONTEXT_KEYWORDS_RE = re.compile(
    r"(?i)(身份证|银行卡|密码|口令|护照|社保|"
    r"\bpassword\b|\bpasswd\b|\bid\s*card\b|\bpassport\b|\bssn\b|\bsecret\b)"
)

PATTERNS = [
    ("jwt", JWT_RE),
    ("bearer", BEARER_RE),
    ("credential_assignment", ASSIGNMENT_RE),
    ("email", EMAIL_RE),
    ("phone", PHONE_RE),
    ("id_card", ID_CARD_RE),
    ("credit_card", CREDIT_CARD_RE),
]

MASK = "[REDACTED]"


@dataclass
class Finding:
    kind: str
    count: int


@dataclass
class ScanResult:
    text: str
    findings: list = field(default_factory=list)
    needs_manual_review: bool = False
    review_reasons: list = field(default_factory=list)


def _redact_assignment(match: re.Match) -> str:
    return match.group(1) + "=" + MASK


def scan_text(text: str, combined_threshold: int = 2) -> ScanResult:
    """Redact known sensitive patterns in free text.

    Flags manual review when the text combines multiple distinct entity
    types (combined info) or mentions sensitive context keywords whose
    values do not match any known pattern.
    """
    result = ScanResult(text=text)
    counts = {}
    scrubbed = text
    for kind, pattern in PATTERNS:
        hits = pattern.findall(scrubbed)
        if not hits:
            continue
        counts[kind] = len(hits)
        if kind == "credential_assignment":
            scrubbed = pattern.sub(_redact_assignment, scrubbed)
        else:
            scrubbed = pattern.sub(MASK, scrubbed)
    result.findings = [Finding(kind=k, count=n) for k, n in sorted(counts.items())]
    result.text = scrubbed

    distinct = set(counts)
    if len(distinct) >= combined_threshold:
        result.needs_manual_review = True
        result.review_reasons.append(
            "combined_info:%s" % ",".join(sorted(distinct))
        )
    if CONTEXT_KEYWORDS_RE.search(text) and not distinct:
        result.needs_manual_review = True
        result.review_reasons.append("sensitive_context_without_pattern")
    return result
