"""CVSS v3.0/v3.1 base score from a vector string, and severity buckets."""

from __future__ import annotations

import math
from dataclasses import dataclass

from .errors import InputError

_BASE: dict[str, dict[str, float]] = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "PR": {"N": 0.85, "L": 0.62, "H": 0.27},
    "UI": {"N": 0.85, "R": 0.62},
    "S": {"U": 0.0, "C": 0.0},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}
_TEMPORAL_ENV = {
    "E": "XUPFH",
    "RL": "XOTWU",
    "RC": "XURC",
    "CR": "XLMH",
    "IR": "XLMH",
    "AR": "XLMH",
    "MAV": "XNALP",
    "MAC": "XLH",
    "MPR": "XNLH",
    "MUI": "XNR",
    "MS": "XUC",
    "MC": "XNLH",
    "MI": "XNLH",
    "MA": "XNLH",
}
SEVERITIES = ("NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL")


@dataclass(frozen=True)
class Cvss:
    """A parsed CVSS v3 vector and its base score."""

    vector: str
    version: str
    base_score: float


def roundup_31(value: float) -> float:
    """CVSS 3.1 Roundup: smallest one-decimal number >= value, float-safe."""
    as_int = round(value * 100000)
    if as_int % 10000 == 0:
        return as_int / 100000.0
    return (math.floor(as_int / 10000) + 1) / 10.0


def roundup_30(value: float) -> float:
    """CVSS 3.0 round up to one decimal."""
    return math.ceil(value * 10) / 10


def parse_v3(vector: str) -> dict[str, str]:
    """Split and validate a CVSS:3.x vector into metric -> value."""
    parts = vector.strip().split("/")
    if parts[0] not in ("CVSS:3.0", "CVSS:3.1"):
        raise InputError(f"not a CVSS v3 vector: {vector!r}")
    metrics: dict[str, str] = {}
    for part in parts[1:]:
        key, sep, val = part.partition(":")
        if not sep or not val:
            raise InputError(f"malformed CVSS metric {part!r} in {vector!r}")
        if key in metrics:
            raise InputError(f"duplicate CVSS metric {key} in {vector!r}")
        allowed = _BASE[key].keys() if key in _BASE else _TEMPORAL_ENV.get(key, "")
        if val not in allowed or len(val) != 1:
            raise InputError(f"invalid CVSS value {key}:{val} in {vector!r}")
        metrics[key] = val
    missing = [k for k in _BASE if k not in metrics]
    if missing:
        raise InputError(f"CVSS vector {vector!r} lacks base metrics {', '.join(missing)}")
    return metrics


def score_v3(vector: str) -> Cvss:
    """Compute the CVSS v3.0/v3.1 base score of a vector."""
    m = parse_v3(vector)
    version = vector.strip()[5:8]
    changed = m["S"] == "C"
    iss = 1 - (1 - _BASE["C"][m["C"]]) * (1 - _BASE["I"][m["I"]]) * (1 - _BASE["A"][m["A"]])
    impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if changed else 6.42 * iss
    pr = _PR_CHANGED[m["PR"]] if changed else _BASE["PR"][m["PR"]]
    exploitability = 8.22 * _BASE["AV"][m["AV"]] * _BASE["AC"][m["AC"]] * pr * _BASE["UI"][m["UI"]]
    roundup = roundup_31 if version == "3.1" else roundup_30
    if impact <= 0:
        score = 0.0
    elif changed:
        score = roundup(min(1.08 * (impact + exploitability), 10))
    else:
        score = roundup(min(impact + exploitability, 10))
    return Cvss(vector=vector.strip(), version=version, base_score=score)


def severity_of(score: float) -> str:
    """Qualitative CVSS v3 rating of a base score."""
    if not 0.0 <= score <= 10.0:
        raise InputError(f"CVSS score {score} is outside 0..10")
    if score == 0.0:
        return "NONE"
    if score < 4.0:
        return "LOW"
    if score < 7.0:
        return "MEDIUM"
    if score < 9.0:
        return "HIGH"
    return "CRITICAL"


def normalize_label(label: str | None) -> str | None:
    """Map a scanner's severity word onto the CVSS rating names, or None."""
    if not label:
        return None
    word = label.strip().upper()
    if word == "MODERATE":
        word = "MEDIUM"
    if word == "NEGLIGIBLE":
        word = "LOW"
    return word if word in SEVERITIES else None
