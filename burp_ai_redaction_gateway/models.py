from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True)
class HttpRequest:
    method: str
    url: str
    headers: dict[str, str] = field(default_factory=dict)
    body: Any = ""


@dataclass(frozen=True)
class HttpResponse:
    status: int
    headers: dict[str, str] = field(default_factory=dict)
    body: Any = ""


@dataclass(frozen=True)
class RawEvent:
    raw_id: str
    request: HttpRequest
    response: HttpResponse
    source: str = "input"


@dataclass(frozen=True)
class SanitizedEvent:
    evidence_id: str
    raw_reference: str
    raw_values_included: bool
    request: dict[str, Any]
    response: dict[str, Any]
    redaction: dict[str, Any]
    signals: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

