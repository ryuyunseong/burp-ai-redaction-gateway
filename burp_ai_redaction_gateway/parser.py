from __future__ import annotations

import base64
import json
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .models import HttpRequest, HttpResponse, RawEvent


def load_events(path: Path) -> list[RawEvent]:
    suffix = path.suffix.lower()
    if suffix == ".xml":
        return _load_burp_xml(path)

    text = path.read_text(encoding="utf-8")
    data = json.loads(text)
    if isinstance(data, dict) and "log" in data:
        return _load_har(data)
    if isinstance(data, dict):
        items = data.get("events", [])
    elif isinstance(data, list):
        items = data
    else:
        raise ValueError("Unsupported input format")
    return [_fixture_event(item, index) for index, item in enumerate(items, start=1)]


def _fixture_event(item: dict[str, Any], index: int) -> RawEvent:
    request = item.get("request", {})
    response = item.get("response", {})
    return RawEvent(
        raw_id=str(item.get("id") or item.get("raw_id") or f"input-{index:04d}"),
        request=HttpRequest(
            method=str(request.get("method", "GET")).upper(),
            url=str(request.get("url", "")),
            headers=_headers_to_dict(request.get("headers", {})),
            body=request.get("body", ""),
        ),
        response=HttpResponse(
            status=int(response.get("status", 0)),
            headers=_headers_to_dict(response.get("headers", {})),
            body=response.get("body", ""),
        ),
        source="fixture_json",
    )


def _load_har(data: dict[str, Any]) -> list[RawEvent]:
    events: list[RawEvent] = []
    entries = data.get("log", {}).get("entries", [])
    for index, entry in enumerate(entries, start=1):
        request = entry.get("request", {})
        response = entry.get("response", {})
        events.append(
            RawEvent(
                raw_id=f"har-{index:04d}",
                request=HttpRequest(
                    method=str(request.get("method", "GET")).upper(),
                    url=str(request.get("url", "")),
                    headers=_headers_to_dict(request.get("headers", [])),
                    body=request.get("postData", {}).get("text", ""),
                ),
                response=HttpResponse(
                    status=int(response.get("status", 0)),
                    headers=_headers_to_dict(response.get("headers", [])),
                    body=response.get("content", {}).get("text", ""),
                ),
                source="har",
            )
        )
    return events


def _load_burp_xml(path: Path) -> list[RawEvent]:
    root = ET.parse(path).getroot()
    events: list[RawEvent] = []
    for index, item in enumerate(root.findall(".//item"), start=1):
        fallback_url = _node_text(item, "url")
        fallback_method = _node_text(item, "method") or "GET"
        request_text = _decode_http_message(item.find("request"))
        response_text = _decode_http_message(item.find("response"))
        request = _parse_request_message(request_text, fallback_url, fallback_method)
        response = _parse_response_message(response_text)
        events.append(
            RawEvent(
                raw_id=f"burp-history-{index:04d}",
                request=request,
                response=response,
                source="burp_xml",
            )
        )
    return events


def _parse_request_message(message: str, fallback_url: str, fallback_method: str) -> HttpRequest:
    if not message.strip():
        return HttpRequest(method=fallback_method.upper(), url=fallback_url, headers={}, body="")
    head, body = _split_http_message(message)
    lines = head.splitlines()
    method = fallback_method.upper()
    url = fallback_url
    headers: dict[str, str] = {}
    if lines:
        parts = lines[0].split()
        if len(parts) >= 2:
            method = parts[0].upper()
            url = _absolute_url(parts[1], fallback_url)
        headers = _parse_header_lines(lines[1:])
    if not url and "Host" in headers:
        url = f"https://{headers['Host']}/"
    return HttpRequest(method=method, url=url, headers=headers, body=body)


def _parse_response_message(message: str) -> HttpResponse:
    if not message.strip():
        return HttpResponse(status=0, headers={}, body="")
    head, body = _split_http_message(message)
    lines = head.splitlines()
    status = 0
    if lines:
        parts = lines[0].split()
        if len(parts) >= 2 and parts[1].isdigit():
            status = int(parts[1])
    return HttpResponse(status=status, headers=_parse_header_lines(lines[1:]), body=body)


def _split_http_message(message: str) -> tuple[str, str]:
    normalized = message.replace("\r\n", "\n")
    if "\n\n" not in normalized:
        return normalized, ""
    head, body = normalized.split("\n\n", 1)
    return head, body


def _parse_header_lines(lines: list[str]) -> dict[str, str]:
    headers: dict[str, str] = {}
    for line in lines:
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        headers[name.strip()] = value.strip()
    return headers


def _absolute_url(value: str, fallback_url: str) -> str:
    if value.startswith(("http://", "https://")):
        return value
    if not fallback_url:
        return value
    split = urlsplit(fallback_url)
    if not split.scheme or not split.netloc:
        return value
    if value.startswith("/"):
        return f"{split.scheme}://{split.netloc}{value}"
    return fallback_url


def _decode_http_message(node: ET.Element | None) -> str:
    if node is None or node.text is None:
        return ""
    text = node.text.strip()
    if node.attrib.get("base64", "").lower() == "true":
        return base64.b64decode(text).decode("utf-8", errors="replace")
    return text


def _node_text(node: ET.Element, name: str) -> str:
    child = node.find(name)
    if child is None or child.text is None:
        return ""
    return child.text.strip()


def _headers_to_dict(headers: Any) -> dict[str, str]:
    if isinstance(headers, dict):
        return {str(key): str(value) for key, value in headers.items()}
    if isinstance(headers, list):
        result: dict[str, str] = {}
        for item in headers:
            if isinstance(item, dict) and "name" in item:
                result[str(item["name"])] = str(item.get("value", ""))
        return result
    return {}

