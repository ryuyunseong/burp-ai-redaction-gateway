from __future__ import annotations

import base64
import json
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path


OUTPUT_PATH = Path("local_only") / "real_burp_history_sample.xml"


@dataclass(frozen=True)
class SampleItem:
    method: str
    url: str
    host: str
    path: str
    status: int
    mimetype: str
    request: str
    response: str
    host_ip: str = "203.0.113.10"
    port: int = 443
    protocol: str = "https"


def main() -> int:
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    root = ET.Element("items")
    for index, item in enumerate(_sample_items(), start=1):
        _append_item(root, index, item)

    tree = ET.ElementTree(root)
    ET.indent(tree, space="  ")
    tree.write(OUTPUT_PATH, encoding="utf-8", xml_declaration=True)
    print(f"Wrote safe synthetic Burp XML sample: {OUTPUT_PATH}")
    return 0


def _append_item(root: ET.Element, index: int, item: SampleItem) -> None:
    element = ET.SubElement(root, "item")
    ET.SubElement(element, "time").text = f"Thu Jun 04 07:{index:02d}:00 KST 2026"
    ET.SubElement(element, "url").text = item.url
    host = ET.SubElement(element, "host", {"ip": item.host_ip})
    host.text = item.host
    ET.SubElement(element, "port").text = str(item.port)
    ET.SubElement(element, "protocol").text = item.protocol
    ET.SubElement(element, "method").text = item.method
    ET.SubElement(element, "path").text = item.path
    ET.SubElement(element, "extension").text = item.mimetype.lower()
    request = ET.SubElement(element, "request", {"base64": "true"})
    request.text = _b64(item.request)
    ET.SubElement(element, "status").text = str(item.status)
    ET.SubElement(element, "responselength").text = str(len(item.response.encode("utf-8")))
    ET.SubElement(element, "mimetype").text = item.mimetype
    response = ET.SubElement(element, "response", {"base64": "true"})
    response.text = _b64(item.response)


def _sample_items() -> list[SampleItem]:
    fake_jwt = (
        "FAKE_eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "FAKE_eyJzdWIiOiJzYWZlLXN5bnRoZXRpYy11c2VyIn0."
        "FAKE_SIGNATURE_FOR_SAFE_SAMPLE"
    )
    dummy_entropy = "DUMMY_QWERTY1234567890ASDFGHJKLZXCVBNM9876543210"
    return [
        SampleItem(
            method="GET",
            url=f"https://safe-api.example.test/api/users/1001/profile?sessionToken={fake_jwt}",
            host="safe-api.example.test",
            path="/api/users/1001/profile",
            status=200,
            mimetype="JSON",
            request=_http_request(
                "GET",
                f"/api/users/1001/profile?sessionToken={fake_jwt}",
                "safe-api.example.test",
                [
                    "Authorization: Bearer FAKE_BEARER_TOKEN_FOR_SAFE_SAMPLE_1001",
                    "Cookie: JSESSIONID=FAKE_COOKIE_VALUE_1001; theme=demo",
                    "Accept: application/json",
                ],
            ),
            response=_http_response(
                200,
                "OK",
                [
                    "Content-Type: application/json",
                    "Set-Cookie: api_session=FAKE_RESPONSE_COOKIE_1001; HttpOnly; SameSite=None",
                ],
                {
                    "userId": 1001,
                    "email": "safe-user@example.test",
                    "phone": "010-1234-5678",
                    "role": "user",
                },
            ),
        ),
        SampleItem(
            method="POST",
            url="https://safe-api.example.test/api/orders",
            host="safe-api.example.test",
            path="/api/orders",
            status=201,
            mimetype="JSON",
            request=_http_request(
                "POST",
                "/api/orders",
                "safe-api.example.test",
                [
                    "Authorization: Bearer FAKE_BEARER_TOKEN_FOR_SAFE_SAMPLE_ORDERS",
                    "Content-Type: application/json",
                ],
                {
                    "accountNumber": "1234567890123456",
                    "csrf": "FAKE_CSRF_TOKEN_FOR_SAFE_SAMPLE",
                    "notes": dummy_entropy,
                    "amount": 12000,
                },
            ),
            response=_http_response(
                201,
                "Created",
                ["Content-Type: application/json"],
                {"orderId": "ABCDEF1234567890", "status": "created"},
            ),
        ),
        SampleItem(
            method="GET",
            url="https://safe-web.example.test/settings",
            host="safe-web.example.test",
            path="/settings",
            status=200,
            mimetype="HTML",
            request=_http_request(
                "GET",
                "/settings",
                "safe-web.example.test",
                [
                    "Cookie: JSESSIONID=FAKE_HTML_COOKIE_VALUE",
                    "Accept: text/html",
                ],
            ),
            response=_http_response(
                200,
                "OK",
                ["Content-Type: text/html"],
                (
                    "<html><head><title>Safe Settings</title></head><body>"
                    "<form><input type=\"hidden\" name=\"csrf\" value=\"FAKE_HIDDEN_CSRF\">"
                    "<input type=\"email\" name=\"email\" value=\"safe-html-user@example.test\">"
                    "</form></body></html>"
                ),
            ),
        ),
        SampleItem(
            method="GET",
            url="http://192.168.56.25/internal/admin/404",
            host="192.168.56.25",
            host_ip="192.168.56.25",
            path="/internal/admin/404",
            status=404,
            mimetype="JSON",
            port=80,
            protocol="http",
            request=_http_request(
                "GET",
                "/internal/admin/404",
                "192.168.56.25",
                [
                    "Authorization: Bearer FAKE_INTERNAL_BEARER_TOKEN",
                    "Cookie: adminsid=FAKE_INTERNAL_COOKIE_VALUE",
                    "Accept: application/json",
                ],
            ),
            response=_http_response(
                404,
                "Not Found",
                ["Content-Type: application/json"],
                {"error": "not_found", "requestId": "DUMMY_REQUEST_ID_404"},
            ),
        ),
        SampleItem(
            method="GET",
            url="https://safe-api.example.test/api/reports/403",
            host="safe-api.example.test",
            path="/api/reports/403",
            status=403,
            mimetype="JSON",
            request=_http_request(
                "GET",
                "/api/reports/403",
                "safe-api.example.test",
                [
                    "Authorization: Bearer FAKE_FORBIDDEN_BEARER_TOKEN",
                    "Accept: application/json",
                ],
            ),
            response=_http_response(
                403,
                "Forbidden",
                ["Content-Type: application/json"],
                {"error": "forbidden", "email": "forbidden-user@example.test"},
            ),
        ),
    ]


def _http_request(
    method: str,
    path: str,
    host: str,
    headers: list[str],
    body: dict[str, object] | str | None = None,
) -> str:
    body_text = _body_text(body)
    lines = [f"{method} {path} HTTP/1.1", f"Host: {host}", *headers]
    if body_text:
        lines.append(f"Content-Length: {len(body_text.encode('utf-8'))}")
    return "\r\n".join(lines) + "\r\n\r\n" + body_text


def _http_response(status: int, reason: str, headers: list[str], body: dict[str, object] | str | None) -> str:
    body_text = _body_text(body)
    lines = [f"HTTP/1.1 {status} {reason}", *headers]
    if body_text:
        lines.append(f"Content-Length: {len(body_text.encode('utf-8'))}")
    return "\r\n".join(lines) + "\r\n\r\n" + body_text


def _body_text(body: dict[str, object] | str | None) -> str:
    if body is None:
        return ""
    if isinstance(body, str):
        return body
    return json.dumps(body, separators=(",", ":"))


def _b64(value: str) -> str:
    return base64.b64encode(value.encode("utf-8")).decode("ascii")


if __name__ == "__main__":
    raise SystemExit(main())

