from __future__ import annotations

import json
import re
from collections import Counter
from typing import Any
from urllib.parse import parse_qs, urlsplit

from .models import RawEvent, SanitizedEvent
from .policy import RedactionPolicy, load_policy
from .scanner import (
    DOMAIN_RE,
    EMAIL_RE,
    FINANCIAL_RE,
    JWT_RE,
    KOR_RRN_RE,
    PHONE_RE,
    has_high_entropy_secret,
    scan_text,
)


UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
HASH_SEGMENT_RE = re.compile(r"^[A-Fa-f0-9]{16,}$")
SENSITIVE_NAME_RE = re.compile(
    r"(?i)(password|passwd|pwd|token|secret|api[_-]?key|apikey|csrf|session|cookie|auth|credential|nonce|state|code|email|phone|rrn|account|card|key)"
)
IDENTIFIER_NAME_RE = re.compile(r"(?i)(id|uuid|user|account|member|customer|order|invoice)")
URL_CONTEXT_NAME_RE = re.compile(r"(?i)(url|uri|redirect|callback|domain|host|origin|referer|location)")
SAFE_OUTPUT_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.:-]{0,63}$")
SAFE_PATH_SEGMENT_RE = re.compile(r"^[A-Za-z0-9_-]{1,48}$")
MAX_DIAGNOSTICS_PER_EVENT = 80

REQUEST_VALUE_HEADERS = {
    "accept",
    "content-type",
    "x-requested-with",
}
RESPONSE_VALUE_HEADERS = {
    "content-type",
    "cache-control",
    "strict-transport-security",
    "x-content-type-options",
    "content-security-policy",
    "x-frame-options",
    "access-control-allow-origin",
    "access-control-allow-credentials",
    "allow",
}


class Redactor:
    def __init__(self, policy: RedactionPolicy | None = None) -> None:
        self.policy = policy or load_policy(None)
        self._host_aliases: dict[str, str] = {}
        self._private_ip_aliases: dict[str, str] = {}

    def sanitize_event(self, event: RawEvent, index: int) -> SanitizedEvent:
        evidence_id = f"EV-{index:04d}"
        counters: Counter[str] = Counter()
        diagnostics: list[dict[str, str]] = []
        request_url = self._sanitize_url(event.request.url, counters, diagnostics, evidence_id, event.source)
        request_headers, request_header_signals = self._sanitize_headers(
            event.request.headers, "request", counters, diagnostics, evidence_id, event.source
        )
        response_headers, response_header_signals = self._sanitize_headers(
            event.response.headers, "response", counters, diagnostics, evidence_id, event.source
        )
        request_body, request_body_signals = self._body_schema(event.request.body, "request", counters)
        response_body, response_body_signals = self._body_schema(event.response.body, "response", counters, event.response.status)
        _diagnose_body_fields(diagnostics, evidence_id, "request.body_schema", event.source, request_body_signals["sensitive_fields"])
        _diagnose_body_fields(diagnostics, evidence_id, "response.body_schema", event.source, response_body_signals["sensitive_fields"])

        auth_observed = request_header_signals["auth_observed"] or bool(request_url["sensitive_query_params"])
        identifier_observed = request_url["identifier_observed"]
        user_specific_response = any(
            field.lower().endswith(("userid", "user_id", ".id", ".email", ".accountid", "account_id"))
            for field in response_body_signals["schema_fields"]
        )

        signals = {
            "method": event.request.method.upper(),
            "host_alias": request_url["host_alias"],
            "path_template": request_url["path_template"],
            "query_param_names": sorted(request_url["query_schema"].keys()),
            "identifier_observed": identifier_observed,
            "auth_observed": auth_observed,
            "status": event.response.status,
            "content_type": _header_value(response_headers, "Content-Type"),
            "response_security_headers": response_header_signals["security_headers"],
            "set_cookie_security": response_header_signals["set_cookie_security"],
            "cors": response_header_signals["cors"],
            "cache_control": _header_value(response_headers, "Cache-Control"),
            "allow_methods": _header_value(response_headers, "Allow"),
            "response_sensitive_fields": response_body_signals["sensitive_fields"],
            "user_specific_response": user_specific_response,
            "error_snippet_present": response_body_signals["snippet_present"],
        }

        return SanitizedEvent(
            evidence_id=evidence_id,
            raw_reference=f"LOCAL_ONLY:{event.raw_id}",
            raw_values_included=False,
            request={
                "method": event.request.method.upper(),
                "host": request_url["host_alias"],
                "path_template": request_url["path_template"],
                "headers": request_headers,
                "query_schema": request_url["query_schema"],
                "body_schema": request_body,
            },
            response={
                "status": event.response.status,
                "headers": response_headers,
                "body_schema": response_body,
            },
            redaction={
                "strategy": "allowlist_schema_only",
                "counts": dict(sorted(counters.items())),
                "diagnostics": diagnostics[:MAX_DIAGNOSTICS_PER_EVENT],
                "diagnostics_truncated": len(diagnostics) > MAX_DIAGNOSTICS_PER_EVENT,
            },
            signals=signals,
        )

    def _sanitize_url(
        self,
        url: str,
        counters: Counter[str],
        diagnostics: list[dict[str, str]],
        event_id: str,
        source_kind: str,
    ) -> dict[str, Any]:
        split = urlsplit(url)
        host = split.hostname or "unknown-host"
        host_alias = self._host_alias(host)
        if host != host_alias:
            counters["host_alias"] += 1
            _add_diagnostic(diagnostics, "domain_or_host_alias", event_id, _url_field_path(source_kind), source_kind)
        path_template, path_identifier = _template_path(split.path or "/", counters)
        query_schema: dict[str, Any] = {}
        sensitive_query_params: list[str] = []
        query_identifier = False
        for name, values in parse_qs(split.query, keep_blank_values=True).items():
            safe_name = _safe_output_name(name, counters, "query_param")
            if safe_name != name:
                _add_diagnostic(diagnostics, "unsafe_query_name", event_id, f"request.query.{safe_name}", source_kind)
            query_schema[safe_name] = {
                "type": _infer_values_type(values),
                "sample_removed": True,
                "transformation": "schema_only",
            }
            if SENSITIVE_NAME_RE.search(name):
                counters["query_sensitive_value"] += len(values) or 1
                sensitive_query_params.append(safe_name)
                query_schema[safe_name]["transformation"] = "redacted_sensitive_parameter"
                _add_diagnostic(diagnostics, "sensitive_query_value", event_id, f"request.query.{safe_name}", source_kind)
            elif URL_CONTEXT_NAME_RE.search(name):
                counters["query_url_reference"] += len(values) or 1
                query_schema[safe_name]["transformation"] = "redacted_url_reference"
                _add_diagnostic(diagnostics, "url_reference_query_value", event_id, f"request.query.{safe_name}", source_kind)
            if query_schema[safe_name]["type"] == "secret_redacted":
                _add_diagnostic(diagnostics, "high_entropy_or_secret_query_value", event_id, f"request.query.{safe_name}", source_kind)
            if IDENTIFIER_NAME_RE.search(name) or query_schema[safe_name]["type"] in {"integer", "uuid"}:
                query_identifier = True
                query_schema[safe_name]["identifier_candidate"] = True
        return {
            "host_alias": host_alias,
            "path_template": path_template,
            "query_schema": query_schema,
            "sensitive_query_params": sensitive_query_params,
            "identifier_observed": path_identifier or query_identifier,
        }

    def _host_alias(self, host: str) -> str:
        normalized = host.strip().strip("[]").lower()
        if not normalized or normalized == "unknown-host":
            return "unknown-host"
        if _is_private_ip(normalized):
            if normalized not in self._private_ip_aliases:
                self._private_ip_aliases[normalized] = f"private_ip_{len(self._private_ip_aliases) + 1:03d}"
            return self._private_ip_aliases[normalized]
        if normalized not in self._host_aliases:
            self._host_aliases[normalized] = f"host_{len(self._host_aliases) + 1:03d}"
        return self._host_aliases[normalized]

    def _sanitize_headers(
        self,
        headers: dict[str, str],
        context: str,
        counters: Counter[str],
        diagnostics: list[dict[str, str]],
        event_id: str,
        source_kind: str,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        sanitized: dict[str, Any] = {}
        auth_observed = False
        security_headers: dict[str, bool] = {}
        set_cookie_security: list[dict[str, Any]] = []
        cors: dict[str, Any] = {}

        allowed_headers = REQUEST_VALUE_HEADERS if context == "request" else RESPONSE_VALUE_HEADERS
        for name, value in headers.items():
            canonical = _canonical_header(name)
            lower = name.lower()
            if lower == "authorization":
                auth_observed = True
                scheme = value.split()[0].upper() if value.split() else "PRESENT"
                sanitized[canonical] = f"<REDACTED:{scheme}>"
                counters["authorization_header"] += 1
                _add_diagnostic(diagnostics, "authorization_header", event_id, f"{context}.headers.{canonical}", source_kind)
                continue
            if lower == "cookie":
                auth_observed = True
                sanitized[canonical] = _redact_cookie_header(value, counters)
                _add_diagnostic(diagnostics, "cookie_header", event_id, f"{context}.headers.{canonical}", source_kind)
                continue
            if lower == "set-cookie":
                cookie_info = self._redact_set_cookie(value, counters)
                sanitized[canonical] = cookie_info["summary"]
                set_cookie_security.append(cookie_info["security"])
                _add_diagnostic(diagnostics, "set_cookie_header", event_id, f"{context}.headers.{canonical}", source_kind)
                continue
            if lower == "host" and context == "request":
                sanitized[canonical] = self._host_header_alias(value, counters)
                _add_diagnostic(diagnostics, "host_header_alias", event_id, f"{context}.headers.{canonical}", source_kind)
                continue
            if lower in {"origin", "referer"} and context == "request":
                sanitized[canonical] = self._sanitize_url_reference(value, counters)
                _add_diagnostic(diagnostics, "url_reference_header", event_id, f"{context}.headers.{canonical}", source_kind)
                continue
            if lower == "location" and context == "response":
                sanitized[canonical] = self._sanitize_url_reference(value, counters)
                _add_diagnostic(diagnostics, "url_reference_header", event_id, f"{context}.headers.{canonical}", source_kind)
                continue
            if SENSITIVE_NAME_RE.search(name):
                sanitized[canonical] = "<REDACTED:HEADER>"
                counters["sensitive_header"] += 1
                _add_diagnostic(diagnostics, "sensitive_header", event_id, f"{context}.headers.{canonical}", source_kind)
                continue
            if lower in allowed_headers:
                sanitized[canonical] = self._sanitize_allowed_header(lower, value, counters)
                if lower.startswith("access-control"):
                    cors[canonical] = sanitized[canonical]
                if context == "response":
                    security_headers[canonical] = True
                continue
            sanitized[canonical] = "<OMITTED>"

        if context == "response":
            for header in [
                "Strict-Transport-Security",
                "X-Content-Type-Options",
                "Content-Security-Policy",
                "X-Frame-Options",
            ]:
                security_headers.setdefault(header, False)

        return sanitized, {
            "auth_observed": auth_observed,
            "security_headers": security_headers,
            "set_cookie_security": set_cookie_security,
            "cors": cors,
        }

    def _host_header_alias(self, value: str, counters: Counter[str]) -> str:
        host = value.split(":", 1)[0].strip()
        counters["host_header_alias"] += 1
        return self._host_alias(host)

    def _sanitize_url_reference(self, value: str, counters: Counter[str]) -> str:
        text = value.strip()
        split = urlsplit(text)
        if split.hostname:
            counters["url_reference_alias"] += 1
            path_template, _ = _template_path(split.path or "/", counters)
            query = _templated_query(split.query, counters)
            return f"{split.scheme or 'https'}://{self._host_alias(split.hostname)}{path_template}{query}"
        if text.startswith("/"):
            path_template, _ = _template_path(split.path or "/", counters)
            return f"{path_template}{_templated_query(split.query, counters)}"
        if DOMAIN_RE.search(text) or has_high_entropy_secret(text):
            counters["url_reference_redacted"] += 1
            return "<REDACTED:URL_REFERENCE>"
        return "<OMITTED>"

    def _sanitize_allowed_header(self, lower_name: str, value: str, counters: Counter[str]) -> str:
        if lower_name in {"access-control-allow-origin"}:
            if value.strip() == "*":
                return "*"
            split = urlsplit(value)
            if split.hostname:
                counters["cors_origin_alias"] += 1
                return f"{split.scheme or 'https'}://{self._host_alias(split.hostname)}"
        if scan_text(value) or has_high_entropy_secret(value):
            counters["header_value_redacted"] += 1
            return "<REDACTED:HEADER_VALUE>"
        return value[:200]

    def _redact_set_cookie(self, value: str, counters: Counter[str]) -> dict[str, Any]:
        parts = [part.strip() for part in value.split(";") if part.strip()]
        cookie_name = parts[0].split("=", 1)[0] if parts else "cookie"
        safe_cookie_name = _safe_output_name(cookie_name, counters, "cookie")
        attrs = {part.split("=", 1)[0].lower(): part for part in parts[1:]}
        secure = "secure" in attrs
        httponly = "httponly" in attrs
        samesite = attrs.get("samesite", "SameSite=None")
        domain_alias = ""
        if "domain" in attrs and "=" in attrs["domain"]:
            domain_value = attrs["domain"].split("=", 1)[1].strip().lstrip(".")
            domain_alias = self._host_alias(domain_value)
            counters["set_cookie_domain_alias"] += 1
        if "=" in samesite:
            samesite_value = samesite.split("=", 1)[1]
        else:
            samesite_value = "present"
        counters["set_cookie_value"] += 1
        domain_part = f"; Domain={domain_alias}" if domain_alias else ""
        return {
            "summary": f"{safe_cookie_name}=<REDACTED>{domain_part}; Secure={secure}; HttpOnly={httponly}; SameSite={samesite_value}",
            "security": {
                "name": safe_cookie_name,
                "domain": domain_alias or "not_reported",
                "secure": secure,
                "httponly": httponly,
                "samesite": samesite_value,
            },
        }

    def _body_schema(
        self, body: Any, context: str, counters: Counter[str], status: int = 0
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        sensitive_fields: list[str] = []
        schema_fields: list[str] = []
        parsed = _parse_json_body(body)
        if parsed is not None:
            return _json_schema(parsed, counters, sensitive_fields, schema_fields), {
                "sensitive_fields": sensitive_fields,
                "schema_fields": schema_fields,
                "snippet_present": False,
            }

        text = "" if body is None else str(body)
        if not text:
            return {"type": "empty"}, {"sensitive_fields": [], "schema_fields": [], "snippet_present": False}
        html_schema = _html_schema(text, counters, sensitive_fields, schema_fields, self._host_alias)
        if html_schema is not None:
            return html_schema, {
                "sensitive_fields": sensitive_fields,
                "schema_fields": schema_fields,
                "snippet_present": False,
            }
        form_schema = _urlencoded_form_schema(text, counters, sensitive_fields, schema_fields)
        if form_schema is not None:
            return form_schema, {
                "sensitive_fields": sensitive_fields,
                "schema_fields": schema_fields,
                "snippet_present": False,
            }
        multipart_schema = _multipart_schema(text, counters, sensitive_fields, schema_fields)
        if multipart_schema is not None:
            return multipart_schema, {
                "sensitive_fields": sensitive_fields,
                "schema_fields": schema_fields,
                "snippet_present": False,
            }
        if _looks_like_blob_text(text):
            counters["blob_or_binary_body"] += 1
            return {"type": "blob_or_binary", "length": len(text), "mode": "metadata_only"}, {
                "sensitive_fields": sensitive_fields,
                "schema_fields": schema_fields,
                "snippet_present": False,
            }
        summary: dict[str, Any] = {"type": "text", "length": len(text), "mode": "schema_only"}
        snippet_present = False
        if (
            context == "response"
            and status >= 400
            and self.policy.response_snippet_allowed
            and self.policy.allow_error_snippet_after_scan
        ):
            snippet = _safe_error_snippet(text, counters, self.policy.max_snippet_chars)
            if snippet:
                summary["error_snippet"] = snippet
                snippet_present = True
        return summary, {
            "sensitive_fields": sensitive_fields,
            "schema_fields": schema_fields,
            "snippet_present": snippet_present,
        }


def _template_path(path: str, counters: Counter[str]) -> tuple[str, bool]:
    identifier_found = False
    parts = []
    for raw_segment in path.split("/"):
        segment = raw_segment.strip()
        if not segment:
            parts.append("")
            continue
        replacement = None
        if segment.isdigit():
            replacement = "{id}"
        elif UUID_RE.match(segment):
            replacement = "{uuid}"
        elif HASH_SEGMENT_RE.match(segment):
            replacement = "{hash}"
        elif EMAIL_RE.search(segment):
            replacement = "{email}"
        elif DOMAIN_RE.search(segment):
            replacement = "{domain_ref}"
        elif has_high_entropy_secret(segment):
            replacement = "{secret}"
        elif len(segment) > 64 or not SAFE_PATH_SEGMENT_RE.match(segment):
            replacement = "{opaque}"
        if replacement:
            identifier_found = True
            counters[f"path_template_{replacement.strip('{}')}"] += 1
            parts.append(replacement)
        else:
            parts.append(segment)
    templated = "/".join(parts)
    return templated if templated.startswith("/") else f"/{templated}", identifier_found


def _json_schema(
    value: Any,
    counters: Counter[str],
    sensitive_fields: list[str],
    schema_fields: list[str],
    path: str = "$",
) -> Any:
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key, child in value.items():
            key_text = str(key)
            safe_key = _safe_output_name(key_text, counters, "field")
            if safe_key in result:
                counters["field_name_collision"] += 1
                safe_key = f"{safe_key}_{counters['field_name_collision']:03d}"
            child_path = f"{path}.{safe_key}"
            schema_fields.append(child_path)
            if SENSITIVE_NAME_RE.search(key_text):
                counters["body_sensitive_field"] += 1
                sensitive_fields.append(child_path)
                result[safe_key] = _sensitive_placeholder_for_key(key_text)
                continue
            if URL_CONTEXT_NAME_RE.search(key_text):
                counters["body_url_reference_field"] += 1
                sensitive_fields.append(child_path)
                result[safe_key] = _url_reference_schema(child)
                continue
            result[safe_key] = _json_schema(child, counters, sensitive_fields, schema_fields, child_path)
        return result
    if isinstance(value, list):
        if not value:
            return []
        return [_json_schema(value[0], counters, sensitive_fields, schema_fields, f"{path}[]")]
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    text = str(value)
    if FINANCIAL_RE.search(text):
        counters["body_financial_id"] += 1
        sensitive_fields.append(path)
        return "<FINANCIAL_ID>"
    if EMAIL_RE.search(text):
        counters["body_email"] += 1
        sensitive_fields.append(path)
        return "email_redacted"
    if PHONE_RE.search(text):
        counters["body_phone"] += 1
        sensitive_fields.append(path)
        return "phone_redacted"
    if KOR_RRN_RE.search(text):
        counters["body_kor_rrn"] += 1
        sensitive_fields.append(path)
        return "<KOR_RRN>"
    if JWT_RE.search(text) or has_high_entropy_secret(text):
        counters["body_secret"] += 1
        sensitive_fields.append(path)
        return "<REDACTED:SECRET>"
    if DOMAIN_RE.search(text) or _looks_like_url(text):
        counters["body_url_reference_value"] += 1
        sensitive_fields.append(path)
        return "url_reference_redacted"
    return "string"


def _parse_json_body(body: Any) -> Any | None:
    if isinstance(body, (dict, list)):
        return body
    if not isinstance(body, str):
        return None
    text = body.strip()
    if not text or text[0] not in "[{":
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


def _urlencoded_form_schema(
    text: str, counters: Counter[str], sensitive_fields: list[str], schema_fields: list[str]
) -> dict[str, Any] | None:
    stripped = text.strip()
    if "=" not in stripped or ("\n" in stripped and "&" not in stripped):
        return None
    parsed = parse_qs(stripped, keep_blank_values=True)
    if not parsed:
        return None
    fields: dict[str, Any] = {}
    for name, values in parsed.items():
        safe_name = _safe_output_name(name, counters, "form_field")
        field_path = f"$.{safe_name}"
        schema_fields.append(field_path)
        field_type = _infer_values_type(values)
        fields[safe_name] = {"type": field_type, "sample_removed": True}
        if (
            SENSITIVE_NAME_RE.search(name)
            or URL_CONTEXT_NAME_RE.search(name)
            or field_type.endswith("_redacted")
            or field_type == "secret_redacted"
        ):
            counters["form_sensitive_field"] += 1
            sensitive_fields.append(field_path)
            fields[safe_name]["transformation"] = "redacted_sensitive_parameter"
        else:
            fields[safe_name]["transformation"] = "schema_only"
    return {"type": "form_urlencoded", "fields": fields}


def _multipart_schema(
    text: str, counters: Counter[str], sensitive_fields: list[str], schema_fields: list[str]
) -> dict[str, Any] | None:
    stripped = text.lstrip()
    if not stripped.startswith("--") or "multipart" in stripped[:80].lower():
        return None
    names = re.findall(r'name="([^"]+)"', text)
    if not names:
        return None
    fields: list[dict[str, Any]] = []
    for name in names:
        safe_name = _safe_output_name(name, counters, "multipart_field")
        field_path = f"$.{safe_name}"
        schema_fields.append(field_path)
        is_sensitive = bool(SENSITIVE_NAME_RE.search(name))
        if is_sensitive:
            counters["multipart_sensitive_field"] += 1
            sensitive_fields.append(field_path)
        fields.append({"name": safe_name, "sensitive_name": is_sensitive, "value_removed": True})
    return {
        "type": "multipart",
        "part_count": len(names),
        "fields": fields,
        "raw_part_values_included": False,
    }


def _html_schema(
    text: str,
    counters: Counter[str],
    sensitive_fields: list[str],
    schema_fields: list[str],
    host_aliaser: Any,
) -> dict[str, Any] | None:
    if "<html" not in text.lower() and "<form" not in text.lower():
        return None
    inputs: list[dict[str, Any]] = []
    for match in re.finditer(r"<input\b[^>]*>", text, re.IGNORECASE):
        tag = match.group(0)
        raw_name = _html_attr(tag, "name") or ""
        name = _safe_output_name(raw_name, counters, "html_input") if raw_name else ""
        input_type = _html_attr(tag, "type") or "text"
        if name:
            field_path = f"$.html.form.{name}"
            schema_fields.append(field_path)
            if SENSITIVE_NAME_RE.search(raw_name) or input_type.lower() in {"password", "hidden"}:
                counters["html_sensitive_input"] += 1
                sensitive_fields.append(field_path)
        inputs.append({"name": name or "<unnamed>", "type": input_type.lower(), "value_removed": True})
    references = _html_references(text, counters, host_aliaser)
    return {
        "type": "html",
        "title_present": bool(re.search(r"<title\b", text, re.IGNORECASE)),
        "form_count": len(re.findall(r"<form\b", text, re.IGNORECASE)),
        "inputs": inputs[:30],
        "external_references": references[:30],
        "raw_html_included": False,
    }


def _html_attr(tag: str, name: str) -> str | None:
    match = re.search(rf'\b{name}\s*=\s*["\']([^"\']*)["\']', tag, re.IGNORECASE)
    if not match:
        return None
    return match.group(1)


def _html_references(text: str, counters: Counter[str], host_aliaser: Any) -> list[dict[str, str]]:
    references: list[dict[str, str]] = []
    for match in re.finditer(r"\b(href|src|action)\s*=\s*[\"']([^\"']+)[\"']", text, re.IGNORECASE):
        attr = match.group(1).lower()
        value = match.group(2).strip()
        split = urlsplit(value)
        item: dict[str, str] = {"attribute": attr}
        if split.hostname:
            item["host"] = host_aliaser(split.hostname)
            path_template, _ = _template_path(split.path or "/", counters)
            item["path_template"] = path_template
            counters["html_url_reference_alias"] += 1
        elif value.startswith("/"):
            path_template, _ = _template_path(split.path or "/", counters)
            item["path_template"] = path_template
            counters["html_relative_reference_template"] += 1
        else:
            item["reference"] = "omitted"
        references.append(item)
    return references


def _url_reference_schema(value: Any) -> Any:
    if isinstance(value, list):
        return ["url_reference_redacted"] if value else []
    if isinstance(value, dict):
        return {"type": "object", "values_removed": True}
    return "url_reference_redacted"


def _safe_output_name(name: str, counters: Counter[str], prefix: str) -> str:
    text = str(name).strip()
    if (
        not text
        or len(text) > 64
        or not SAFE_OUTPUT_NAME_RE.match(text)
        or scan_text(text)
        or has_high_entropy_secret(text)
    ):
        counter_key = f"{prefix}_name_redacted"
        counters[counter_key] += 1
        return f"{prefix}_{counters[counter_key]:03d}"
    return text


def _templated_query(query: str, counters: Counter[str]) -> str:
    if not query:
        return ""
    parts: list[str] = []
    for name in parse_qs(query, keep_blank_values=True):
        safe_name = _safe_output_name(name, counters, "query_param")
        parts.append(f"{safe_name}={{value}}")
    return f"?{'&'.join(parts)}" if parts else ""


def _looks_like_url(value: str) -> bool:
    split = urlsplit(value)
    return bool(split.scheme and split.hostname)


def _looks_like_blob_text(text: str) -> bool:
    stripped = text.strip()
    if len(stripped) < 80:
        return False
    if "\x00" in stripped:
        return True
    compact = re.sub(r"\s+", "", stripped)
    if len(compact) >= 120 and re.fullmatch(r"[A-Za-z0-9+/=_-]+", compact):
        return True
    return False


def _add_diagnostic(
    diagnostics: list[dict[str, str]],
    failure_type: str,
    event_id: str,
    field_path: str,
    source_kind: str,
) -> None:
    item = {
        "failure_type": failure_type,
        "event_id": event_id,
        "field_path": _safe_diagnostic_field_path(field_path),
        "source_kind": source_kind,
        "value_preview": "<REDACTED>",
    }
    if item not in diagnostics:
        diagnostics.append(item)


def _safe_diagnostic_field_path(field_path: str) -> str:
    if not field_path or len(field_path) > 160 or scan_text(field_path) or has_high_entropy_secret(field_path):
        if field_path.startswith("request.body_schema"):
            return "request.body_schema.<redacted_field>"
        if field_path.startswith("response.body_schema"):
            return "response.body_schema.<redacted_field>"
        if field_path.startswith("request.headers"):
            return "request.headers.<redacted_field>"
        if field_path.startswith("response.headers"):
            return "response.headers.<redacted_field>"
        if field_path.startswith("request.query"):
            return "request.query.<redacted_field>"
        return "<redacted_field>"
    return field_path


def _diagnose_body_fields(
    diagnostics: list[dict[str, str]],
    event_id: str,
    base_path: str,
    source_kind: str,
    fields: list[str],
) -> None:
    for field in fields[:MAX_DIAGNOSTICS_PER_EVENT]:
        suffix = field[1:] if field.startswith("$") else f".{field}"
        _add_diagnostic(diagnostics, "body_sensitive_or_url_field", event_id, f"{base_path}{suffix}", source_kind)


def _url_field_path(source_kind: str) -> str:
    return "xml.url" if source_kind == "burp_xml" else "request.url"


def _safe_error_snippet(text: str, counters: Counter[str], max_chars: int) -> str | None:
    snippet = " ".join(text.strip().split())[:max_chars]
    if not snippet:
        return None
    redacted = _redact_plain_text(snippet, counters)
    if scan_text(redacted) or has_high_entropy_secret(redacted):
        counters["blocked_error_snippet"] += 1
        return None
    return redacted


def _redact_plain_text(text: str, counters: Counter[str]) -> str:
    replacements = [
        (JWT_RE, "<REDACTED:JWT>"),
        (EMAIL_RE, "<EMAIL>"),
        (PHONE_RE, "<PHONE>"),
        (KOR_RRN_RE, "<KOR_RRN>"),
        (FINANCIAL_RE, "<FINANCIAL_ID>"),
    ]
    result = text
    for pattern, placeholder in replacements:
        result, count = pattern.subn(placeholder, result)
        counters[f"text_{placeholder.strip('<>').lower()}"] += count
    return result


def _redact_cookie_header(value: str, counters: Counter[str]) -> str:
    names: list[str] = []
    for part in value.split(";"):
        name = part.split("=", 1)[0].strip()
        if not name:
            continue
        names.append(f"{name}=<REDACTED>")
        counters["cookie_value"] += 1
    return "; ".join(names) if names else "<REDACTED:COOKIE_PRESENT>"


def _redact_set_cookie(value: str, counters: Counter[str]) -> dict[str, Any]:
    parts = [part.strip() for part in value.split(";") if part.strip()]
    cookie_name = parts[0].split("=", 1)[0] if parts else "cookie"
    attrs = {part.split("=", 1)[0].lower(): part for part in parts[1:]}
    secure = "secure" in attrs
    httponly = "httponly" in attrs
    samesite = attrs.get("samesite", "SameSite=None")
    if "=" in samesite:
        samesite_value = samesite.split("=", 1)[1]
    else:
        samesite_value = "present"
    counters["set_cookie_value"] += 1
    return {
        "summary": f"{cookie_name}=<REDACTED>; Secure={secure}; HttpOnly={httponly}; SameSite={samesite_value}",
        "security": {
            "name": cookie_name,
            "secure": secure,
            "httponly": httponly,
            "samesite": samesite_value,
        },
    }


def _sensitive_placeholder_for_key(key: str) -> str:
    lowered = key.lower()
    if "email" in lowered:
        return "email_redacted"
    if "phone" in lowered:
        return "phone_redacted"
    if "rrn" in lowered:
        return "<KOR_RRN>"
    if "account" in lowered or "card" in lowered:
        return "<FINANCIAL_ID>"
    if "password" in lowered or "pwd" in lowered or "passwd" in lowered:
        return "<REDACTED:PASSWORD>"
    return "<REDACTED:SENSITIVE_FIELD>"


def _infer_values_type(values: list[str]) -> str:
    value = values[0] if values else ""
    if value == "":
        return "empty"
    if UUID_RE.match(value):
        return "uuid"
    lowered = value.lower()
    if lowered in {"true", "false"}:
        return "boolean"
    if EMAIL_RE.search(value):
        return "email_redacted"
    if FINANCIAL_RE.search(value):
        return "financial_id_redacted"
    if PHONE_RE.search(value):
        return "phone_redacted"
    if KOR_RRN_RE.search(value):
        return "kor_rrn_redacted"
    if value.isdigit():
        return "integer"
    if JWT_RE.search(value) or has_high_entropy_secret(value):
        return "secret_redacted"
    return "string"


def _canonical_header(name: str) -> str:
    return "-".join(part[:1].upper() + part[1:].lower() for part in name.split("-"))


def _header_value(headers: dict[str, Any], canonical_name: str) -> str:
    value = headers.get(canonical_name, "")
    return value if isinstance(value, str) else ""


def _is_private_ip(host: str) -> bool:
    return host.startswith(("10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.", "172.2", "172.30.", "172.31.", "127."))


def _private_ip_bucket(host: str) -> str:
    if host.startswith("10."):
        return "10.0.0.0/8"
    if host.startswith("192.168."):
        return "192.168.0.0/16"
    if host.startswith("127."):
        return "127.0.0.0/8"
    return "172.16.0.0/12"
