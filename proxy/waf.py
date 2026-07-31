import html
import json
import re
import urllib.parse


def _normalize_text(value: str) -> str:
    if not value:
        return ''
    text = value
    for _ in range(4):
        decoded = urllib.parse.unquote(text)
        if decoded == text:
            break
        text = decoded
    return text.replace('+', ' ')


WAF_PATTERNS = {
    'sql_injection': re.compile(
        r"(?i)(?:\b(select|union|insert|update|delete|drop|alter|create|from|where)\b|--|;|\b(or|and)\b\s+\w+\s*=\s*\w+|\bexec\b|\bscript\b|\binformation_schema\b|\bbenchmark\b|/\*|\*/)",
        re.MULTILINE,
    ),
    'xss': re.compile(
        r"(?i)(?:<script|<img|javascript:|onerror=|onload=|document\.cookie|<iframe|<svg|<body|<link|expression\s*\(|<style|<meta|<object|<embed)",
        re.MULTILINE,
    ),
    'path_traversal': re.compile(
        r"(?i)(?:\.\./|\.\\|/etc/passwd|/proc/self|%2e%2e|%2f|%5c|\\x2e\\x2e|\\0|/windows/win.ini)",
        re.MULTILINE,
    ),
}


def scan_request_components(path: str, query: str, body_text: str, enabled_rules: dict, headers: dict | None = None) -> tuple[bool, str, dict] | None:
    header_text = ' '.join(_normalize_text(str(value)) for value in (headers or {}).values())
    combined = ' '.join([
        _normalize_text(path),
        _normalize_text(query),
        _normalize_text(body_text),
        header_text,
    ])
    for name, pattern in WAF_PATTERNS.items():
        if not enabled_rules.get(name, False):
            continue
        if pattern.search(combined):
            return True, name, {'matched': pattern.pattern, 'sample': combined[:400]}
    return None


def render_blocked_page(rule_name: str, details: dict) -> str:
    safe_rule_name = html.escape(str(rule_name))
    safe_details = html.escape(json.dumps(details, ensure_ascii=False))
    return f"<html><body><h1>403 Forbidden</h1><p>Request blocked by WAF rule: <strong>{safe_rule_name}</strong></p><pre>{safe_details}</pre></body></html>"
