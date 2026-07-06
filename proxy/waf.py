import re
import urllib.parse


def _normalize_text(value: str) -> str:
    if not value:
        return ''
    return urllib.parse.unquote(value).replace('+', ' ')


WAF_PATTERNS = {
    'sql_injection': re.compile(
        r"(?i)(?:\b(select|union|insert|update|delete|drop|alter|create|from|where)\b|--|;|\b(or|and)\b\s+\w+\s*=\s*\w+|\bexec\b|\bscript\b|\binformation_schema\b|\bbenchmark\b)",
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


def scan_request_components(path: str, query: str, body_text: str, enabled_rules: dict) -> tuple[bool, str, dict] | None:
    combined = ' '.join([_normalize_text(path), _normalize_text(query), _normalize_text(body_text)])
    for name, pattern in WAF_PATTERNS.items():
        if not enabled_rules.get(name, False):
            continue
        if pattern.search(combined):
            return True, name, {'matched': pattern.pattern, 'sample': combined[:400]}
    return None


def render_blocked_page(rule_name: str, details: dict) -> str:
    return f"<html><body><h1>403 Forbidden</h1><p>Request blocked by WAF rule: <strong>{rule_name}</strong></p><pre>{details}</pre></body></html>"
