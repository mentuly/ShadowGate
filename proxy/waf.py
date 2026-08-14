import html
import json
import re
import urllib.parse


def _normalize_text(value: str) -> str:
    if not value:
        return ''
    text = str(value)
    for _ in range(6):
        decoded = urllib.parse.unquote(text)
        if decoded == text:
            break
        text = decoded
    text = html.unescape(text)
    text = text.replace('+', ' ')
    text = re.sub(r'[\x00-\x20]+', ' ', text)
    return text.lower()


WAF_PATTERNS = {
    'sql_injection': re.compile(
        r"(?i)(?:\b(?:select|union|insert|update|delete|drop|alter|create|from|where|information_schema|benchmark|exec)\b|--|;|\b(?:or|and)\b\s+\w+\s*=\s*\w+|/\*|\*/)",
        re.MULTILINE,
    ),
    'xss': re.compile(
        r"(?i)(?:<script|<img|javascript:|onerror=|onload=|document\.cookie|<iframe|<svg|<body|<link|expression\s*\(|<style|<meta|<object|<embed|srcdoc|vbscript:)",
        re.MULTILINE,
    ),
    'path_traversal': re.compile(
        r"(?i)(?:\.\./|\.\\|/etc/passwd|/proc/self|%2e%2e|%2f|%5c|\\x2e\\x2e|\\0|/windows/win.ini|\.\.|/\.\.)",
        re.MULTILINE,
    ),
}

WAF_LITERAL_RULES = {
    'sql_injection': (
        'select ', 'union ', 'insert ', 'update ', 'delete ', 'drop ', 'alter ', 'create ', 'from ', 'where ',
        'information_schema', 'benchmark(', 'exec ', 'or 1=1', '--', '/*', '*/', ';'
    ),
    'xss': (
        '<script', 'javascript:', 'onerror=', 'onload=', 'document.cookie', '<iframe', '<svg', '<body',
        '<img', '<meta', 'srcdoc', 'vbscript:'
    ),
    'path_traversal': (
        '../', '..\\', '/etc/passwd', '/proc/self', '/windows/win.ini', '%2e%2e', '%2f', '\\x2e\\x2e', '\\0'
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
        if any(marker in combined for marker in WAF_LITERAL_RULES[name]):
            return True, name, {'matched': [marker for marker in WAF_LITERAL_RULES[name] if marker in combined][:10], 'sample': combined[:400]}
        if pattern.search(combined):
            return True, name, {'matched': pattern.pattern, 'sample': combined[:400]}
    return None


def render_blocked_page(rule_name: str, details: dict) -> str:
    safe_rule_name = html.escape(str(rule_name))
    safe_details = html.escape(json.dumps(details, ensure_ascii=False))
    return f"<html><body><h1>403 Forbidden</h1><p>Request blocked by WAF rule: <strong>{safe_rule_name}</strong></p><pre>{safe_details}</pre></body></html>"
