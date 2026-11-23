"""
AegisSOC AI Security Analyst - Input Sanitizer & Prompt Injection Defense
Sanitizes untrusted logs, network payloads, external intelligence, and imported documents.
Enforces redaction of sensitive credentials, secrets, and injection markers.
"""

import re
from typing import Optional


# Prompt injection keywords and patterns commonly found in adversarial attacks
INJECTION_PATTERNS = [
    re.compile(r"(?i)\bignore\s+(all\s+)?(previous|prior|above)\s+instructions\b"),
    re.compile(r"(?i)\bdisregard\s+(all\s+)?(previous|prior|system)\s+instructions\b"),
    re.compile(r"(?i)\byou\s+are\s+now\s+(in\s+)?(dan|developer|god|jailbreak)\s+mode\b"),
    re.compile(r"(?i)\bprompt\s*injection\b"),
    re.compile(r"(?i)\bsystem\s*:\s*override\b"),
    re.compile(r"(?i)\bnew\s+system\s+prompt\b"),
    re.compile(r"(?i)<\s*/?\s*system\s*>"),
    re.compile(r"(?i)<\s*/?\s*im_start\s*>"),
    re.compile(r"(?i)<\s*/?\s*im_end\s*>"),
    re.compile(r"(?i)\[\s*INST\s*\]"),
    re.compile(r"(?i)\[\s*/\s*INST\s*\]"),
]

# Sensitive information patterns: passwords, tokens, private keys, API keys
CREDENTIAL_PATTERNS = [
    (re.compile(r"(?i)(password|passwd|pwd)[\s\"'=:]+([^\s,;\"'}{]{4,})"), r"\1=[REDACTED]"),
    (re.compile(r"(?i)(bearer\s+)[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.?[A-Za-z0-9\-_=]*"), r"\1[REDACTED_JWT]"),
    (re.compile(r"(?i)(api[_-]?key|secret[_-]?key|access[_-]?token)[\s\"'=:]+([^\s,;\"'}{]{8,})"), r"\1=[REDACTED]"),
    (re.compile(r"-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----[\s\S]*?-----END\s+(?:RSA\s+)?PRIVATE\s+KEY-----"), "[REDACTED_PRIVATE_KEY]"),
]


def mask_sensitive_data(text: Optional[str]) -> str:
    """Masks credentials, secrets, private keys, and authorization tokens."""
    if not text:
        return ""
    result = text
    for pattern, replacement in CREDENTIAL_PATTERNS:
        result = pattern.sub(replacement, result)
    return result


def sanitize_untrusted_input(text: Optional[str], max_length: int = 4000) -> str:
    """
    Sanitizes untrusted text (logs, payloads, external intelligence).
    - Neutralizes jailbreak / prompt injection markers.
    - Masks sensitive credentials.
    - Limits length to prevent token exhaustion.
    """
    if not text:
        return ""

    # Truncate to maximum length
    clean = text[:max_length]

    # Neutralize prompt injection phrases
    for pattern in INJECTION_PATTERNS:
        clean = pattern.sub("[FILTERED_POTENTIAL_INJECTION]", clean)

    # Redact sensitive credentials
    clean = mask_sensitive_data(clean)

    return clean.strip()


def format_untrusted_evidence(evidence_id: str, evidence_type: str, content: str) -> str:
    """
    Wraps sanitized untrusted data in strict XML delimiter tags
    instructing the LLM to process it strictly as data, never as prompt instructions.
    """
    sanitized = sanitize_untrusted_input(content)
    return (
        f'<untrusted_evidence_data id="{evidence_id}" type="{evidence_type}">\n'
        f"{sanitized}\n"
        f"</untrusted_evidence_data>"
    )
