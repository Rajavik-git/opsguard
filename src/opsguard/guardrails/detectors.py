"""Detectors shared by input and output guardrails: prompt injection,
jailbreak attempts, secrets and PII (banking-grade redaction)."""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass
class Finding:
    kind: str  # injection | jailbreak | secret | pii
    rule: str
    excerpt: str


# --- Prompt injection (indirect, inside logs / events / documents) -----------
INJECTION_PATTERNS = {
    "ignore_instructions": r"\b(ignore|disregard|forget|oublie[zr]?|ignore[zr]?)\b.{0,40}\b(previous|prior|above|all|précédentes?|toutes?)\b.{0,20}\b(instructions?|rules|règles|consignes)",
    "system_override": r"\b(system|admin|developer)\s*(override|mode|prompt)\b|\[\s*system\s*\]|<\s*/?\s*system\s*>",
    "role_hijack": r"\byou\s+are\s+now\b|\bact\s+as\b|\btu\s+es\s+maintenant\b|\bnew\s+instructions?\b",
    "agent_directive": r"\b(as|to)\s+the\s+(ai|sre|llm)?\s*(agent|assistant)\b.{0,60}\b(must|should|need)",
}

# --- Direct jailbreak attempts from the user --------------------------------
JAILBREAK_PATTERNS = {
    "dan": r"\bDAN\b|do\s+anything\s+now",
    "rules_bypass": r"\b(bypass|ignore|désactive[zr]?|contourne[zr]?)\b.{0,30}\b(guardrails?|safety|sécurité|policy|politique|règles|rules|restrictions?)",
    "no_approval": r"\b(sans|without)\s+(validation|approval|confirmation)\b",
}

# --- Secrets ------------------------------------------------------------------
SECRET_PATTERNS = {
    # UPPER_CASE env vars (DB_PASSWORD=...), case-sensitive on purpose
    "env_secret": r"\b([A-Z0-9_]*(?:PASSWORD|PASSWD|SECRET|TOKEN|API_KEY|APIKEY)[A-Z0-9_]*)\s*[=:]\s*([^\s\"'<>,]{4,})",
    # lower-case config / YAML forms (password: ...)
    "config_secret": r"(?i)\b(?:password|passwd|api[_-]?key|secret|token)\s*[:=]\s*[\"']?[^\s\"'<>,]{4,}",
    "aws_key": r"\bAKIA[0-9A-Z]{16}\b",
    "bearer": r"(?i)\bbearer\s+[A-Za-z0-9\-_.=]{20,}",
    "private_key": r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----",
    "kubeconfig_key": r"(client-key-data|client-certificate-data|token):\s*[A-Za-z0-9+/=]{20,}",
    "openai_key": r"\bsk-[A-Za-z0-9\-_]{20,}",
}

# --- PII (customer data must never leave the perimeter, e.g. to an LLM API) ---
PII_PATTERNS = {
    "iban": r"\b[A-Z]{2}\d{2}(?:\s?[A-Z0-9]{4}){3,7}(?:\s?[A-Z0-9]{1,3})?\b",
    "card": r"\b(?:\d[ -]?){13,16}\b",
    "email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
    "phone_fr": r"(?<!\d)(?:\+33\s?|0)[1-9](?:[\s.-]?\d{2}){4}(?!\d)",
}

_C = {k: re.compile(v, re.IGNORECASE) for k, v in INJECTION_PATTERNS.items()}
_J = {k: re.compile(v, re.IGNORECASE) for k, v in JAILBREAK_PATTERNS.items()}
_S = {k: re.compile(v) for k, v in SECRET_PATTERNS.items()}
_P = {k: re.compile(v) for k, v in PII_PATTERNS.items()}


def detect_injection(text: str) -> list[Finding]:
    return [Finding("injection", k, m.group(0)[:80]) for k, rx in _C.items() if (m := rx.search(text))]


def detect_jailbreak(text: str) -> list[Finding]:
    return [Finding("jailbreak", k, m.group(0)[:80]) for k, rx in _J.items() if (m := rx.search(text))]


def redact(text: str, secrets: bool = True, pii: bool = True) -> tuple[str, list[Finding]]:
    findings: list[Finding] = []
    if secrets:
        for k, rx in _S.items():
            def _sub(m, k=k):
                findings.append(Finding("secret", k, m.group(0)[:12] + "…"))
                if k == "env_secret":
                    return f"{m.group(1)}=[REDACTED:SECRET]"
                return "[REDACTED:SECRET]"

            text = rx.sub(_sub, text)
    if pii:
        for k, rx in _P.items():
            def _sub(m, k=k):
                findings.append(Finding("pii", k, "***"))
                return f"[REDACTED:{k.upper()}]"

            text = rx.sub(_sub, text)
    return text, findings
