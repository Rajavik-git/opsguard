"""Guardrails layer: input (user), untrusted data (tools/RAG) and output (actions)."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

import yaml

from ..llm.tokens import truncate_to_tokens
from .detectors import Finding, detect_injection, detect_jailbreak, redact


class Decision(str, Enum):
    ALLOW = "allow"
    REQUIRE_APPROVAL = "require_approval"
    BLOCK = "block"


@dataclass
class CommandVerdict:
    command: str
    decision: Decision
    rule: str
    reason: str


@dataclass
class GuardEvent:
    layer: str  # input | untrusted | output | tool_scope
    action: str  # blocked | redacted | neutralized | downgraded | flagged
    detail: str
    findings: list[Finding] = field(default_factory=list)


@dataclass
class InputVerdict:
    allowed: bool
    text: str
    events: list[GuardEvent]


class Guardrails:
    """All guardrails in one object so they can be toggled for red-team A/B runs."""

    def __init__(self, policy_path: str | Path, enabled: bool = True):
        cfg = yaml.safe_load(Path(policy_path).read_text(encoding="utf-8"))
        self.enabled = enabled
        self.rules = [
            (r["id"], re.compile(r["pattern"], re.IGNORECASE), Decision(r["decision"]), r["reason"])
            for r in cfg["command_rules"]
        ]
        self.namespace_allowlist: set[str] = set(cfg.get("tool_namespace_allowlist", []))
        self.max_untrusted_tokens: int = cfg.get("max_untrusted_tokens", 1200)

    # ---------------------------------------------------------------- input
    def check_input(self, text: str) -> InputVerdict:
        """User request: block jailbreaks, redact secrets/PII before any LLM call."""
        if not self.enabled:
            return InputVerdict(True, text, [])
        events: list[GuardEvent] = []
        jb = detect_jailbreak(text) + detect_injection(text)
        if jb:
            events.append(GuardEvent("input", "blocked", "tentative de contournement détectée", jb))
            return InputVerdict(False, text, events)
        clean, found = redact(text)
        if found:
            events.append(GuardEvent("input", "redacted", f"{len(found)} donnée(s) sensible(s) masquée(s)", found))
        return InputVerdict(True, clean, events)

    # ------------------------------------------------------- untrusted data
    def sanitize_untrusted(self, text: str, source: str) -> tuple[str, list[GuardEvent]]:
        """Tool outputs and RAG chunks are DATA, never instructions:
        redact secrets/PII, neutralise injected directives, bound size, and
        spotlight with explicit delimiters."""
        if not self.enabled:
            return text, []
        events: list[GuardEvent] = []
        text, found = redact(text)
        if found:
            events.append(GuardEvent("untrusted", "redacted", f"{source}: {len(found)} secret(s)/PII masqué(s)", found))
        kept = []
        for line in text.splitlines():
            inj = detect_injection(line)
            if inj:
                events.append(GuardEvent("untrusted", "neutralized", f"{source}: instruction injectée retirée", inj))
                kept.append("[QUARANTINED: suspected prompt injection removed by OpsGuard]")
            else:
                kept.append(line)
        text = truncate_to_tokens("\n".join(kept), self.max_untrusted_tokens)
        return f'<untrusted_data source="{source}">\n{text}\n</untrusted_data>', events

    def check_tool_scope(self, tool: str, args: dict) -> GuardEvent | None:
        """Least privilege: agents can only read allow-listed namespaces."""
        if not self.enabled:
            return None
        ns = args.get("namespace")
        if ns is not None and ns not in self.namespace_allowlist:
            return GuardEvent("tool_scope", "blocked", f"{tool}: namespace '{ns}' hors périmètre")
        return None

    # --------------------------------------------------------------- output
    def classify_command(self, command: str) -> CommandVerdict:
        for rule_id, rx, decision, reason in self.rules:
            if rx.search(command):
                return CommandVerdict(command, decision, rule_id, reason)
        return CommandVerdict(command, Decision.REQUIRE_APPROVAL, "DEFAULT", "Commande non répertoriée — validation requise")

    def check_output_text(self, text: str) -> tuple[str, list[GuardEvent]]:
        if not self.enabled:
            return text, []
        clean, found = redact(text)
        return clean, ([GuardEvent("output", "redacted", "fuite de secret/PII bloquée dans la réponse", found)] if found else [])

    def check_action(self, action: dict, known_citations: set[str], environment: str) -> tuple[dict | None, list[GuardEvent]]:
        """Returns the (possibly downgraded) action, or None when blocked."""
        if not self.enabled:
            action["decision"] = Decision.ALLOW.value
            return action, []
        events: list[GuardEvent] = []
        verdict = self.classify_command(action["command"])
        if verdict.decision is Decision.BLOCK:
            events.append(GuardEvent("output", "blocked", f"{verdict.rule}: {verdict.reason} — `{action['command']}`"))
            return None, events
        decision = verdict.decision
        # Grounding: a mutating action must cite a runbook section actually retrieved
        # during this run — otherwise it may come from an injection or a hallucination.
        cites = set(action.get("citations", []))
        if decision is not Decision.ALLOW and not (cites & known_citations):
            events.append(GuardEvent("output", "blocked", f"GROUNDING: action de modification non sourcée — `{action['command']}`"))
            return None, events
        if environment == "prod" and decision is Decision.ALLOW and action.get("risk") == "high":
            decision = Decision.REQUIRE_APPROVAL
        action["decision"] = decision.value
        action["policy_rule"] = verdict.rule
        return action, events
